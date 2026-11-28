// Durable audit trail: records survive a restart, writes are batched and serialized, a conflicting writer never loses
// records, failures retry, the GitHub store only ever touches audit/ paths and never leaks its token.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { freePort } from './free-port.mjs';

const TENANT = '11111111-1111-1111-1111-111111111111';
const CLIENT = '22222222-2222-2222-2222-222222222222';
const OID = '33333333-3333-3333-3333-333333333333';
Object.assign(process.env, { DEMO_MODE: 'false', ENTRA_TENANT_ID: TENANT, ENTRA_CLIENT_ID: CLIENT, ENTRA_CERT_THUMBPRINT: 'A'.repeat(40), ENTRA_CERT_PRIVATE_KEY_PATH: 'C:\\outside\\entity360\\test-key.pem' });
const { AuditTrail, createLocalAuditStore, createGitHubAuditStore, auditStoreFromEnv, partPath, AUDIT_PREFIX } = await import('../server/audit-trail.mjs');
const { auditStatusText } = await import('../public/authz-log.js');
const { createApp } = await import('../server/index.mjs');

const NOW = Date.parse('2026-11-13T04:30:00Z');
const tmp = async t => { const dir = await mkdtemp(path.join(os.tmpdir(), 'e360-audit-')); t.after(() => rm(dir, { recursive: true, force: true })); return dir; };
const quiet = { write: () => {}, delayMs: 60_000 };
const lines = text => text.trim().split('\n').map(l => JSON.parse(l));

// An in-memory GitHub contents API: enough to check paths, headers, base64 bodies and sha conflicts.
function fakeGitHub({ token = 'test-token' } = {}) {
  const files = new Map(), calls = [];
  let n = 0;
  const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
  const fetchImpl = async (url, init = {}) => {
    const u = new URL(url), p = decodeURIComponent(u.pathname.replace(/^\/repos\/[^/]+\/[^/]+\/contents\//, ''));
    calls.push({ method: init.method || 'GET', path: p, auth: init.headers?.authorization, redirect: init.redirect });
    if (init.headers?.authorization !== `Bearer ${token}`) return json({ message: 'Bad credentials' }, 401);
    if ((init.method || 'GET') === 'GET') {
      if (files.has(p)) { const f = files.get(p); return json({ type: 'file', name: p.split('/').pop(), sha: f.sha, size: Buffer.byteLength(f.text), encoding: 'base64', content: Buffer.from(f.text).toString('base64').replace(/(.{60})/g, '$1\n') }); }
      const kids = [...files.keys()].filter(k => k.startsWith(p + '/') && !k.slice(p.length + 1).includes('/'));
      return kids.length ? json(kids.map(k => ({ type: 'file', name: k.split('/').pop(), size: Buffer.byteLength(files.get(k).text) }))) : json({ message: 'Not Found' }, 404);
    }
    const body = JSON.parse(init.body), cur = files.get(p);
    if ((cur?.sha ?? undefined) !== body.sha) return json({ message: `${p} does not match` }, cur ? 409 : 422);
    const sha = `sha${++n}`;
    files.set(p, { text: Buffer.from(body.content, 'base64').toString('utf8'), sha });
    return json({ content: { sha } }, cur ? 200 : 201);
  };
  return { files, calls, fetchImpl };
}

// ---------------------------------------------------------------- the trail
test('a record goes to stdout at once and to one day file, batched into a single write', async t => {
  const dir = await tmp(t), out = [];
  const store = createLocalAuditStore(dir); let puts = 0; const put = store.put.bind(store); store.put = (...a) => { puts++; return put(...a); };
  const trail = new AuditTrail({ store, write: l => out.push(l), now: () => NOW, delayMs: 60_000 });
  const a = trail.record({ type: 'remediation-run', reason: 'vpn' });
  trail.record({ type: 'authz', outcome: 'denied' });
  assert.equal(out.length, 2); assert.ok(out[0].startsWith(AUDIT_PREFIX)); assert.equal(JSON.parse(out[0].slice(AUDIT_PREFIX.length)).id, a.id);
  assert.match(a.id, /^[0-9a-f-]{36}$/); assert.equal(a.time, '2026-11-13T04:30:00.000Z');
  assert.equal(trail.status().pending, 2);
  await trail.flush();
  assert.equal(puts, 1, 'one commit for the batch');
  const file = await readFile(path.join(dir, 'audit', '2026-11', '2026-11-13.jsonl'), 'utf8');
  assert.deepEqual(lines(file).map(r => r.type), ['remediation-run', 'authz']);
  assert.equal(trail.status().pending, 0); assert.ok(trail.status().lastWriteAt);
  trail.record({ type: 'authz', outcome: 'denied' }); await trail.flush();
  assert.equal(lines(await readFile(path.join(dir, 'audit', '2026-11', '2026-11-13.jsonl'), 'utf8')).length, 3, 'appends to the same day');
});

test('a full part rolls to the next one, and recent() reads every part in order across a restart', async t => {
  const dir = await tmp(t);
  const trail = new AuditTrail({ store: createLocalAuditStore(dir), ...quiet, now: () => NOW, maxPart: 600 });
  for (let i = 0; i < 12; i++) trail.record({ type: 'authz', outcome: 'denied', reason: `r${i}`.padEnd(60, '.') });
  await trail.flush();
  const later = new AuditTrail({ store: createLocalAuditStore(dir), ...quiet, now: () => NOW + 3600_000, maxPart: 600 });
  const back = await later.recent({ days: 2 });
  assert.deepEqual(back.map(r => r.reason.replace(/\.+$/, '')), Array.from({ length: 12 }, (_, i) => `r${i}`));
  assert.ok((await readFile(path.join(dir, ...partPath('2026-11-13', 1).split('/')), 'utf8')).length > 0, 'a second part exists');
  later.record({ type: 'authz', outcome: 'denied', reason: 'after restart' }); await later.flush();
  assert.equal((await later.recent({ days: 1 })).at(-1).reason, 'after restart');
  assert.deepEqual((await later.recent({ days: 1, types: ['remediation-run'] })), []);
});

test('another writer between read and write is not overwritten: the trail re-reads and appends', async t => {
  const dir = await tmp(t), store = createLocalAuditStore(dir);
  const trail = new AuditTrail({ store, ...quiet, now: () => NOW });
  trail.record({ type: 'authz', reason: 'first' }); await trail.flush();
  const other = new AuditTrail({ store, ...quiet, now: () => NOW });
  other.record({ type: 'authz', reason: 'other writer' }); await other.flush();
  trail.record({ type: 'authz', reason: 'second' }); await trail.flush();
  assert.deepEqual((await trail.recent({ days: 1 })).map(r => r.reason), ['first', 'other writer', 'second']);
});

test('a failed write keeps the records, reports the error and retries; a retried write is not duplicated on read', async t => {
  const dir = await tmp(t), store = createLocalAuditStore(dir), put = store.put.bind(store);
  let fail = true; store.put = (...a) => fail ? Promise.reject(Object.assign(new Error('audit repository returned HTTP 503'), { status: 503 })) : put(...a);
  const trail = new AuditTrail({ store, ...quiet, now: () => NOW, retryMs: [60_000] });
  const rec = trail.record({ type: 'remediation-run', reason: 'kept' });
  await trail.flush();
  assert.equal(trail.status().pending, 1); assert.match(trail.status().lastError, /503/);
  assert.match(auditStatusText(trail.status()), /Writing is failing \(audit repository returned HTTP 503\); 1 record\(s\) are waiting/);
  fail = false; await trail.flush();
  assert.equal(trail.status().pending, 0); assert.equal(trail.status().lastError, null);
  // The same record written twice (an answer lost after a successful write) is read back once.
  const again = new AuditTrail({ store, ...quiet, now: () => NOW });
  again.pending.push(rec); await again.flush();
  assert.equal((await again.recent({ days: 1 })).filter(r => r.id === rec.id).length, 1);
  clearTimeout(trail.timer);
});

test('pending records are bounded while writing fails, and close() writes what is pending', async t => {
  const out = [];
  const never = { kind: 'local', label: 'x', list: async () => [], get: async () => null, put: () => Promise.reject(new Error('down')) };
  const trail = new AuditTrail({ store: never, write: l => out.push(l), now: () => NOW, maxPending: 3, delayMs: 60_000 });
  for (let i = 0; i < 5; i++) trail.record({ type: 'authz', reason: String(i) });
  assert.deepEqual(trail.pending.map(r => r.reason), ['2', '3', '4']);
  assert.equal(trail.status().dropped, 2);
  assert.ok(out.some(l => l.includes('"type":"audit-dropped"')), 'a drop is itself logged');
  const dir = await tmp(t);
  const ok = new AuditTrail({ store: createLocalAuditStore(dir), ...quiet, now: () => NOW });
  ok.record({ type: 'authz', reason: 'on shutdown' });
  await ok.close({ timeoutMs: 5000 });
  assert.equal((await ok.recent({ days: 1 }))[0].reason, 'on shutdown');
  await trail.close({ timeoutMs: 50 });
});

test('without a store records still reach stdout, and the status says they are not durable', async () => {
  const out = [];
  const trail = new AuditTrail({ write: l => out.push(l), problem: 'not configured (set E360_AUDIT_REPO and E360_AUDIT_GITHUB_TOKEN)' });
  trail.record({ type: 'authz' });
  assert.equal(out.length, 1); assert.equal(trail.pending.length, 0);
  assert.deepEqual(await trail.recent(), []);
  assert.match(auditStatusText(trail.status()), /not configured.*lost when the app restarts/);
});

// ---------------------------------------------------------------- GitHub store
test('GitHub store: audit/ paths only, bearer token, base64 content with sha, conflicts re-read, token never in errors', async () => {
  const gh = fakeGitHub();
  const store = createGitHubAuditStore({ repo: 'contoso/e360-audit', token: 'test-token', fetchImpl: gh.fetchImpl });
  const trail = new AuditTrail({ store, ...quiet, now: () => NOW });
  trail.record({ type: 'remediation-run', reason: 'one' }); await trail.flush();
  trail.record({ type: 'pim-request', outcome: 'ok' }); await trail.flush();
  assert.deepEqual([...gh.files.keys()], ['audit/2026-11/2026-11-13.jsonl']);
  assert.deepEqual(lines(gh.files.get('audit/2026-11/2026-11-13.jsonl').text).map(r => r.type), ['remediation-run', 'pim-request']);
  assert.ok(gh.calls.every(c => c.path.startsWith('audit/') && c.auth === 'Bearer test-token' && c.redirect === 'error'));
  // Someone else commits to the day file: the next write gets a conflict, re-reads and keeps both.
  const f = gh.files.get('audit/2026-11/2026-11-13.jsonl');
  gh.files.set('audit/2026-11/2026-11-13.jsonl', { text: f.text + JSON.stringify({ id: 'x', time: '2026-11-13T04:31:00.000Z', type: 'authz' }) + '\n', sha: 'external' });
  trail.record({ type: 'authz', reason: 'after conflict' }); await trail.flush();
  assert.equal(trail.status().lastError, null);
  assert.equal(lines(gh.files.get('audit/2026-11/2026-11-13.jsonl').text).length, 4);
  assert.equal((await trail.recent({ days: 1 })).length, 4);
  await assert.rejects(store.get('../secrets.json'), /refusing audit path/);
  await assert.rejects(store.put('audit/2026-11/notes.txt', 'x', null), /refusing audit path/);
  const bad = createGitHubAuditStore({ repo: 'contoso/e360-audit', token: 'wrong-token', fetchImpl: gh.fetchImpl });
  await assert.rejects(bad.list('audit/2026-11'), e => /HTTP 401/.test(e.message) && !e.message.includes('wrong-token'));
});

test('settings: a repo needs a token, the repo name is checked, a folder works locally, nothing configured is reported', () => {
  assert.equal(auditStoreFromEnv({ E360_AUDIT_REPO: 'contoso/e360-audit', E360_AUDIT_GITHUB_TOKEN: 'test-token' }).store.kind, 'github');
  assert.match(auditStoreFromEnv({ E360_AUDIT_REPO: 'contoso/e360-audit' }).problem, /E360_AUDIT_GITHUB_TOKEN is not set/);
  assert.match(auditStoreFromEnv({ E360_AUDIT_REPO: 'https://github.com/x', E360_AUDIT_GITHUB_TOKEN: 't' }).problem, /owner\/repo/);
  assert.equal(auditStoreFromEnv({ E360_AUDIT_DIR: os.tmpdir() }).store.kind, 'local');
  assert.match(auditStoreFromEnv({}).problem, /not configured/);
});

// ---------------------------------------------------------------- server
async function boot(t, port, { dir, roles }) {
  const account = { homeAccountId: `u.${TENANT}`, localAccountId: OID, tenantId: TENANT, username: 'admin@contoso.example', name: 'Admin', idTokenClaims: { oid: OID } };
  let last;
  const mock = {
    getAuthCodeUrl: async o => { last = o; return `https://login.example.test/authorize?state=${o.state}`; },
    acquireTokenByCode: async () => ({ account, idTokenClaims: { nonce: last.nonce, roles }, accessToken: 'x' }),
    acquireTokenSilent: async () => ({ accessToken: 'x', account }),
    getTokenCache: () => ({ serialize: () => '{}', deserialize() {} }),
  };
  const audit = new AuditTrail({ store: createLocalAuditStore(dir), write: () => {}, delayMs: 60_000 });
  const server = createApp({ port, confidential: true, enforceRoles: true, demoMode: false, audit, createConfidential: () => mock, certificate: () => ({ thumbprint: 'A'.repeat(40), privateKey: 'test' }),
    apiFetcher: async () => new Response(JSON.stringify({ value: [] }), { status: 200, headers: { 'content-type': 'application/json' } }) }).listen(port, '127.0.0.1');
  await new Promise(r => server.once('listening', r));
  const close = () => new Promise(r => server.close(r));
  t.after(close);
  const base = `http://127.0.0.1:${port}`;
  const first = await fetch(base + '/api/session');
  const cookie = first.headers.get('set-cookie').split(';')[0];
  const get = p => fetch(base + p, { redirect: 'manual', headers: { Cookie: cookie } });
  await get('/auth/login');
  await get(`/auth/callback?code=${'c'.repeat(20)}&state=${last.state}`);
  return { get, audit, close };
}

test('after a restart the authorization log and Run requests show what happened before it', async t => {
  const dir = await tmp(t);
  // Before the restart: a Reader is denied Billing, and an earlier Run now request is in the trail.
  const before = await boot(t, await freePort(), { dir, roles: ['E360.Reader'] });
  assert.equal((await before.get('/api/billing')).status, 403);
  before.audit.record({ type: 'remediation-run', requester: { upn: 'admin@contoso.example', objectId: OID }, reason: 'user reports no VPN', device: 'PC01', managedDeviceId: 'aaaaaaaa-1111-2222-3333-444444444444', user: 'user@contoso.example', scriptId: null, result: 'accepted', error: null });
  await before.audit.close();
  await before.close();
  // After: a fresh process (new memory) with the same store.
  const after = await boot(t, await freePort(), { dir, roles: ['E360.Admin'] });
  const log = await (await after.get('/api/authz/log')).json();
  assert.ok(log.rows.some(r => r.path === '/api/billing' && r.outcome === 'denied' && r.role === 'E360.Billing'), 'the denial from before the restart is back');
  assert.ok(log.rows.some(r => r.path === '/auth/callback' && r.user === 'admin@contoso.example'), 'sign-ins are back');
  assert.equal(log.audit.durable, true); assert.equal(log.audit.kind, 'local');
  assert.equal(new Set(log.rows.map(r => r.id)).size, log.rows.length, 'no row twice');
  const runs = await (await after.get('/api/intune/remediation-runs')).json();
  assert.equal(runs.rows.length, 1); assert.equal(runs.rows[0].reason, 'user reports no VPN'); assert.equal(runs.rows[0].device, 'PC01');
  assert.equal(runs.audit.durable, true);
});

test('every audit producer writes through the trail, not straight to the console', () => {
  const src = readFileSync(new URL('../server/index.mjs', import.meta.url), 'utf8');
  assert.match(src, /new RunAudit\(\{ record: rec => audit\.record\(rec\) \}\)/);
  assert.match(src, /audit\.record\(auditRecord\(/);
  assert.match(src, /audit\.record\(\{ type: 'pim-request'/);
  assert.match(src, /if \(durableDecision\(row\)\) audit\.record\(\{ type: 'authz', \.\.\.row \}\)/);
  assert.doesNotMatch(src, /console\.log\(auditLine|event: 'pim\.request'/);
  assert.match(src, /process\.once\('SIGTERM'/);
});
