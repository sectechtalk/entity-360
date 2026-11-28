import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import os from 'node:os';
import { mkdtemp, readFile, stat } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { buildServer, createHttpApp, httpKey } from '../server/mcp.mjs';
import { TOOLS, compact, SHORT } from '../server/mcp-tools.mjs';
import { createAuth, SIGN_IN_AGAIN } from '../server/mcp-auth.mjs';
import { fail } from '../server/model.mjs';
import { freePort } from './free-port.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const demo = async () => ({ mode: 'demo', profile: 'analyst', roles: [], enforce: false });
const ALEX = '8f210001-6b21-4818-83bc-fae28e1242ab';
const denied = { request: async () => { throw fail('Access not granted.', 403); }, pages: async () => { throw fail('Access not granted.', 403); } };

async function connect(getContext, extra = {}) {
  const [a, b] = InMemoryTransport.createLinkedPair();
  const server = buildServer({ getContext, ...extra });
  await server.connect(a);
  const client = new Client({ name: 'test', version: '1.0.0' });
  await client.connect(b);
  return client;
}
const text = r => r.content[0].text;

test('MCP lists eight read-only tools, none of them write', async () => {
  const client = await connect(demo);
  const { tools } = await client.listTools();
  assert.deepEqual(tools.map(t => t.name), ['search', 'investigate', 'device', 'findings', 'signins', 'emergency_access', 'find_group_or_role', 'access_report']);
  for (const t of tools) { assert.equal(t.annotations.readOnlyHint, true); assert.equal(t.annotations.destructiveHint, false); assert.ok(t.description.length > 40); }
  assert.ok(!TOOLS.some(t => /remediation|pim|collect|run-now/i.test(t.route)), 'no write routes are exposed');
});

test('MCP demo: search, investigate, device and signins answer in compact form', async () => {
  const client = await connect(demo);
  const found = JSON.parse(text(await client.callTool({ name: 'search', arguments: { query: 'Alex' } })));
  assert.equal(found.results[0].id, ALEX);
  const device = found.results.find(r => r.type === 'device');
  assert.ok(device.entraId);
  const report = await client.callTool({ name: 'investigate', arguments: { id: ALEX } });
  const r = JSON.parse(text(report));
  assert.equal(r.entity.name, 'Alex Morgan');
  assert.ok(r.recentEvents.length <= SHORT.list + 1);
  assert.ok(text(report).length < 12000, 'short form fits a small context window');
  const full = await client.callTool({ name: 'investigate', arguments: { id: ALEX, detail: true } });
  assert.ok(text(full).length > text(report).length);
  const d = JSON.parse(text(await client.callTool({ name: 'device', arguments: { entraId: device.entraId } })));
  assert.equal(d.device.name, device.name);
  const s = JSON.parse(text(await client.callTool({ name: 'signins', arguments: { users: ['alex.morgan@contoso.example'] } })));
  assert.equal(s.users[0].status, 'complete');
  assert.ok(s.groups.length >= 1 && s.groups[0].app);
});

test('MCP demo: live-only tools explain themselves, bad ids are refused before any lookup', async () => {
  const client = await connect(demo);
  const f = await client.callTool({ name: 'findings', arguments: {} });
  assert.equal(f.isError, true);
  assert.match(text(f), /live Microsoft sign-in/);
  const bad = await client.callTool({ name: 'investigate', arguments: { id: 'not-a-guid' } });
  assert.equal(bad.isError, true);
  const none = await client.callTool({ name: 'device', arguments: {} });
  assert.match(text(none), /entraId or intuneId/);
});

test('MCP live: E360 app roles gate tools like the web app, and every call is audited', async () => {
  const records = [];
  const audit = { record: r => records.push(r) };
  let roles = [];
  let unconfirmed = false;
  const live = async () => ({ mode: 'live', api: denied, tenant: 't', azure: false, roles, rolesUnconfirmed: unconfirmed, enforce: true, requester: { upn: 'aaron@example.com', objectId: ALEX } });
  const client = await connect(live, { audit, transport: 'http' });
  let r = await client.callTool({ name: 'investigate', arguments: { id: ALEX } });
  assert.equal(r.isError, true);
  assert.match(text(r), /needs E360\.Reader/);
  roles = ['E360.Reader'];
  r = await client.callTool({ name: 'access_report', arguments: { kind: 'group', id: ALEX } });
  assert.match(text(r), /needs E360\.Admin/);
  r = await client.callTool({ name: 'findings', arguments: {} });
  assert.equal(r.isError, undefined, 'findings reports unreadable sources instead of failing');
  const findings = JSON.parse(text(r)).findings;
  assert.ok(findings.length > 3 && findings.every(f => f.status === 'unavailable'));
  roles = ['E360.Admin'];
  unconfirmed = true;
  r = await client.callTool({ name: 'access_report', arguments: { kind: 'user', id: ALEX } });
  assert.match(text(r), /could not confirm your roles/);
  assert.deepEqual(records.map(x => [x.tool, x.outcome]), [['investigate', 'denied'], ['access_report', 'denied'], ['findings', 'ok'], ['access_report', 'failed']]);
  assert.equal(records[0].type, 'mcp-tool');
  assert.equal(records[0].transport, 'http');
  assert.equal(records[0].requester.upn, 'aaron@example.com');
  assert.equal(records[1].scopeId, ALEX);
  assert.equal(records[3].scopeId, null, 'a user id is never written as an access-report scope');
});

test('MCP demo calls are not written to the audit trail', async () => {
  const records = [];
  const client = await connect(demo, { audit: { record: r => records.push(r) } });
  await client.callTool({ name: 'search', arguments: { query: 'Alex' } });
  assert.equal(records.length, 0);
});

test('compact keeps the first rows and says how many more there are', () => {
  const out = compact({ rows: Array.from({ length: 40 }, (_, i) => i), long: 'x'.repeat(500), empty: '', gone: null });
  assert.equal(out.rows.length, SHORT.list + 1);
  assert.match(out.rows.at(-1), /25 more not shown/);
  assert.equal(out.long.length, SHORT.string + 1);
  assert.ok(!('empty' in out) && !('gone' in out));
});

test('MCP over HTTP: key, Host and Origin are checked; a real client can list and call tools', async () => {
  const key = 'k'.repeat(64);
  const app = createHttpApp({ port: 0, key, makeServer: () => buildServer({ getContext: demo, transport: 'http' }) });
  const server = await new Promise(resolve => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
  const port = server.address().port;
  // The app checks Host against the port it was created with; rebuild with the real port.
  server.close();
  const app2 = createHttpApp({ port, key, makeServer: () => buildServer({ getContext: demo, transport: 'http' }) });
  const s2 = await new Promise(resolve => { const s = app2.listen(port, '127.0.0.1', () => resolve(s)); });
  try {
    const url = `http://127.0.0.1:${port}/mcp`;
    const body = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' });
    const headers = { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' };
    assert.equal((await fetch(url, { method: 'POST', headers, body })).status, 401);
    assert.equal((await fetch(url, { method: 'POST', headers: { ...headers, Authorization: 'Bearer wrong' }, body })).status, 401);
    assert.equal((await fetch(url, { method: 'POST', headers: { ...headers, Authorization: `Bearer ${key}`, Origin: 'https://evil.example' }, body })).status, 403);
    assert.equal((await fetch(url, { method: 'GET', headers: { Authorization: `Bearer ${key}` } })).status, 405);
    const client = new Client({ name: 'test', version: '1.0.0' });
    await client.connect(new StreamableHTTPClientTransport(new URL(url), { requestInit: { headers: { Authorization: `Bearer ${key}` } } }));
    const { tools } = await client.listTools();
    assert.equal(tools.length, 8);
    const found = JSON.parse(text(await client.callTool({ name: 'search', arguments: { query: 'Jordan' } })));
    assert.ok(found.results.length >= 1);
    await client.close();
  } finally { s2.close(); }
  assert.throws(() => createHttpApp({ port, key: 'short', makeServer: () => null }), /at least 32/);
});

test('MCP HTTP key is created once and reused', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'e360-mcp-'));
  const k1 = await httpKey(dir), k2 = await httpKey(dir);
  assert.equal(k1, k2);
  assert.match(k1, /^[0-9a-f]{64}$/);
  if (process.platform !== 'win32') assert.equal((await stat(path.join(dir, 'http-key.txt'))).mode & 0o777, 0o600);
});

test('MCP over stdio: stdout carries only the protocol (a real client works end to end)', async () => {
  const client = new Client({ name: 'test', version: '1.0.0' });
  await client.connect(new StdioClientTransport({ command: process.execPath, args: [path.join(root, 'server', 'mcp.mjs'), '--demo'], cwd: root, stderr: 'pipe' }));
  const { tools } = await client.listTools();
  assert.equal(tools.length, 8);
  const r = JSON.parse(text(await client.callTool({ name: 'search', arguments: { query: 'Alex' } })));
  assert.equal(r.results[0].name, 'Alex Morgan');
  await client.close();
});

// ---------------------------------------------------------------- sign-in
const ENV = { ENTRA_TENANT_ID: '11111111-1111-4111-8111-111111111111', ENTRA_CLIENT_ID: '22222222-2222-4222-8222-222222222222', ENTRA_CERT_THUMBPRINT: 'a'.repeat(40), ENTRA_KEYVAULT_URI: 'https://kv-e360test.vault.azure.net', ENTRA_KEYVAULT_CERT_NAME: 'e360-cert' };

function fakeClient({ roles = ['E360.Admin'], tenant = ENV.ENTRA_TENANT_ID } = {}) {
  const calls = { authUrl: null, byCode: null, options: null };
  let cacheText = '';
  const account = { homeAccountId: 'home-1', username: 'aaron@example.com', tenantId: tenant, localAccountId: ALEX, idTokenClaims: { oid: ALEX } };
  return {
    calls,
    create(options) {
      calls.options = options;
      const plugin = options.cache.cachePlugin;
      const tokenCache = { serialize: () => cacheText, deserialize: t => { cacheText = t; }, getAccountByHomeId: async id => (cacheText.includes(id) ? account : null) };
      const touch = async changed => { const c = { tokenCache, cacheHasChanged: false }; await plugin.beforeCacheAccess(c); if (changed) { cacheText = JSON.stringify({ account: 'home-1', rt: 'secret-refresh-token' }); c.cacheHasChanged = true; } await plugin.afterCacheAccess(c); };
      return {
        getTokenCache: () => tokenCache,
        async getAuthCodeUrl(req) { calls.authUrl = req; return `https://login.microsoftonline.com/x/oauth2/v2.0/authorize?state=${req.state}`; },
        async acquireTokenByCode(req) { calls.byCode = req; if (req.nonce !== calls.authUrl.nonce) throw Object.assign(new Error('nonce mismatch'), { errorCode: 'nonce_mismatch' }); await touch(true); return { account, idTokenClaims: { nonce: calls.authUrl.nonce, roles, tid: tenant, oid: ALEX } }; },
        async acquireTokenSilent() { await touch(false); return { accessToken: 'at', account, idTokenClaims: { tid: tenant, aud: ENV.ENTRA_CLIENT_ID, oid: ALEX, iat: 1, roles } }; },
      };
    },
  };
}

test('MCP sign-in: auth code + PKCE on a localhost listener, cache saved through the protector, roles read from the ID token', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'e360-mcp-'));
  const fake = fakeClient();
  const protector = { kind: 'test', protect: async t => `P(${Buffer.from(t).toString('base64')})`, unprotect: async t => Buffer.from(t.slice(2, -1), 'base64').toString() };
  const auth = createAuth({ env: ENV, dir, protector, createClient: o => fake.create(o) });
  assert.equal(auth.configured, true);
  await assert.rejects(auth.context(), e => e.message === SIGN_IN_AGAIN && e.status === 401);
  let opened = null;
  const port = await freePort();
  const result = await auth.signIn({ port, log: () => {}, open: url => { opened = url; const state = new URL(url).searchParams.get('state'); fetch(`http://127.0.0.1:${port}/auth/callback?code=abcdefghijkl&state=${state}`).catch(() => {}); } });
  assert.ok(opened);
  assert.equal(result.account, 'aaron@example.com');
  assert.deepEqual(result.roles, ['E360.Admin']);
  assert.equal(fake.calls.authUrl.redirectUri, `http://localhost:${port}/auth/callback`);
  assert.equal(fake.calls.authUrl.codeChallengeMethod, 'S256');
  assert.equal(fake.calls.byCode.nonce, fake.calls.authUrl.nonce, 'the nonce sent to Entra is passed to MSAL, which checks it against the ID token');
  assert.ok(fake.calls.options.auth.clientAssertion, 'uses the Key Vault certificate like the web app');
  const stored = await readFile(path.join(dir, 'token-cache.bin'), 'utf8');
  assert.match(stored, /^P\(/);
  assert.ok(!stored.includes('secret-refresh-token'), 'the refresh token is only stored protected');
  const ctx = await auth.context({ fetcher: async () => new Response('{}') });
  assert.equal(ctx.mode, 'live');
  assert.deepEqual(ctx.roles, ['E360.Admin']);
  assert.equal(ctx.requester.upn, 'aaron@example.com');
  assert.equal(ctx.enforce, true);
  assert.equal((await auth.status()).signedIn, true);
  await auth.signOut();
  assert.equal((await auth.status()).signedIn, false);
});

test('MCP sign-in rejects a callback with the wrong state', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'e360-mcp-'));
  const fake = fakeClient();
  const auth = createAuth({ env: ENV, dir, protector: { kind: 't', protect: async t => t, unprotect: async t => t }, createClient: o => fake.create(o) });
  const port = await freePort();
  await assert.rejects(auth.signIn({ port, log: () => {}, open: () => { fetch(`http://127.0.0.1:${port}/auth/callback?code=abcdefghijkl&state=forged`).catch(() => {}); } }), /did not match/);
  assert.equal(fake.calls.byCode, null, 'no code was redeemed');
});

test('MCP sign-in without confidential configuration explains what is missing', async () => {
  const auth = createAuth({ env: {}, dir: os.tmpdir() });
  assert.equal(auth.configured, false);
  await assert.rejects(auth.signIn({ log: () => {} }), /not configured/);
});

test('findings short form: count = items listed + more, for every finding size', async () => {
  const { shapeFindings, SHORT_FINDING_ITEMS } = await import('../server/mcp-tools.mjs');
  const item = i => ({ text: `user${i}`, detail: 'No MFA method registered' });
  const finding = (n, extra = {}) => ({ title: `f${n}`, status: n ? 'open' : 'pass', count: n, items: Array.from({ length: Math.min(n, 50) }, (_, i) => item(i)), more: Math.max(0, n - 50), ...extra });
  // 6 users without MFA is the reported case: 5 listed, more must be 1 (it was 0).
  const sizes = [0, 1, SHORT_FINDING_ITEMS, 6, 50, 73];
  for (const detail of [false, true]) {
    const out = shapeFindings({ findings: sizes.map(n => finding(n)) }, detail).findings;
    out.forEach((f, i) => {
      const n = sizes[i];
      assert.equal(f.items.length + f.more, n, `${detail ? 'detail' : 'short'} view of ${n}: ${f.items.length} listed + ${f.more} more`);
      assert.equal(f.items.length, detail ? Math.min(n, 50) : Math.min(n, SHORT_FINDING_ITEMS));
    });
  }
  const six = shapeFindings({ findings: [finding(6)] }).findings[0];
  assert.equal(six.more, 1);
  assert.match(six.moreHint, /detail: true/);
  const unavailable = shapeFindings({ findings: [{ title: 'x', status: 'unavailable', count: null, reason: 'denied', items: [] }] }).findings[0];
  assert.equal(unavailable.more, 0);
});
