// In-session access re-check: roles follow Entra during the session, a sign-in Entra no longer accepts ends the session,
// and a re-check that cannot reach Entra closes role-gated features until one succeeds.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { openRail } from './open-rail.mjs';
import { freePort } from './free-port.mjs';

const TENANT = '11111111-1111-1111-1111-111111111111';
const CLIENT = '22222222-2222-2222-2222-222222222222';
const OID = '33333333-3333-3333-3333-333333333333';
Object.assign(process.env, { DEMO_MODE: 'false', ENTRA_TENANT_ID: TENANT, ENTRA_CLIENT_ID: CLIENT, ENTRA_CERT_THUMBPRINT: 'A'.repeat(40), ENTRA_CERT_PRIVATE_KEY_PATH: 'C:\\outside\\entity360\\test-key.pem' });
const { recheckDue, recheckRoles, signInRequired, roleChange, rolesUnconfirmed, markChecked, ROLE_RECHECK_MS, RECHECK_RETRY_MS, FORCED_RECHECK_MS } = await import('../server/role-recheck.mjs');
const { AuditTrail } = await import('../server/audit-trail.mjs');
const { createApp } = await import('../server/index.mjs');

const account = { homeAccountId: `u.${TENANT}`, localAccountId: OID, tenantId: TENANT, username: 'viewer@contoso.example', name: 'Viewer', idTokenClaims: { oid: OID } };
const claims = (roles, extra = {}) => ({ tid: TENANT, oid: OID, aud: CLIENT, iat: Math.floor(Date.now() / 1000), roles, ...extra });

// ---------------------------------------------------------------- unit
test('due only for confidential live sessions, every 5 minutes, sooner after a failure, forced at most every 10 s', () => {
  const s = { authType: 'confidential', mode: 'live', msal: {}, account }, T = Date.parse('2026-11-13T00:00:00Z');
  markChecked(s, T);
  assert.equal(recheckDue(s, T + ROLE_RECHECK_MS - 1), false);
  assert.equal(recheckDue(s, T + ROLE_RECHECK_MS), true);
  assert.equal(recheckDue(s, T + 1, { force: true }), true, 'right after sign-in a forced re-check is allowed');
  s.rolesCheck = { at: T, attemptedAt: T };
  assert.equal(recheckDue(s, T + FORCED_RECHECK_MS - 1, { force: true }), false, 'forced re-check is rate limited');
  assert.equal(recheckDue(s, T + FORCED_RECHECK_MS, { force: true }), true);
  s.rolesCheck = { at: T, attemptedAt: T + 1_000, failedAt: T + 1_000 };
  assert.equal(rolesUnconfirmed(s), true);
  assert.equal(recheckDue(s, T + 1_000 + RECHECK_RETRY_MS - 1), false);
  assert.equal(recheckDue(s, T + 1_000 + RECHECK_RETRY_MS), true);
  for (const other of [{ ...s, authType: 'device-code' }, { ...s, mode: 'demo' }, { ...s, mode: 'signedout' }, { ...s, msal: null }]) assert.equal(recheckDue(other, T + 10 * ROLE_RECHECK_MS), false);
});

test('sign-in-required errors are told apart from network trouble', () => {
  assert.equal(signInRequired({ name: 'InteractionRequiredAuthError', errorCode: 'interaction_required' }), true);
  assert.equal(signInRequired({ name: 'ServerError', errorCode: 'invalid_grant', errorMessage: 'AADSTS50057: The user account is disabled.' }), true);
  assert.equal(signInRequired({ errorCode: 'no_tokens_found' }), true);
  assert.equal(signInRequired({ name: 'ClientAuthError', errorCode: 'network_error' }), false);
  assert.equal(signInRequired(new Error('fetch failed')), false);
  assert.deepEqual(roleChange(['E360.Reader', 'E360.Admin'], ['E360.Reader', 'E360.Billing']), { added: ['E360.Billing'], removed: ['E360.Admin'] });
});

test('a fresh ID token replaces the roles; unknown role names are still dropped; concurrent checks share one token call', async () => {
  let calls = 0;
  const msal = { acquireTokenSilent: async o => { calls++; assert.equal(o.forceRefresh, true); await new Promise(r => setTimeout(r, 5)); return { account, idTokenClaims: claims(['E360.Reader', 'Not.ARole']) }; } };
  const s = { authType: 'confidential', mode: 'live', msal, account, appRoles: ['E360.Reader', 'E360.Admin'], connections: new Map([['k', { account }]]), connectionKey: 'k' };
  const [a, b] = await Promise.all([recheckRoles(s, { scopes: ['x'], tenantId: TENANT, clientId: CLIENT }), recheckRoles(s, { scopes: ['x'], tenantId: TENANT, clientId: CLIENT })]);
  assert.equal(calls, 1);
  assert.equal(a.status, 'changed'); assert.deepEqual(a.removed, ['E360.Admin']); assert.equal(b.joined, true);
  assert.deepEqual(s.appRoles, ['E360.Reader']);
  assert.ok(s.rolesCheck.at && !s.rolesCheck.inflight && !s.rolesCheck.failedAt);
});

test('a token for another person, tenant or app ends the session; no new ID token leaves roles unconfirmed', async () => {
  const run = async result => { const s = { authType: 'confidential', mode: 'live', account, appRoles: ['E360.Admin'], msal: { acquireTokenSilent: async () => result } }; return [await recheckRoles(s, { scopes: [], tenantId: TENANT, clientId: CLIENT }), s]; };
  assert.equal((await run({ account, idTokenClaims: claims(['E360.Admin'], { oid: '44444444-4444-4444-4444-444444444444' }) }))[0].status, 'ended');
  assert.equal((await run({ account, idTokenClaims: claims(['E360.Admin'], { tid: '55555555-5555-5555-5555-555555555555' }) }))[0].status, 'ended');
  assert.equal((await run({ account, idTokenClaims: claims(['E360.Admin'], { aud: '66666666-6666-6666-6666-666666666666' }) }))[0].status, 'ended');
  assert.equal((await run({ account: { ...account, homeAccountId: 'someone.else' }, idTokenClaims: claims(['E360.Admin']) }))[0].status, 'ended');
  const [r, s] = await run({ account, idTokenClaims: {} });
  assert.equal(r.status, 'unavailable'); assert.deepEqual(s.appRoles, ['E360.Admin'], 'roles are not stripped on a non-answer'); assert.equal(rolesUnconfirmed(s), true);
  // The next successful re-check confirms the roles again.
  s.msal = { acquireTokenSilent: async () => ({ account, idTokenClaims: claims(['E360.Admin']) }) };
  assert.equal((await recheckRoles(s, { scopes: [], tenantId: TENANT, clientId: CLIENT })).status, 'unchanged');
  assert.equal(rolesUnconfirmed(s), false);
});

// ---------------------------------------------------------------- server
async function boot(t, port, { roleRecheckMs = 0, roles = ['E360.Reader', 'E360.Admin'] } = {}) {
  const ctl = { roles, silent: null, forced: 0 };
  let last;
  const mock = {
    getAuthCodeUrl: async o => { last = o; return `https://login.example.test/authorize?state=${o.state}`; },
    acquireTokenByCode: async () => ({ account, idTokenClaims: { ...claims(ctl.roles), nonce: last.nonce }, accessToken: 'x' }),
    acquireTokenSilent: async o => {
      if (!o.forceRefresh) return { accessToken: 'x', account };
      ctl.forced++;
      if (ctl.silent) throw ctl.silent;
      return { accessToken: 'x', account, idTokenClaims: claims(ctl.roles) };
    },
    getTokenCache: () => ({ serialize: () => '{}', deserialize() {} }),
  };
  const lines = [];
  const audit = new AuditTrail({ write: l => lines.push(l) });
  const server = createApp({ port, confidential: true, enforceRoles: true, demoMode: false, roleRecheckMs, audit, createConfidential: () => mock, certificate: () => ({ thumbprint: 'A'.repeat(40), privateKey: 'test' }),
    apiFetcher: async () => new Response(JSON.stringify({ value: [] }), { status: 200, headers: { 'content-type': 'application/json' } }) }).listen(port, '127.0.0.1');
  await new Promise(r => server.once('listening', r));
  t.after(() => new Promise(r => server.close(r)));
  const base = `http://127.0.0.1:${port}`;
  const first = await fetch(base + '/api/session');
  const cookie = first.headers.get('set-cookie').split(';')[0];
  const get = p => fetch(base + p, { redirect: 'manual', headers: { Cookie: cookie } });
  await get('/auth/login');
  await get(`/auth/callback?code=${'c'.repeat(20)}&state=${last.state}`);
  const { csrf } = await (await get('/api/session')).json();
  const post = p => fetch(base + p, { method: 'POST', body: '{}', headers: { Cookie: cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': csrf } });
  const records = () => lines.map(l => JSON.parse(l.slice('E360_AUDIT '.length)));
  return { ctl, get, post, records };
}

test('a role removed in Entra stops working on the next request, and the change is audited', async t => {
  const { ctl, get, records } = await boot(t, await freePort());
  assert.equal((await get('/api/authz/log')).status, 200);
  ctl.roles = ['E360.Reader'];
  const r = await get('/api/authz/log');
  assert.equal(r.status, 403);
  assert.equal((await r.json()).requiredRole, 'E360.Admin');
  const s = await (await get('/api/session')).json();
  assert.deepEqual(s.appRoles, ['E360.Reader']);
  assert.ok(s.rolesCheckedAt);
  const change = records().find(x => x.type === 'authz' && x.source === 'role-check');
  assert.match(change.reason, /removed E360\.Admin/);
  assert.equal(change.user, 'viewer@contoso.example');
  assert.ok(records().some(x => x.type === 'authz' && x.path === '/auth/callback' && x.outcome === 'allowed'), 'the sign-in is audited');
});

test('a sign-in Entra no longer accepts (disabled account) ends the session with 401 and the sign-in path', async t => {
  const { ctl, get, records } = await boot(t, await freePort());
  ctl.silent = Object.assign(new Error('AADSTS50057: The user account is disabled.'), { name: 'InteractionRequiredAuthError', errorCode: 'invalid_grant', errorMessage: 'AADSTS50057: The user account is disabled.' });
  const r = await get('/api/entities?q=ab');
  assert.equal(r.status, 401);
  assert.equal((await r.json()).signin, '/auth/login');
  assert.match(r.headers.get('set-cookie') || '', /entity360=;/, 'the session cookie is cleared');
  const after = await get('/api/session');
  assert.equal((await after.json()).mode, 'signedout');
  const ended = records().find(x => x.type === 'authz' && x.source === 'role-check');
  assert.match(ended.reason, /AADSTS50057/); assert.match(ended.reason, /session ended/);
});

test('when Entra cannot be reached, role-gated features fail closed (503), others keep working, and Entra is not retried at once', async t => {
  const { ctl, get } = await boot(t, await freePort());
  ctl.silent = Object.assign(new Error('network down'), { name: 'ClientAuthError', errorCode: 'network_error' });
  const gated = await get('/api/authz/log');
  assert.equal(gated.status, 503);
  assert.equal((await gated.json()).rolesUnconfirmed, true);
  const open = await get('/api/session');
  assert.equal(open.status, 200);
  assert.equal((await open.json()).rolesUnconfirmed, true);
  ctl.silent = null;
  // RECHECK_RETRY_MS has not passed, so the next request is still closed and does not call Entra again.
  const before = ctl.forced;
  assert.equal((await get('/api/authz/log')).status, 503);
  assert.equal(ctl.forced, before);
});

test('Check my roles again forces a re-check (rate limited); without it the check waits 5 minutes', async t => {
  const p3794 = await freePort();
  const { ctl, get, post } = await boot(t, p3794, { roleRecheckMs: ROLE_RECHECK_MS, roles: ['E360.Reader'] });
  assert.equal((await get('/api/authz/log')).status, 403);
  ctl.roles = ['E360.Reader', 'E360.Admin'];
  assert.equal((await get('/api/authz/log')).status, 403, 'within 5 minutes the session keeps the roles it was given');
  assert.equal(ctl.forced, 0);
  const s = await (await post('/api/session/recheck')).json();
  assert.deepEqual(s.appRoles, ['E360.Reader', 'E360.Admin']);
  assert.equal(ctl.forced, 1);
  assert.equal((await get('/api/authz/log')).status, 200);
  await post('/api/session/recheck');
  assert.equal(ctl.forced, 1, 'a second forced re-check within 10 seconds does not call Entra');
  // The route needs a signed-in session (no app role, like My PIM) and the CSRF header.
  const anon = await fetch(`http://127.0.0.1:${p3794}/api/session`), anonCookie = anon.headers.get('set-cookie').split(';')[0], { csrf } = await anon.json();
  const signedOut = await fetch(`http://127.0.0.1:${p3794}/api/session/recheck`, { method: 'POST', body: '{}', headers: { Cookie: anonCookie, 'Content-Type': 'application/json', 'X-CSRF-Token': csrf } });
  assert.equal(signedOut.status, 401);
  const noCsrf = await fetch(`http://127.0.0.1:${p3794}/api/session/recheck`, { method: 'POST', body: '{}', headers: { Cookie: anonCookie, 'Content-Type': 'application/json' } });
  assert.equal(noCsrf.status, 403);
});

test('browser: Check my roles again on the denial opens the page once Entra issues the role; the authz page says where audit records go', async t => {
  let chromium; try { ({ chromium } = await import('@playwright/test')); } catch { t.skip('playwright not installed'); return; }
  let browser; try { browser = await chromium.launch({ channel: 'msedge' }); } catch { try { browser = await chromium.launch(); } catch { t.skip('no browser available'); return; } }
  t.after(() => browser.close());
  const PORT = await freePort(), ctl = { roles: ['E360.Reader'] };
  let last;
  const mock = { getAuthCodeUrl: async o => { last = o; return `http://127.0.0.1:${PORT}/auth/callback?code=${'c'.repeat(20)}&state=${o.state}`; },
    acquireTokenByCode: async () => ({ account, idTokenClaims: { ...claims(ctl.roles), nonce: last.nonce }, accessToken: 'x' }),
    acquireTokenSilent: async o => ({ accessToken: 'x', account, ...(o.forceRefresh ? { idTokenClaims: claims(ctl.roles) } : {}) }),
    getTokenCache: () => ({ serialize: () => '{}', deserialize() {} }) };
  const server = createApp({ port: PORT, confidential: true, enforceRoles: true, demoMode: false, audit: new AuditTrail({ write: () => {}, problem: 'not configured (set E360_AUDIT_REPO and E360_AUDIT_GITHUB_TOKEN)' }), createConfidential: () => mock, certificate: () => ({ thumbprint: 'A'.repeat(40), privateKey: 'test' }),
    apiFetcher: async () => new Response(JSON.stringify({ value: [], id: OID, displayName: 'Viewer', userPrincipalName: account.username, accountEnabled: true }), { status: 200, headers: { 'content-type': 'application/json' } }) }).listen(PORT, '127.0.0.1');
  await new Promise(r => server.once('listening', r));
  t.after(() => new Promise(r => server.close(r)));
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 } }); await openRail(ctx); const page = await ctx.newPage(), errors = [];
  page.on('pageerror', e => errors.push(e.message));
  await page.goto(`http://127.0.0.1:${PORT}/`);
  await page.waitForFunction(() => document.querySelector('#mode-badge')?.textContent.includes('LIVE'), null, { timeout: 15000 });
  await page.click('#navigation [data-view="billing"]');
  await page.waitForSelector('#denied-panel:not([hidden]) [data-denied-recheck]');
  // Not active yet: the denial stays and says so.
  await page.click('#denied-panel [data-denied-recheck]');
  await page.waitForFunction(() => /not changed yet/.test(document.querySelector('#toast')?.textContent || ''));
  assert.equal(await page.isVisible('#denied-panel'), true);
  // The PIM activation reaches Entra: the next check opens the page without signing in again.
  ctl.roles = ['E360.Reader', 'E360.Billing', 'E360.Admin'];
  await page.waitForTimeout(FORCED_RECHECK_MS + 200);
  await page.click('#denied-panel [data-denied-recheck]');
  await page.waitForFunction(() => document.querySelector('#denied-panel').hidden && !document.querySelector('#billing-panel').hidden, null, { timeout: 10000 });
  await page.click('#navigation [data-view="authz"]');
  await page.waitForFunction(() => /Durable audit trail: not configured/.test(document.querySelector('#authz-durable')?.textContent || ''), null, { timeout: 10000 });
  assert.match(await page.textContent('#authz-panel'), /role re-check|roles re-checked/i);
  assert.deepEqual(errors, []);
  await ctx.close();
});

test('roles still come only from a validated ID token: the re-check asks MSAL for a forced refresh of the same account', () => {
  const src = readFileSync(new URL('../server/role-recheck.mjs', import.meta.url), 'utf8');
  assert.match(src, /acquireTokenSilent\(\{ account: s\.account, scopes, forceRefresh: true \}\)/);
  assert.match(src, /rolesFromClaims\(claims\)/);
  assert.doesNotMatch(src, /clientCredential|acquireTokenByClientCredential|onBehalfOf/);
});
