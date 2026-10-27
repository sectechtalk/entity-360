// Session resilience: an Azure-only token failure is not a sign-out, the cookie rolls, and a lost session resumes with a login hint.
process.env.DEMO_MODE ??= 'true';
import test from 'node:test';
import assert from 'node:assert/strict';

const TENANT = '11111111-1111-1111-1111-111111111111';
process.env.ENTRA_TENANT_ID = TENANT;
process.env.ENTRA_CLIENT_ID = '22222222-2222-2222-2222-222222222222';
process.env.ENTRA_CERT_THUMBPRINT = 'A'.repeat(40);
process.env.ENTRA_CERT_PRIVATE_KEY_PATH = 'C:\\outside\\entity360\\test-key.pem';
const { createApp } = await import('../server/index.mjs');
const ARM = 'https://management.azure.com/user_impersonation';

async function boot(t, port, silentOk, flags = {}) {
  const account = { homeAccountId: `u.${TENANT}`, localAccountId: '33333333-3333-3333-3333-333333333333', tenantId: TENANT, username: 'viewer@example.test', name: 'Viewer' };
  const calls = { urls: [], silent: [], codes: [], deviceCode: 0 };
  let last;
  const mock = {
    getAuthCodeUrl: async o => { last = o; calls.urls.push(o); return `https://login.example.test/authorize?state=${o.state}`; },
    acquireTokenByCode: async o => { calls.codes.push(o.scopes); return { account, idTokenClaims: { nonce: last.nonce, roles: [] }, accessToken: 'x' }; },
    acquireTokenSilent: async o => { calls.silent.push(o.scopes); if (flags.armDown && o.scopes.includes(ARM)) throw Object.assign(new Error('expired'), { errorCode: 'invalid_grant' }); if (silentOk || calls.codes.some(s => s.includes(ARM))) return { accessToken: 'arm' }; throw Object.assign(new Error('consent'), { errorCode: 'interaction_required' }); },
    getTokenCache: () => ({ serialize: () => '{}', deserialize() {} }),
  };
  const apiFetcher = async url => { const u = new URL(url); const body = u.origin.includes('graph') ? { id: '33333333-3333-3333-3333-333333333333', displayName: 'Viewer', userPrincipalName: 'viewer@example.test' } : flags.arm401 ? { error: { code: 'InvalidAuthenticationToken' } } : { value: [] }; return new Response(JSON.stringify(body), { status: !u.origin.includes('graph') && flags.arm401 ? 401 : 200, headers: { 'content-type': 'application/json' } }); };
  const server = createApp({ apiFetcher, port, confidential: true, enforceRoles: false, createConfidential: () => mock, createMsal: () => { calls.deviceCode++; throw new Error('device code must not be used'); }, certificate: () => ({ thumbprint: 'A'.repeat(40), privateKey: 'test' }) }).listen(port, '127.0.0.1');
  await new Promise(r => server.once('listening', r));
  t.after(() => new Promise(r => server.close(r)));
  const base = `http://127.0.0.1:${port}`;
  const first = await fetch(base + '/api/session');
  const { csrf } = await first.json();
  const cookie = first.headers.get('set-cookie').split(';')[0];
  const get = p => fetch(base + p, { redirect: 'manual', headers: { Cookie: cookie } });
  const post = (p, body) => fetch(base + p, { method: 'POST', body: JSON.stringify(body), headers: { Cookie: cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': csrf } });
  await get('/auth/login');
  const cb = await get(`/auth/callback?code=${'c'.repeat(20)}&state=${last.state}`);
  const hint = (cb.headers.get('set-cookie') || '').match(/entity360hint=[^;]+/)?.[0];
  return { calls, get, post, state: () => last.state, base, cookie, last: () => last, hint };
}


test('an Azure token failure returns 403 and drops Azure, never 401', async t => {
  const flags = {};
  const { get, calls } = await boot(t, 3681, true, flags);
  assert.equal((await (await get('/api/session')).json()).azureConnected, true);
  flags.armDown = true;
  const res = await get('/api/activity?id=33333333-3333-3333-3333-333333333333&days=1');
  assert.notEqual(res.status, 401);
  const s = await (await get('/api/session')).json();
  assert.equal(s.mode, 'live');
  assert.equal(s.azureConnected, false);
  assert.ok(calls.silent.filter(x => x.includes(ARM)).length >= 2, 'retries silently with forceRefresh');
});

test('cookie rolls on every request', async t => {
  const { get } = await boot(t, 3682, true);
  const res = await get('/api/session');
  assert.match(res.headers.get('set-cookie') || '', /entity360=[0-9a-f]{64}.*Max-Age=\d+/i);
});

test('a lost session resumes with the last account as login hint and no account picker', async t => {
  const { hint, base, calls } = await boot(t, 3683, true);
  assert.ok(hint, 'hint cookie set at sign-in');
  // New browser session (server restarted): only the hint cookie survives.
  await fetch(base + '/auth/login?resume=1', { redirect: 'manual', headers: { Cookie: hint } });
  const o = calls.urls.at(-1);
  assert.equal(o.loginHint, 'viewer@example.test');
  assert.equal(o.prompt, undefined);
  await fetch(base + '/auth/login', { redirect: 'manual', headers: { Cookie: hint } });
  assert.equal(calls.urls.at(-1).prompt, 'select_account');
});

test('an upstream Azure 401 is a reconnect (403), not a sign-out', async t => {
  const flags = {};
  const { get } = await boot(t, 3684, true, flags);
  flags.arm401 = true;
  const res = await get('/api/activity?id=33333333-3333-3333-3333-333333333333&days=1');
  assert.equal(res.status, 403);
  assert.equal((await res.json()).signin, undefined);
  assert.equal((await (await get('/api/session')).json()).mode, 'live');
});
