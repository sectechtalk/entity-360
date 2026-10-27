// Confidential sign-in connects Azure without device code: silently from the cached account, else by redirect consent.
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

async function boot(t, port, silentOk) {
  const account = { homeAccountId: `u.${TENANT}`, localAccountId: '33333333-3333-3333-3333-333333333333', tenantId: TENANT, username: 'viewer@example.test', name: 'Viewer' };
  const calls = { urls: [], silent: [], codes: [], deviceCode: 0 };
  let last;
  const mock = {
    getAuthCodeUrl: async o => { last = o; calls.urls.push(o); return `https://login.example.test/authorize?state=${o.state}`; },
    acquireTokenByCode: async o => { calls.codes.push(o.scopes); return { account, idTokenClaims: { nonce: last.nonce, roles: [] }, accessToken: 'x' }; },
    acquireTokenSilent: async o => { calls.silent.push(o.scopes); if (silentOk || calls.codes.some(s => s.includes(ARM))) return { accessToken: 'arm' }; throw Object.assign(new Error('consent'), { errorCode: 'interaction_required' }); },
    getTokenCache: () => ({ serialize: () => '{}', deserialize() {} }),
  };
  const server = createApp({ port, confidential: true, enforceRoles: false, createConfidential: () => mock, createMsal: () => { calls.deviceCode++; throw new Error('device code must not be used'); }, certificate: () => ({ thumbprint: 'A'.repeat(40), privateKey: 'test' }) }).listen(port, '127.0.0.1');
  await new Promise(r => server.once('listening', r));
  t.after(() => new Promise(r => server.close(r)));
  const base = `http://127.0.0.1:${port}`;
  const first = await fetch(base + '/api/session');
  const { csrf } = await first.json();
  const cookie = first.headers.get('set-cookie').split(';')[0];
  const get = p => fetch(base + p, { redirect: 'manual', headers: { Cookie: cookie } });
  const post = (p, body) => fetch(base + p, { method: 'POST', body: JSON.stringify(body), headers: { Cookie: cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': csrf } });
  await get('/auth/login');
  await get(`/auth/callback?code=${'c'.repeat(20)}&state=${last.state}`);
  return { calls, get, post, state: () => last.state };
}

test('silent ARM token after confidential sign-in connects Azure with no click', async t => {
  const { calls, get } = await boot(t, 3671, true);
  const s = await (await get('/api/session')).json();
  assert.equal(s.mode, 'live');
  assert.equal(s.azureConnected, true);
  assert.equal(s.azureConnectMode, 'redirect');
  assert.ok(calls.silent.some(x => x.includes(ARM)));
  assert.equal(calls.deviceCode, 0);
});

test('when silent needs consent, Connect Azure redirects with PKCE for the ARM scope and returns connected', async t => {
  const { calls, get, post, state } = await boot(t, 3672, false);
  assert.equal((await (await get('/api/session')).json()).azureConnected, false);
  const start = await (await post('/api/auth/start', { resource: 'azure' })).json();
  assert.deepEqual(start, { status: 'redirect', url: '/auth/connect?resource=azure' });
  const connect = await get(start.url);
  assert.equal(connect.status, 302);
  const req = calls.urls.at(-1);
  assert.deepEqual(req.scopes, [ARM]);
  assert.equal(req.codeChallengeMethod, 'S256');
  assert.equal(req.loginHint, 'viewer@example.test');
  const back = await get(`/auth/callback?code=${'d'.repeat(20)}&state=${state()}`);
  assert.equal(back.headers.get('location'), '/');
  const s = await (await get('/api/session')).json();
  assert.equal(s.azureConnected, true);
  assert.equal(s.mode, 'live');
  assert.equal(calls.deviceCode, 0);
});
