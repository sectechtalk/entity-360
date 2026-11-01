process.env.DEMO_MODE ??= 'true';
import test from 'node:test';
import assert from 'node:assert/strict';

const TENANT = '11111111-1111-1111-1111-111111111111';
process.env.ENTRA_TENANT_ID = TENANT;
process.env.ENTRA_CLIENT_ID = '22222222-2222-2222-2222-222222222222';
process.env.ENTRA_CERT_THUMBPRINT = 'A'.repeat(40);
process.env.ENTRA_CERT_PRIVATE_KEY_PATH = 'C:\\outside\\entity360\\test-key.pem';

const { APP_ROLES, decide, rolesFromClaims } = await import('../server/authflow.mjs');
const { createApp } = await import('../server/index.mjs');
const { authzVisible } = await import('../public/authz-log.js');

async function start(t, port, options) {
  const server = createApp({ port, ...options }).listen(port, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  return 'http://127.0.0.1:' + port;
}

// Signs in through the real callback with a mocked token that carries the given roles.
async function signedIn(t, port, roles) {
  let authRequest;
  const account = { homeAccountId: `u.${TENANT}`, localAccountId: '33333333-3333-3333-3333-333333333333', tenantId: TENANT, username: 'person@example.test', name: 'Person' };
  const mock = {
    getAuthCodeUrl: async o => { authRequest = o; return `https://login.example.test/authorize?state=${o.state}`; },
    acquireTokenByCode: async () => ({ account, idTokenClaims: { nonce: authRequest.nonce, roles }, accessToken: 'x' }),
    getTokenCache: () => ({ serialize: () => '{}', deserialize() {} }),
  };
  const base = await start(t, port, { confidential: true, enforceRoles: true, demoMode: false, createConfidential: () => mock, certificate: () => ({ thumbprint: 'A'.repeat(40), privateKey: 'test' }) });
  const first = await fetch(base + '/api/session');
  const cookie = first.headers.get('set-cookie').split(';')[0];
  const get = p => fetch(base + p, { redirect: 'manual', headers: { Cookie: cookie } });
  await get('/auth/login');
  assert.equal((await get(`/auth/callback?code=${'c'.repeat(20)}&state=${authRequest.state}`)).status, 302);
  return get;
}

test('E360.Admin is a known role and implies no other role, and no other role implies it', () => {
  assert.ok(APP_ROLES.includes('E360.Admin'));
  assert.deepEqual(rolesFromClaims({ roles: ['E360.Admin', 'Not.AnEntityRole'] }), ['E360.Admin']);
  const on = { mode: 'live', enforce: true };
  assert.equal(decide({ ...on, path: '/api/authz/log', roles: ['E360.Admin'] }).allowed, true);
  for (const role of APP_ROLES.filter(r => r !== 'E360.Admin')) {
    assert.equal(decide({ ...on, path: '/api/authz/log', roles: [role] }).allowed, false, role);
  }
  assert.equal(decide({ ...on, path: '/api/authz/log', roles: APP_ROLES.filter(r => r !== 'E360.Admin') }).allowed, false);
  for (const p of ['/api/billing', '/api/licenses', '/api/signins/lookup', '/api/intune/health']) {
    assert.equal(decide({ ...on, path: p, roles: ['E360.Admin'] }).allowed, false, p);
  }
});

test('signed out: the authorization log is not open', async t => {
  const base = await start(t, 3660, { confidential: true, enforceRoles: true, demoMode: false });
  const r = await fetch(base + '/api/authz/log', { redirect: 'manual' });
  assert.ok(r.status === 401 || (r.status >= 300 && r.status < 400), `got ${r.status}`);
  if (r.status === 401) assert.equal((await r.json()).signin, '/auth/login');
});

test('every non-admin role gets 403 with requiredRole E360.Admin', async t => {
  let port = 3661;
  for (const roles of [['E360.Reader'], ['E360.SignIns'], ['E360.Intune'], ['E360.Billing'], ['E360.Reader', 'E360.SignIns', 'E360.Intune', 'E360.Billing'], []]) {
    const get = await signedIn(t, port++, roles);
    const r = await get('/api/authz/log');
    assert.equal(r.status, 403, roles.join(','));
    assert.equal((await r.json()).requiredRole, 'E360.Admin');
  }
});

test('E360.Admin gets 200 with rows and no tokens, but cannot open other features', async t => {
  const get = await signedIn(t, 3667, ['E360.Admin']);
  assert.equal((await get('/api/billing')).status, 403);
  const r = await get('/api/authz/log');
  assert.equal(r.status, 200);
  const log = await r.json();
  assert.ok(log.rows.some(x => x.path === '/api/billing' && x.outcome === 'denied'));
  assert.ok(log.rows.every(x => !JSON.stringify(x).includes('accessToken')));
});

test('client hides the page unless the session has E360.Admin (or roles are not enforced)', () => {
  assert.equal(authzVisible(null), false);
  assert.equal(authzVisible({ mode: 'signedout', rolesEnforced: true, appRoles: [] }), false);
  assert.equal(authzVisible({ mode: 'live', rolesEnforced: true, appRoles: ['E360.Reader', 'E360.Billing'] }), false);
  assert.equal(authzVisible({ mode: 'live', rolesEnforced: true, appRoles: ['E360.Admin'] }), true);
  assert.equal(authzVisible({ mode: 'live', rolesEnforced: false, appRoles: [] }), true);
});