// These tests exercise demo routes; the hosted default is DEMO_MODE off.
process.env.DEMO_MODE ??= 'true';
import test from 'node:test';
import assert from 'node:assert/strict';

const TENANT = '11111111-1111-1111-1111-111111111111';
const CLIENT = '22222222-2222-2222-2222-222222222222';
process.env.ENTRA_TENANT_ID = TENANT;
process.env.ENTRA_CLIENT_ID = CLIENT;
process.env.ENTRA_CERT_THUMBPRINT = 'A'.repeat(40);
process.env.ENTRA_CERT_PRIVATE_KEY_PATH = 'C:\\outside\\entity360\\test-key.pem';

const { roleForPath, rolesFromClaims, decide, checkCallback, claimsChallenge, newPending, DecisionLog, PENDING_TTL } = await import('../server/authflow.mjs');
const { createApp } = await import('../server/index.mjs');

test('each feature maps to exactly one role, and the longest prefix wins', () => {
  assert.equal(roleForPath('/api/signins/lookup'), 'E360.SignIns');
  assert.equal(roleForPath('/api/intune/health'), 'E360.Intune');
  assert.equal(roleForPath('/api/billing'), 'E360.Billing');
  assert.equal(roleForPath('/api/licenses'), 'E360.Reader');
  assert.equal(roleForPath('/api/session'), null);
  assert.equal(roleForPath('/api/billingx'), null);
});

test('role claims: unknown names are dropped and non-arrays are ignored', () => {
  assert.deepEqual(rolesFromClaims({ roles: ['E360.Reader', 'Global.Admin', 7, 'E360.Reader'] }), ['E360.Reader']);
  assert.deepEqual(rolesFromClaims({ roles: 'E360.Billing' }), []);
  assert.deepEqual(rolesFromClaims(null), []);
});

test('decisions: demo is open, enforced live needs the exact role, roles never imply each other', () => {
  assert.equal(decide({ mode: 'demo', path: '/api/billing', roles: [], enforce: true }).allowed, true);
  assert.equal(decide({ mode: 'live', path: '/api/billing', roles: ['E360.Reader'], enforce: true }).allowed, false);
  assert.equal(decide({ mode: 'live', path: '/api/billing', roles: ['E360.Billing'], enforce: true }).allowed, true);
  assert.equal(decide({ mode: 'live', path: '/api/intune/health', roles: ['E360.Billing', 'E360.Reader'], enforce: true }).allowed, false);
  assert.match(decide({ mode: 'live', path: '/api/billing', roles: [], enforce: false }).reason, /not enforced/);
  assert.equal(decide({ mode: 'live', path: '/api/session', roles: [], enforce: true }).allowed, true);
});

test('callback validation rejects missing, expired, mismatched, error and code-less responses', () => {
  const p = newPending({ verifier: 'v', challenge: 'c' }, 1000);
  assert.match(checkCallback(null, {}), /No sign-in/);
  assert.match(checkCallback(p, { state: p.state, code: 'x'.repeat(20) }, 1000 + PENDING_TTL + 1), /expired/);
  assert.match(checkCallback(p, { error: 'access_denied', state: p.state }, 2000), /did not complete/);
  assert.match(checkCallback(p, { state: 'other', code: 'x'.repeat(20) }, 2000), /did not match/);
  assert.match(checkCallback(p, { state: p.state }, 2000), /no authorization code/);
  assert.equal(checkCallback(p, { state: p.state, code: 'x'.repeat(20) }, 2000), null);
});

test('claims challenge is decoded, and absence is null', () => {
  const claims = Buffer.from(JSON.stringify({ access_token: { acrs: { essential: true, value: 'c1' } } })).toString('base64');
  assert.match(claimsChallenge(`Bearer error="insufficient_claims", claims="${claims}"`), /acrs/);
  assert.equal(claimsChallenge('Bearer realm=""'), null);
});

test('decision log is bounded and newest first', () => {
  const log = new DecisionLog(3);
  for (let i = 0; i < 5; i++) log.add({ path: `/p${i}`, outcome: 'denied', reason: 'role missing' });
  assert.deepEqual(log.list().map(r => r.path), ['/p4', '/p3', '/p2']);
});

test('full sign-in: PKCE and nonce are sent, roles are read from the validated token, features are gated server-side, replay is refused', async t => {
  let authRequest, redeemed = 0;
  const account = { homeAccountId: `u.${TENANT}`, localAccountId: '33333333-3333-3333-3333-333333333333', tenantId: TENANT, username: 'viewer@example.test', name: 'Viewer' };
  const mock = {
    getAuthCodeUrl: async options => { authRequest = options; return `https://login.example.test/authorize?state=${options.state}&code_challenge=${options.codeChallenge}`; },
    acquireTokenByCode: async options => { redeemed++; assert.ok(options.codeVerifier); assert.equal(options.nonce, authRequest.nonce, 'msal 4+ needs the nonce at redemption'); return { account, idTokenClaims: { nonce: authRequest.nonce, roles: ['E360.Reader', 'Not.AnEntityRole'] }, accessToken: 'x' }; },
    getTokenCache: () => ({ serialize: () => '{}', deserialize() {} }),
  };
  const server = createApp({ port: 3644, confidential: true, enforceRoles: true, createConfidential: () => mock, certificate: () => ({ thumbprint: 'A'.repeat(40), privateKey: 'test' }) }).listen(3644, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const base = 'http://127.0.0.1:3644';
  const first = await fetch(base + '/api/session');
  const session = await first.json();
  const cookie = first.headers.get('set-cookie').split(';')[0];
  const get = (p, extra = {}) => fetch(base + p, { redirect: 'manual', headers: { Cookie: cookie, ...extra } });

  const login = await get('/auth/login');
  assert.equal(login.status, 302);
  assert.equal(authRequest.codeChallengeMethod, 'S256');
  assert.ok(authRequest.codeChallenge && authRequest.state && authRequest.nonce);
  assert.equal(authRequest.redirectUri, 'http://localhost:3644/auth/callback');

  const bad = await get(`/auth/callback?code=${'c'.repeat(20)}&state=wrong`);
  assert.equal(bad.status, 302);
  assert.equal(redeemed, 0);

  // the failed attempt consumed the pending request; start again
  await get('/auth/login');
  const ok = await get(`/auth/callback?code=${'c'.repeat(20)}&state=${authRequest.state}`);
  assert.equal(ok.status, 302);
  assert.equal(redeemed, 1);
  const replay = await get(`/auth/callback?code=${'c'.repeat(20)}&state=${authRequest.state}`);
  assert.equal(redeemed, 1);
  assert.equal(replay.status, 302);

  const live = await (await get('/api/session')).json();
  assert.equal(live.mode, 'live');
  assert.deepEqual(live.appRoles, ['E360.Reader']);
  assert.equal(live.rolesEnforced, true);

  const post = (p) => fetch(base + p, { method: 'POST', body: '{}', headers: { Cookie: cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': session.csrf } });
  const intune = await post('/api/intune/health');
  assert.equal(intune.status, 403);
  assert.equal((await intune.json()).requiredRole, 'E360.Intune');
  assert.equal((await get('/api/billing')).status, 403);
  assert.equal((await post('/api/signins/lookup')).status, 403);

  const log = await (await get('/api/authz/log')).json();
  assert.ok(log.rows.some(r => r.path === '/api/intune/health' && r.outcome === 'denied'));
  assert.ok(log.rows.every(r => !JSON.stringify(r).includes('accessToken')));
});

test('without a configured certificate the sign-in route refuses instead of falling back', async t => {
  const server = createApp({ port: 3645, confidential: false }).listen(3645, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const base = 'http://127.0.0.1:3645';
  const first = await fetch(base + '/api/session');
  const cookie = first.headers.get('set-cookie').split(';')[0];
  const r = await fetch(base + '/auth/login', { redirect: 'manual', headers: { Cookie: cookie } });
  assert.equal(r.status, 409);
});
