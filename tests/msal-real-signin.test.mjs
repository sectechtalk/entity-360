// Regression test: sign-in against the REAL @azure/msal-node (only the network is stubbed).
// msal-node 4+ validates the ID token nonce itself and rejects it (nonce_mismatch) unless the nonce that was sent in
// getAuthCodeUrl is also passed to acquireTokenByCode. Mock-only tests cannot see that, so this one uses real MSAL.
process.env.DEMO_MODE ??= 'true';
import test from 'node:test';
import assert from 'node:assert/strict';
import { ConfidentialClientApplication } from '@azure/msal-node';

const TENANT = '11111111-1111-1111-1111-111111111111';
const CLIENT = '22222222-2222-2222-2222-222222222222';
const OID = '33333333-3333-3333-3333-333333333333';
process.env.ENTRA_TENANT_ID = TENANT;
process.env.ENTRA_CLIENT_ID = CLIENT;
process.env.ENTRA_CERT_THUMBPRINT = 'A'.repeat(40);
process.env.ENTRA_CERT_PRIVATE_KEY_PATH = 'C:\\outside\\entity360\\test-key.pem';
const { createApp } = await import('../server/index.mjs');

const b64 = o => Buffer.from(JSON.stringify(o)).toString('base64url');
const AUTH = `https://login.microsoftonline.com/${TENANT}`;

// Stubbed network. Token endpoint answers with an ID token carrying `idTokenNonce(lastAuthorizeNonce)`.
function stubNetwork(idTokenNonce) {
  const seen = { tokenBodies: [] };
  const meta = { token_endpoint: `${AUTH}/oauth2/v2.0/token`, authorization_endpoint: `${AUTH}/oauth2/v2.0/authorize`, issuer: `https://login.microsoftonline.com/${TENANT}/v2.0`, end_session_endpoint: `${AUTH}/oauth2/v2.0/logout`, jwks_uri: `${AUTH}/discovery/v2.0/keys` };
  const client = {
    sendGetRequestAsync: async url => {
      if (String(url).includes('instance/discovery')) return { status: 200, headers: {}, body: { tenant_discovery_endpoint: `${AUTH}/v2.0/.well-known/openid-configuration`, metadata: [{ preferred_network: 'login.microsoftonline.com', preferred_cache: 'login.windows.net', aliases: ['login.microsoftonline.com', 'login.windows.net'] }] } };
      return { status: 200, headers: {}, body: meta };
    },
    sendPostRequestAsync: async (url, options) => {
      seen.tokenBodies.push(String(options?.body));
      const now = Math.floor(Date.now() / 1000);
      const claims = { aud: CLIENT, iss: meta.issuer, iat: now, nbf: now, exp: now + 3600, tid: TENANT, oid: OID, sub: 'sub-1', ver: '2.0', name: 'Viewer', preferred_username: 'viewer@example.test', roles: ['E360.Reader'], ...(idTokenNonce(seen) === undefined ? {} : { nonce: idTokenNonce(seen) }) };
      return { status: 200, headers: {}, body: { token_type: 'Bearer', scope: 'https://graph.microsoft.com/User.Read', expires_in: 3600, ext_expires_in: 3600, access_token: 'test-access', id_token: `${b64({ alg: 'none', typ: 'JWT' })}.${b64(claims)}.sig`, client_info: Buffer.from(JSON.stringify({ uid: OID, utid: TENANT })).toString('base64url') } };
    },
  };
  return { client, seen };
}

async function boot(t, port, idTokenNonce) {
  const { client, seen } = stubNetwork(idTokenNonce);
  const server = createApp({
    port, confidential: true, enforceRoles: true,
    createConfidential: () => new ConfidentialClientApplication({ auth: { clientId: CLIENT, authority: AUTH, clientAssertion: 'test.client.assertion' }, system: { networkClient: client, loggerOptions: { loggerCallback: () => {} } } }),
    certificate: () => ({ thumbprint: 'A'.repeat(40), privateKey: 'test' }),
  }).listen(port, '127.0.0.1');
  await new Promise(r => server.once('listening', r));
  t.after(() => new Promise(r => server.close(r)));
  const base = `http://127.0.0.1:${port}`;
  const first = await fetch(base + '/api/session');
  const cookie = first.headers.get('set-cookie').split(';')[0];
  const get = p => fetch(base + p, { redirect: 'manual', headers: { Cookie: cookie } });
  return { get, seen };
}

test('real MSAL sign-in: the nonce sent to /authorize is passed to the code redemption and the ID token validates', async t => {
  let sentNonce;
  const { get, seen } = await boot(t, 3871, () => sentNonce);
  const login = await get('/auth/login');
  assert.equal(login.status, 302);
  const url = new URL(login.headers.get('location'));
  assert.equal(url.hostname, 'login.microsoftonline.com');
  sentNonce = url.searchParams.get('nonce');
  assert.match(sentNonce, /^[0-9a-f]{32}$/);
  const cb = await get(`/auth/callback?code=${'c'.repeat(20)}&state=${url.searchParams.get('state')}`);
  assert.equal(cb.status, 302);
  assert.equal(cb.headers.get('location'), '/', 'sign-in must complete, not land on /auth/error');
  assert.ok(seen.tokenBodies.some(b => b.includes('code_verifier=')), 'PKCE verifier was redeemed');
  const me = await (await get('/api/session')).json();
  assert.equal(me.mode, 'live');
});

test('real MSAL sign-in: an ID token whose nonce does not match the one we sent is refused', async t => {
  const { get } = await boot(t, 3872, () => 'f'.repeat(32));
  const url = new URL((await get('/auth/login')).headers.get('location'));
  const cb = await get(`/auth/callback?code=${'c'.repeat(20)}&state=${url.searchParams.get('state')}`);
  assert.equal(cb.headers.get('location'), '/auth/error');
});

test('real MSAL sign-in: an ID token with no nonce at all is refused', async t => {
  const { get } = await boot(t, 3873, () => undefined);
  const url = new URL((await get('/auth/login')).headers.get('location'));
  const cb = await get(`/auth/callback?code=${'c'.repeat(20)}&state=${url.searchParams.get('state')}`);
  assert.equal(cb.headers.get('location'), '/auth/error');
});
