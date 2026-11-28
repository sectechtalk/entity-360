// Public exposure hardening: nothing useful before sign-in, the fleet log only for signed-in readers,
// no backups or dotfiles served, HSTS when hosted, and a basic rate limit for clients without a session.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { roleForPath } from '../server/authflow.mjs';
import { VIEW_ROLES } from '../public/access-denied.js';
import { startHarness } from './e360-browser-harness.mjs';
import { freePort } from './free-port.mjs';

async function hostedApp(t) {
  const PORT = await freePort();
  Object.assign(process.env, { DEMO_MODE: 'false', ENTRA_TENANT_ID: '11111111-1111-1111-1111-111111111111', ENTRA_CLIENT_ID: '22222222-2222-2222-2222-222222222222', ENTRA_CERT_THUMBPRINT: 'A'.repeat(40), ENTRA_CERT_PRIVATE_KEY_PATH: 'C:\\outside\\x.pem' });
  const { createApp } = await import('../server/index.mjs');
  const server = createApp({ port: PORT, confidential: true, enforceRoles: true, demoMode: false, publicBaseUrl: 'https://e360.contoso.example', createConfidential: () => ({ getAuthCodeUrl: async () => 'https://login.microsoftonline.com/x', getTokenCache: () => ({ serialize: () => '{}', deserialize() {} }) }), certificate: () => ({ thumbprint: 'A'.repeat(40), privateKey: 'test' }) }).listen(PORT, '127.0.0.1');
  await new Promise(r => server.once('listening', r));
  t.after(() => new Promise(r => server.close(r)));
  return (path, init = {}) => fetch(`http://127.0.0.1:${PORT}${path}`, { redirect: 'manual', ...init });
}

test('signed out on the hosted app: /api/session carries no tenant, lab users, host name or role names; HSTS is sent', async t => {
  const get = await hostedApp(t);
  const r = await get('/api/session'), body = await r.json(), text = JSON.stringify(body);
  assert.equal(r.headers.get('strict-transport-security'), 'max-age=31536000; includeSubDomains');
  // Hosted session cookie: __Host- prefix with Secure, Path=/ and no Domain.
  const sc = r.headers.get('set-cookie') || '';
  assert.match(sc, /^__Host-entity360=[0-9a-f]{64};/); assert.match(sc, /; Secure/); assert.match(sc, /; Path=\//); assert.doesNotMatch(sc, /Domain=/i);
  assert.equal(body.mode, 'signedout'); assert.equal(body.signin, '/auth/login'); assert.ok(body.csrf);
  for (const k of ['defaultTenant', 'activeTenant', 'serverHost', 'multiTenantEnabled', 'personalConfigured']) assert.equal(k in body, false, k);
  assert.deepEqual(body.labSignInUsers, []); assert.deepEqual(body.signInDefaults, []); assert.deepEqual(body.knownRoles, []);
  assert.doesNotMatch(text, /11111111-1111|labentra|E360\.|@/);
});

test('the fleet log, backups and dotfiles are not static files; the log API needs a sign-in', async t => {
  const get = await hostedApp(t);
  for (const p of ['/deployment-log.json', '/DEPLOYMENT-LOG.JSON', '/app.js.pre-47-20261030', '/styles.css.pre-remfix', '/index.html.bak', '/.env', '/.git/config', '/x/.hidden', '/%2e%2e/package.json', '/..%2fserver/index.mjs']) {
    const r = await get(p); const b = await r.text();
    assert.ok([400, 403, 404].includes(r.status), `${p} -> ${r.status}`);
    assert.doesNotMatch(b, /"title":\s*"Fleet|DEVICE01|import express|require\(/, p);
  }
  const api = await get('/api/deployment-log');
  assert.equal(api.status, 401);
  assert.equal(roleForPath('/api/deployment-log'), 'E360.Reader');
  assert.equal(VIEW_ROLES.deployment, 'E360.Reader');
  const app = await get('/app.js'); assert.equal(app.status, 200, 'normal static files still served');
  const setup = await get('/setup.html'); assert.equal(setup.status, 302, 'the setup guide (lab names) needs a sign-in'); assert.equal(setup.headers.get('location'), '/auth/login');
  const unknown = await get('/api/nope'); assert.equal(unknown.status, 401, 'unknown API while signed out: sign-in first, no route list');
  assert.doesNotMatch(await (await get('/api/nope')).text(), /at |\.mjs|stack/i);
});

test('rate limit: a client without a session gets 429 after 120 requests a minute', async t => {
  const get = await hostedApp(t);
  let limited = 0, retry = null;
  for (let i = 0; i < 130; i++) { const r = await get('/api/session'); if (r.status === 429) { limited++; retry = r.headers.get('retry-after'); } }
  assert.ok(limited >= 9, `limited ${limited}`); assert.ok(Number(retry) > 0);
});

test('static: the image leaves out backups, and the page loads the log from the API', () => {
  const ignore = readFileSync(new URL('../.dockerignore', import.meta.url), 'utf8');
  assert.match(ignore, /^\*\*\/\*\.pre-\*$/m);
  const page = readFileSync(new URL('../public/deployment.js', import.meta.url), 'utf8');
  assert.match(page, /fetch\('\/api\/deployment-log'/); assert.doesNotMatch(page, /fetch\('\/deployment-log\.json'/);
});

test('browser: a signed-in reader still sees the deployment log', async t => {
  const h = await startHarness(t, { roles: ['E360.Reader'] }); if (!h) return;
  try {
    const { ctx, page } = await h.open();
    const r = await page.evaluate(async () => { const x = await fetch('/api/deployment-log'); return [x.status, (await x.text()).slice(0, 200)]; });
    assert.equal(r[0], 200); assert.match(r[1], /"title"/);
    await ctx.close();
  } finally { await h.close(); }
});

test('hosted: a browser still holding the old unprefixed cookie gets it cleared', async t => {
  const get = await hostedApp(t);
  const r = await get('/api/session', { headers: { Cookie: 'entity360=old' } });
  const all = r.headers.getSetCookie();
  assert.ok(all.some(c => /^__Host-entity360=/.test(c)));
  assert.ok(all.some(c => /^entity360=;/.test(c) && /Expires=Thu, 01 Jan 1970/.test(c)), all.join(' | '));
});
