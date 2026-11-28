import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { freePort } from './free-port.mjs';

const HOME = '11111111-1111-1111-1111-111111111111';
const VISITOR = '44444444-4444-4444-4444-444444444444';
const CLIENT = '22222222-2222-2222-2222-222222222222';
process.env.ENTRA_TENANT_ID = HOME;
process.env.ENTRA_CLIENT_ID = CLIENT;
process.env.ENTRA_CERT_THUMBPRINT = 'A'.repeat(40);
process.env.ENTRA_CERT_PRIVATE_KEY_PATH = 'C:\\outside\\entity360\\test-key.pem';

const { readOnlyScopes, hostedBlock, visitorTenant, redactAudit, hostedAudit, hostedSignInError } = await import('../server/hosted-demo.mjs');
const { AuditTrail } = await import('../server/audit-trail.mjs');
const { createApp } = await import('../server/index.mjs');

const acct = (tid, id = '33333333-3333-3333-3333-333333333333') => ({ homeAccountId: `${id}.${tid}`, localAccountId: id, tenantId: tid, username: 'visitor@fabrikam.example', name: 'Visitor' });

test('read-only scopes drop every write and privileged scope', () => {
  const kept = readOnlyScopes(['User.Read.All', 'RoleAssignmentSchedule.ReadWrite.Directory', 'PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup', 'DeviceManagementManagedDevices.PrivilegedOperations.All', 'ThreatHunting.Read.All', 'Mail.Write']);
  assert.deepEqual(kept, ['User.Read.All', 'ThreatHunting.Read.All']);
});

test('write, host-only and tenant-mixing routes are blocked; reads are not', () => {
  for (const [m, p] of [['POST', '/api/me/pim/request'], ['POST', '/api/intune/remediation-run'], ['GET', '/api/authz/log'], ['GET', '/api/intune/remediation-runs'], ['POST', '/api/device/collect'], ['POST', '/api/portfolio/discover'], ['POST', '/api/auth/start'], ['POST', '/api/connections/switch'], ['GET', '/api/deployment-log']])
    assert.ok(hostedBlock(m, p), `${m} ${p}`);
  for (const [m, p] of [['GET', '/api/investigate'], ['GET', '/api/me/pim'], ['POST', '/api/me/pim/policy'], ['POST', '/api/signins/lookup'], ['GET', '/api/findings'], ['GET', '/api/authzx']])
    assert.equal(hostedBlock(m, p), null, `${m} ${p}`);
});

test('visitor tenant: tid must be a GUID, match iss and the account, and not be the personal-account tenant', () => {
  const ok = { account: acct(VISITOR), idTokenClaims: { tid: VISITOR, iss: `https://login.microsoftonline.com/${VISITOR}/v2.0` } };
  assert.equal(visitorTenant(ok), VISITOR);
  assert.throws(() => visitorTenant({ ...ok, idTokenClaims: { tid: VISITOR, iss: `https://login.microsoftonline.com/${HOME}/v2.0` } }), /wrong_issuer/);
  assert.throws(() => visitorTenant({ ...ok, account: acct(HOME) }), /wrong_tenant/);
  assert.throws(() => visitorTenant({ ...ok, idTokenClaims: { tid: 'common', iss: 'https://login.microsoftonline.com/common/v2.0' } }), /wrong_tenant/);
  const msa = '9188040d-6c67-4c5b-b112-36a304b66dad';
  assert.throws(() => visitorTenant({ account: acct(msa), idTokenClaims: { tid: msa, iss: `https://login.microsoftonline.com/${msa}/v2.0` } }), /personal_account/);
});

test('audit lines keep tenant and outcome, never who', () => {
  assert.deepEqual(redactAudit({ type: 'authz', user: 'a@b', tenant: VISITOR, outcome: 'allowed', requester: { upn: 'a@b' } }), { type: 'authz', tenant: VISITOR, outcome: 'allowed' });
  const lines = [];
  const audit = hostedAudit(new AuditTrail({ write: l => lines.push(l) }));
  audit.record({ type: 'pim-request', requester: { upn: 'x@y' }, outcome: 'ok' });
  assert.ok(!lines[0].includes('x@y') && lines[0].includes('pim-request'));
  assert.equal(audit.status().durable, false);
});

test('consent errors tell the visitor how their admin approves the app', () => {
  assert.match(hostedSignInError('AADSTS65001', 'https://demo.example/auth/login?consent=1'), /Global Administrator or Privileged Role Administrator.*consent=1/);
  assert.match(hostedSignInError('consent_required AADSTS90094', 'u'), /not approved/);
  assert.equal(hostedSignInError('AADSTS50076', 'u'), null);
});

test('welcome page is self-contained (no inline script or style) and states the demo terms', () => {
  const html = readFileSync(new URL('../public/hosted-welcome.html', import.meta.url), 'utf8');
  assert.ok(!/<script|style=/.test(html));
  assert.match(html, /href="\/auth\/login\?consent=1"/);
  assert.match(html, /test tenant, not production/);
  assert.match(html, /Nothing about you is stored/);
});

test('hosted demo end to end: /organizations sign-in, visitor tenant from the token, host data hidden, writes refused', async t => {
  const created = [], requests = [], lines = [];
  let issuer = `https://login.microsoftonline.com/${VISITOR}/v2.0`;
  const createConfidential = options => {
    created.push(options.auth.authority);
    return {
      getAuthCodeUrl: async o => { requests.push(o); return `https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize?state=${o.state}`; },
      acquireTokenByCode: async o => ({ account: acct(VISITOR), idTokenClaims: { nonce: requests.at(-1).nonce, tid: VISITOR, iss: issuer, roles: [] }, accessToken: 'x' }),
      acquireTokenSilent: async () => { throw new Error('no azure'); },
      getTokenCache: () => ({ serialize: () => '{"cache":1}', deserialize() {} }),
    };
  };
  assert.throws(() => createApp({ port: 3691, confidential: true, hosted: true, publicBaseUrl: '' }), /PUBLIC_BASE_URL/);
  const PORT = await freePort();
  const audit = hostedAudit(new AuditTrail({ write: l => lines.push(l) }));
  const server = createApp({ port: PORT, confidential: true, enforceRoles: true, hosted: true, publicBaseUrl: 'https://demo.e360.example', createConfidential, certificate: () => ({ thumbprint: 'A'.repeat(40), privateKey: 'test' }), audit }).listen(PORT, '127.0.0.1');
  await new Promise(r => server.once('listening', r));
  t.after(() => new Promise(r => server.close(r)));
  const base = `http://localhost:${PORT}`;
  const start = async () => {
    const first = await fetch(base + '/api/session');
    const s = await first.json();
    assert.equal(s.mode, 'signedout');
    assert.equal(s.hostedDemo, true);
    const cookie = first.headers.get('set-cookie').split(';')[0];
    assert.match(cookie, /^__Host-entity360=/);
    return { csrf: s.csrf, get: (p) => fetch(base + p, { redirect: 'manual', headers: { Cookie: cookie } }), post: (p, body = {}) => fetch(base + p, { method: 'POST', body: JSON.stringify(body), headers: { Cookie: cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': s.csrf } }) };
  };

  // Signed out: the welcome page, not a redirect into Microsoft.
  const c = await start();
  const home = await c.get('/');
  assert.equal(home.status, 200);
  assert.match(await home.text(), /hosted demo/);

  // Sign-in goes to /organizations with read-only scopes; ?consent=1 asks for consent.
  assert.equal((await c.get('/auth/login?consent=1')).status, 302);
  assert.equal(created.at(-1), 'https://login.microsoftonline.com/organizations');
  assert.equal(requests.at(-1).prompt, 'consent');
  assert.equal(requests.at(-1).redirectUri, 'https://demo.e360.example/auth/callback');
  assert.ok(requests.at(-1).scopes.length > 10);
  assert.ok(requests.at(-1).scopes.every(s => !/ReadWrite|PrivilegedOperations/.test(s)), 'no write scopes');
  const done = await c.get(`/auth/callback?code=${'c'.repeat(20)}&state=${requests.at(-1).state}`);
  assert.equal(done.headers.get('location'), '/');
  // Later token calls use a client bound to the visitor's own tenant.
  assert.equal(created.at(-1), `https://login.microsoftonline.com/${VISITOR}`);

  const live = await (await c.get('/api/session')).json();
  assert.equal(live.mode, 'live');
  assert.equal(live.activeTenant, VISITOR);
  assert.equal(live.defaultTenant, null);
  assert.equal(live.rolesEnforced, false);
  assert.deepEqual(live.labSignInUsers, []);
  assert.equal(live.serverHost, '');
  assert.equal(live.hostedDemo, true);
  assert.deepEqual((await (await c.get('/api/hosting')).json()).groups, []);

  // Writes, host data and tenant switching are refused with 403.
  for (const [m, p] of [['POST', '/api/me/pim/request'], ['POST', '/api/intune/remediation-run'], ['GET', '/api/authz/log'], ['GET', '/api/deployment-log'], ['POST', '/api/auth/start'], ['POST', '/api/portfolio/discover']]) {
    const r = m === 'GET' ? await c.get(p) : await c.post(p);
    assert.equal(r.status, 403, `${m} ${p}`);
    assert.match((await r.json()).error, /Not available in the hosted demo/);
  }
  // Audit lines name the tenant, never the visitor.
  assert.ok(lines.length > 0);
  assert.ok(lines.every(l => !l.includes('visitor@fabrikam.example')), 'no UPN in audit lines');
  assert.ok(lines.some(l => l.includes(VISITOR)));

  // A token whose iss names another tenant is refused.
  const d = await start();
  issuer = `https://login.microsoftonline.com/${HOME}/v2.0`;
  await d.get('/auth/login');
  const bad = await d.get(`/auth/callback?code=${'c'.repeat(20)}&state=${requests.at(-1).state}`);
  assert.equal(bad.headers.get('location'), '/auth/error');
  assert.match(await (await d.get('/auth/error')).text(), /did not match its tenant/);
  assert.equal((await (await d.get('/api/session')).json()).mode, 'signedout');

  // Entra's consent refusal comes back as an error query: the visitor is told how their admin approves.
  const e = await start();
  await e.get('/auth/login');
  await e.get(`/auth/callback?error=consent_required&error_description=${encodeURIComponent('AADSTS65001: The user or administrator has not consented')}&state=${requests.at(-1).state}`);
  assert.match(await (await e.get('/auth/error')).text(), /https:\/\/demo\.e360\.example\/auth\/login\?consent=1/);
});
