// These tests exercise demo routes; the hosted default is DEMO_MODE off.
process.env.DEMO_MODE ??= 'true';
import test from 'node:test';
import assert from 'node:assert/strict';
import { accountReport, demoAccountReport, normalizeSnapshot } from '../server/account.mjs';
import { createApp } from '../server/index.mjs';

const id = '11111111-1111-1111-1111-111111111111';
const denied = () => { throw Object.assign(new Error('SECRET denied details'), { status: 403 }); };
test('self investigation binds to Graph /me, omits denied data, and names denied sources as not available', async () => {
  const paths = [];
  const api = { async request(p) { paths.push(p); if (p.includes('/conditionalAccess/evaluate')) return denied(); return { id, displayName: 'Viewer', userPrincipalName: 'viewer@example.test' }; }, async pages(p) { paths.push(p); return denied(); } };
  const r = await accountReport(api, { tenant: id });
  assert.match(paths[0], /^\/v1.0\/me\?/);
  assert.equal(r.identity.id, id);
  assert.deepEqual(r.sources.map(s => s.id), ['self-directory']);
  assert.deepEqual(r.sections, {});
  // Denied (403) sources are listed as not available, not counted as incomplete, and upstream error text is never echoed.
  assert.equal(r.partial, false);
  assert.ok(r.unavailable.some(u => u.source === 'My registered authentication methods' && /not granted/.test(u.reason)));
  assert.ok(!JSON.stringify(r).includes('SECRET'));
  assert.ok(!JSON.stringify(r.sources).includes('Intune'));
});
test('self evidence preserves license provisioning, unknown device states, and current/event policy distinction', async () => {
  const api = { async request(p) { if (p === '/v1.0/identity/conditionalAccess/evaluate') return { value: [{ id, displayName: 'Require MFA', state: 'enabled', grantControls: { builtInControls: ['mfa'] }, conditions: {} }] }; return { id, userPrincipalName: 'viewer@example.test' }; }, async pages(p) {
    if (p.includes('licenseDetails')) return { rows: [{ skuPartNumber: 'TEST', servicePlans: [{ servicePlanName: 'INTUNE_A', provisioningStatus: 'Disabled', appliesTo: 'User' }] }] };
    if (p.includes('registeredDevices')) return { rows: [{ id, deviceId: id, displayName: 'PC' }], truncated: true };
    if (p.includes('conditionalAccess/policies')) return { rows: [{ id, displayName: 'Require MFA', conditions: { users: { includeUsers: ['All'] } } }] };
    if (p.includes('/signIns')) return { rows: [{ id, createdDateTime: new Date().toISOString(), status: {} }] };
    return { rows: [], truncated: false };
  } };
  const r = await accountReport(api, { tenant: id });
  assert.equal(r.sections.licenses[0].plans[0].status, 'Disabled');
  assert.equal(r.sections.devices[0].managed, undefined);
  assert.match(r.sections.conditionalAccess[0].targeting, /^Applies to /);
  assert.equal(r.sections.signins[0].policiesReturned, false);
  assert.equal(r.sections.signins[0].code, null);
  assert.equal(r.partial, true);
});
test('local snapshot validates bounded metadata, removes unknown payloads, and never asserts browser identity', () => {
  const raw = { schemaVersion: 1, kind: 'entity360-device-snapshot', host: 'DEVICE02', collectedAt: new Date().toISOString(), windowsAccount: 'PC\\user', facts: [{ area: 'Identity', key: 'Account', value: '<script>alert(1)</script>', source: 'local' }], deviceIds: [{ deviceId: id, tenantId: id }], password: 'SECRET' };
  const r = normalizeSnapshot(raw);
  assert.match(r.provenance, /user-supplied/);
  assert.equal(r.password, undefined);
  assert.equal(r.facts[0].value, raw.facts[0].value); // UI must render as escaped text.
  assert.throws(() => normalizeSnapshot({ ...raw, facts: [{ area: 'Unknown', key: 'x', value: true }] }));
  assert.throws(() => normalizeSnapshot({ ...raw, collectedAt: new Date(Date.now() + 3600000).toISOString() }));
  assert.throws(() => normalizeSnapshot({ ...raw, facts: Array(121).fill(raw.facts[0]) }));
});
test('restricted demo account omits license and device evidence', () => {
  const r = demoAccountReport('reader');
  assert.deepEqual(r.sections, {});
  assert.deepEqual(r.sources.map(s => s.id), ['self-directory']);
});
test('snapshot import requires CSRF, validates structure, and does not persist between sessions', async t => {
  const server = createApp({ port: 3622 }).listen(3622, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const base = 'http://127.0.0.1:3622';
  const response = await fetch(base + '/api/session'); const session = await response.json();
  const cookie = response.headers.get('set-cookie').split(';')[0];
  const headers = { Cookie: cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': session.csrf };
  assert.equal((await fetch(base + '/api/device/import', { method: 'POST', body: '{}', headers: { 'Content-Type': 'application/json', Cookie: cookie } })).status, 403);
  assert.equal((await fetch(base + '/api/device/import', { method: 'POST', body: '{}', headers })).status, 400);
  assert.equal((await fetch(base + '/api/account/report?hours=99999', { headers })).status, 400);
  const r = await fetch(base + '/api/account/report?userId=other', { headers });
  assert.equal((await r.json()).identity.upn, 'morgan.lee@contoso.example');
  const other = await fetch(base + '/api/session'); assert.ok(!(await other.json()).deviceSnapshot);
});
