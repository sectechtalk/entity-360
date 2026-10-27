// These tests exercise demo routes; the hosted default is DEMO_MODE off.
process.env.DEMO_MODE ??= 'true';
import test from 'node:test';
import assert from 'node:assert/strict';
import { collectIntuneCloud, evaluateIntuneHealth, intuneHealthReport, demoIntuneReport, snapshotEnrollments, INTUNE_ENROLLMENT_APP_ID } from '../server/intune.mjs';
import { normalizeSnapshot } from '../server/account.mjs';
import { createApp } from '../server/index.mjs';

const T = '11111111-1111-1111-1111-111111111111';
const DEV = '00000000-0000-4000-8000-0000000000a6';
const USER = '33333333-3333-3333-3333-333333333333';
const NOW = Date.parse('2026-10-12T12:00:00Z');
const iso = ms => new Date(NOW - ms).toISOString();

const baseCloud = (over = {}) => ({
  tenant: T, identity: { id: USER, upn: 'admin@contoso.com' }, unavailable: [], collectedAt: iso(0),
  licenses: [{ sku: 'E7', plans: [{ name: 'INTUNE_A', status: 'Success' }] }],
  mdmScope: [{ name: 'Microsoft Intune', appliesTo: 'all', discoveryUrl: 'https://enrollment.manage.microsoft.com/enrollmentserver/discovery.svc' }],
  enrollmentCa: [], compliancePolicies: [{ id: 'c1', name: 'Windows baseline', assigned: 1 }], complianceSettings: { secureByDefault: false, validityDays: 30 },
  managedDevices: [{ id: 'm1', deviceName: 'DEVICE02', operatingSystem: 'Windows', osVersion: '10.0.26300', userId: USER, userPrincipalName: 'admin@contoso.com', managementAgent: 'mdm', deviceEnrollmentType: 'windowsAzureADJoin', managedDeviceOwnerType: 'company', complianceState: 'compliant', enrolledDateTime: iso(3600000), lastSyncDateTime: iso(3600000), azureADDeviceId: DEV }],
  entraDevices: [{ id: 'e1', deviceId: DEV, displayName: 'DEVICE02', trustType: 'AzureAd', isManaged: true, isCompliant: true, mdmAppId: '0000000a-0000-0000-c000-000000000000' }],
  users: { [USER]: { id: USER, upn: 'admin@contoso.com', mail: 'admin@contoso.com', aliases: ['admin@contoso.onmicrosoft.com'] } }, upnLookups: {}, ...over,
});
const snap = (facts, deviceIds = [{ deviceId: DEV, tenantId: T }]) => normalizeSnapshot({ schemaVersion: 1, kind: 'entity360-device-snapshot', host: 'DEVICE02', collectedAt: new Date(NOW - 60000).toISOString(), windowsAccount: 'AzureAD\\AaronBrooks', facts: facts.map(([key, value, area = 'Entra']) => ({ area, key, value, source: 'test' })), deviceIds });
const healthy = [
  ['AzureAdJoined', 'YES'], ['DeviceAuthStatus', 'SUCCESS'], ['AzureAdPrt', 'YES'], ['MdmUrl', 'https://enrollment.manage.microsoft.com/x'],
  ['MDM enrollment 1', 'Provider=MS DM Server; UPN=admin@contoso.onmicrosoft.com; Discovery=https://enrollment.manage.microsoft.com/enrollmentserver/discovery.svc; State=1; Type=6', 'Intune'],
  ['EnterpriseMgmt task Schedule #1', 'State=Ready; LastRun=2026-10-12T05:00:00.0000000Z; LastResult=0', 'Intune'],
  ['MDM log errors and warnings (24 hours)', '0', 'Intune'],
];
const by = (r, id) => r.checks.find(c => c.id === id);

test('healthy tenant and computer pass the key checks, and the old UPN resolves as an alias of the same account', () => {
  const r = evaluateIntuneHealth({ cloud: baseCloud(), snapshot: snap(healthy), now: NOW });
  for (const id of ['lic-intune', 'mdm-scope', 'ca-compliant', 'compliance-basis', 'joined-enrolled', 'client-joined', 'client-prt', 'client-mdmurl', 'client-enrollment', 'client-tasks', 'client-mdmlog', 'xcheck', 'user-identity']) assert.equal(by(r, id)?.status, 'pass', id);
  assert.equal(r.summary.fail, 0);
});

test('the lab case: joined computer with only a Defender record and no enrollment key is a failure with the auto-enroll fix', () => {
  const cloud = baseCloud({ managedDevices: [{ id: 'm1', deviceName: 'DEVICE02', managementAgent: 'msSense', complianceState: 'unknown', lastSyncDateTime: iso(3600000), azureADDeviceId: DEV }], entraDevices: [{ id: 'e1', deviceId: DEV, displayName: 'DEVICE02', trustType: 'AzureAd', mdmAppId: '0000000a-0000-0000-c000-000000000000' }] });
  const r = evaluateIntuneHealth({ cloud, snapshot: snap([['AzureAdJoined', 'YES'], ['AzureAdPrt', 'YES'], ['Microsoft MDM enrollment records', 0, 'Intune']]), now: NOW });
  assert.equal(by(r, 'joined-enrolled').status, 'fail');
  assert.match(by(r, 'joined-enrolled').evidence[0], /msSense|not mdm/);
  assert.equal(by(r, 'client-enrollment').status, 'fail');
  assert.match(by(r, 'client-enrollment').fix.steps.join(' '), /AutoEnrollMDM/);
  assert.equal(by(r, 'defender-only').status, 'info');
  assert.equal(by(r, 'client-mdmurl').status, 'fail');
});

test('a registered-only computer is not failed for lacking an enrollment', () => {
  const r = evaluateIntuneHealth({ cloud: baseCloud(), snapshot: snap([['AzureAdJoined', 'NO'], ['WorkplaceJoined', 'YES'], ['AzureAdPrt', 'NO'], ['Microsoft MDM enrollment records', 0, 'Intune']], []), now: NOW });
  assert.equal(by(r, 'client-enrollment').status, 'info');
  assert.equal(by(r, 'client-prt').status, 'info');
  assert.equal(by(r, 'client-joined').status, 'warn');
  assert.equal(r.summary.fail, 0);
});

test('Compliant with no assigned policy is called out and explained, not accepted as proof', () => {
  const cloud = baseCloud({ compliancePolicies: [] });
  const r = evaluateIntuneHealth({ cloud, snapshot: null, now: NOW });
  assert.equal(by(r, 'compliance-basis').status, 'warn');
  assert.match(by(r, 'compliance-basis').finding, /without any setting being evaluated/);
  assert.match(r.devices[0].why.join(' '), /no compliance policy is assigned/);
  assert.equal(by(r, 'client-snapshot').status, 'unknown');
});

test('unreadable sources are unknown, never pass, and do not echo upstream detail', async () => {
  const api = {
    async request(p) { if (p.startsWith('/v1.0/me?')) return { id: USER, userPrincipalName: 'admin@contoso.com' }; throw Object.assign(new Error('SECRET denied'), { status: 403 }); },
    async pages() { throw new Error('SECRET denied'); },
  };
  const r = await intuneHealthReport(api, { tenant: T, beta: false });
  assert.ok(r.unavailable.includes('managedDevices'));
  for (const id of ['lic-intune', 'mdm-scope', 'ca-compliant', 'compliance-basis', 'joined-enrolled']) assert.equal(by(r, id).status, 'unknown', id);
  assert.ok(!JSON.stringify(r).includes('SECRET'));
});

test('cloud collection only reads, skips the preview endpoint unless enabled, and resolves users by object ID', async () => {
  const seen = [];
  const mk = () => ({
    async request(p, o = {}) {
      seen.push([o.method || 'GET', p]);
      if (p.startsWith('/v1.0/me?')) return { id: USER, displayName: 'Aaron', userPrincipalName: 'admin@contoso.com' };
      if (p.startsWith('/v1.0/organization')) return { value: [{ id: T, displayName: 'SecTechTalk' }] };
      if (p.startsWith('/v1.0/deviceManagement?')) return { settings: { secureByDefault: false, deviceComplianceCheckinThresholdDays: 30 } };
      if (p.startsWith(`/v1.0/users/${USER}`)) return { id: USER, userPrincipalName: 'admin@contoso.com', proxyAddresses: ['SMTP:admin@contoso.com', 'smtp:admin@contoso.onmicrosoft.com'] };
      if (p.startsWith('/v1.0/users/')) throw Object.assign(new Error('missing'), { status: 404 });
      return { value: [] };
    },
    async pages(p) {
      seen.push(['GET', p]);
      if (p.includes('managedDevices')) return { rows: [{ id: 'dev1', deviceName: 'DEVICE02', userId: USER, managementAgent: 'mdm', azureADDeviceId: DEV }] };
      return { rows: [] };
    },
  });
  const off = await collectIntuneCloud(mk(), { tenant: T, beta: false, snapshotUpns: ['gone@contoso.com', 'not an email', '../x'] });
  // The only POST is Conditional Access What If, which is a read-only evaluation.
  assert.ok(seen.every(([m, p]) => m === 'GET' || (m === 'POST' && p === '/v1.0/identity/conditionalAccess/evaluate')));
  assert.ok(!seen.some(([, p]) => p.startsWith('/beta/')));
  assert.ok(off.unavailable.includes('mdmScope'));
  assert.deepEqual(off.users[USER].aliases, ['admin@contoso.com', 'admin@contoso.onmicrosoft.com']);
  assert.equal(off.upnLookups['gone@contoso.com'], 'notFound');
  assert.deepEqual(Object.keys(off.upnLookups), ['gone@contoso.com']);
  const on = await collectIntuneCloud(mk(), { tenant: T, beta: true });
  assert.ok(seen.some(([, p]) => p.startsWith('/beta/policies/mobileDeviceManagementPolicies')));
  assert.ok(Array.isArray(on.mdmScope));
});

test('enrollment name that is a different account, or no longer exists, is not treated as a match', () => {
  const lone = n => baseCloud({ users: { [USER]: { id: USER, upn: 'admin@contoso.com', mail: null, aliases: [] } }, upnLookups: n });
  const s = snap([['AzureAdJoined', 'YES'], ['MDM enrollment 1', 'Provider=MS DM Server; UPN=other@contoso.com; Discovery=https://enrollment.manage.microsoft.com/e; State=1; Type=6', 'Intune']]);
  const diff = evaluateIntuneHealth({ cloud: lone({ 'other@contoso.com': { id: '44444444-4444-4444-4444-444444444444', upn: 'other@contoso.com' } }), snapshot: s, now: NOW });
  assert.equal(by(diff, 'user-identity').status, 'fail');
  const gone = evaluateIntuneHealth({ cloud: lone({ 'other@contoso.com': 'notFound' }), snapshot: s, now: NOW });
  assert.equal(by(gone, 'user-identity').status, 'warn');
  const same = evaluateIntuneHealth({ cloud: lone({ 'other@contoso.com': { id: USER, upn: 'other@contoso.com' } }), snapshot: s, now: NOW });
  assert.equal(by(same, 'user-identity').status, 'pass');
});

test('a compliant-device policy that Microsoft says applies to Intune Enrollment is flagged', () => {
  const policy = { id: 'p', name: 'Require compliant', state: 'enabled', controls: ['compliantDevice'], missing: [] };
  assert.equal(by(evaluateIntuneHealth({ cloud: baseCloud({ enrollmentCa: [policy] }), snapshot: null, now: NOW }), 'ca-compliant').status, 'warn');
  assert.equal(by(evaluateIntuneHealth({ cloud: baseCloud({ enrollmentCa: [] }), snapshot: null, now: NOW }), 'ca-compliant').status, 'pass');
  assert.equal(by(evaluateIntuneHealth({ cloud: baseCloud({ enrollmentCa: [{ ...policy, state: 'enabledForReportingButNotEnforced' }] }), snapshot: null, now: NOW }), 'ca-compliant').status, 'pass');
});

test('snapshot enrollment facts parse; stale sync and mdm log errors warn', () => {
  const s = snap([...healthy.filter(f => !String(f[0]).startsWith('MDM log')), ['MDM log errors and warnings (24 hours)', '14 events: ID 404 x12, ID 454 x2', 'Intune']]);
  assert.equal(snapshotEnrollments(s)[0].State, '1');
  const cloud = baseCloud();
  cloud.managedDevices[0].lastSyncDateTime = iso(9 * 86400000);
  const r = evaluateIntuneHealth({ cloud, snapshot: s, now: NOW });
  assert.equal(by(r, 'client-mdmlog').status, 'warn');
  assert.equal(by(r, 'sync-fresh').status, 'warn');
});

test('demo report evaluates, and the route requires CSRF and rejects bad snapshots', async t => {
  const demo = demoIntuneReport(null, NOW);
  assert.equal(demo.mode, 'demo');
  assert.ok(demo.checks.length >= 8);
  const server = createApp({ port: 3633 }).listen(3633, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const base = 'http://127.0.0.1:3633';
  const response = await fetch(base + '/api/session');
  const session = await response.json();
  const cookie = response.headers.get('set-cookie').split(';')[0];
  const headers = { Cookie: cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': session.csrf };
  assert.equal((await fetch(base + '/api/intune/health', { method: 'POST', body: '{}', headers: { 'Content-Type': 'application/json', Cookie: cookie } })).status, 403);
  assert.equal((await fetch(base + '/api/intune/health', { method: 'POST', body: JSON.stringify({ snapshot: { nope: 1 } }), headers })).status, 400);
  const ok = await fetch(base + '/api/intune/health', { method: 'POST', body: '{}', headers });
  assert.equal(ok.status, 200);
  assert.equal((await ok.json()).mode, 'demo');
});
