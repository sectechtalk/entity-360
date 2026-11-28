// Single-entity PDF report: the PDF writer, the gather step (each source read on its own, failures reported, never dropped),
// the route (E360.Reader, demo PDFs, audit line) and the Summary and device page buttons.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { inflateSync } from 'node:zlib';
import { renderPdf, winAnsi, wrap, textWidth, display } from '../server/pdf.mjs';
import { gatherEntity, buildDocument, propertyRows, defenderDays, daysOf, reportFileName, demoGather, USER_SELECT } from '../server/entity-report.mjs';
import { roleForPath, decide } from '../server/authflow.mjs';
import { createApp } from '../server/index.mjs';
import { entities, demoReport } from '../server/demo.mjs';
import { DEMO_DEVICES } from '../server/devices.mjs';
import { reportUrl, downloadReport } from '../public/entity-pdf.js';
import { freePort } from './free-port.mjs';

const read = f => readFileSync(new URL(`../${f}`, import.meta.url), 'utf8');
const NOW = Date.parse('2026-11-14T12:00:00Z');
const RANGE = { from: '2026-11-07T12:00:00.000Z', to: '2026-11-14T12:00:00.000Z' };
const USER = '11111111-1111-4111-8111-111111111111', SP = '22222222-2222-4222-8222-222222222222', APPID = '33333333-3333-4333-8333-333333333333';
const GROUP = '44444444-4444-4444-8444-444444444444', DEV = '55555555-5555-4555-8555-555555555555', MDM = '66666666-6666-4666-8666-666666666666';
const denied = () => Object.assign(new Error('Access not granted.'), { status: 403, upstreamCode: 'Authorization_RequestDenied' });

// Lists come back through pages(), objects through request(). The first fixture key found in the URL wins.
function fakeApi(fixtures) {
  const calls = [];
  const hit = u => Object.entries(fixtures).find(([k]) => decodeURIComponent(u).includes(k))?.[1];
  const resolve = async u => { calls.push(u); const f = typeof hit(u) === 'function' ? hit(u)(u) : hit(u); if (f instanceof Error) throw f; return f; };
  return { calls,
    request: async u => (await resolve(u)) ?? {},
    pages: async u => { const f = await resolve(u); return { rows: f?.value || (Array.isArray(f) ? f : []) }; } };
}
// Text drawn on the pages (Tj operands), decoded from the deflated streams, so tests can look for words.
function pdfText(buf) {
  const s = buf.toString('latin1'), out = [];
  for (const m of s.matchAll(/<< \/Length (\d+) \/Filter \/FlateDecode >>\nstream\n/g)) {
    const start = m.index + m[0].length, body = inflateSync(buf.subarray(start, start + Number(m[1]))).toString('latin1');
    for (const t of body.matchAll(/\((.*?)\) Tj/g)) out.push(t[1].replace(/\\([()\\])/g, '$1'));
  }
  return out.join('\n');
}

test('pdf: WinAnsi text, wrapping, display values', () => {
  assert.equal(winAnsi('Café – “ok” → done ✓'), 'Café \x96 \x93ok\x94 -> done Yes');
  assert.equal(winAnsi('emoji 😀'), 'emoji ?');
  assert.equal(winAnsi('a\u0000b\tc'), 'ab c');
  for (const l of wrap(winAnsi('a'.repeat(400) + ' short words here'), 'F1', 9, 200)) assert.ok(textWidth(l, 'F1', 9) <= 200);
  assert.equal(display('2026-11-14T12:34:56Z'), '2026-11-14 12:34 UTC');
  assert.equal(display('0001-01-01T00:00:00Z'), '-');
  assert.equal(display(true), 'Yes'); assert.equal(display([]), '-'); assert.equal(display(null), '-');
  assert.equal(display({ a: 1, b: null }), 'a: 1');
});

test('pdf: valid structure, xref offsets, page numbers and bookmarks', () => {
  const rows = Array.from({ length: 120 }, (_, i) => [`Row ${i}`, 'x '.repeat(i % 30), i % 2 === 0]);
  const buf = renderPdf({ title: 'Test entity', subtitle: 'User', meta: [['Object ID', USER]], footer: 'Entity 360 · Test',
    sections: [{ title: 'First', status: 'ok', blocks: [{ type: 'table', columns: [{ label: 'A', w: 1 }, { label: 'B', w: 3 }, { label: 'C', w: 1 }], rows }] },
      { title: 'Second (with (parens) and \\ slash)', status: 'unavailable', reason: 'not granted', blocks: [{ type: 'kv', rows: [['Key', 'Value']] }] }] });
  const s = buf.toString('latin1');
  assert.ok(s.startsWith('%PDF-1.4')); assert.ok(s.trimEnd().endsWith('%%EOF'));
  const startxref = Number(/startxref\n(\d+)/.exec(s)[1]);
  assert.ok(s.slice(startxref).startsWith('xref'));
  const offsets = [...s.slice(startxref).matchAll(/^(\d{10}) 00000 n $/gm)].map(m => Number(m[1]));
  offsets.forEach((o, i) => assert.ok(s.slice(o).startsWith(`${i + 1} 0 obj`), `object ${i + 1} offset`));
  const pages = Number(/\/Type \/Pages \/Kids \[[^\]]*\] \/Count (\d+)/.exec(s)[1]);
  assert.ok(pages >= 3);
  const text = pdfText(buf);
  assert.match(text, new RegExp(`Page ${pages} of ${pages}`));
  assert.match(text, /Row 119/);
  assert.match(text, /Could not be read: not granted/);
  assert.match(s, /\/Outlines \d+ 0 R \/PageMode \/UseOutlines/);
  assert.match(s, /\/Title \(2\. Second \\\(with \\\(parens\\\) and \\\\ slash\\\)\)/);
});

const userFixtures = (over = {}) => ({
  [`/v1.0/users/${USER}?$select=${USER_SELECT}`]: { id: USER, displayName: 'Pat Example', userPrincipalName: 'pat@example.test', jobTitle: 'Engineer', department: 'Platform', accountEnabled: true, proxyAddresses: ['SMTP:pat@example.test'], onPremisesExtensionAttributes: { extensionAttribute1: 'A1', extensionAttribute2: null } },
  [`/v1.0/users/${USER}?$select=id,signInActivity`]: { signInActivity: { lastSignInDateTime: '2026-11-13T08:00:00Z' } },
  [`/v1.0/users/${USER}/manager`]: { id: GROUP, displayName: 'Morgan Boss', userPrincipalName: 'boss@example.test' },
  [`/v1.0/users/${USER}/directReports`]: [],
  [`/v1.0/users/${USER}/licenseDetails`]: [{ skuPartNumber: 'SPE_E5', servicePlans: [{ servicePlanName: 'EXCHANGE_S_ENTERPRISE', provisioningStatus: 'Success' }] }],
  userRegistrationDetails: { isMfaRegistered: true, methodsRegistered: ['microsoftAuthenticatorPush'] },
  [`/v1.0/users/${USER}/transitiveMemberOf/microsoft.graph.group`]: [{ id: GROUP, displayName: 'SEC-Engineering', groupTypes: [], onPremisesSyncEnabled: false }],
  [`/v1.0/users/${USER}/memberOf/microsoft.graph.administrativeUnit`]: denied(),
  [`/v1.0/users/${USER}?$select=id,displayName,onPremisesSyncEnabled`]: { id: USER, onPremisesSyncEnabled: false },
  [`/v1.0/users/${USER}?`]: { id: USER, displayName: 'Pat Example', userPrincipalName: 'pat@example.test', accountEnabled: true, userType: 'Member' },
  [`/v1.0/users/${USER}`]: { id: USER, displayName: 'Pat Example', userPrincipalName: 'pat@example.test', accountEnabled: true },
  'auditLogs/signIns': [{ id: 's1', createdDateTime: '2026-11-13T08:00:00Z', appDisplayName: 'Office 365 Exchange Online', resourceDisplayName: 'Office 365 Exchange Online', status: { errorCode: 0 }, ipAddress: '192.0.2.10', appliedConditionalAccessPolicies: [{ id: 'p1', displayName: 'Require MFA', result: 'success' }] }],
  'runHuntingQuery': denied(),
  '/v1.0/applications?': [],
  ...over,
});

test('gather: a user report lists every section, and a source that fails says why instead of disappearing', async () => {
  const api = fakeApi(userFixtures());
  const g = await gatherEntity(api, { id: USER, type: 'user' }, { range: RANGE, tenant: 'Example', now: NOW, ad: { config: { cloud: true } } });
  const doc = buildDocument(g, { viewer: 'viewer@example.test', hosting: 'cloud', azure: false });
  const titles = doc.sections.map(s => s.title);
  for (const t of ['Identity overview', 'Directory profile (all attributes)', 'Authentication methods and MFA registration', 'Licenses', 'Organization', 'Group memberships',
    'Entra admin roles', 'Azure roles (RBAC)', 'Privileged Identity Management', 'PIM requests', 'Administrative units', 'Application assignments', 'Delegated permission grants (consents)',
    'Conditional Access', 'Access packages (entitlement management)', 'Devices', 'On-premises Active Directory', 'Objects this identity owns', 'Sign-ins (7 days)',
    'Directory changes (Entra audit, 7 days)', 'Provisioning (7 days)', 'Azure activity log', 'Defender process events', 'Findings', 'Coverage and notes']) assert.ok(titles.includes(t), `missing ${t}`);
  const by = t => doc.sections.find(s => s.title === t);
  assert.equal(by('Administrative units').status, 'unavailable');
  assert.match(by('Administrative units').reason, /not granted.*Authorization_RequestDenied/);
  assert.equal(by('Azure roles (RBAC)').status, 'unavailable');
  assert.match(by('Azure activity log').reason, /Connect Azure/);
  assert.equal(by('Defender process events').status, 'unavailable');
  assert.equal(by('Group memberships').summary, '1 group(s)');
  const buf = renderPdf(doc), text = pdfText(buf);
  for (const w of ['Pat Example', 'SEC-Engineering', 'SPE_E5', 'EXCHANGE_S_ENTERPRISE', 'Morgan Boss', 'SMTP:pat@example.test', 'extensionAttribute1: A1', 'Office 365 Exchange Online', 'Require MFA: success', 'NOT READ', 'Cloud-hosted copy']) assert.ok(text.includes(w), `PDF lacks ${w}`);
  assert.ok(!text.includes('extensionAttribute2'), 'empty attributes are left out');
});

test('gather: on-premises AD from a cloud-hosted copy says it cannot reach a domain controller', async () => {
  const api = fakeApi(userFixtures({ [`/v1.0/users/${USER}?$select=id,displayName,onPremisesSyncEnabled`]: { id: USER, onPremisesSyncEnabled: true, onPremisesSecurityIdentifier: 'S-1-5-21-1-2-3-1001', onPremisesSamAccountName: 'pat', onPremisesDomainName: 'example.test' } }));
  const g = await gatherEntity(api, { id: USER, type: 'user' }, { range: RANGE, now: NOW, findings: false, ad: { config: { cloud: true } } });
  const s = buildDocument(g, { hosting: 'cloud' }).sections.find(x => x.title === 'On-premises Active Directory');
  assert.equal(s.status, 'partial');
  assert.ok(s.blocks.some(b => b.type === 'callout' && /cannot reach a domain controller/.test(b.text)));
});

test('gather: an application report covers who has access, owners, credentials, SSO and the app registration', async () => {
  const api = fakeApi({
    [`/v1.0/servicePrincipals/${SP}/appRoleAssignedTo`]: [{ principalDisplayName: 'SEC-Finance', principalType: 'Group', appRoleId: 'r1', createdDateTime: '2026-01-01T00:00:00Z' }],
    [`/v1.0/servicePrincipals/${SP}/owners`]: [{ id: USER, displayName: 'Pat Example' }],
    [`/v1.0/servicePrincipals/${SP}?$select=id,appId,displayName,appRoles,preferredSingleSignOnMode`]: { appRoles: [{ id: 'r1', displayName: 'Approver', value: 'Approve', allowedMemberTypes: ['User'] }], preferredSingleSignOnMode: 'saml', replyUrls: ['https://app.example.test/acs'] },
    [`/v1.0/servicePrincipals/${SP}`]: { id: SP, appId: APPID, displayName: 'Finance App', servicePrincipalType: 'Application', appRoleAssignmentRequired: true, appRoles: [{ id: 'r1', displayName: 'Approver' }], accountEnabled: true },
    [`appId eq '${APPID}'`]: { value: [{ id: 'app1', appId: APPID, displayName: 'Finance App', signInAudience: 'AzureADMyOrg', passwordCredentials: [{ keyId: 'k1', displayName: 'ci secret', endDateTime: '2027-01-01T00:00:00Z' }], requiredResourceAccess: [{ resourceAppId: '00000003-0000-0000-c000-000000000000', resourceAccess: [{ id: 'perm1', type: 'Role' }] }] }] },
    "servicePrincipals(appId='00000003": { displayName: 'Microsoft Graph', appRoles: [{ id: 'perm1', value: 'User.Read.All', displayName: 'Read all users' }] },
    '/v1.0/applications/app1/owners': [{ displayName: 'Dev Owner', userPrincipalName: 'dev@example.test' }],
  });
  const g = await gatherEntity(api, { id: SP, type: 'application' }, { range: RANGE, now: NOW, findings: false });
  const text = pdfText(renderPdf(buildDocument(g)));
  for (const w of ['Finance App', 'Who has access to this app', 'SEC-Finance', 'Approver', 'Pat Example', 'Dev Owner', 'ci secret', 'SAML', 'User.Read.All', 'Read all users', 'AzureADMyOrg']) assert.ok(text.includes(w), `PDF lacks ${w}`);
});

test('gather: a device report covers people, groups, policy states and both raw objects', async () => {
  const api = fakeApi({
    [`/v1.0/devices/${DEV}/transitiveMemberOf`]: [{ id: GROUP, displayName: 'Autopilot devices', membershipRule: '(device.devicePhysicalIDs -any _ -contains "[ZTDId]")' }],
    [`/v1.0/devices/${DEV}/registered`]: [],
    [`/v1.0/devices/${DEV}?$select`]: { id: DEV, deviceId: 'd1d1d1d1-0000-4000-8000-000000000001', displayName: 'LAPTOP-TEST', trustType: 'AzureAd', operatingSystem: 'Windows' },
    [`/v1.0/devices/${DEV}`]: { id: DEV, displayName: 'LAPTOP-TEST', extensionAttributes: { extensionAttribute3: 'Kiosk' }, physicalIds: ['[ZTDId]:abc'] },
    "azureADDeviceId eq": { value: [{ id: MDM, deviceName: 'LAPTOP-TEST', serialNumber: 'SN123', complianceState: 'compliant' }] },
    [`managedDevices/${MDM}/deviceCompliancePolicyStates`]: [{ id: 'c1', displayName: 'Windows baseline', state: 'compliant', settingCount: 12 }],
    [`managedDevices/${MDM}/deviceConfigurationStates`]: [],
    [`managedDevices/${MDM}`]: { id: MDM, deviceName: 'LAPTOP-TEST', serialNumber: 'SN123', totalStorageSpaceInBytes: 256e9 },
  });
  const g = await gatherEntity(api, { type: 'device', entraId: DEV }, { now: NOW, findings: false });
  const doc = buildDocument(g);
  assert.deepEqual(doc.sections.map(s => s.title).slice(0, 6), ['Device overview', 'People on this device', 'Group memberships', 'Intune compliance and configuration', 'Entra device (all properties)', 'Intune managed device (all properties)']);
  const text = pdfText(renderPdf(doc));
  for (const w of ['LAPTOP-TEST', 'Autopilot devices', 'Windows baseline', 'extensionAttribute3: Kiosk', 'SN123']) assert.ok(text.includes(w), `PDF lacks ${w}`);
});

test('helpers: property rows, windows and file names', () => {
  assert.deepEqual(propertyRows({ '@odata.context': 'x', displayName: 'A', empty: '', list: [], plans: [{ servicePlanName: 'P1' }, { x: 1 }], skipMe: 1 }, ['skipMe']), [['Display Name', 'A'], ['Plans', '2: P1']]);
  assert.equal(defenderDays(7), 7); assert.equal(defenderDays(10), 7); assert.equal(defenderDays(90), 30);
  assert.equal(daysOf(RANGE), 7);
  assert.equal(reportFileName('Pat Example / ü', '2026-11-14T00:00:00Z'), 'entity-360-Pat-Example-u-2026-11-14.pdf');
});

test('demo: every demo identity renders a PDF', () => {
  for (const e of entities) {
    const r = demoReport(e.id, RANGE, 'analyst', NOW);
    const buf = renderPdf(buildDocument(demoGather(r, RANGE, NOW)));
    assert.match(pdfText(buf), new RegExp(e.name));
  }
});

test('route: E360.Reader, demo PDFs for people and devices, bad input rejected', async t => {
  assert.equal(roleForPath('/api/investigate/report.pdf'), 'E360.Reader');
  assert.equal(decide({ mode: 'live', path: '/api/investigate/report.pdf', roles: ['E360.Intune', 'E360.SignIns'], enforce: true }).allowed, false);
  assert.equal(decide({ mode: 'live', path: '/api/investigate/report.pdf', roles: ['E360.Reader'], enforce: true }).allowed, true);
  const port = await freePort();
  const app = createApp({ port, demoMode: true });
  const server = app.listen(port, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const base = `http://127.0.0.1:${port}`;
  const cookie = (await fetch(`${base}/api/session`)).headers.get('set-cookie').split(';')[0];
  const get = path => fetch(base + path, { headers: { Cookie: cookie } });
  const user = entities[0];
  const r = await get(reportUrl(user, RANGE));
  assert.equal(r.status, 200);
  assert.equal(r.headers.get('content-type'), 'application/pdf');
  assert.match(r.headers.get('content-disposition'), /attachment; filename="entity-360-Alex-Morgan-\d{4}-\d{2}-\d{2}\.pdf"/);
  assert.equal(r.headers.get('cache-control'), 'no-store');
  const buf = Buffer.from(await r.arrayBuffer());
  assert.match(pdfText(buf), /Alex Morgan/);
  const dev = await get(reportUrl({ type: 'device', entraId: DEMO_DEVICES[0].entraId }));
  assert.equal(dev.status, 200);
  assert.match(pdfText(Buffer.from(await dev.arrayBuffer())), new RegExp(DEMO_DEVICES[0].name));
  assert.equal((await get('/api/investigate/report.pdf?type=group&id=x')).status, 400);
  assert.equal((await get(`/api/investigate/report.pdf?type=user&id=nope&from=${RANGE.from}&to=${RANGE.to}`)).status, 400);
  assert.equal((await get(`/api/investigate/report.pdf?type=user&id=${user.id}`)).status, 400);
  assert.equal((await get(`/api/investigate/report.pdf?type=user&id=00000000-0000-4000-8000-000000000000&from=${RANGE.from}&to=${RANGE.to}`)).status, 404);
});

test('browser: report URL, download and error text', async () => {
  assert.equal(reportUrl({ type: 'device', entraId: DEV }), `/api/investigate/report.pdf?type=device&entraId=${DEV}`);
  assert.match(reportUrl({ type: 'user', id: USER }, RANGE), new RegExp(`id=${USER}&type=user&from=`));
  const clicked = [];
  const doc = { createElement: () => ({ click() { clicked.push(this.download); }, remove() {} }), body: { appendChild() {} } };
  const ok = { ok: true, blob: async () => new Blob(['%PDF']), headers: new Headers({ 'content-disposition': 'attachment; filename="entity-360-Pat-2026-11-14.pdf"' }) };
  assert.equal(await downloadReport('/x', { fetcher: async () => ok, doc }), 'Downloaded entity-360-Pat-2026-11-14.pdf');
  assert.deepEqual(clicked, ['entity-360-Pat-2026-11-14.pdf']);
  await assert.rejects(downloadReport('/x', { fetcher: async () => ({ ok: false, json: async () => ({ error: 'Access not granted.' }) }), doc }), /Access not granted/);
});

test('pages: the Summary strip and the device card carry the PDF report button', () => {
  const app = read('public/app.js'), device = read('public/device-lookup.js');
  assert.match(app, /id="entity-pdf"/);
  assert.match(app, /bindReportButton\(\$\('#entity-pdf'\)/);
  assert.match(device, /id="device-lookup-pdf"/);
  assert.match(read('package.json'), /node --check server\/pdf\.mjs/);
});
