// Device lookup: search by name, serial number or ID; one device's details and people; Entra-only devices on a person's
// Devices page; the demo routes; and the page's pure helpers.
process.env.DEMO_MODE ??= 'true';
import test from 'node:test';
import assert from 'node:assert/strict';
import { searchDevices, deviceDetails, mergeDeviceRows, searchDemoDevices, demoDeviceDetails, DEMO_DEVICES } from '../server/devices.mjs';
import { searchLive, liveReport, mergeEntraDevices } from '../server/live.mjs';
import { roleForPath, decide } from '../server/authflow.mjs';
import { createApp } from '../server/index.mjs';
import { deviceFacts, peopleHtml, deviceQuery, complianceText } from '../public/device-lookup.js';
import { VIEW_ROLES } from '../public/access-denied.js';
import { freePort } from './free-port.mjs';

const E1 = '11111111-1111-4111-8111-111111111111', D1 = '22222222-2222-4222-8222-222222222222', M1 = '33333333-3333-4333-8333-333333333333';
const U1 = '44444444-4444-4444-8444-444444444444', U2 = '55555555-5555-4555-8555-555555555555', U3 = '66666666-6666-4666-8666-666666666666';
const E2 = '77777777-7777-4777-8777-777777777777', D2 = '88888888-8888-4888-8888-888888888888';
const denied = () => { throw Object.assign(new Error('denied'), { status: 403 }); };
const notFound = () => { throw Object.assign(new Error('nf'), { status: 404 }); };
const entraDev = { id: E1, deviceId: D1, displayName: 'DEVICE02', operatingSystem: 'Windows', operatingSystemVersion: '10.0.26100', trustType: 'AzureAd', accountEnabled: true, registrationDateTime: '2026-01-01T00:00:00Z', deviceOwnership: 'Company' };
const intuneDev = { id: M1, deviceName: 'DEVICE02', serialNumber: 'SN123', manufacturer: 'Contoso', model: 'Book 5', operatingSystem: 'Windows', osVersion: '10.0.26100.1', complianceState: 'compliant', isEncrypted: true, enrolledDateTime: '2026-01-02T00:00:00Z', lastSyncDateTime: '2026-11-12T00:00:00Z', managedDeviceOwnerType: 'company', userId: U1, userPrincipalName: 'aaron@example.test', userDisplayName: 'Aaron', azureADDeviceId: D1 };

test('device search joins Entra and Intune on the Entra device ID and searches serial numbers exactly', async () => {
  const seen = [];
  const api = { async request(url) { seen.push(decodeURIComponent(url)); if (url.startsWith('/v1.0/devices')) return { value: [entraDev] }; if (url.includes('serialNumber')) return { value: [intuneDev] }; return { value: [] }; } };
  const r = await searchDevices(api, 'SN123');
  assert.equal(r.entities.length, 1);
  assert.deepEqual([r.entities[0].type, r.entities[0].entraId, r.entities[0].intuneId, r.entities[0].name], ['device', E1, M1, 'DEVICE02']);
  assert.match(r.entities[0].subtitle, /Serial SN123/);
  assert.ok(seen.some(u => u.includes("serialNumber eq 'SN123'")));
  assert.ok(seen.some(u => u.includes("contains(deviceName,'SN123')")));
  assert.ok(seen.some(u => u.includes("startsWith(displayName,'SN123')")));
});
test('device search keeps Entra results when Intune is denied, escapes quotes, and ignores one-letter queries', async () => {
  const seen = [];
  const api = { async request(url) { seen.push(decodeURIComponent(url)); if (url.startsWith('/v1.0/devices')) return { value: [{ ...entraDev, deviceId: null }] }; return denied(); } };
  const r = await searchDevices(api, "o'neil");
  assert.equal(r.entities.length, 1); assert.equal(r.entities[0].intuneId, null); assert.match(r.entities[0].subtitle, /Not in Intune/);
  assert.equal(r.partial, false); assert.equal(r.denied, 2);
  assert.ok(seen.every(u => !u.includes("o'neil'")) && seen.some(u => u.includes("o''neil")));
  assert.deepEqual((await searchDevices(api, 'a')).entities, []);
});
test('a GUID finds the device by Entra object ID, Entra device ID or Intune ID; an Intune 404 is a miss', async () => {
  const api = { async request(url) { if (url.startsWith(`/v1.0/deviceManagement/managedDevices/${E1}`)) return notFound(); if (url.startsWith('/v1.0/devices')) return { value: [entraDev] }; return { value: [] }; } };
  const r = await searchDevices(api, E1);
  assert.equal(r.entities.length, 1); assert.equal(r.partial, false);
});
test('mergeDeviceRows lists Intune-only and Entra-only devices separately and never duplicates an Intune record', () => {
  const rows = mergeDeviceRows([entraDev, { id: E2, deviceId: D2, displayName: 'PHONE' }], [intuneDev, intuneDev, { ...intuneDev, id: '99999999-9999-4999-8999-999999999999', azureADDeviceId: null, deviceName: 'KIOSK' }]);
  assert.deepEqual(rows.map(r => [r.name, Boolean(r.entraId), Boolean(r.intuneId)]), [['DEVICE02', true, true], ['PHONE', true, false], ['KIOSK', false, true]]);
});
test('entity search returns devices with people and apps, and still answers when only device search is allowed', async () => {
  const api = { async request(url) { if (url.startsWith('/v1.0/users') || url.startsWith('/v1.0/servicePrincipals')) return denied(); if (url.startsWith('/v1.0/devices')) return { value: [entraDev] }; return { value: [] }; } };
  const r = await searchLive(api, 'ABLAP', 't1');
  assert.deepEqual(r.entities.map(e => [e.type, e.name, e.tenant]), [['device', 'DEVICE02', 't1']]);
  const none = { async request() { return denied(); } };
  await assert.rejects(searchLive(none, 'ABLAP', 't1'), e => e.status === 403);
});
test('device details: full facts, people from Intune primary user, Entra owners and (beta) logged-on users', async () => {
  const seen = [];
  const api = {
    async request(url) {
      seen.push(url);
      if (url.startsWith(`/v1.0/devices/${E1}`)) return entraDev;
      if (url.startsWith('/v1.0/deviceManagement/managedDevices?')) return { value: [intuneDev] };
      if (url.startsWith(`/beta/deviceManagement/managedDevices/${M1}`)) return { usersLoggedOn: [{ userId: U1, lastLogOnDateTime: '2026-11-12T08:00:00Z' }, { userId: U3, lastLogOnDateTime: '2026-11-11T08:00:00Z' }] };
      if (url.startsWith(`/v1.0/users/${U3}`)) return { id: U3, displayName: 'Shared Sam', userPrincipalName: 'sam@example.test', accountEnabled: true };
      if (url.startsWith(`/v1.0/users/${U1}`)) return { id: U1, displayName: 'Aaron', userPrincipalName: 'aaron@example.test', accountEnabled: true };
      return notFound();
    },
    async pages(url) {
      if (url.includes('/registeredOwners/')) return { rows: [{ id: U1, displayName: 'Aaron', userPrincipalName: 'aaron@example.test', accountEnabled: true }], truncated: false };
      if (url.includes('/registeredUsers/')) return { rows: [{ id: U2, displayName: 'Bea', userPrincipalName: 'bea@example.test', accountEnabled: false }], truncated: false };
      return { rows: [], truncated: false };
    },
  };
  const r = await deviceDetails(api, { entraId: E1 }, { beta: true, tenant: 't1' });
  assert.equal(r.device.intuneId, M1); assert.equal(r.device.serialNumber, 'SN123'); assert.equal(r.device.model, 'Book 5');
  assert.equal(r.device.encrypted, true); assert.equal(r.device.ownership, 'Corporate'); assert.equal(r.device.joinType, 'Entra joined');
  assert.match(r.device.entraLink, new RegExp(E1)); assert.match(r.device.intuneLink, new RegExp(M1));
  assert.deepEqual(r.people.map(p => [p.name, p.relations]), [
    ['Aaron', ['Primary user (Intune)', 'Registered owner (Entra)', 'Logged on (Intune)']],
    ['Bea', ['Registered user (Entra)']],
    ['Shared Sam', ['Logged on (Intune)']],
  ]);
  assert.equal(r.people[0].lastLogOn, '2026-11-12T08:00:00Z'); assert.equal(r.people[1].enabled, false);
  assert.ok(seen.some(u => decodeURIComponent(u).includes(`azureADDeviceId eq '${D1}'`)));
  assert.equal(r.partial, false); assert.deepEqual(r.unavailable, []);
});
test('device details without Graph beta says how to see logged-on users; Intune-only and Entra-only notes', async () => {
  const api = { async request(url) { if (url.startsWith(`/v1.0/deviceManagement/managedDevices/${M1}`)) return { ...intuneDev, azureADDeviceId: null }; return notFound(); }, async pages() { return { rows: [] }; } };
  const r = await deviceDetails(api, { intuneId: M1 }, { beta: false });
  assert.equal(r.device.entraId, null); assert.equal(r.device.joinType, 'Not in Entra');
  assert.ok(r.notes.some(n => /ENABLE_GRAPH_BETA/.test(n)));
  assert.ok(r.notes.some(n => /no Entra device object/.test(n)));
  assert.deepEqual(r.people.map(p => p.relations), [['Primary user (Intune)']]);
});
test('device details: a source the viewer cannot read is listed as unavailable; nothing readable is a 403', async () => {
  const api = { async request(url) { if (url.startsWith(`/v1.0/devices/${E1}`)) return { ...entraDev }; return denied(); }, async pages() { return denied(); } };
  const r = await deviceDetails(api, { entraId: E1 }, { beta: true });
  assert.equal(r.device.intuneId, null);
  assert.ok(r.unavailable.some(u => /Intune device/.test(u.source)));
  assert.ok(r.unavailable.some(u => /registered owner/.test(u.source)));
  await assert.rejects(deviceDetails({ async request() { return denied(); } }, { entraId: E1 }), e => e.status === 403);
  await assert.rejects(deviceDetails({ async request() { return notFound(); } }, { entraId: E1 }), e => e.status === 404);
  await assert.rejects(deviceDetails({}, { entraId: 'not-a-guid' }), e => e.status === 400);
  await assert.rejects(deviceDetails({}, {}), e => e.status === 400);
});
test('a person’s Devices page adds Entra devices that are not in Intune and links matched ones', () => {
  const report = { policies: [{ kind: 'Device', source: 'intune', id: M1, azureADDeviceId: D1, trustType: null }] };
  mergeEntraDevices(report, [entraDev, { id: E2, deviceId: D2, displayName: 'BYOD-PHONE', trustType: 'Workplace' }]);
  assert.equal(report.policies.length, 2);
  assert.equal(report.policies[0].entraId, E1); assert.equal(report.policies[0].trustType, 'AzureAd');
  const extra = report.policies[1];
  assert.deepEqual([extra.name, extra.status, extra.source, extra.deviceId, extra.entraId, extra.intuneId], ['BYOD-PHONE', 'Not in Intune', 'directory', null, E2, null]);
});
test('liveReport reads registered and owned devices for a user', async () => {
  const id = U1, range = { from: '2026-11-01T00:00:00.000Z', to: '2026-11-13T00:00:00.000Z' };
  const api = {
    async request(url) { if (url === `/v1.0/users/${id}`) return { id, displayName: 'Aaron', userPrincipalName: 'aaron@example.test' }; return denied(); },
    async pages(url) {
      if (url.includes('/registeredDevices/microsoft.graph.device')) return { rows: [{ id: E2, deviceId: D2, displayName: 'BYOD-PHONE', trustType: 'Workplace' }], truncated: false };
      if (url.includes('/ownedDevices/microsoft.graph.device')) return { rows: [{ id: E2, deviceId: D2, displayName: 'BYOD-PHONE', trustType: 'Workplace' }], truncated: false };
      if (url.includes('memberOf')) return { rows: [], truncated: false };
      return denied();
    },
  };
  const report = await liveReport(api, id, 'user', range, { tenant: 't1' });
  const devices = report.policies.filter(p => p.kind === 'Device');
  assert.deepEqual(devices.map(d => [d.name, d.status]), [['BYOD-PHONE', 'Not in Intune']]);
});
test('device routes: E360.Reader role, demo search and details, invalid IDs rejected', async t => {
  assert.equal(roleForPath('/api/device/details'), 'E360.Reader');
  assert.equal(decide({ mode: 'live', path: '/api/device/details', roles: ['E360.Intune', 'E360.SignIns'], enforce: true }).allowed, false);
  assert.equal(decide({ mode: 'live', path: '/api/device/details', roles: ['E360.Reader'], enforce: true }).allowed, true);
  assert.equal(VIEW_ROLES.device, 'E360.Reader');
  const port = await freePort();
  const server = createApp({ port }).listen(port, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const base = `http://127.0.0.1:${port}`;
  const cookie = (await fetch(`${base}/api/session`)).headers.get('set-cookie').split(';')[0];
  const get = path => fetch(base + path, { headers: { Cookie: cookie } });
  const search = await (await get('/api/entities?q=KIOSK')).json();
  assert.deepEqual(search.entities.map(e => [e.type, e.name]), [['device', 'KIOSK-FIN-01']]);
  const kiosk = DEMO_DEVICES[1];
  const details = await (await get(`/api/device/details?${deviceQuery(kiosk)}`)).json();
  assert.equal(details.device.serialNumber, 'KSK0099ABC'); assert.equal(details.people.length, 2);
  assert.equal((await get('/api/device/details?entraId=nope')).status, 400);
  assert.equal((await get('/api/device/details')).status, 400);
  assert.equal((await get('/api/device/details?entraId=00000000-0000-4000-8000-000000000000')).status, 404);
});
test('demo devices: search matches serial numbers; details exist for each demo device', () => {
  assert.deepEqual(searchDemoDevices('cnd1234').map(d => d.name), ['LAPTOP-AM-042']);
  for (const d of DEMO_DEVICES) assert.ok(demoDeviceDetails(d)?.device?.name === d.name);
});
test('device page helpers: facts say what is missing, people are escaped, query carries only known IDs', () => {
  const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const facts = Object.fromEntries(deviceFacts({ entraId: E1, intuneId: null, operatingSystem: 'iOS', osVersion: '18.1', ownership: 'Personal', joinType: 'Registered' }));
  assert.equal(facts['Operating system'], 'iOS 18.1'); assert.equal(facts['Serial number'], 'Needs an Intune record'); assert.equal(facts['Enrolled in Intune'], 'Not enrolled');
  assert.equal(facts['Model'], 'Not returned');
  const html = peopleHtml([{ id: U1, name: '<b>x</b>', upn: 'a@b', relations: ['Logged on (Intune)'], lastLogOn: null, enabled: true }], esc);
  assert.match(html, /&lt;b&gt;x&lt;\/b&gt;/); assert.match(html, /data-device-person="0"/);
  assert.match(peopleHtml([], esc), /No person is linked/);
  assert.equal(String(deviceQuery({ entraId: E1, intuneId: null })), `entraId=${E1}`);
  assert.equal(complianceText('noncompliant'), 'Not compliant');
});
