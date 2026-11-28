// Device lookup: find a device by name, serial number or ID, and read one device's details and the people tied to it.
// Read-only, with the viewer's own delegated token. Entra device objects need Device.Read.All; Intune records need
// DeviceManagementManagedDevices.Read.All. Each source is optional: a 403 from one leaves the other's data in place.
import { GUID, fail, describeError, odata, queryUrl } from './model.mjs';
import { entraDeviceLink, intuneDeviceLink, joinTypeLabel } from '../public/device-links.js';

const ZERO = '00000000-0000-0000-0000-000000000000';
export const ENTRA_DEVICE_SELECT = 'id,deviceId,displayName,operatingSystem,operatingSystemVersion,trustType,isCompliant,isManaged,accountEnabled,approximateLastSignInDateTime,registrationDateTime,deviceOwnership,manufacturer,model,profileType,enrollmentType';
export const INTUNE_DEVICE_SELECT = 'id,deviceName,manufacturer,model,serialNumber,operatingSystem,osVersion,complianceState,isEncrypted,enrolledDateTime,lastSyncDateTime,managedDeviceOwnerType,userId,userPrincipalName,userDisplayName,azureADDeviceId,deviceEnrollmentType,managementAgent,totalStorageSpaceInBytes,freeStorageSpaceInBytes';
const PERSON_SELECT = 'id,displayName,userPrincipalName,accountEnabled';
const MAX_PEOPLE = 25;

const entraKey = id => (GUID.test(id || '') && id !== ZERO ? id.toLowerCase() : null);
const ownership = (intune, entra) => {
  const v = String(intune?.managedDeviceOwnerType || entra?.deviceOwnership || '').toLowerCase();
  return v === 'company' ? 'Corporate' : v === 'personal' ? 'Personal' : 'Not returned';
};

// One search row per physical device: an Entra device and its Intune record are joined on the Entra device ID.
export function mergeDeviceRows(entraRows = [], intuneRows = [], tenant) {
  const byKey = new Map(), out = [];
  for (const e of entraRows) { const row = { entra: e, intune: null }; out.push(row); const k = entraKey(e.deviceId); if (k) byKey.set(k, row); }
  for (const m of intuneRows) {
    if (out.some(r => r.intune?.id === m.id)) continue;
    const row = byKey.get(entraKey(m.azureADDeviceId));
    if (row && !row.intune) row.intune = m; else out.push({ entra: null, intune: m });
  }
  return out.map(({ entra, intune }) => deviceEntity(entra, intune, tenant));
}
export function deviceEntity(entra, intune, tenant) {
  const name = intune?.deviceName || entra?.displayName || intune?.id || entra?.id;
  const os = [intune?.operatingSystem || entra?.operatingSystem, intune?.osVersion || entra?.operatingSystemVersion].filter(Boolean).join(' ');
  const subtitle = [os, intune?.serialNumber ? `Serial ${intune.serialNumber}` : '', intune?.userPrincipalName ? `Primary user ${intune.userPrincipalName}` : '', intune ? '' : 'Not in Intune'].filter(Boolean).join(' · ');
  return { id: entra?.id || intune?.id, type: 'device', name, subtitle: subtitle || 'Device', entraId: entra?.id || null, intuneId: intune?.id || null, tenant };
}

// Search: Entra by display name (or object/device ID), Intune by device name, serial number (or ID).
export async function searchDevices(api, query) {
  const raw = query.trim(), q = odata(raw);
  if (q.length < 2) return { entities: [], partial: false, denied: 0, attempted: 0 };
  const guid = GUID.test(raw);
  const entraCalls = [api.request(queryUrl('/v1.0/devices', { '$filter': guid ? `id eq '${q}' or deviceId eq '${q}'` : `startsWith(displayName,'${q}')`, '$select': ENTRA_DEVICE_SELECT, '$top': '25' }))];
  const intuneCalls = guid
    ? [api.request(`/v1.0/deviceManagement/managedDevices/${q}?$select=${INTUNE_DEVICE_SELECT}`).then(d => ({ value: [d] })), api.request(queryUrl('/v1.0/deviceManagement/managedDevices', { '$filter': `azureADDeviceId eq '${q}'`, '$select': INTUNE_DEVICE_SELECT, '$top': '25' }))]
    : [api.request(queryUrl('/v1.0/deviceManagement/managedDevices', { '$filter': `contains(deviceName,'${q}')`, '$select': INTUNE_DEVICE_SELECT, '$top': '25' })), api.request(queryUrl('/v1.0/deviceManagement/managedDevices', { '$filter': `serialNumber eq '${q}'`, '$select': INTUNE_DEVICE_SELECT, '$top': '25' }))];
  const results = await Promise.allSettled([...entraCalls, ...intuneCalls]);
  const rows = i => results[i].status === 'fulfilled' ? results[i].value.value || [] : [];
  const entra = rows(0), intune = results.slice(1).flatMap((_, i) => rows(i + 1));
  // An object ID that is not a device returns 404 from Intune; that is a miss, not a failure.
  const failed = results.filter(r => r.status === 'rejected' && ![401, 403, 404].includes(r.reason?.status));
  const denied = results.filter(r => r.status === 'rejected' && [401, 403].includes(r.reason?.status)).length;
  return { entities: mergeDeviceRows(entra, intune), partial: failed.length > 0 || results.some(r => r.status === 'fulfilled' && r.value['@odata.nextLink']), denied, attempted: results.length };
}

// Details for one device. Pass the Entra object ID, the Intune managed-device ID, or both; the other is looked up.
export async function deviceDetails(api, { entraId = '', intuneId = '' } = {}, { beta = false, tenant } = {}) {
  if (entraId && !GUID.test(entraId)) throw fail('Invalid device identifier.');
  if (intuneId && !GUID.test(intuneId)) throw fail('Invalid device identifier.');
  if (!entraId && !intuneId) throw fail('Invalid device identifier.');
  const notes = [], unavailable = [], partialReasons = [];
  const miss = (source, e) => { if ([401, 403].includes(e?.status)) unavailable.push({ source, reason: describeError(e) }); else if (e?.status !== 404) partialReasons.push({ source, reason: describeError(e) }); };
  let entra = null, intune = null;
  if (entraId) entra = await api.request(`/v1.0/devices/${entraId}?$select=${ENTRA_DEVICE_SELECT}`).catch(e => { miss('Entra device (Device.Read.All)', e); return null; });
  if (intuneId) intune = await api.request(`/v1.0/deviceManagement/managedDevices/${intuneId}?$select=${INTUNE_DEVICE_SELECT}`).catch(e => { miss('Intune device (DeviceManagementManagedDevices.Read.All)', e); return null; });
  if (!intune && !intuneId && entraKey(entra?.deviceId)) {
    intune = await api.request(queryUrl('/v1.0/deviceManagement/managedDevices', { '$filter': `azureADDeviceId eq '${entra.deviceId}'`, '$select': INTUNE_DEVICE_SELECT, '$top': '1' }))
      .then(r => r.value?.[0] || null).catch(e => { miss('Intune device (DeviceManagementManagedDevices.Read.All)', e); return null; });
  }
  if (!entra && !entraId && entraKey(intune?.azureADDeviceId)) {
    entra = await api.request(queryUrl('/v1.0/devices', { '$filter': `deviceId eq '${intune.azureADDeviceId}'`, '$select': ENTRA_DEVICE_SELECT }))
      .then(r => r.value?.[0] || null).catch(e => { miss('Entra device (Device.Read.All)', e); return null; });
  }
  if (!entra && !intune) {
    if (unavailable.length) throw Object.assign(fail('This device could not be read with your permissions.', 403), { reason: unavailable.map(u => u.source).join('; ') });
    if (partialReasons.length) throw fail(`The device could not be read (${partialReasons[0].reason}). Try again.`, 502);
    throw fail('Device not found.', 404);
  }

  // People: Intune primary user, Entra registered owners and users, and (Graph beta) users who logged on to the device.
  const people = new Map();
  const addPerson = (id, fields, relation) => {
    if (!GUID.test(id || '')) return;
    const key = id.toLowerCase();
    const p = people.get(key) || { id, name: null, upn: null, enabled: null, relations: [], lastLogOn: null };
    p.name ||= fields.displayName || fields.userDisplayName || null;
    p.upn ||= fields.userPrincipalName || null;
    if (typeof fields.accountEnabled === 'boolean') p.enabled = fields.accountEnabled;
    if (fields.lastLogOnDateTime && (!p.lastLogOn || fields.lastLogOnDateTime > p.lastLogOn)) p.lastLogOn = fields.lastLogOnDateTime;
    if (!p.relations.includes(relation)) p.relations.push(relation);
    people.set(key, p);
  };
  if (intune?.userId) addPerson(intune.userId, intune, 'Primary user (Intune)');
  const tasks = [];
  if (entra) {
    for (const [path, relation] of [['registeredOwners', 'Registered owner (Entra)'], ['registeredUsers', 'Registered user (Entra)']]) {
      tasks.push(api.pages(`/v1.0/devices/${entra.id}/${path}/microsoft.graph.user?$select=${PERSON_SELECT}`, { maxPages: 2 })
        .then(r => { for (const u of r.rows) addPerson(u.id, u, relation); if (r.truncated) partialReasons.push({ source: `Entra ${path}`, reason: 'more than 2 pages; the first ones are shown' }); })
        .catch(e => miss(`Entra ${relation.toLowerCase()} (Device.Read.All)`, e)));
    }
  }
  let loggedOn = null;
  if (intune && beta) {
    tasks.push(api.request(`/beta/deviceManagement/managedDevices/${intune.id}?$select=id,usersLoggedOn`)
      .then(r => { loggedOn = r.usersLoggedOn || []; })
      .catch(e => miss('Intune logged-on users (Graph beta)', e)));
  } else if (intune) notes.push('People who log on to this device without being its primary user come from Intune’s logged-on users list, which is only in Microsoft Graph beta. Set ENABLE_GRAPH_BETA=true to show them.');
  await Promise.all(tasks);
  if (loggedOn) {
    const sorted = loggedOn.filter(u => GUID.test(u.userId || '')).sort((a, b) => String(b.lastLogOnDateTime || '').localeCompare(String(a.lastLogOnDateTime || '')));
    if (sorted.length > MAX_PEOPLE) notes.push(`Intune lists ${sorted.length} logged-on users; the ${MAX_PEOPLE} most recent are shown.`);
    for (const u of sorted.slice(0, MAX_PEOPLE)) addPerson(u.userId, { lastLogOnDateTime: u.lastLogOnDateTime }, 'Logged on (Intune)');
  }
  // Fill in names for people known only by ID (logged-on users, or a primary user without a display name).
  await Promise.all([...people.values()].filter(p => !p.name || p.enabled === null).slice(0, MAX_PEOPLE).map(p =>
    api.request(`/v1.0/users/${p.id}?$select=${PERSON_SELECT}`).then(u => { p.name ||= u.displayName || null; p.upn ||= u.userPrincipalName || null; if (typeof u.accountEnabled === 'boolean') p.enabled = u.accountEnabled; }).catch(() => {})));

  const device = {
    name: intune?.deviceName || entra?.displayName || 'Unnamed device',
    operatingSystem: intune?.operatingSystem || entra?.operatingSystem || null,
    osVersion: intune?.osVersion || entra?.operatingSystemVersion || null,
    manufacturer: intune?.manufacturer || entra?.manufacturer || null,
    model: intune?.model || entra?.model || null,
    serialNumber: intune?.serialNumber || null,
    ownership: ownership(intune, entra),
    joinType: entra ? joinTypeLabel(entra.trustType) : 'Not in Entra',
    trustType: entra?.trustType || null,
    compliance: intune?.complianceState || (entra?.isCompliant === true ? 'compliant' : entra?.isCompliant === false ? 'noncompliant' : null),
    encrypted: typeof intune?.isEncrypted === 'boolean' ? intune.isEncrypted : null,
    enrolled: intune?.enrolledDateTime || null,
    registered: entra?.registrationDateTime || null,
    lastSync: intune?.lastSyncDateTime || null,
    lastSignIn: entra?.approximateLastSignInDateTime || null,
    enabled: typeof entra?.accountEnabled === 'boolean' ? entra.accountEnabled : null,
    managed: intune ? true : entra?.isManaged ?? null,
    enrollmentType: intune?.deviceEnrollmentType || entra?.enrollmentType || null,
    managementAgent: intune?.managementAgent || null,
    storage: intune?.totalStorageSpaceInBytes ? { total: intune.totalStorageSpaceInBytes, free: intune.freeStorageSpaceInBytes ?? null } : null,
    entraId: entra?.id || null, deviceId: entra?.deviceId || (entraKey(intune?.azureADDeviceId) ? intune.azureADDeviceId : null), intuneId: intune?.id || null,
    entraLink: entra ? entraDeviceLink(entra) : null, intuneLink: intune ? intuneDeviceLink(intune.id) : null,
  };
  if (!intune && !unavailable.some(u => /Intune/.test(u.source))) notes.push('This device has no Intune record, so compliance detail, serial number, encryption and enrollment date are not available.');
  if (!entra && !unavailable.some(u => /Entra/.test(u.source))) notes.push('This device has no Entra device object, so join type and registered owners are not available.');
  const order = { 'Primary user (Intune)': 0, 'Registered owner (Entra)': 1, 'Registered user (Entra)': 2, 'Logged on (Intune)': 3 };
  const rank = p => Math.min(...p.relations.map(r => order[r] ?? 9));
  return {
    mode: 'live', tenant, device,
    people: [...people.values()].sort((a, b) => rank(a) - rank(b) || String(b.lastLogOn || '').localeCompare(String(a.lastLogOn || '')) || String(a.name || '').localeCompare(String(b.name || ''))),
    notes, unavailable, partial: partialReasons.length > 0, partialReasons, updatedAt: new Date().toISOString(),
  };
}

// Demo data for the fictional Contoso tenant.
export const DEMO_DEVICES = [
  { id: 'de7c0001-6b21-4818-83bc-fae28e1242ab', type: 'device', name: 'LAPTOP-AM-042', subtitle: 'Windows 10.0.26100 · Serial CND1234XYZ · Primary user alex.morgan@contoso.example', entraId: 'de7c0001-6b21-4818-83bc-fae28e1242ab', intuneId: 'de7c1001-6b21-4818-83bc-fae28e1242ab', tenant: 'Contoso · Demo' },
  { id: 'de7c0002-6b21-4818-83bc-fae28e1242ab', type: 'device', name: 'KIOSK-FIN-01', subtitle: 'Windows 10.0.22631 · Serial KSK0099ABC · Shared device', entraId: 'de7c0002-6b21-4818-83bc-fae28e1242ab', intuneId: 'de7c1002-6b21-4818-83bc-fae28e1242ab', tenant: 'Contoso · Demo' },
  { id: 'de7c0003-6b21-4818-83bc-fae28e1242ab', type: 'device', name: 'JLEE-IPHONE', subtitle: 'iOS 18.1 · Not in Intune', entraId: 'de7c0003-6b21-4818-83bc-fae28e1242ab', intuneId: null, tenant: 'Contoso · Demo' },
];
export function searchDemoDevices(q) {
  const needle = String(q || '').toLowerCase().trim();
  if (!needle) return DEMO_DEVICES;
  return DEMO_DEVICES.filter(d => [d.name, d.subtitle, d.entraId, d.intuneId].some(v => v?.toLowerCase().includes(needle)));
}
export function demoDeviceDetails({ entraId = '', intuneId = '' } = {}) {
  const d = DEMO_DEVICES.find(x => (entraId && x.entraId === entraId) || (intuneId && x.intuneId === intuneId));
  if (!d) return null;
  const alex = { id: '8f210001-6b21-4818-83bc-fae28e1242ab', name: 'Alex Morgan', upn: 'alex.morgan@contoso.example', enabled: true };
  const jordan = { id: '8f210002-6b21-4818-83bc-fae28e1242ab', name: 'Jordan Lee', upn: 'jordan.lee@contoso.example', enabled: true };
  const ago = h => new Date(Date.now() - h * 3600000).toISOString();
  const base = { name: d.name, entraId: d.entraId, intuneId: d.intuneId, deviceId: d.entraId, entraLink: 'https://entra.microsoft.com/', intuneLink: d.intuneId ? 'https://intune.microsoft.com/' : null, enabled: true, managementAgent: d.intuneId ? 'mdm' : null, storage: null };
  const device = d.name === 'LAPTOP-AM-042'
    ? { ...base, operatingSystem: 'Windows', osVersion: '10.0.26100.2314', manufacturer: 'Contoso Devices', model: 'ProBook 450', serialNumber: 'CND1234XYZ', ownership: 'Corporate', joinType: 'Entra joined', trustType: 'AzureAd', compliance: 'noncompliant', encrypted: true, enrolled: ago(24 * 200), registered: ago(24 * 200), lastSync: ago(3), lastSignIn: ago(5), managed: true, enrollmentType: 'windowsAzureADJoin' }
    : d.name === 'KIOSK-FIN-01'
      ? { ...base, operatingSystem: 'Windows', osVersion: '10.0.22631.4460', manufacturer: 'Contoso Devices', model: 'EliteDesk 800', serialNumber: 'KSK0099ABC', ownership: 'Corporate', joinType: 'Entra joined', trustType: 'AzureAd', compliance: 'compliant', encrypted: true, enrolled: ago(24 * 90), registered: ago(24 * 90), lastSync: ago(1), lastSignIn: ago(2), managed: true, enrollmentType: 'windowsAutoEnrollment' }
      : { ...base, operatingSystem: 'iOS', osVersion: '18.1', manufacturer: 'Apple', model: 'iPhone', serialNumber: null, ownership: 'Personal', joinType: 'Registered', trustType: 'Workplace', compliance: null, encrypted: null, enrolled: null, registered: ago(24 * 30), lastSync: null, lastSignIn: ago(30), managed: false, enrollmentType: null };
  const people = d.name === 'LAPTOP-AM-042' ? [{ ...alex, relations: ['Primary user (Intune)', 'Registered owner (Entra)', 'Logged on (Intune)'], lastLogOn: ago(5) }]
    : d.name === 'KIOSK-FIN-01' ? [{ ...jordan, relations: ['Logged on (Intune)'], lastLogOn: ago(2) }, { ...alex, relations: ['Logged on (Intune)'], lastLogOn: ago(26) }]
      : [{ ...jordan, relations: ['Registered owner (Entra)', 'Registered user (Entra)'], lastLogOn: null }];
  return { mode: 'demo', tenant: d.tenant, device, people, notes: ['Fictional data. Portal links open the real portal; these device IDs do not exist.', ...(d.intuneId ? [] : ['This device has no Intune record, so compliance detail, serial number, encryption and enrollment date are not available.'])], unavailable: [], partial: false, partialReasons: [], updatedAt: new Date().toISOString() };
}
