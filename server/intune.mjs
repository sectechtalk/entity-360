import { evaluateConditionalAccess } from './access.mjs';
import { GUID, fail, queryUrl } from './model.mjs';

// Read-only Intune health: what the tenant says (Graph, delegated to the signed-in viewer), how this Windows
// computer is configured (an imported or collected snapshot) and how the two relate. Nothing here changes a tenant
// or a device. A check that cannot be evaluated is reported as "unknown", never as a pass.

export const INTUNE_ENROLLMENT_APP_ID = 'd4ebce55-015a-49b5-a083-c84d1797ae8c';
export const INTUNE_APP_ID = '0000000a-0000-0000-c000-000000000000';
const DAY = 86400000;
const source = (id, name, url) => ({ id, name, url });
const SRC = {
  intune: source('intune-health', 'Intune admin center', 'https://intune.microsoft.com/'),
  tenant: source('intune-tenant-status', 'Intune tenant status', 'https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/TenantAdminMenu/~/tenantStatus'),
  entra: source('intune-entra-devices', 'Entra devices', 'https://entra.microsoft.com/#view/Microsoft_AAD_Devices/DevicesMenuBlade/~/Devices'),
  ca: source('intune-ca', 'Conditional Access', 'https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies'),
  mobility: source('intune-mobility', 'Mobility (MDM and MAM)', 'https://entra.microsoft.com/#view/Microsoft_AAD_IAM/MobilityManagementMenuBlade/~/MobilityManagement'),
  licenses: source('intune-licenses', 'My Microsoft 365 licenses', 'https://admin.microsoft.com/'),
};

// How Intune and Windows arrive at each value shown in the device table. Learn pages are the authority for the
// compliance rules; the enrollment-type and agent values are Graph enum values.
export const CALCULATION = [
  { field: 'managementAgent', title: 'Management agent', how: 'Which management channel created the record. mdm = the Windows MDM client enrolled through OMA-DM; msSense = Microsoft Defender for Endpoint (security settings management) reporting the device; configurationManagerClient* = Configuration Manager. A device with only msSense is known to Intune but is not MDM-enrolled: it receives no Intune policy.', client: 'Created when Windows enrolls (HKLM\\SOFTWARE\\Microsoft\\Enrollments, ProviderID "MS DM Server") or when the Defender sensor onboards.', url: 'https://learn.microsoft.com/graph/api/resources/intune-devices-manageddevice' },
  { field: 'deviceEnrollmentType', title: 'Enrollment type', how: 'How the device enrolled, set by the enrollment path. windowsAzureADJoin = automatic enrollment at Entra join (MDM user scope). windowsAutoEnrollment = group-policy/hybrid automatic enrollment. windowsCoManagement = Configuration Manager co-management. A blank or unknown value usually means the record did not come from an MDM enrollment.', client: 'Windows records the type in the enrollment key (EnrollmentType) and the discovery URL it enrolled against.', url: 'https://learn.microsoft.com/graph/api/resources/intune-devices-deviceenrollmenttype' },
  { field: 'userPrincipalName / userId', title: 'Primary user', how: 'The user the device was enrolled by (user affinity). Intune stores the Entra object ID in userId and shows the UPN that object has now. The enrollment key on the computer keeps the UPN string Windows used when it enrolled, so the two can differ after a rename, or when a different name for the same account was used. Compare object IDs, not strings.', client: 'UPN value in the enrollment key under HKLM\\SOFTWARE\\Microsoft\\Enrollments\\<id>.', url: 'https://learn.microsoft.com/intune/device-enrollment/overview' },
  { field: 'complianceState', title: 'Compliance', how: 'Computed by Intune, not reported by the device alone: (1) the compliance policies assigned to the device or its user are evaluated; (2) a device with no assigned policy takes the tenant setting “Mark devices with no compliance policy assigned as” (default Compliant); (3) a device that has not reported within the validity period (default 30 days) is treated as noncompliant; (4) Not evaluated is the initial state and also applies when nothing triggers a check.', client: 'The device only reports per-setting results for policies it was sent. It never decides “compliant” itself.', url: 'https://learn.microsoft.com/intune/device-security/compliance/overview#compliance-policy-settings' },
  { field: 'isManaged / isCompliant / mdmAppId (Entra)', title: 'Entra device object', how: 'Intune writes management and compliance back to the Entra device object. Conditional Access reads isCompliant from there. mdmAppId identifies the managing MDM (Microsoft Intune is 0000000a-0000-0000-c000-000000000000).', client: 'dsregcmd /status shows MdmUrl and MdmComplianceUrl when Entra has told Windows an MDM exists for this user.', url: 'https://learn.microsoft.com/entra/identity/devices/overview' },
  { field: 'enrolledDateTime / lastSyncDateTime', title: 'Enrolled and last sync', how: 'enrolledDateTime is when the enrollment was created. lastSyncDateTime is the last successful check-in. A check-in does not by itself evaluate compliance.', client: 'The EnterpriseMgmt scheduled tasks start each check-in; their last result is in Task Scheduler.', url: 'https://learn.microsoft.com/intune/device-security/compliance/monitor-policy' },
];

const FIX = {
  license: { summary: 'Assign an Intune license (Plan 1 or a suite that includes it) to the user, then wait for provisioning.', steps: ['Microsoft 365 admin center > Users > Active users > the user > Licenses and apps.', 'Make sure the service plan Microsoft Intune (INTUNE_A) is switched on within the assigned license.'], change: 'tenant' },
  mdmScope: { summary: 'Set the Intune MDM user scope to All, or to a group that contains the user.', steps: ['Entra admin center > Mobility (MDM and MAM) > Microsoft Intune > MDM user scope.', 'Choose All, or Some and add the group. Save. Existing devices pick it up at the next user sign-in or Entra token refresh.'], change: 'tenant' },
  caCompliant: { summary: 'Exclude the Microsoft Intune Enrollment app (and Microsoft Intune) from policies that require a compliant device, or scope those policies away from enrollment.', steps: ['Entra admin center > Conditional Access > the policy > Target resources > Exclude.', 'Add Microsoft Intune Enrollment (d4ebce55-015a-49b5-a083-c84d1797ae8c) and Microsoft Intune. Test in report-only first.'], change: 'tenant' },
  noPolicy: { summary: 'Create and assign at least one compliance policy, and decide the tenant default for unassigned devices.', steps: ['Intune admin center > Devices > Compliance > Create policy (Windows 10 and later), assign it to a group containing the user or device.', 'Intune admin center > Devices > Compliance > Compliance policy settings: set “Mark devices with no compliance policy assigned as” to Not compliant if Conditional Access relies on compliance.'], change: 'tenant' },
  autoEnroll: { summary: 'Trigger automatic MDM enrollment on that computer, then re-run this check.', steps: ['On the computer, open Windows PowerShell as administrator, signed in as the user.', 'Run: & "$env:windir\\System32\\deviceenroller.exe" /c /AutoEnrollMDM  (it prints nothing and sets no exit code).', 'Wait a minute, then run Intune health again. The tenant record, not the exit code, is the proof.', 'Undo if needed: Retire or Delete the device in the Intune admin center.'], change: 'device', note: 'Verified in this lab on Windows 11 build 26300 (journal step I06). It is not a Microsoft guarantee for every build.' },
  prt: { summary: 'Get a primary refresh token: sign out and in, or lock and unlock with Windows Hello, then check dsregcmd /status again.', steps: ['dsregcmd /status > SSO State > AzureAdPrt should say YES.', 'If it stays NO, look at dsregcmd /status > Diagnostic Data > Previous PRT Attempt for the error.'], change: 'device' },
  joined: { summary: 'The computer is not Entra joined. Join it (Settings > Accounts > Access work or school > Connect > Join this device to Microsoft Entra ID) or accept that it is only registered.', steps: ['Registered (Workplace) devices can be enrolled as personal devices; automatic enrollment at join applies only to joined devices.'], change: 'device' },
  mdmLog: { summary: 'Read the errors, then decide: Policy CSP/DMClient add failures alone do not stop enrollment.', steps: ['Event Viewer > Applications and Services Logs > Microsoft > Windows > DeviceManagement-Enterprise-Diagnostics-Provider > Admin.', 'Look up the event ID in the troubleshooting journal (Remote Control and Intune, step I07) before changing anything.'], change: 'none' },
  syncNow: { summary: 'Sync the device: Settings > Accounts > Access work or school > the work account > Info > Sync.', steps: ['Or in the Intune admin center: Devices > the device > Sync.'], change: 'device' },
  reconcile: { summary: 'Decide whether the enrollment UPN and the Intune user are one account by comparing object IDs; if they are different accounts, re-enroll under the intended user.', steps: ['Entra admin center > Users: search each name; compare Object ID.', 'If the Object IDs match, the difference is an alias or a rename and needs no action.', 'If they differ: retire the device in Intune, then enroll again signed in as the intended user.'], change: 'none' },
};

const STATUS_ORDER = ['fail', 'warn', 'unknown', 'info', 'pass'];
// Where to see or fix each check in Microsoft's portals. Client checks read this computer, so they have no portal page.
const INTUNE = 'https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings';
export const CHECK_PORTALS = {
  'lic-intune': { url: 'https://admin.microsoft.com/#/licenses', label: 'Open licenses (M365 admin)' },
  'user-identity': { url: 'https://entra.microsoft.com/#view/Microsoft_AAD_UsersAndTenants/UserManagementMenuBlade/~/AllUsers', label: 'Open users (Entra)' },
  'mdm-scope': { url: `${INTUNE}/DevicesEnrollmentMenu/~/windowsEnrollment`, label: 'Open Windows enrollment (Intune)' },
  'ca-compliant': { url: 'https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies', label: 'Open CA policies (Entra)' },
  'compliance-basis': { url: `${INTUNE}/DevicesMenu/~/compliance`, label: 'Open compliance policies (Intune)' },
  'joined-enrolled': { url: `${INTUNE}/DevicesMenu/~/windows`, label: 'Open Windows devices (Intune)' },
  'sync-fresh': { url: `${INTUNE}/DevicesMenu/~/windows`, label: 'Open Windows devices (Intune)' },
  'xcheck': { url: 'https://entra.microsoft.com/#view/Microsoft_AAD_Devices/DevicesMenuBlade/~/Devices', label: 'Open devices (Entra)' },
  'entra-writeback': { url: 'https://entra.microsoft.com/#view/Microsoft_AAD_Devices/DevicesMenuBlade/~/Devices', label: 'Open devices (Entra)' },
  'defender-only': { url: 'https://security.microsoft.com/machines', label: 'Open device inventory (Defender)' },
};
export const portalFor = id => CHECK_PORTALS[id] || (String(id).startsWith('client-') ? { reason: 'Checked on this computer from its snapshot; there is no portal page for it.' } : { url: 'https://intune.microsoft.com/', label: 'Open Intune' });
function check(id, area, title, status, finding, extra = {}) { return { id, area, title, status, finding, evidence: extra.evidence || [], how: extra.how || '', fix: extra.fix || null, journal: extra.journal || '', portal: portalFor(id) }; }

const norm = v => String(v ?? '').trim().toLowerCase();
const ageDays = (iso, now) => Number.isFinite(Date.parse(iso)) ? (now - Date.parse(iso)) / DAY : null;
const planStatus = (licenses, name) => (licenses || []).flatMap(l => l.plans || []).filter(p => p.name === name).map(p => p.status);

// ---- collection (Graph, delegated, read only) -------------------------------------------------
export async function collectIntuneCloud(api, { tenant, beta = false, snapshotUpns = [], now = Date.now() } = {}) {
  const me = await api.request('/v1.0/me?$select=id,displayName,userPrincipalName,mail');
  if (!GUID.test(me.id)) throw fail('Microsoft did not return a valid viewer identity.', 502);
  const cloud = { tenant, identity: { id: me.id, name: me.displayName, upn: me.userPrincipalName }, unavailable: [], users: {}, upnLookups: {}, collectedAt: new Date(now).toISOString() };
  const read = async (name, fn) => { try { cloud[name] = await fn(); } catch { cloud[name] = null; cloud.unavailable.push(name); } };
  await Promise.all([
    read('licenses', async () => (await api.pages('/v1.0/me/licenseDetails')).rows.map(l => ({ sku: l.skuPartNumber, plans: (l.servicePlans || []).map(p => ({ name: p.servicePlanName, status: p.provisioningStatus })) }))),
    read('organization', async () => { const r = await api.request('/v1.0/organization?$select=id,displayName'); const o = (r.value || [])[0] || {}; return { id: o.id, name: o.displayName }; }),
    read('mdmScope', async () => {
      if (!beta) throw new Error('beta disabled');
      // Beta endpoint: MDM user scope has no v1.0 equivalent yet. Only called when ENABLE_GRAPH_BETA=true; recheck before relying on it.
      const r = await api.request('/beta/policies/mobileDeviceManagementPolicies');
      return (r.value || []).map(p => ({ name: p.displayName, appliesTo: p.appliesTo, valid: p.isValid, discoveryUrl: p.discoveryUrl }));
    }),
    read('managedDevices', async () => (await api.pages(queryUrl('/v1.0/deviceManagement/managedDevices', { '$select': 'id,deviceName,operatingSystem,osVersion,userId,userPrincipalName,managementAgent,deviceEnrollmentType,managedDeviceOwnerType,complianceState,enrolledDateTime,lastSyncDateTime,azureADDeviceId', '$top': '100' }))).rows),
    read('entraDevices', async () => (await api.pages(queryUrl('/v1.0/devices', { '$select': 'id,deviceId,displayName,operatingSystem,trustType,isManaged,isCompliant,mdmAppId,approximateLastSignInDateTime,accountEnabled', '$top': '100' }))).rows),
    // Microsoft evaluates Conditional Access for this user signing in to Microsoft Intune Enrollment, instead of matching conditions by hand.
    read('enrollmentCa', async () => (await evaluateConditionalAccess(api, { id: me.id, type: 'user', apps: [{ id: INTUNE_ENROLLMENT_APP_ID, name: 'Microsoft Intune Enrollment' }] })).rows.map(p => ({ id: p.id, name: p.name, state: p.state, controls: p.grant, missing: p.missing }))),
    read('compliancePolicies', async () => (await api.pages(queryUrl('/v1.0/deviceManagement/deviceCompliancePolicies', { '$select': 'id,displayName', '$expand': 'assignments' }))).rows.map(p => ({ id: p.id, name: p.displayName, assigned: Array.isArray(p.assignments) ? p.assignments.length : null }))),
    read('complianceSettings', async () => { const r = await api.request('/v1.0/deviceManagement?$select=settings'); const s = r.settings; if (!s || typeof s.secureByDefault !== 'boolean') throw new Error('not returned'); return { secureByDefault: s.secureByDefault, validityDays: Number.isFinite(s.deviceComplianceCheckinThresholdDays) ? s.deviceComplianceCheckinThresholdDays : null }; }),
  ]);
  // Resolve the people behind the managed devices and any UPN the computer reports, by object ID.
  const ids = [...new Set((cloud.managedDevices || []).map(d => d.userId).filter(id => GUID.test(id)))].slice(0, 20);
  await Promise.all(ids.map(async id => { try { const u = await api.request(`/v1.0/users/${id}?$select=id,userPrincipalName,mail,proxyAddresses,accountEnabled`); cloud.users[id] = { id: u.id, upn: u.userPrincipalName, mail: u.mail, aliases: (u.proxyAddresses || []).filter(a => /^smtp:/i.test(a)).map(a => a.slice(5).toLowerCase()), enabled: u.accountEnabled }; } catch { cloud.users[id] = null; } }));
  const upns = [...new Set(snapshotUpns.map(norm).filter(u => /^[^\s@\/\\]+@[^\s@\/\\]+$/.test(u)))].slice(0, 5);
  await Promise.all(upns.map(async upn => { try { const u = await api.request(`/v1.0/users/${encodeURIComponent(upn)}?$select=id,userPrincipalName`); cloud.upnLookups[upn] = { id: u.id, upn: u.userPrincipalName }; } catch (e) { cloud.upnLookups[upn] = e.status === 404 ? 'notFound' : 'unreadable'; } }));
  return cloud;
}

// ---- snapshot helpers -------------------------------------------------------------------------
const factValue = (snap, key) => snap?.facts?.find(f => f.key === key && f.status !== 'unavailable')?.value;
function parsePairs(text) { const out = {}; for (const part of String(text).split('; ')) { const i = part.indexOf('='); if (i > 0) out[part.slice(0, i)] = part.slice(i + 1); } return out; }
export function snapshotEnrollments(snap) { return (snap?.facts || []).filter(f => /^MDM enrollment \d+$/.test(f.key) && f.status !== 'unavailable').map(f => parsePairs(f.value)); }
export function snapshotUpns(snap) { return snapshotEnrollments(snap).map(e => e.UPN).filter(Boolean); }
const snapshotTasks = snap => (snap?.facts || []).filter(f => f.key.startsWith('EnterpriseMgmt task ') && f.status !== 'unavailable').map(f => ({ name: f.key.slice('EnterpriseMgmt task '.length), ...parsePairs(f.value) }));

// ---- evaluation (pure; unit tested) -----------------------------------------------------------
export function evaluateIntuneHealth({ cloud, snapshot, now = Date.now() }) {
  const checks = [];
  const down = name => !cloud || cloud[name] === null || cloud[name] === undefined || cloud.unavailable?.includes(name);
  const NA = 'Not available to this account or not returned, so this was not evaluated.';

  // Tenant and account
  if (down('licenses')) checks.push(check('lic-intune', 'Tenant & account', 'Intune license is provisioned for the signed-in user', 'unknown', NA, { how: 'Reads the signed-in user’s license details and the INTUNE_A service plan status.', journal: 'I03' }));
  else {
    const st = planStatus(cloud.licenses, 'INTUNE_A');
    const suite = planStatus(cloud.licenses, 'INTUNE_P2').length > 0;
    if (!st.length) checks.push(check('lic-intune', 'Tenant & account', 'Intune license is provisioned for the signed-in user', 'fail', 'No Intune (INTUNE_A) service plan on any license assigned to this user.', { evidence: [`Intune Plan 2 or suite plans present: ${suite}`], how: 'A user needs an Intune service plan to enroll devices and have them evaluated.', fix: FIX.license, journal: 'I03' }));
    else if (st.every(s => s === 'Success')) checks.push(check('lic-intune', 'Tenant & account', 'Intune license is provisioned for the signed-in user', 'pass', 'INTUNE_A is Success.', { how: 'Service plan provisioningStatus Success means the service is provisioned for this user.', journal: 'I03' }));
    else checks.push(check('lic-intune', 'Tenant & account', 'Intune license is provisioned for the signed-in user', st.includes('Disabled') ? 'fail' : 'warn', `INTUNE_A status: ${[...new Set(st)].join(', ')}.`, { evidence: ['Microsoft documents PendingInput as “not provisioned and awaiting service confirmation”.', 'In this lab devices enrolled successfully while the plan showed PendingInput, so it is not by itself a blocker.'], how: 'Reads provisioningStatus of the service plan on the user’s license.', fix: st.includes('Disabled') ? FIX.license : null, journal: 'I03' }));
  }
  if (down('mdmScope')) checks.push(check('mdm-scope', 'Tenant & account', 'MDM user scope includes the user', 'unknown', cloud?.unavailable?.includes('mdmScope') ? 'The scope is only readable through a preview Graph endpoint. Set ENABLE_GRAPH_BETA=true to read it, or check Entra > Mobility (MDM and MAM).' : NA, { how: 'Automatic enrollment happens only for users in the MDM user scope (None, Some groups, or All).', journal: 'I02' }));
  else {
    const p = cloud.mdmScope[0];
    const a = norm(p?.appliesTo);
    checks.push(a === 'all' ? check('mdm-scope', 'Tenant & account', 'MDM user scope includes the user', 'pass', 'MDM user scope applies to all users.', { evidence: [`Discovery URL: ${p.discoveryUrl || 'not returned'}`], how: 'Entra tells Windows where the MDM is (MdmUrl) only for users in scope.', journal: 'I02' })
      : a === 'none' ? check('mdm-scope', 'Tenant & account', 'MDM user scope includes the user', 'fail', 'MDM user scope is None: no user is automatically enrolled.', { how: 'Entra tells Windows where the MDM is (MdmUrl) only for users in scope.', fix: FIX.mdmScope, journal: 'I02' })
      : check('mdm-scope', 'Tenant & account', 'MDM user scope includes the user', 'warn', `MDM user scope applies to: ${p?.appliesTo || 'not returned'}. Confirm the user is in an included group.`, { how: 'Entra tells Windows where the MDM is (MdmUrl) only for users in scope.', fix: FIX.mdmScope, journal: 'I02' }));
  }
  if (down('enrollmentCa')) checks.push(check('ca-compliant', 'Tenant & account', 'No Conditional Access policy blocks enrollment', 'unknown', NA, { how: 'Microsoft Conditional Access What If (Graph v1.0) for this user signing in to Microsoft Intune Enrollment. Device platform, location and device state are not supplied, so a policy limited by those may not appear.', journal: 'I04' }));
  else {
    const hits = cloud.enrollmentCa.filter(p => p.state === 'enabled' && p.controls.some(c => ['compliantDevice', 'domainJoinedDevice'].includes(c)));
    checks.push(hits.length ? check('ca-compliant', 'Tenant & account', 'No Conditional Access policy blocks enrollment', 'warn', `${hits.length} enabled polic${hits.length === 1 ? 'y applies' : 'ies apply'} to Microsoft Intune Enrollment for this user and require a compliant or joined device.`, { evidence: hits.map(p => p.name), how: 'Microsoft Conditional Access What If (Graph v1.0) for this user signing in to Microsoft Intune Enrollment. Device platform, location and device state are not supplied, so a policy limited by those may not appear.', fix: FIX.caCompliant, journal: 'I04' })
      : check('ca-compliant', 'Tenant & account', 'No Conditional Access policy blocks enrollment', 'pass', 'Microsoft evaluation found no enabled policy that requires a compliant or joined device for Microsoft Intune Enrollment.', { how: 'Microsoft Conditional Access What If (Graph v1.0) for this user signing in to Microsoft Intune Enrollment. Device platform, location and device state are not supplied, so a policy limited by those may not appear.', journal: 'I04' }));
  }

  // Compliance calculation
  if (down('compliancePolicies') || down('complianceSettings')) checks.push(check('compliance-basis', 'How compliance is calculated', 'Compliance is backed by an assigned policy', 'unknown', NA, { how: 'Reads the compliance policies and the tenant setting for devices with no policy.', journal: 'I03' }));
  else {
    const assigned = cloud.compliancePolicies.filter(p => p.assigned === null ? true : p.assigned > 0).length;
    const dflt = cloud.complianceSettings.secureByDefault ? 'Not compliant' : 'Compliant';
    if (assigned === 0 && !cloud.complianceSettings.secureByDefault) checks.push(check('compliance-basis', 'How compliance is calculated', 'Compliance is backed by an assigned policy', 'warn', 'No compliance policy is assigned and unassigned devices are marked Compliant, so every enrolled device shows Compliant without any setting being evaluated.', { evidence: [`Compliance policies in tenant: ${cloud.compliancePolicies.length}; assigned: ${assigned}`, `Unassigned devices are marked: ${dflt}`, `Validity period: ${cloud.complianceSettings.validityDays ?? 'not returned'} days`], how: 'Intune evaluates assigned policies; with none, it applies the tenant default (Compliant unless changed).', fix: FIX.noPolicy, journal: 'I03' }));
    else checks.push(check('compliance-basis', 'How compliance is calculated', 'Compliance is backed by an assigned policy', 'pass', assigned ? `${assigned} compliance polic${assigned === 1 ? 'y is' : 'ies are'} assigned; unassigned devices are marked ${dflt}.` : `No policy is assigned, but unassigned devices are marked ${dflt}.`, { evidence: [`Validity period: ${cloud.complianceSettings.validityDays ?? 'not returned'} days`], how: 'Intune evaluates assigned policies; with none, it applies the tenant default.', journal: 'I03' }));
  }

  // Devices: Entra joined vs Intune MDM record
  const managed = cloud?.managedDevices || [];
  const entra = cloud?.entraDevices || [];
  const mdmRecord = d => managed.find(m => norm(m.azureADDeviceId) === norm(d.deviceId));
  if (down('managedDevices') || down('entraDevices')) checks.push(check('joined-enrolled', 'Devices', 'Every Entra-joined device is MDM-enrolled', 'unknown', NA, { how: 'Compares Entra device objects with trust type AzureAd against Intune managed devices whose management agent is mdm.', journal: 'I01' }));
  else {
    const joined = entra.filter(d => d.trustType === 'AzureAd');
    const bad = joined.filter(d => { const m = mdmRecord(d); return !m || norm(m.managementAgent) !== 'mdm'; });
    checks.push(bad.length ? check('joined-enrolled', 'Devices', 'Every Entra-joined device is MDM-enrolled', 'fail', `${bad.length} joined device${bad.length === 1 ? ' has' : 's have'} no MDM enrollment in Intune.`, { evidence: bad.map(d => { const m = mdmRecord(d); return `${d.displayName}: ${m ? 'Intune record exists but agent is ' + (m.managementAgent || 'unknown') + ' (not mdm)' : 'no Intune record'}`; }), how: 'Compares Entra device objects with trust type AzureAd against Intune managed devices whose management agent is mdm.', fix: FIX.autoEnroll, journal: 'I05' })
      : check('joined-enrolled', 'Devices', 'Every Entra-joined device is MDM-enrolled', 'pass', joined.length ? `All ${joined.length} joined device${joined.length === 1 ? ' is' : 's are'} MDM-enrolled.` : 'No Entra-joined devices were returned.', { how: 'Compares Entra device objects with trust type AzureAd against Intune managed devices whose management agent is mdm.', journal: 'I01' }));
    const stale = managed.filter(m => norm(m.managementAgent) === 'mdm' && ageDays(m.lastSyncDateTime, now) !== null && ageDays(m.lastSyncDateTime, now) > 7);
    checks.push(stale.length ? check('sync-fresh', 'Devices', 'MDM devices checked in within 7 days', 'warn', `${stale.length} device${stale.length === 1 ? '' : 's'} last synced more than 7 days ago.`, { evidence: stale.map(m => `${m.deviceName}: ${m.lastSyncDateTime}`), how: 'A device that does not report for the compliance validity period (default 30 days) is treated as noncompliant.', fix: FIX.syncNow, journal: 'I06' }) : check('sync-fresh', 'Devices', 'MDM devices checked in within 7 days', 'pass', 'All MDM devices synced in the last 7 days.', { how: 'Uses lastSyncDateTime from Intune.', journal: 'I06' }));
    const sense = managed.filter(m => norm(m.managementAgent) === 'mssense');
    if (sense.length) checks.push(check('defender-only', 'Devices', 'Devices known only through Defender for Endpoint', 'info', `${sense.length} device${sense.length === 1 ? ' is' : 's are'} in Intune only as Defender for Endpoint (msSense) objects.`, { evidence: sense.map(m => m.deviceName), how: 'These records come from Defender security settings management. They are not MDM enrollments and receive no Intune policy.', journal: 'I01' }));
    const mism = entra.filter(d => { const m = mdmRecord(d); return m && norm(m.managementAgent) === 'mdm' && d.isManaged === false; });
    if (mism.length) checks.push(check('entra-writeback', 'Devices', 'Entra device object reflects Intune management', 'warn', `${mism.length} Intune-managed device${mism.length === 1 ? '' : 's'} show isManaged = false in Entra.`, { evidence: mism.map(d => d.displayName), how: 'Intune writes management and compliance back to the Entra device object; a delay is normal, a persistent difference is not.', journal: 'I06' }));
  }

  // User identity reconciliation by object ID
  const enrollments = snapshotEnrollments(snapshot);
  if (managed.length) {
    const rows = [];
    for (const m of managed.filter(x => norm(x.managementAgent) === 'mdm')) {
      const u = cloud.users?.[m.userId];
      if (u === undefined || u === null) { rows.push({ status: 'unknown', text: `${m.deviceName}: the Intune user could not be resolved by object ID.` }); continue; }
      const local = enrollments.map(e => norm(e.UPN)).filter(Boolean);
      for (const upn of [...new Set(local)]) {
        if (upn === norm(u.upn) || upn === norm(u.mail) || u.aliases.includes(upn)) rows.push({ status: 'pass', text: `${m.deviceName}: the enrollment name ${upn} is a name of the same account (${u.upn}).` });
        else {
          const lookup = cloud.upnLookups?.[upn];
          if (lookup && typeof lookup === 'object') rows.push(lookup.id === u.id ? { status: 'pass', text: `${m.deviceName}: ${upn} resolves to the same object ID as ${u.upn}.` } : { status: 'fail', text: `${m.deviceName}: ${upn} is a different account (object ${lookup.id}) from the Intune user ${u.upn} (object ${u.id}).` });
          else if (lookup === 'notFound') rows.push({ status: 'warn', text: `${m.deviceName}: ${upn} is not a current name in this tenant (renamed or removed); Intune shows ${u.upn}. Likely the same account under an old name; confirm.` });
          else rows.push({ status: 'unknown', text: `${m.deviceName}: ${upn} could not be resolved.` });
        }
      }
    }
    if (rows.length) {
      const worst = STATUS_ORDER.find(s => rows.some(r => r.status === s));
      checks.push(check('user-identity', 'Devices', 'Enrollment user matches the Intune user (by object ID)', worst, worst === 'pass' ? 'Every enrollment name on this computer resolves to the Intune user.' : 'At least one enrollment name differs from the Intune user.', { evidence: rows.map(r => r.text), how: 'The enrollment key keeps the name Windows used when it enrolled. Intune keeps the user’s object ID. Names can differ after a rename or by alias; object IDs do not.', fix: worst === 'pass' ? null : FIX.reconcile, journal: 'I07' }));
    }
  }

  // This computer
  if (!snapshot) checks.push(check('client-snapshot', 'This computer', 'Client configuration', 'unknown', 'No device snapshot loaded. Collect the server host or import a snapshot to evaluate how this computer is configured.', { how: 'The client checks read dsregcmd, the enrollment registry, the EnterpriseMgmt tasks and the MDM log on the computer itself.' }));
  else {
    const joined = factValue(snapshot, 'AzureAdJoined');
    const work = factValue(snapshot, 'WorkplaceJoined');
    const prt = factValue(snapshot, 'AzureAdPrt');
    const mdmUrl = factValue(snapshot, 'MdmUrl');
    const auth = factValue(snapshot, 'DeviceAuthStatus');
    const how = 'dsregcmd /status on the computer.';
    checks.push(joined === 'YES' ? check('client-joined', 'This computer', 'Computer is Entra joined', 'pass', 'AzureAdJoined = YES.', { evidence: [`DeviceAuthStatus: ${auth ?? 'not returned'}`, `Tenant: ${factValue(snapshot, 'TenantName') ?? 'not returned'}`], how, journal: 'I01' })
      : check('client-joined', 'This computer', 'Computer is Entra joined', work === 'YES' ? 'warn' : 'fail', `AzureAdJoined = ${joined ?? 'not returned'}${work === 'YES' ? '; the computer is only registered (WorkplaceJoined = YES).' : '.'}`, { how, fix: FIX.joined, journal: 'I01' }));
    if (joined === 'YES' && auth && auth !== 'SUCCESS') checks.push(check('client-device-auth', 'This computer', 'Device authenticates to Entra', 'fail', `DeviceAuthStatus = ${auth}.`, { how: 'FAILED means Entra rejected the device credential (device disabled, deleted or time/network problem).', journal: 'I01' }));
    checks.push(prt === 'YES' ? check('client-prt', 'This computer', 'Primary refresh token present', 'pass', 'AzureAdPrt = YES for the collecting user.', { how: 'The PRT is what lets Windows enroll and sign in silently.', journal: 'I01' }) : check('client-prt', 'This computer', 'Primary refresh token present', prt === undefined ? 'unknown' : joined === 'YES' ? 'warn' : 'info', `AzureAdPrt = ${prt ?? 'not returned'}${prt !== undefined && joined !== 'YES' ? ' (expected to matter only on a joined computer)' : ''}.`, { how: 'The PRT is what lets Windows enroll and sign in silently. It is per user and per session.', fix: prt === undefined || joined !== 'YES' ? null : FIX.prt, journal: 'I01' }));
    checks.push(mdmUrl ? check('client-mdmurl', 'This computer', 'Entra has told Windows where the MDM is', 'pass', 'MdmUrl is set.', { evidence: [mdmUrl, `MdmComplianceUrl: ${factValue(snapshot, 'MdmComplianceUrl') ?? 'not returned'}`], how: 'MdmUrl appears only when the user is in the MDM user scope and licensed at the last token refresh.', journal: 'I02' })
      : check('client-mdmurl', 'This computer', 'Entra has told Windows where the MDM is', joined === 'YES' ? 'fail' : 'info', joined === 'YES' ? 'MdmUrl is empty on a joined computer: Entra did not return an MDM for this user.' : 'MdmUrl is empty (a registered-only computer is not auto-enrolled).', { how: 'MdmUrl appears only when the user is in the MDM user scope and licensed at the last token refresh.', fix: joined === 'YES' ? FIX.mdmScope : null, journal: 'I02' }));
    const live = enrollments.filter(e => norm(e.Provider) === 'ms dm server' || norm(e.Discovery).includes('manage.microsoft.com'));
    if (live.length) {
      const ok = live.filter(e => String(e.State) === '1');
      checks.push(check('client-enrollment', 'This computer', 'Windows holds an MDM enrollment', ok.length ? 'pass' : 'warn', `${live.length} enrollment record${live.length === 1 ? '' : 's'}; ${ok.length} in state 1 (enrolled).`, { evidence: live.map(e => `Provider ${e.Provider || 'n/a'}; UPN ${e.UPN || 'n/a'}; discovery ${e.Discovery || 'n/a'}; state ${e.State || 'n/a'}; type ${e.Type || 'n/a'}`), how: 'HKLM\\SOFTWARE\\Microsoft\\Enrollments holds one key per enrollment. A UPN and a discovery URL show a real MDM enrollment; the other keys are built-in authorities.', journal: 'I05' }));
    } else {
      checks.push(check('client-enrollment', 'This computer', 'Windows holds an MDM enrollment', joined === 'YES' ? 'fail' : 'info', joined === 'YES' ? 'No enrollment record with a UPN or an MDM discovery URL.' : 'No MDM enrollment record. That is expected for a computer that is not Entra joined.', { evidence: [`MDM records with provider “MS DM Server”: ${factValue(snapshot, 'Microsoft MDM enrollment records') ?? 'not returned'}`], how: 'HKLM\\SOFTWARE\\Microsoft\\Enrollments holds one key per enrollment. Joining Entra does not by itself create one; automatic enrollment must have run.', fix: joined === 'YES' ? FIX.autoEnroll : null, journal: 'I05' }));
    }
    const tasks = snapshotTasks(snapshot);
    if (!tasks.length) checks.push(check('client-tasks', 'This computer', 'Check-in tasks ran successfully', 'unknown', 'No EnterpriseMgmt scheduled tasks were returned. This is expected if the computer is not enrolled.', { how: 'Enrollment creates scheduled tasks under \\Microsoft\\Windows\\EnterpriseMgmt that start each check-in.', journal: 'I06' }));
    else {
      const bad = tasks.filter(t => t.LastResult && !['0', '267011', '267009', '267008'].includes(String(t.LastResult)));
      checks.push(bad.length ? check('client-tasks', 'This computer', 'Check-in tasks ran successfully', 'warn', `${bad.length} of ${tasks.length} task${tasks.length === 1 ? '' : 's'} reported a nonzero last result.`, { evidence: bad.map(t => `${t.name}: ${t.LastResult} at ${t.LastRun}`), how: 'LastTaskResult 0 is success; 267011 means never run; 267009 and 267008 mean running or ready.', journal: 'I06' }) : check('client-tasks', 'This computer', 'Check-in tasks ran successfully', 'pass', `${tasks.length} EnterpriseMgmt task${tasks.length === 1 ? '' : 's'} reported success or have not needed to run.`, { evidence: tasks.map(t => `${t.name}: ${t.State}; last result ${t.LastResult}`), how: 'LastTaskResult 0 is success; 267011 means never run.', journal: 'I06' }));
    }
    const log = factValue(snapshot, 'MDM log errors and warnings (24 hours)');
    if (log === undefined) checks.push(check('client-mdmlog', 'This computer', 'MDM event log is quiet', 'unknown', 'The MDM diagnostics log was not readable by the collecting user (it may need an administrator window).', { how: 'Reads errors and warnings from DeviceManagement-Enterprise-Diagnostics-Provider/Admin for the last 24 hours.', journal: 'I07' }));
    else checks.push(String(log).startsWith('0') ? check('client-mdmlog', 'This computer', 'MDM event log is quiet', 'pass', 'No errors or warnings in the last 24 hours.', { how: 'Reads errors and warnings from the MDM diagnostics log for the last 24 hours.', journal: 'I07' }) : check('client-mdmlog', 'This computer', 'MDM event log is quiet', 'warn', `Errors or warnings in the last 24 hours: ${log}`, { how: 'Policy CSP and DMClient add failures can repeat while the device still reports compliant; the event ID decides whether they matter.', fix: FIX.mdmLog, journal: 'I07' }));
    const edition = factValue(snapshot, 'Windows edition');
    if (edition) checks.push(check('client-edition', 'This computer', 'Windows edition supports Entra join and MDM', /^(Core|CoreN|CoreSingleLanguage|CoreCountrySpecific)$/i.test(edition) ? 'warn' : 'pass', `Edition: ${edition}.`, { how: 'Windows Home cannot be Entra joined; Pro, Enterprise and Education can.', journal: 'I01' }));
    const auto = factValue(snapshot, 'Automatic MDM enrollment policy (AutoEnrollMDM)');
    if (auto !== undefined) checks.push(check('client-autoenroll-policy', 'This computer', 'Group-policy automatic enrollment setting', 'info', `AutoEnrollMDM: ${auto}.`, { how: 'Entra-joined devices enroll through the MDM user scope; this policy is the hybrid/group-policy route and is normally not configured on a cloud-only computer.', journal: 'I05' }));
  }

  // Cross-check: this computer against the tenant, by device ID
  if (snapshot && cloud && !down('entraDevices')) {
    const ids = (snapshot.deviceIds || []).filter(d => norm(d.tenantId) === norm(cloud.tenant)).map(d => norm(d.deviceId));
    const entraMatch = entra.find(d => ids.includes(norm(d.deviceId)));
    const mdm = managed.find(m => ids.includes(norm(m.azureADDeviceId)));
    const clientHas = snapshotEnrollments(snapshot).length > 0;
    if (!ids.length) checks.push(check('xcheck', 'Cross-check', 'This computer matches a device in the tenant', 'unknown', 'The snapshot has no device ID for this tenant, so it cannot be matched to a cloud record.', { how: 'Matches the device ID from dsregcmd to the Entra device and the Intune record.', journal: 'I01' }));
    else if (!entraMatch) checks.push(check('xcheck', 'Cross-check', 'This computer matches a device in the tenant', 'warn', 'No Entra device object matched the device ID reported by this computer.', { how: 'Matches the device ID from dsregcmd to the Entra device and the Intune record. A deleted or different-tenant device object would show here.', journal: 'I01' }));
    else if (clientHas && (!mdm || norm(mdm.managementAgent) !== 'mdm')) checks.push(check('xcheck', 'Cross-check', 'This computer matches a device in the tenant', 'warn', `The computer reports an MDM enrollment, but Intune ${mdm ? 'knows it only as ' + mdm.managementAgent : 'has no record of it'}.`, { evidence: [`Entra device: ${entraMatch.displayName}`], how: 'Possible causes: the record was retired or deleted in Intune, or the first check-in has not completed.', fix: FIX.autoEnroll, journal: 'I05' }));
    else if (!clientHas && mdm && norm(mdm.managementAgent) === 'mdm') checks.push(check('xcheck', 'Cross-check', 'This computer matches a device in the tenant', 'warn', 'Intune shows an MDM enrollment, but this computer holds no enrollment record.', { evidence: [`Intune record: ${mdm.deviceName}`], how: 'Possible causes: the collector ran as a user who cannot read the enrollment keys, or the device was reset without being retired in Intune.', journal: 'I05' }));
    else checks.push(check('xcheck', 'Cross-check', 'This computer matches a device in the tenant', 'pass', `Matched Entra device ${entraMatch.displayName}${mdm ? ` and Intune record (${mdm.managementAgent}, ${mdm.complianceState})` : ''}.`, { evidence: mdm ? [`Intune user: ${mdm.userPrincipalName || 'not returned'}`, `Last sync: ${mdm.lastSyncDateTime || 'not returned'}`] : [], how: 'Matches the device ID from dsregcmd to the Entra device and the Intune record.', journal: 'I06' }));
  }

  // Device table with explanations of how each state was reached
  const devices = managed.map(m => {
    const e = entra.find(d => norm(d.deviceId) === norm(m.azureADDeviceId));
    const noPolicy = !down('compliancePolicies') && cloud.compliancePolicies.filter(p => p.assigned === null || p.assigned > 0).length === 0;
    const why = [];
    if (norm(m.managementAgent) === 'mssense') why.push('Known only through Defender for Endpoint; not MDM-enrolled, so no Intune compliance evaluation applies.');
    if (norm(m.managementAgent) === 'mdm' && m.complianceState === 'compliant' && noPolicy) why.push(`Shown Compliant because no compliance policy is assigned and the tenant default is ${cloud.complianceSettings?.secureByDefault ? 'Not compliant' : 'Compliant'}; no device setting was evaluated.`);
    if (m.complianceState === 'compliant' && !noPolicy && !down('compliancePolicies')) why.push('Compliant under the assigned compliance policies.');
    if (!m.userId) why.push('No primary user recorded.');
    return { name: m.deviceName, os: `${m.operatingSystem || ''} ${m.osVersion || ''}`.trim(), agent: m.managementAgent, enrollment: m.deviceEnrollmentType, ownership: m.managedDeviceOwnerType, compliance: m.complianceState, user: m.userPrincipalName, enrolled: m.enrolledDateTime, lastSync: m.lastSyncDateTime, entra: e ? { trust: e.trustType, isManaged: e.isManaged, isCompliant: e.isCompliant, mdmApp: e.mdmAppId === INTUNE_APP_ID ? 'Microsoft Intune' : e.mdmAppId || null } : null, why };
  });
  const order = new Map(STATUS_ORDER.map((s, i) => [s, i]));
  checks.sort((a, b) => order.get(a.status) - order.get(b.status));
  const summary = Object.fromEntries(STATUS_ORDER.map(s => [s, checks.filter(c => c.status === s).length]));
  return { checks, devices, summary, calculation: CALCULATION, sources: [SRC.tenant, SRC.intune, SRC.entra, SRC.ca, SRC.mobility, SRC.licenses] };
}

export async function intuneHealthReport(api, { tenant, beta = false, snapshot = null, now = Date.now() } = {}) {
  const cloud = await collectIntuneCloud(api, { tenant, beta, snapshotUpns: snapshotUpns(snapshot), now });
  const result = evaluateIntuneHealth({ cloud, snapshot, now });
  return { mode: 'live', tenant, identity: cloud.identity, organization: cloud.organization?.name || null, updatedAt: cloud.collectedAt, snapshotHost: snapshot?.host || null, unavailable: cloud.unavailable, ...result, notes: ['Read-only. Each check names what it read and how the value is derived; an unavailable source is shown as unknown, not as healthy.'] };
}

export function demoIntuneReport(snapshot = null, now = Date.now()) {
  const t = '11111111-1111-1111-1111-111111111111';
  const cloud = {
    tenant: t, identity: { id: t, name: 'Morgan Lee', upn: 'morgan.lee@contoso.example' }, unavailable: [], collectedAt: new Date(now).toISOString(), organization: { name: 'Contoso (fictional)' },
    licenses: [{ sku: 'SPE_E5', plans: [{ name: 'INTUNE_A', status: 'Success' }] }],
    mdmScope: [{ name: 'Microsoft Intune', appliesTo: 'all', discoveryUrl: 'https://enrollment.manage.microsoft.com/enrollmentserver/discovery.svc' }],
    enrollmentCa: [{ id: 'p1', name: 'Require compliant device (demo)', state: 'enabled', controls: ['compliantDevice'], missing: [] }],
    compliancePolicies: [], complianceSettings: { secureByDefault: false, validityDays: 30 },
    managedDevices: [
      { id: 'm1', deviceName: 'DEMO-LAPTOP', operatingSystem: 'Windows', osVersion: '10.0.26100', userId: '22222222-2222-2222-2222-222222222222', userPrincipalName: 'morgan.lee@contoso.example', managementAgent: 'mdm', deviceEnrollmentType: 'windowsAzureADJoin', managedDeviceOwnerType: 'company', complianceState: 'compliant', enrolledDateTime: new Date(now - 5 * DAY).toISOString(), lastSyncDateTime: new Date(now - 3600000).toISOString(), azureADDeviceId: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' },
      { id: 'm2', deviceName: 'DEMO-DESKTOP', operatingSystem: 'Windows', osVersion: '10.0.26100', managementAgent: 'msSense', complianceState: 'unknown', lastSyncDateTime: new Date(now - 86400000).toISOString(), azureADDeviceId: 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb' },
    ],
    entraDevices: [
      { id: 'e1', deviceId: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', displayName: 'DEMO-LAPTOP', trustType: 'AzureAd', isManaged: true, isCompliant: true, mdmAppId: INTUNE_APP_ID },
      { id: 'e2', deviceId: 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', displayName: 'DEMO-DESKTOP', trustType: 'AzureAd', isManaged: false },
    ],
    users: { '22222222-2222-2222-2222-222222222222': { id: '22222222-2222-2222-2222-222222222222', upn: 'morgan.lee@contoso.example', mail: 'morgan.lee@contoso.example', aliases: [] } }, upnLookups: {},
  };
  const result = evaluateIntuneHealth({ cloud, snapshot, now });
  return { mode: 'demo', tenant: 'Contoso · fictional', identity: cloud.identity, organization: cloud.organization.name, updatedAt: cloud.collectedAt, snapshotHost: snapshot?.host || null, unavailable: [], ...result, notes: ['Fictional demonstration. Sign in with Microsoft for live results and import a device snapshot to evaluate a real computer.'] };
}
