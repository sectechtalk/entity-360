import { GROUP_SELECT, classifyMemberships } from '../public/group-types.js';
import { myRoles, entraRoleLink, azureScopeLink } from './my-roles.mjs';
import { GUID, fail, describeError, queryUrl } from './model.mjs';
import { evaluateConditionalAccess } from './access.mjs';

// An imported snapshot is user-supplied evidence, never trusted proof of browser/device identity.
export function normalizeSnapshot(input) {
  if (!input || input.schemaVersion !== 1 || input.kind !== 'entity360-device-snapshot') throw fail('Choose an Entity 360 device snapshot JSON file.');
  const text = (v, max = 1000) => typeof v === 'string' ? v.slice(0, max) : '';
  const collectedAt = text(input.collectedAt, 60);
  if (!Number.isFinite(Date.parse(collectedAt)) || Date.parse(collectedAt) > Date.now() + 300000) throw fail('Snapshot collection time is invalid.');
  const areas = new Set(['Identity', 'Windows', 'Entra', 'Group Policy', 'Defender', 'Intune', 'Office', 'Network']);
  if (!Array.isArray(input.facts) || input.facts.length > 120 || !text(input.host, 100)) throw fail('Snapshot structure is invalid.');
  const facts = input.facts.map(f => {
    if (!f || !areas.has(f.area) || typeof f.key !== 'string' || !['string', 'boolean', 'number'].includes(typeof f.value)) throw fail('Snapshot fact is invalid.');
    if (typeof f.value === 'number' && !Number.isFinite(f.value)) throw fail('Snapshot value is invalid.');
    return { area: f.area, key: text(f.key, 100), value: typeof f.value === 'string' ? text(f.value, 6000) : f.value, source: text(f.source, 300), status: f.status === 'unavailable' ? 'unavailable' : 'reported' };
  });
  const deviceIds = (Array.isArray(input.deviceIds) ? input.deviceIds : []).slice(0, 20).filter(x => GUID.test(x?.deviceId) && GUID.test(x?.tenantId)).map(x => ({ deviceId: x.deviceId.toLowerCase(), tenantId: x.tenantId.toLowerCase() }));
  return { schemaVersion: 1, kind: input.kind, host: text(input.host, 100), collectedAt, windowsAccount: text(input.windowsAccount, 200), sid: text(input.sid, 200), facts, deviceIds, provenance: 'Imported, user-supplied local snapshot; not cryptographically verified' };
}

const source = (id, name, url) => ({ id, name, url });
export async function accountReport(api, { tenant, hours = 24, beta = false, now = Date.now() }) {
  if (!Number.isFinite(hours) || hours < .25 || hours > 2160) throw fail('Choose a timeframe from 15 minutes to 90 days.');
  const range = { from: new Date(now - hours * 3600000).toISOString(), to: new Date(now).toISOString() };
  const me = await api.request('/v1.0/me?$select=id,displayName,userPrincipalName,mail,userType');
  if (!GUID.test(me.id)) throw fail('Microsoft did not return a valid viewer identity.', 502);
  const report = { mode: 'live', identity: { id: me.id, name: me.displayName, upn: me.userPrincipalName, mail: me.mail, userType: me.userType, tenant }, range, sources: [], sections: {}, partial: false, partialReasons: [], unavailable: [], updatedAt: new Date(now).toISOString(), notes: ['Cloud identity is the signed-in viewer. Windows sign-in identity requires a snapshot collected on the investigated computer.', 'Personal Microsoft subscriptions are separate from tenant licenses. Review them in the personal account portal; cached account names do not prove subscriptions.'] };
  const run = async (name, metadata, collect, transform = x => x) => {
    try {
      const result = await collect();
      report.sources.push(metadata);
      report.sections[name] = transform(result.rows ?? result);
      if (result.truncated) { report.partial = true; report.partialReasons.push({ source: metadata.name, reason: 'page limit reached (1,000 records); shorten the timeframe' }); }
    } catch (error) {
      // A source this viewer or app is not granted is unavailable, not incomplete. Only failures of granted queries make the report partial.
      if ([401, 403, 404].includes(error.status)) report.unavailable.push({ source: metadata.name, reason: describeError(error) });
      else { report.partial = true; report.partialReasons.push({ source: metadata.name, reason: describeError(error) }); }
    }
  };
  report.sources.push(source('self-directory', 'My Entra identity', 'https://entra.microsoft.com/'));
  let groupError = null;
  const [directM, transM] = await Promise.all([
    api.pages(queryUrl('/v1.0/me/memberOf', { '$select': GROUP_SELECT })),
    api.pages(queryUrl('/v1.0/me/transitiveMemberOf', { '$select': GROUP_SELECT })),
  ].map(p => p.catch(e => { groupError ||= e; return null; })));
  const groups = directM && transM ? { truncated: directM.truncated || transM.truncated } : null;
  if (groups) {
    report.sources.push(source('self-groups', 'My group memberships', 'https://entra.microsoft.com/#view/Microsoft_AAD_IAM/GroupsManagementMenuBlade/~/AllGroups'));
    const c = classifyMemberships(directM.rows, transM.rows);
    report.sections.groups = c.rows; report.sections.groupDirectoryRoles = c.directoryRoles;
    if (groups.truncated) { report.partial = true; report.partialReasons.push({ source: 'My group memberships', reason: 'page limit reached' }); }
  }
  else if ([401, 403, 404].includes(groupError?.status)) report.unavailable.push({ source: 'My group memberships', reason: describeError(groupError) });
  else { report.partial = true; report.partialReasons.push({ source: 'My group memberships', reason: describeError(groupError) }); }
  // Admin roles join the memberships table (Group memberships and Role assignments).
  const roleTask = myRoles(api, me, report.sections.groups || [], { tenant }).then(r => {
    if (r.ok) report.sources.push(source('self-roles', 'My admin roles (Entra and Azure)', 'https://entra.microsoft.com/#view/Microsoft_Azure_PIMCommon/ActivationMenuBlade/~/aadmigratedroles'));
    if (r.ok) report.sections.roles = r.rows;
    report.notes.push(...r.notes);
    report.unavailable.push(...r.problems.unavailable);
    if (r.problems.partial.length) { report.partial = true; report.partialReasons.push(...r.problems.partial); }
  });
  await Promise.all([
    roleTask,
    run('licenses', source('self-licenses', 'My Microsoft 365 licenses', 'https://admin.microsoft.com/'), () => api.pages('/v1.0/me/licenseDetails'), rows => rows.map(l => ({ sku: l.skuPartNumber, skuId: l.skuId, plans: (l.servicePlans || []).map(p => ({ name: p.servicePlanName, status: p.provisioningStatus, appliesTo: p.appliesTo })) }))),
    run('authentication', source('self-authentication', 'My registered authentication methods', 'https://mysignins.microsoft.com/security-info'), () => api.pages('/v1.0/me/authentication/methods'), rows => rows.map(m => ({ type: String(m['@odata.type'] || 'Not returned').replace('#microsoft.graph.', ''), name: m.displayName, model: m.model, aaguid: m.aaGuid, created: m.createdDateTime }))),
    run('devices', source('self-devices', 'My registered Entra devices', 'https://entra.microsoft.com/'), () => api.pages('/v1.0/me/registeredDevices/microsoft.graph.device?$select=id,deviceId,displayName,operatingSystem,operatingSystemVersion,trustType,isManaged,isCompliant,accountEnabled'), rows => rows.map(d => ({ id: d.id, deviceId: d.deviceId, name: d.displayName, os: d.operatingSystem, version: d.operatingSystemVersion, trust: d.trustType, managed: d.isManaged, compliant: d.isCompliant, enabled: d.accountEnabled }))),
    run('intune', source('self-intune', 'My Intune devices', 'https://intune.microsoft.com/'), () => api.pages(queryUrl('/v1.0/me/managedDevices', { '$select': 'id,azureADDeviceId,deviceName,operatingSystem,osVersion,complianceState,managementAgent,lastSyncDateTime,managedDeviceOwnerType,userId' })), rows => rows.map(d => ({ id: d.id, deviceId: d.azureADDeviceId, name: d.deviceName, os: d.operatingSystem, version: d.osVersion, compliance: d.complianceState, agent: d.managementAgent, lastSync: d.lastSyncDateTime, ownership: d.managedDeviceOwnerType }))),
    run('signins', source('self-signins', 'My Entra sign-in evidence', 'https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/SignIns'), () => api.pages(queryUrl(`/${beta ? 'beta' : 'v1.0'}/auditLogs/signIns`, { '$filter': `userId eq '${me.id}' and createdDateTime ge ${range.from} and createdDateTime le ${range.to}${beta ? " and signInEventTypes/any(t:t eq 'interactiveUser' or t eq 'nonInteractiveUser')" : ''}`, '$top': '100' })), rows => rows.map(s => ({ id: s.id, time: s.createdDateTime, app: s.appDisplayName, code: s.status?.errorCode ?? null, reason: s.status?.failureReason, deviceId: s.deviceDetail?.deviceId, deviceName: s.deviceDetail?.displayName, methods: (s.authenticationDetails || []).map(a => ({ method: a.authenticationMethod, succeeded: a.succeeded, detail: a.authenticationStepResultDetail })), policiesReturned: s.appliedConditionalAccessPolicies !== undefined, policies: (s.appliedConditionalAccessPolicies || []).map(p => ({ id: p.id, name: p.displayName, result: p.result })) }))),
    run('conditionalAccess', source('self-ca', 'Conditional Access policies that apply to me (Microsoft What If)', 'https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies'), async () => ({ rows: (await evaluateConditionalAccess(api, { id: me.id, type: 'user' })).rows, truncated: false }), rows => rows.map(p => ({ id: p.id, name: p.name, state: p.state, targeting: `Applies to ${p.apps.join(', ')}${p.missing.length ? `. Incomplete: also depends on ${p.missing.join(', ')}, which were not supplied` : ''}`, groupsComplete: true }))),
  ]);
  return report;
}

export function demoAccountReport(profile) {
  const restricted = profile === 'reader';
  const r = { mode: 'demo', identity: { id: '11111111-1111-1111-1111-111111111111', name: restricted ? 'Casey Rivera' : 'Morgan Lee', upn: restricted ? 'casey.rivera@contoso.example' : 'morgan.lee@contoso.example', userType: 'Member', tenant: 'Contoso · fictional' }, range: { from: new Date(Date.now() - 86400000).toISOString(), to: new Date().toISOString() }, sources: [source('self-directory', 'My Entra identity', 'https://entra.microsoft.com/')], sections: {}, partial: restricted, updatedAt: new Date().toISOString(), notes: ['Fictional demonstration. Import a real device snapshot to inspect local configuration; demo licenses do not apply to it.'] };
  if (!restricted) { r.sources.push(source('self-licenses', 'My Microsoft 365 licenses', 'https://admin.microsoft.com/')); r.sections.licenses = [{ sku: 'Microsoft 365 Business Premium (demo)', plans: [{ name: 'INTUNE_A', status: 'Success', appliesTo: 'User' }, { name: 'MDE_SMB', status: 'Success', appliesTo: 'User' }] }]; r.sections.devices = [{ id: 'demo', deviceId: '22222222-2222-2222-2222-222222222222', name: 'DEMO-PC', os: 'Windows', trust: 'Workplace', managed: false, compliant: false }]; if (!restricted) r.sections.roles = [
    { id: 'demo-role-1', name: 'Security Administrator', kind: 'Directory role', membershipType: 'n/a', roleAssignable: false, membership: 'Active', source: 'Direct', scope: '/', granted: new Date(Date.now() - 3 * 864e5).toISOString(), remaining: 5 * 36e5, link: entraRoleLink('194ae4cb-b126-40b2-bd5b-6091b380977d', 'Security Administrator') },
    { id: 'demo-role-2', name: 'Global Administrator', kind: 'Directory role', membershipType: 'n/a', roleAssignable: false, membership: 'Eligible', source: 'Direct', scope: '/', granted: new Date(Date.now() - 30 * 864e5).toISOString(), remaining: null, link: entraRoleLink('62e90394-69f5-4237-9190-012177145e10', 'Global Administrator') },
    { id: 'demo-role-3', name: 'Reader', kind: 'Azure role', membershipType: 'n/a', roleAssignable: false, membership: 'Permanent', source: 'Direct', scope: '/subscriptions/00000000-0000-0000-0000-000000000000', granted: null, remaining: null, link: azureScopeLink('contoso.onmicrosoft.com', '/subscriptions/00000000-0000-0000-0000-000000000000') },
  ];
  r.sections.groups = classifyMemberships([{ '@odata.type': '#microsoft.graph.group', id: '33333333-3333-3333-3333-333333333333', displayName: 'Employees (demo)', groupTypes: [], securityEnabled: true, mailEnabled: false, onPremisesSyncEnabled: true }], [{ '@odata.type': '#microsoft.graph.group', id: '44444444-4444-4444-4444-444444444444', displayName: 'All staff (demo)', groupTypes: ['Unified', 'DynamicMembership'], securityEnabled: false, mailEnabled: true }]).rows; r.sections.groupDirectoryRoles = 0; }
  return r;
}
