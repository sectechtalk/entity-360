// Single-entity PDF report: everything Entity 360 can read about one user, application, managed identity or device,
// gathered with the viewer's delegated token at request time and rendered by server/pdf.mjs. Nothing is stored.
// Every source is read independently: one that fails becomes a "Could not be read" section with the reason,
// never a silently missing section.
import { GUID, fail, describeError, queryUrl, odata } from './model.mjs';
import { liveReport, activityReport, defenderReport, DEFENDER_DAYS } from './live.mjs';
import { adminUnits, adGroups, pimRequests, provisioning, appSso } from './bucket3.mjs';
import { pimTable } from './pim.mjs';
import { deviceDetails } from './devices.mjs';
import { deviceStates } from './access.mjs';
import { findingsOverview } from './findings.mjs';
import { display } from './pdf.mjs';

export const REPORT_TYPES = ['user', 'application', 'managedIdentity', 'device'];
export const ROW_LIMIT = 500;
const TYPE_LABEL = { user: 'User', application: 'Application (service principal)', managedIdentity: 'Managed identity', device: 'Device' };
// Profile attributes readable with User.Read.All. signInActivity is read separately: it needs AuditLog.Read.All and a reader
// role, and asking for it in the same $select would fail the whole profile read for a viewer without them.
export const USER_SELECT = ['id', 'displayName', 'givenName', 'surname', 'userPrincipalName', 'mail', 'mailNickname', 'otherMails', 'proxyAddresses', 'imAddresses',
  'jobTitle', 'department', 'companyName', 'officeLocation', 'employeeId', 'employeeType', 'employeeHireDate', 'employeeOrgData', 'businessPhones', 'mobilePhone', 'faxNumber',
  'streetAddress', 'city', 'state', 'postalCode', 'country', 'usageLocation', 'preferredLanguage', 'ageGroup', 'consentProvidedForMinor', 'legalAgeGroupClassification',
  'accountEnabled', 'userType', 'creationType', 'createdDateTime', 'lastPasswordChangeDateTime', 'passwordPolicies', 'passwordProfile', 'signInSessionsValidFromDateTime',
  'externalUserState', 'externalUserStateChangeDateTime', 'identities', 'showInAddressList', 'securityIdentifier',
  'onPremisesSyncEnabled', 'onPremisesLastSyncDateTime', 'onPremisesDomainName', 'onPremisesSamAccountName', 'onPremisesUserPrincipalName', 'onPremisesDistinguishedName',
  'onPremisesSecurityIdentifier', 'onPremisesImmutableId', 'onPremisesExtensionAttributes', 'onPremisesProvisioningErrors', 'assignedLicenses', 'assignedPlans', 'provisionedPlans'].join(',');
const DEVICE_GROUP_SELECT = 'id,displayName,groupTypes,membershipRule,securityEnabled,mailEnabled,isAssignableToRole,onPremisesSyncEnabled';

// A read that never throws: { ok, data } or { ok: false, reason, status }.
export const attempt = async fn => { try { return { ok: true, data: await fn() }; } catch (e) { return { ok: false, reason: describeError(e), status: e?.status ?? null }; } };
const skipped = reason => ({ ok: false, reason, status: null, skipped: true });
export const daysOf = range => Math.max(1, Math.ceil((Date.parse(range.to) - Date.parse(range.from)) / 86400000));
// Largest Defender window that fits inside the page range (Defender accepts only fixed windows).
export const defenderDays = days => [...DEFENDER_DAYS].reverse().find(d => d <= days) || DEFENDER_DAYS[0];

// ---------- Gathering ----------
export async function gatherEntity(api, { id, type, entraId = '', intuneId = '' }, { range, tenant, beta = false, azure = false, logs = false, workspaceIds = [], telemetryRoles = {}, ad, now = Date.now(), findings = true } = {}) {
  if (!REPORT_TYPES.includes(type)) throw fail('Invalid entity type.');
  if (type === 'device') return gatherDevice(api, { entraId, intuneId }, { tenant, beta, now, findings });
  if (!GUID.test(String(id))) throw fail('Invalid entity identifier.');
  // The core report is the same one the Summary, Access, Sign-ins and Devices pages use. Not found or no access ends the report.
  const core = await liveReport(api, id, type, range, { tenant, beta, azure, logs, workspaceIds, telemetryRoles });
  const days = daysOf(range), isUser = type === 'user';
  const sp = isUser ? null : attempt(() => api.request(`/v1.0/servicePrincipals/${id}`));
  const tasks = {
    profile: isUser ? attempt(() => api.request(`/v1.0/users/${id}?$select=${USER_SELECT}`).catch(e => { if (e?.status === 400 || e?.status === 403) return api.request(`/v1.0/users/${id}`); throw e; })) : sp,
    signInActivity: isUser ? attempt(async () => (await api.request(`/v1.0/users/${id}?$select=id,signInActivity`)).signInActivity || null) : null,
    manager: isUser ? attempt(() => api.request(`/v1.0/users/${id}/manager?$select=id,displayName,userPrincipalName,jobTitle`).catch(e => { if (e?.status === 404) return null; throw e; })) : null,
    directReports: isUser ? attempt(async () => (await api.pages(`/v1.0/users/${id}/directReports?$select=id,displayName,userPrincipalName,jobTitle`)).rows) : null,
    licenses: isUser ? attempt(async () => (await api.pages(`/v1.0/users/${id}/licenseDetails`)).rows) : null,
    registration: isUser ? attempt(() => api.request(`/v1.0/reports/authenticationMethods/userRegistrationDetails/${id}`)) : null,
    owned: attempt(async () => (await api.pages(`/v1.0/${isUser ? 'users' : 'servicePrincipals'}/${id}/ownedObjects?$select=id,displayName`)).rows),
    pim: isUser ? attempt(() => pimTable(api, { id, self: false }, { azure })) : null,
    adminUnits: attempt(() => adminUnits(api, id, type)),
    adGroups: isUser ? attempt(() => adGroups(api, id, type, { ad })) : null,
    pimRequests: attempt(() => pimRequests(api, id)),
    provisioning: attempt(() => provisioning(api, id, type, { days, now })),
    sso: isUser ? null : attempt(() => appSso(api, id)),
    assignedTo: isUser ? null : attempt(async () => (await api.pages(`/v1.0/servicePrincipals/${id}/appRoleAssignedTo`)).rows),
    grantsToApi: isUser ? null : attempt(async () => (await api.pages(queryUrl('/v1.0/oauth2PermissionGrants', { '$filter': `resourceId eq '${id}'` }))).rows),
    appRegistration: isUser || !core.entity.appId ? null : attempt(() => appRegistration(api, core.entity.appId)),
    activity: azure ? attempt(() => activityReport(api, id, type, Math.min(90, days), { tenant, now })) : skipped('Azure is not connected for this sign-in. Use Connection & setup > Connect Azure, then run the report again.'),
    defender: isUser ? attempt(() => defenderReport(api, id, defenderDays(days), { tenant, now })) : null,
    findings: findings ? attempt(() => findingsOverview(api, { azure, now })) : skipped('Findings were not requested.'),
  };
  const keys = Object.keys(tasks), values = await Promise.all(keys.map(k => tasks[k]));
  const extra = Object.fromEntries(keys.map((k, i) => [k, values[i]]));
  return { kind: 'identity', type, core, extra, range, days, generated: new Date(now).toISOString() };
}

// App registration (when it lives in this tenant), its owners, and the API permissions it asks for with names resolved.
async function appRegistration(api, appId) {
  const list = await api.request(queryUrl('/v1.0/applications', { '$filter': `appId eq '${odata(appId)}'` }));
  const app = list.value?.[0];
  if (!app) return null;
  const owners = await api.pages(`/v1.0/applications/${app.id}/owners?$select=id,displayName,userPrincipalName`).then(r => r.rows, () => null);
  const permissions = [];
  for (const res of (app.requiredResourceAccess || []).slice(0, 30)) {
    const target = await api.request(`/v1.0/servicePrincipals(appId='${odata(res.resourceAppId)}')?$select=displayName,appRoles,oauth2PermissionScopes`).catch(() => null);
    for (const a of res.resourceAccess || []) {
      const def = a.type === 'Role' ? (target?.appRoles || []).find(r => r.id === a.id) : (target?.oauth2PermissionScopes || []).find(s => s.id === a.id);
      permissions.push({ api: target?.displayName || res.resourceAppId, permission: def?.value || a.id, type: a.type === 'Role' ? 'Application' : 'Delegated', description: def?.displayName || def?.adminConsentDisplayName || '' });
    }
  }
  return { app, owners, permissions };
}

async function gatherDevice(api, { entraId, intuneId }, { tenant, beta, now, findings }) {
  if ((!entraId && !intuneId) || (entraId && !GUID.test(entraId)) || (intuneId && !GUID.test(intuneId))) throw fail('Invalid device identifier.');
  const details = await deviceDetails(api, { entraId, intuneId }, { beta, tenant });
  const d = details.device;
  const [states, groups, entraRaw, intuneRaw, overview] = await Promise.all([
    d.intuneId ? attempt(() => deviceStates(api, d.intuneId)) : skipped('This device has no Intune record, so it has no compliance or configuration policy states.'),
    d.entraId ? attempt(async () => (await api.pages(`/v1.0/devices/${d.entraId}/transitiveMemberOf/microsoft.graph.group?$select=${DEVICE_GROUP_SELECT}`)).rows) : skipped('This device has no Entra device object, so it has no Entra group memberships.'),
    d.entraId ? attempt(() => api.request(`/v1.0/devices/${d.entraId}`)) : skipped('No Entra device object.'),
    d.intuneId ? attempt(() => api.request(`/v1.0/deviceManagement/managedDevices/${d.intuneId}`)) : skipped('No Intune record.'),
    findings ? attempt(() => findingsOverview(api, { now })) : skipped('Findings were not requested.'),
  ]);
  return { kind: 'device', type: 'device', details, extra: { states, groups, entraRaw, intuneRaw, findings: overview }, generated: new Date(now).toISOString() };
}

// ---------- Document model ----------
const section = (title, blocks, { status, reason, summary } = {}) => ({ title, blocks: blocks.filter(Boolean), status: status || 'ok', reason, summary });
const table = (columns, rows) => ({ type: 'table', columns: columns.map(([label, w]) => ({ label, w })), rows });
const kv = rows => ({ type: 'kv', rows: rows.filter(r => r && r[1] !== undefined) });
const text = (t, style) => ({ type: 'text', text: t, style });
const callout = (t, tone = 'warn') => ({ type: 'callout', text: t, tone });
const heading = t => ({ type: 'heading', text: t });
const capped = (rows, what = 'rows') => rows.length > ROW_LIMIT ? [rows.slice(0, ROW_LIMIT), callout(`Showing the first ${ROW_LIMIT} of ${rows.length} ${what}. Open the matching page in Entity 360 or the Microsoft portal for the rest.`, 'info')] : [rows, null];
const sortBy = (rows, f) => [...rows].sort((a, b) => String(f(a) ?? '').localeCompare(String(f(b) ?? '')));
const unread = (title, r, extra = []) => section(title, extra, { status: 'unavailable', reason: r.reason });

// Rows of "property: value" for any Graph object: scalars and scalar lists as they are, small objects flattened,
// lists of objects summarized. `skip` names properties another section already shows in full.
export function propertyRows(obj, skip = []) {
  const rows = [];
  const label = k => k.replace(/^@odata\./, 'odata ').replace(/([a-z0-9])([A-Z])/g, '$1 $2').replace(/^./, c => c.toUpperCase());
  for (const [k, v] of Object.entries(obj || {}).sort(([a], [b]) => a.localeCompare(b))) {
    if (skip.includes(k) || k === '@odata.context') continue;
    if (v === null || v === undefined || v === '' || (Array.isArray(v) && !v.length)) continue;
    if (Array.isArray(v) && v.some(x => x && typeof x === 'object')) { const names = v.map(x => x?.displayName || x?.value || x?.name || x?.servicePlanName || x?.service || x?.capability).filter(Boolean); rows.push([label(k), names.length ? `${v.length}: ${names.join('; ')}` : `${v.length} item(s)`]); continue; }
    if (v && typeof v === 'object' && !Array.isArray(v)) {
      const flat = Object.entries(v).filter(([, x]) => x !== null && x !== undefined && x !== '' && !(Array.isArray(x) && !x.length));
      if (flat.length) rows.push([label(k), flat.map(([a, b]) => `${a}: ${display(b)}`).join(', ')]);
      continue;
    }
    rows.push([label(k), v]);
  }
  return rows;
}

const findingsFor = (r, needles) => {
  if (!r?.ok) return { status: 'unavailable', reason: r?.reason, rows: [] };
  const n = needles.filter(Boolean).map(x => String(x).toLowerCase());
  const rows = [], unavailable = [];
  for (const f of r.data.findings || []) {
    if (f.status === 'unavailable') { unavailable.push(`${f.title}: ${f.reason}`); continue; }
    for (const i of f.items || []) {
      const hay = [i.link, i.text, i.detail].filter(Boolean).join(' ').toLowerCase();
      if (n.some(x => hay.includes(x))) rows.push([f.severity, f.title, i.detail || i.text, f.why]);
    }
  }
  return { rows, unavailable };
};
function findingsSection(r, needles, label) {
  const f = findingsFor(r, needles);
  if (r?.skipped || f.status === 'unavailable') return unread('Findings', r);
  return section('Findings', [
    text(`Tenant findings (the TENANT > Security hardening checks) that name this ${label}. Each check lists at most 50 affected objects, so a large tenant can hide a match.`, 'muted'),
    f.rows.length ? table([['Severity', 1], ['Finding', 2], ['Detail', 4], ['Why it matters', 4]], f.rows) : text(`No open finding names this ${label}.`),
    f.unavailable.length ? callout(`Checks that could not run: ${f.unavailable.join(' | ')}`) : null,
  ], { status: f.rows.length ? 'ok' : 'empty', summary: f.rows.length ? `${f.rows.length} open` : 'None open' });
}
const coverageSection = (sources, notes, partialReasons, unavailable) => section('Coverage and notes', [
  text('What each source returned for this report. An empty source means Microsoft answered with no records for this entity, not that the source was skipped.', 'muted'),
  sources.length ? table([['Source', 2], ['Status', 1], ['Records', 0.8], ['Coverage', 3], ['Note', 4]], sources.map(s => [s.name, s.status, s.count, s.coverage, s.note])) : null,
  partialReasons.length ? heading('Incomplete reads') : null,
  partialReasons.length ? table([['Source', 2], ['Reason', 5]], partialReasons.map(p => [p.source, p.reason])) : null,
  unavailable.length ? heading('Not readable with this sign-in') : null,
  unavailable.length ? table([['Source', 2], ['Reason', 5]], unavailable.map(p => [p.source, p.reason])) : null,
  notes.length ? heading('Notes') : null,
  notes.length ? { type: 'list', items: [...new Set(notes)] } : null,
]);

export function buildDocument(g, { viewer = '', hosting = '', azure = false } = {}) {
  return g.kind === 'device' ? deviceDocument(g, { viewer, hosting }) : identityDocument(g, { viewer, hosting, azure });
}

function identityDocument(g, { viewer, hosting, azure }) {
  const { core, extra: x, type } = g, e = core.entity, isUser = type === 'user';
  const policies = core.policies || [], events = core.events || [];
  const of = kind => policies.filter(p => p.kind === kind);
  const sections = [];
  const profile = x.profile?.ok ? x.profile.data : null;

  // 1. Identity overview
  const overview = [['Name', e.name], ['Type', TYPE_LABEL[type]], [isUser ? 'User principal name' : 'Application (client) ID', isUser ? e.subtitle : e.appId], ['Object ID', e.id], ['Enabled', e.enabled]];
  if (isUser) {
    const a = core.account || {}, si = x.signInActivity?.ok ? x.signInActivity.data : null;
    overview.push(['Member or guest', a.userType], ['Created', a.created], ['Source of authority', a.synced], ['Last on-premises sync', a.lastSync], ['Sessions valid from (last revocation)', a.sessionsValidFrom],
      ['Job title', profile?.jobTitle], ['Department', profile?.department || e.department], ['Manager', x.manager?.ok ? (x.manager.data ? `${x.manager.data.displayName} (${x.manager.data.userPrincipalName || x.manager.data.id})` : 'None set') : `Not read: ${x.manager?.reason}`],
      ['Last password change', profile?.lastPasswordChangeDateTime], ['Last interactive sign-in', si ? si.lastSignInDateTime : x.signInActivity?.ok ? 'Never recorded' : `Not read: ${x.signInActivity?.reason}`],
      ['Last non-interactive sign-in', si?.lastNonInteractiveSignInDateTime], ['Last successful sign-in', si?.lastSuccessfulSignInDateTime]);
  } else {
    overview.push(['Service principal type', profile?.servicePrincipalType], ['Publisher', profile?.publisherName || profile?.appOwnerOrganizationId], ['Assignment required', profile?.appRoleAssignmentRequired], ['Sign-in audience', profile?.signInAudience], ['Tags', profile?.tags]);
  }
  sections.push(section('Identity overview', [kv(overview), e.link ? text(`Open in Entra: ${e.link}`, 'muted') : null]));

  // 2. Full directory profile
  if (x.profile?.ok) sections.push(section(isUser ? 'Directory profile (all attributes)' : 'Service principal (all properties)', [
    text('Every attribute Microsoft Graph returned for this object. Lists of objects are summarized; their detail is in the sections that follow.', 'muted'),
    kv(propertyRows(profile, ['assignedPlans', 'provisionedPlans', 'assignedLicenses', 'appRoles', 'oauth2PermissionScopes', 'keyCredentials', 'passwordCredentials'])),
  ]));
  else sections.push(unread(isUser ? 'Directory profile (all attributes)' : 'Service principal (all properties)', x.profile));

  if (isUser) {
    // 3. Authentication and MFA registration
    const r = x.registration;
    sections.push(r?.ok ? section('Authentication methods and MFA registration', [kv([['MFA registered', r.data.isMfaRegistered], ['MFA capable', r.data.isMfaCapable], ['Passwordless capable', r.data.isPasswordlessCapable], ['SSPR registered', r.data.isSsprRegistered], ['SSPR enabled', r.data.isSsprEnabled], ['SSPR capable', r.data.isSsprCapable], ['Admin', r.data.isAdmin], ['Methods registered', r.data.methodsRegistered], ['Default method', r.data.defaultMfaMethod], ['System preferred method enabled', r.data.isSystemPreferredAuthenticationMethodEnabled], ['System preferred methods', r.data.systemPreferredAuthenticationMethods], ['User preferred method', r.data.userPreferredMethodForSecondaryAuthentication], ['Report updated', r.data.lastUpdatedDateTime]])])
      : unread('Authentication methods and MFA registration', r));
    // 4. Licenses
    const l = x.licenses;
    sections.push(l?.ok ? section('Licenses', [
      l.data.length ? table([['License (SKU)', 2], ['Service plans', 6]], l.data.map(s => [s.skuPartNumber, (s.servicePlans || []).map(p => `${p.servicePlanName} (${p.provisioningStatus})`).join(', ')])) : text('No licenses assigned.'),
      profile?.assignedLicenses?.some(a => (a.disabledPlans || []).length) ? text(`Disabled plans: ${profile.assignedLicenses.filter(a => a.disabledPlans?.length).map(a => `${a.skuId}: ${a.disabledPlans.length} plan(s)`).join('; ')}`, 'muted') : null,
    ], { status: l.data.length ? 'ok' : 'empty', summary: `${l.data.length} license(s)` }) : unread('Licenses', l));
    // 5. Organization
    const reports = x.directReports;
    sections.push(section('Organization', [
      kv([['Manager', x.manager?.ok ? (x.manager.data ? `${x.manager.data.displayName} · ${x.manager.data.userPrincipalName || ''} · ${x.manager.data.jobTitle || ''}` : 'None set') : `Not read: ${x.manager?.reason}`]]),
      heading('Direct reports'),
      reports?.ok ? (reports.data.length ? table([['Name', 2], ['User principal name', 3], ['Job title', 2]], sortBy(reports.data, r => r.displayName).map(r => [r.displayName, r.userPrincipalName, r.jobTitle])) : text('No direct reports.')) : callout(`Could not be read: ${reports?.reason}`),
    ]));
  }

  // Group memberships
  const groups = sortBy((core.relationships || []).filter(r => r.relation === 'Transitive membership'), r => r.name);
  sections.push(section('Group memberships', [
    text('Every group this identity is in, directly or through nesting (transitive). Group type comes from Entra.', 'muted'),
    groups.length ? table([['Group', 3], ['Type', 2], ['Object ID', 3]], groups.map(r => [r.name, r.kind, r.objectId])) : text('Not a member of any group, or memberships were not readable (see Coverage).'),
  ], { status: groups.length ? 'ok' : 'empty', summary: `${groups.length} group(s)` }));

  // Admin roles (Entra) and Azure roles
  const roles = policies.filter(p => p.kind === 'Role' && p.source === 'roles'), azureRoles = policies.filter(p => p.kind === 'Role' && p.source === 'azure');
  sections.push(section('Entra admin roles', [
    text('Active and eligible directory roles: direct, through a role-assignable group, or eligible through PIM for Groups. Permissions are summarized from the role definition.', 'muted'),
    roles.length ? table([['Role', 2], ['Status', 1], ['How assigned', 2.5], ['Scope', 2], ['Timing', 1.6], ['Permissions', 3], ['PIM activation rules', 2.5]], sortBy(roles, r => r.name).map(r => [r.name, r.status, r.assignment, r.scopeName || r.evidence?.directoryScopeId || '/', r.timing?.text || '', r.permissionText, r.activation])) : text('No Entra admin roles.'),
    core.pimGroups ? heading('PIM for Groups eligibility') : null,
    core.pimGroups ? (core.pimGroups.readable ? (core.pimGroups.rows.length ? table([['Group', 3], ['Access', 1], ['Eligibility ends', 2]], core.pimGroups.rows.map(r => [r.group, r.access, r.end || 'Permanent'])) : text('No PIM for Groups eligibility.')) : callout(`Could not be read: ${core.pimGroups.reason}`)) : null,
  ], { status: roles.length ? 'ok' : 'empty', summary: `${roles.filter(r => r.status !== 'Eligible').length} active, ${roles.filter(r => r.status === 'Eligible').length} eligible` }));
  sections.push(azure ? section('Azure roles (RBAC)', [
    azureRoles.length ? table([['Role', 2], ['Status', 1], ['How assigned', 2], ['Detail', 5]], sortBy(azureRoles, r => r.name).map(r => [r.name, r.status, r.assignment, r.detail])) : text('No Azure role assignments in any subscription or management group you can read.'),
  ], { status: azureRoles.length ? 'ok' : 'empty', summary: `${azureRoles.length} assignment(s)` }) : section('Azure roles (RBAC)', [], { status: 'unavailable', reason: 'Azure is not connected for this sign-in. Use Connection & setup > Connect Azure, then run the report again.' }));

  // PIM (all types) and PIM request history
  if (isUser) {
    const p = x.pim;
    sections.push(p?.ok ? section('Privileged Identity Management', [
      text('Every PIM assignment and eligibility for this user: Entra roles, groups and (with Azure connected) Azure roles.', 'muted'),
      p.data.rows.length ? table([['Type', 1.2], ['Name', 2.5], ['Scope', 2.5], ['State', 1.2], ['Member type', 1], ['Start', 1.4], ['End', 1.4]], p.data.rows.map(r => [r.type, r.name, r.scopeLabel, r.state, r.memberType, r.start, r.end || 'Permanent'])) : text('No PIM assignments or eligibility.'),
      p.data.problems?.length ? callout(`Partly read: ${p.data.problems.map(display).join(' | ')}`) : null,
      p.data.notes?.length ? { type: 'list', items: p.data.notes } : null,
    ], { status: p.data.rows.length ? 'ok' : 'empty', summary: `${p.data.rows.length} row(s)` }) : unread('Privileged Identity Management', p));
  }
  const pr = x.pimRequests;
  sections.push(pr?.ok ? section('PIM requests', [
    pr.data.rows.length ? table([['Created', 1.4], ['Role', 2], ['Action', 1.4], ['Status', 1.2], ['Approval', 1.6], ['Justification', 3]], pr.data.rows.map(r => [r.created, r.role, r.action, r.status, r.approver, r.justification])) : text('No PIM requests by or for this identity.'),
  ], { status: pr.data.rows.length ? 'ok' : 'empty', summary: `${pr.data.rows.length} request(s)` }) : unread('PIM requests', pr));

  // Admin units
  const au = x.adminUnits;
  sections.push(au?.ok ? section('Administrative units', [
    au.data.rows.length ? table([['Admin unit', 2], ['Membership', 1], ['Management', 1.4], ['Scoped role members', 4]], au.data.rows.map(r => [r.name, r.membership, r.restricted, r.roles])) : text('Not a member of any administrative unit.'),
    au.data.notes?.length ? { type: 'list', items: au.data.notes } : null,
  ], { status: au.data.rows.length ? 'ok' : 'empty', summary: `${au.data.rows.length} unit(s)` }) : unread('Administrative units', au));

  // Application access
  const appRows = [...of('Application assignment'), ...of('API permission')];
  sections.push(section(isUser ? 'Application assignments' : 'API permissions granted to this app (application permissions)', [
    appRows.length ? table([['Application or API', 2.5], ['Role or permission', 2.5], ['Status', 1], ['How assigned', 3]], sortBy(appRows, r => r.name).map(r => [r.name, r.role, r.status, r.assignment])) : text(isUser ? 'No application assignments.' : 'No application permissions granted.'),
  ], { status: appRows.length ? 'ok' : 'empty', summary: `${appRows.length}` }));
  const delegated = of('Delegated permission');
  sections.push(section('Delegated permission grants (consents)', [
    delegated.length ? table([['App', 2.5], ['Scopes', 4], ['Consent', 2.5], ['Detail', 3]], delegated.map(r => [r.name, r.role, r.assignment, r.detail])) : text('No delegated consents.'),
  ], { status: delegated.length ? 'ok' : 'empty', summary: `${delegated.length}` }));

  if (!isUser) {
    // Who has access to this app
    const at = x.assignedTo, spRoles = profile?.appRoles || [];
    const roleName = rid => !rid || rid === '00000000-0000-0000-0000-000000000000' ? 'Default access' : spRoles.find(r => r.id === rid)?.displayName || rid;
    sections.push(at?.ok ? section('Who has access to this app (assigned users, groups and apps)', [
      text(`Assignment required: ${display(profile?.appRoleAssignmentRequired)}. When this is No, any user in the tenant can sign in, not only those listed.`, 'muted'),
      at.data.length ? table([['Principal', 3], ['Type', 1.2], ['App role', 2], ['Assigned', 1.5]], sortBy(at.data, r => r.principalDisplayName).map(r => [r.principalDisplayName, r.principalType, roleName(r.appRoleId), r.createdDateTime])) : text('No users, groups or apps are assigned.'),
    ], { status: at.data.length ? 'ok' : 'empty', summary: `${at.data.length} assignment(s)` }) : unread('Who has access to this app (assigned users, groups and apps)', at));
    const gt = x.grantsToApi;
    if (gt?.ok && gt.data.length) sections.push(section('Delegated access other apps have to this API', [table([['Client app ID', 3], ['Consent type', 1.5], ['Scopes', 4]], gt.data.map(r => [r.clientId, r.consentType === 'AllPrincipals' ? 'Admin consent (all users)' : `User ${r.principalId}`, r.scope]))]));
    // Owners
    const owners = (core.relationships || []).filter(r => r.kind === 'Owner');
    const reg = x.appRegistration;
    sections.push(section('Owners', [
      heading('Enterprise application (service principal) owners'),
      owners.length ? table([['Owner', 3], ['Object ID', 3]], owners.map(o => [o.name, o.objectId])) : text('No owners.'),
      reg?.ok && reg.data?.owners ? heading('App registration owners') : null,
      reg?.ok && reg.data?.owners ? (reg.data.owners.length ? table([['Owner', 3], ['User principal name', 3]], reg.data.owners.map(o => [o.displayName, o.userPrincipalName])) : text('No owners.')) : null,
    ], { status: owners.length ? 'ok' : 'empty', summary: `${owners.length} owner(s)` }));
    // Credentials
    const creds = of('Credential'), spCreds = [...(profile?.passwordCredentials || []).map(c => ['Secret', c]), ...(profile?.keyCredentials || []).map(c => ['Certificate', c])];
    sections.push(section('Credentials (secrets and certificates)', [
      heading('App registration'),
      creds.length ? table([['Name', 3], ['Status', 1.4], ['Expires', 1.6], ['Detail', 3]], creds.map(c => [c.name, c.status, c.expires, c.detail])) : text(e.appId ? 'No credentials on the app registration, or the registration is in another tenant.' : 'Managed identities have no app registration credentials.'),
      heading('Service principal'),
      spCreds.length ? table([['Type', 1], ['Name', 3], ['Starts', 1.6], ['Expires', 1.6]], spCreds.map(([t, c]) => [t, c.displayName || c.keyId, c.startDateTime, c.endDateTime])) : text('No credentials on the service principal.'),
    ], { status: creds.length || spCreds.length ? 'ok' : 'empty', summary: `${creds.length + spCreds.length}` }));
    // App roles and SSO
    const sso = x.sso;
    sections.push(sso?.ok ? section('Single sign-on and app roles', [
      kv([['SSO mode', sso.data.sso.mode], ['Reply URLs', sso.data.sso.replyUrls], ['Sign-on URL', sso.data.sso.loginUrl], ['Relay state', sso.data.sso.relayState]]),
      sso.data.rows.length ? table([['App role', 2], ['Value', 2], ['Allowed members', 2], ['State', 1]], sso.data.rows.map(r => [r.role, r.value, r.members, r.enabled])) : text('The app defines no app roles.'),
    ]) : unread('Single sign-on and app roles', sso));
    // App registration
    if (reg && !reg.ok) sections.push(unread('App registration', reg));
    else if (reg?.ok && !reg.data) sections.push(section('App registration', [text('No app registration for this app ID in this tenant. It is published by another organization (multi-tenant or Microsoft app), so its registration settings live in the publisher tenant.')], { status: 'empty' }));
    else if (reg?.ok) sections.push(section('App registration', [
      heading('Requested API permissions'),
      reg.data.permissions.length ? table([['API', 2], ['Permission', 2.5], ['Type', 1.2], ['Description', 4]], reg.data.permissions.map(p => [p.api, p.permission, p.type, p.description])) : text('No API permissions requested.'),
      heading('All properties'),
      kv(propertyRows(reg.data.app, ['passwordCredentials', 'keyCredentials'])),
    ]));
  }

  // Conditional Access
  const ca = of('Conditional Access'), caRank = { Applies: 0, Incomplete: 1 };
  sections.push(section('Conditional Access', [
    text('Microsoft What If evaluation of every enabled and report-only policy for this identity. Policies that depend on device, location, client app or risk are Incomplete, not excluded.', 'muted'),
    ca.length ? table([['Policy', 3], ['Result', 1.3], ['State', 1.3], ['Controls', 3], ['Why', 3]], [...ca].sort((a, b) => (caRank[a.result] ?? 2) - (caRank[b.result] ?? 2) || String(a.name).localeCompare(String(b.name))).map(p => [p.name, p.result || p.status, p.state, p.controls, p.assignment])) : text('No Conditional Access results (policies unreadable, or none exist).'),
  ], { status: ca.length ? 'ok' : 'empty', summary: `${ca.filter(p => p.result === 'Applies').length} apply` }));

  // Access packages
  if (isUser) {
    const ap = core.accessPackages;
    sections.push(ap ? section('Access packages (entitlement management)', [
      ap.packages.length ? table([['Access package', 2.5], ['Catalog', 1.6], ['Policy', 2.2], ['State', 1.1], ['Expires', 1.4], ['Resources it grants', 3.5]], ap.packages.map(p => [p.name, p.catalog, p.policy, [p.state, p.status].filter(Boolean).join(', '), p.expires || 'No expiry', (p.resources || []).map(r => `${r.name} (${r.role})`).join('; ')])) : text('No access package assignments.'),
      ap.requests?.length ? heading('Requests') : null,
      ap.requests?.length ? table([['Access package', 3], ['Type', 1.5], ['State', 1.5], ['Created', 1.5]], ap.requests.map(q => [q.name, q.type, [q.state, q.status].filter(Boolean).join(', '), q.created])) : null,
    ], { status: ap.packages.length ? 'ok' : 'empty', summary: `${ap.packages.length} assignment(s)` }) : section('Access packages (entitlement management)', [], { status: 'unavailable', reason: (core.unavailable || []).find(u => /entitlement|governance/i.test(u.source))?.reason || 'Not returned. See Coverage.' }));
    // Devices
    const devices = of('Device');
    sections.push(section('Devices', [
      devices.length ? table([['Device', 2], ['Status', 1.4], ['Relationship', 2], ['Join type', 1.2], ['Detail', 3]], devices.map(d => [d.name, d.status, d.relation || d.assignment, d.trustType, d.detail])) : text('No Intune or Entra devices tied to this user.'),
    ], { status: devices.length ? 'ok' : 'empty', summary: `${devices.length} device(s)` }));
    // On-premises AD
    sections.push(onPremSection(x.adGroups, hosting));
  }

  // Owned objects
  const owned = x.owned;
  sections.push(owned?.ok ? section('Objects this identity owns', [
    owned.data.length ? table([['Object', 3], ['Type', 2], ['Object ID', 3]], sortBy(owned.data, o => o.displayName).map(o => [o.displayName, String(o['@odata.type'] || '').replace('#microsoft.graph.', ''), o.id])) : text('Owns no directory objects.'),
  ], { status: owned.data.length ? 'ok' : 'empty', summary: `${owned.data.length}` }) : unread('Objects this identity owns', owned));

  // Activity
  const signIns = events.filter(ev => ev.source === 'signin'), changes = events.filter(ev => ev.source === 'audit'), other = events.filter(ev => !['signin', 'audit'].includes(ev.source));
  const signinSource = (core.sources || []).find(s => s.id === 'signin');
  const signinUnread = (core.unavailable || []).find(u => /sign-in/i.test(u.source));
  const [siRows, siMore] = capped(signIns, 'sign-ins');
  sections.push(section(`Sign-ins (${g.days} day${g.days === 1 ? '' : 's'})`, [
    text(signinSource?.note || 'Interactive sign-ins from Microsoft Graph.', 'muted'),
    siRows.length ? table([['Time', 1.5], ['App', 2.4], ['Result', 1], ['IP', 1.5], ['Conditional Access', 2.6], ['Reason', 3]], siRows.map(s => [s.time, s.target || s.title, s.result, s.ip, (s.evaluatedPolicies || []).filter(p => p.status === 'success' || p.status === 'failure').map(p => `${p.name}: ${p.status}`).join('; '), s.explanation])) : text(signinSource ? 'No sign-ins recorded in this window.' : 'Sign-ins were not collected.'),
    siMore,
  ], signinUnread && !signIns.length ? { status: 'unavailable', reason: signinUnread.reason } : { status: signIns.length ? 'ok' : 'empty', summary: `${signIns.length}` }));
  const [chRows, chMore] = capped(changes, 'directory changes');
  sections.push(section(`Directory changes (Entra audit, ${g.days} day${g.days === 1 ? '' : 's'})`, [
    chRows.length ? table([['Time', 1.5], ['Activity', 2.6], ['Role', 1.1], ['Initiated by', 2], ['Target', 2.4], ['Result', 1]], chRows.map(a => [a.time, a.title, a.direction, a.actor, a.target, a.result])) : text('No directory changes by or to this identity in this window.'),
    chMore,
  ], { status: changes.length ? 'ok' : 'empty', summary: `${changes.length}` }));
  const prov = x.provisioning;
  sections.push(prov?.ok ? section(`Provisioning (${g.days} day${g.days === 1 ? '' : 's'})`, [
    prov.data.rows.length ? table([['Time', 1.5], ['App', 2], ['Action', 1.4], ['Status', 1.2], ['Error', 3]], prov.data.rows.map(p => [p.time, p.app, p.action, p.status, p.error])) : text('No provisioning events in this window.'),
  ], { status: prov.data.rows.length ? 'ok' : 'empty', summary: `${prov.data.rows.length}` }) : unread(`Provisioning (${g.days} days)`, prov));
  const act = x.activity;
  if (act?.ok) {
    const [rows, more] = capped(act.data.events, 'Azure activity events');
    sections.push(section(`Azure activity log (${act.data.days} days)`, [
      text(`Management-plane operations this identity performed across ${act.data.subscriptions} subscription(s).`, 'muted'),
      rows.length ? table([['Time', 1.5], ['Operation', 3], ['Resource', 3], ['Result', 1]], rows.map(a => [a.time, a.title, a.target, a.result])) : text('No Azure operations by this identity in this window.'),
      more, act.data.notes?.length ? { type: 'list', items: act.data.notes } : null,
    ], { status: act.data.partial ? 'partial' : rows.length ? 'ok' : 'empty', reason: act.data.partial ? 'Some subscriptions could not be read; see the notes.' : undefined, summary: `${act.data.events.length}` }));
  } else sections.push(unread('Azure activity log', act));
  if (isUser) {
    const d = x.defender;
    if (d?.ok && d.data.unavailable?.length) sections.push(section('Defender process events', [], { status: 'unavailable', reason: d.data.unavailable.map(u => u.reason).join('; ') }));
    else if (d?.ok) {
      const [rows, more] = capped(d.data.events, 'process events');
      sections.push(section(`Defender process events (${d.data.days} day${d.data.days === 1 ? '' : 's'})`, [
        rows.length ? table([['Time', 1.5], ['Device', 1.6], ['Process', 1.6], ['Command line', 5]], rows.map(p => [p.time, p.device, p.title, p.command])) : text('No process events for this user in this window.'),
        more,
      ], { status: d.data.partial ? 'partial' : rows.length ? 'ok' : 'empty', reason: d.data.partialReasons?.map(p => p.reason).join('; ') || undefined, summary: `${d.data.events.length}` }));
    } else sections.push(unread('Defender process events', d));
  }
  if (other.length) {
    const [rows, more] = capped(other, 'workspace records');
    sections.push(section('Log Analytics workspace records', [table([['Time', 1.5], ['Category', 1.2], ['Event', 3], ['Target', 2.5], ['Result', 1]], rows.map(o => [o.time, o.category, o.title, o.target, o.result])), more], { summary: `${other.length}` }));
  }

  sections.push(findingsSection(x.findings, [e.id, e.appId, isUser ? e.subtitle : null], isUser ? 'user' : 'app'));
  sections.push(coverageSection(core.sources || [], core.notes || [], core.partialReasons || [], core.unavailable || []));
  return frame({ title: e.name, subtitle: `${TYPE_LABEL[type]} · ${isUser ? e.subtitle : `App ID ${e.appId || 'none'}`}`, entityId: e.id, range: g.range, generated: g.generated, viewer, hosting, tenant: e.tenant, sections });
}

function onPremSection(r, hosting) {
  const title = 'On-premises Active Directory';
  if (!r) return section(title, [], { status: 'unavailable', reason: 'Not read.' });
  if (!r.ok) return unread(title, r);
  const { user, ad = {}, rows = [], notes = [], cloudGroups } = r.data;
  const live = ad.status === 'live';
  const blocks = [
    kv([['Synced from AD', user?.synced], ['SAM account name', user?.sam], ['Distinguished name', user?.dn], ['On-premises SID', user?.sid], ['Live AD read', live ? `Yes, from ${[ad.server, ad.forest].filter(Boolean).join(' in forest ') || 'a domain controller'}` : 'No'], ['Cloud-only groups (not from AD)', cloudGroups]]),
    !live && user?.synced && ad.message ? callout(`${ad.message}${hosting === 'cloud' ? ' This copy of Entity 360 is cloud hosted and cannot reach a domain controller; run the report from the local copy for live AD data.' : ''}`) : null,
    rows.length ? table([['Group', 2.5], ['SAM name', 2], ['Type', 1.5], ['Membership', 1], ['Via', 2.5], ['In Entra', 1]], rows.map(g => [g.name, g.sam, g.type, g.membership, g.via, g.inEntra || 'Synced'])) : text(user?.synced ? 'No AD groups returned.' : 'Cloud-only user: on-premises AD has no record of them.'),
    notes.length ? { type: 'list', items: notes } : null,
  ];
  return section(title, blocks, { status: !user?.synced ? 'empty' : live ? 'ok' : 'partial', reason: user?.synced && !live ? 'Only groups that sync to Entra are listed; the live domain controller read did not run.' : undefined, summary: user?.synced ? `${rows.length} group(s)${live ? '' : ', synced only'}` : 'Cloud-only user' });
}

function deviceDocument(g, { viewer, hosting }) {
  const { details: r, extra: x } = g, d = r.device;
  const gb = n => n == null ? null : `${(n / 1073741824).toFixed(1)} GB`;
  const sections = [];
  sections.push(section('Device overview', [kv([['Name', d.name], ['Operating system', [d.operatingSystem, d.osVersion].filter(Boolean).join(' ')], ['Manufacturer', d.manufacturer], ['Model', d.model], ['Serial number', d.serialNumber], ['Ownership', d.ownership], ['Join type', d.joinType], ['Compliance', d.compliance], ['Encrypted', d.encrypted], ['Managed', d.managed], ['Enabled in Entra', d.enabled], ['Enrollment type', d.enrollmentType], ['Management agent', d.managementAgent], ['Enrolled', d.enrolled], ['Registered in Entra', d.registered], ['Last Intune sync', d.lastSync], ['Last Entra sign-in', d.lastSignIn], ['Storage', d.storage ? `${gb(d.storage.free)} free of ${gb(d.storage.total)}` : null], ['Entra object ID', d.entraId], ['Entra device ID', d.deviceId], ['Intune device ID', d.intuneId], ['Open in Entra', d.entraLink], ['Open in Intune', d.intuneLink]])]));
  sections.push(section('People on this device', [r.people.length ? table([['Name', 2], ['User principal name', 3], ['Relationship', 3], ['Enabled', 0.8], ['Last logon', 1.5]], r.people.map(p => [p.name, p.upn, p.relations, p.enabled, p.lastLogOn])) : text('No people tied to this device.')], { status: r.people.length ? 'ok' : 'empty', summary: `${r.people.length}` }));
  const gr = x.groups;
  sections.push(gr.ok ? section('Group memberships', [gr.data.length ? table([['Group', 3], ['Dynamic rule', 4], ['Synced from AD', 1]], sortBy(gr.data, g2 => g2.displayName).map(g2 => [g2.displayName, g2.membershipRule, g2.onPremisesSyncEnabled === true])) : text('Not a member of any group.')], { status: gr.data.length ? 'ok' : 'empty', summary: `${gr.data.length} group(s)` }) : unread('Group memberships', gr));
  const st = x.states;
  sections.push(st.ok ? section('Intune compliance and configuration', [st.data.states.length ? table([['Policy or profile', 4], ['Kind', 1.4], ['State', 1.4], ['Settings', 1]], st.data.states.map(s => [s.name, s.kind, s.state, s.settingCount])) : text('No policy states reported.')], { status: st.data.partial ? 'partial' : st.data.states.length ? 'ok' : 'empty', summary: `${st.data.states.length}` }) : unread('Intune compliance and configuration', st));
  sections.push(x.entraRaw.ok ? section('Entra device (all properties)', [kv(propertyRows(x.entraRaw.data))]) : unread('Entra device (all properties)', x.entraRaw));
  sections.push(x.intuneRaw.ok ? section('Intune managed device (all properties)', [kv(propertyRows(x.intuneRaw.data))]) : unread('Intune managed device (all properties)', x.intuneRaw));
  sections.push(findingsSection(x.findings, [d.entraId, d.intuneId, d.deviceId], 'device'));
  sections.push(coverageSection([], r.notes || [], r.partialReasons || [], r.unavailable || []));
  return frame({ title: d.name, subtitle: `Device · ${[d.operatingSystem, d.joinType].filter(Boolean).join(' · ')}`, entityId: d.entraId || d.intuneId, generated: g.generated, viewer, hosting, tenant: r.tenant, sections });
}

function frame({ title, subtitle, entityId, range, generated, viewer, hosting, tenant, sections }) {
  const read = sections.filter(s => s.status !== 'unavailable').length;
  return {
    title, subtitle, eyebrow: 'ENTITY 360 · SINGLE-ENTITY REPORT',
    meta: [['Object ID', entityId], ['Tenant', tenant], ['Generated', generated], ['Generated by', viewer || 'Not recorded'], range ? ['Activity window', `${display(range.from)} to ${display(range.to)}`] : null, ['Running from', hosting === 'cloud' ? 'Cloud-hosted copy (no on-premises AD access)' : 'Local copy'], ['Sections read', `${read} of ${sections.length}`]].filter(Boolean),
    intro: 'Everything Entity 360 could read about this entity with your sign-in at the time shown. Sections marked NOT READ say why (a missing role, scope or connection). An empty table means the source answered with nothing. Handle this report as confidential directory data.',
    sections,
    footer: `Entity 360 · ${title} · generated ${display(generated)}`,
  };
}

export const reportFileName = (name, generated) => `entity-360-${String(name || 'entity').normalize('NFKD').replace(/[^\w.-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 60) || 'entity'}-${String(generated).slice(0, 10)}.pdf`;

// Demo mode: the fictional report the pages show, with every extra source marked as not available in demo mode.
const DEMO_KEYS = ['profile', 'signInActivity', 'manager', 'directReports', 'licenses', 'registration', 'owned', 'pim', 'adminUnits', 'adGroups', 'pimRequests', 'provisioning', 'sso', 'assignedTo', 'grantsToApi', 'appRegistration', 'activity', 'defender', 'findings'];
export function demoGather(report, range, now = Date.now()) {
  const extra = Object.fromEntries(DEMO_KEYS.map(k => [k, skipped('Demo mode has no data for this source. Connect a live tenant to read it.')]));
  return { kind: 'identity', type: report.entity.type, core: report, extra, range, days: daysOf(range), generated: new Date(now).toISOString() };
}
export function demoDeviceGather(details, now = Date.now()) {
  const s = skipped('Demo mode has no data for this source. Connect a live tenant to read it.');
  return { kind: 'device', type: 'device', details, extra: { states: s, groups: s, entraRaw: s, intuneRaw: s, findings: s }, generated: new Date(now).toISOString() };
}
