// Coverage bucket 3: new tables on existing pages. Delegated Graph and ARM reads only, loaded when a tab is opened.
import { GUID, fail, odata, describeError, queryUrl } from './model.mjs';
import { evaluateConditionalAccess, whatIfConditions, caControls } from './access.mjs';

export const B3_TABLES = ['adminUnits', 'pimRequests', 'entraAudit', 'provisioning', 'appSso', 'diagnostics'];
// Rows of bucket 3 that stay deferred until their scope is consented. Shown in the UI so nothing silently disappears.
export const B3_DEFERRED = [
  ['Terms of use accepted', 'AgreementAcceptance.Read'],
  ['Authentication methods for any user', 'UserAuthenticationMethod.Read.All'],
  ['Risky user and detections', 'IdentityRiskyUser.Read.All, IdentityRiskEvent.Read.All'],
  ['Risky workload identity', 'IdentityRiskyServicePrincipal.Read.All'],
  ['Access review decisions', 'AccessReview.Read.All'],
];
const MEMBERSHIP = { Dynamic: 'Dynamic', Assigned: 'Assigned' };
const PROV_STATUS = { success: 'Success', failure: 'Failed', skipped: 'Skipped', warning: 'Warning' };

// Administrative units the identity belongs to, with the roles scoped to each one.
export async function adminUnits(api, id, type) {
  const coll = type === 'user' ? 'users' : 'servicePrincipals';
  const aus = await api.pages(`/v1.0/${coll}/${id}/memberOf/microsoft.graph.administrativeUnit?$select=id,displayName,membershipType,visibility,isMemberManagementRestricted`);
  const rows = [], notes = [];
  for (const au of aus.rows) {
    let roles = 'Not returned';
    try {
      const sr = await api.pages(`/v1.0/directory/administrativeUnits/${au.id}/scopedRoleMembers`);
      roles = sr.rows.map(r => `${r.roleMemberInfo?.displayName || r.roleMemberInfo?.id || 'Unknown'} (role ${r.roleId})`).join('; ') || 'None';
    } catch (e) { notes.push(`Scoped roles for ${au.displayName}: ${describeError(e)}`); }
    rows.push({ id: au.id, name: au.displayName || au.id, membership: MEMBERSHIP[au.membershipType] || 'Assigned', restricted: au.isMemberManagementRestricted ? 'Restricted management' : 'Standard', roles, link: `https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AdministrativeUnitMenuBlade/~/Overview/objectId/${au.id}` });
  }
  return { rows, notes };
}

// PIM requests for directory roles made by or for this principal. Approver is not returned by this API.
export async function pimRequests(api, id) {
  const r = await api.pages(queryUrl('/v1.0/roleManagement/directory/roleAssignmentScheduleRequests', { '$filter': `principalId eq '${odata(id)}'`, '$expand': 'roleDefinition' }));
  const rows = r.rows.map(x => ({ id: x.id, role: x.roleDefinition?.displayName || x.roleDefinitionId, action: x.action, status: x.status, approver: x.approvalId ? 'Approval required (approver not returned)' : 'No approval', justification: x.justification || '', created: x.createdDateTime || null, scope: x.directoryScopeId || '/' }));
  rows.sort((a, b) => String(b.created).localeCompare(String(a.created)));
  return { rows, notes: [] };
}

// Entra directory audit for this identity as actor or target, newest first. RoleManagement covers PIM.
export async function entraAudit(api, id, type, appId, { days = 7, now = Date.now() } = {}) {
  const since = new Date(now - days * 86400000).toISOString();
  const actor = type === 'user' ? `initiatedBy/user/id eq '${odata(id)}'` : `initiatedBy/app/appId eq '${odata(appId || '')}'`;
  const filters = [actor, `targetResources/any(t:t/id eq '${odata(id)}')`];
  const seen = new Map(), notes = [];
  let lastError = null;
  for (const [i, f] of filters.entries()) {
    try {
      const r = await api.pages(queryUrl('/v1.0/auditLogs/directoryAudits', { '$filter': `activityDateTime ge ${since} and ${f}`, '$top': '100' }));
      for (const a of r.rows) {
        const prev = seen.get(a.id);
        if (prev) { prev.role = 'Actor & Target'; continue; }
        seen.set(a.id, { id: a.id, time: a.activityDateTime, activity: a.activityDisplayName, category: a.category, pim: a.category === 'RoleManagement' || /PIM|privileged/i.test(a.loggedByService || ''), initiator: a.initiatedBy?.user?.userPrincipalName || a.initiatedBy?.user?.displayName || a.initiatedBy?.app?.displayName || 'Unknown', target: (a.targetResources || []).map(t => t.displayName || t.userPrincipalName || t.id).join(', '), result: a.result === 'success' ? 'Success' : a.result === 'failure' ? 'Failed' : 'Observed', role: i === 0 ? 'Actor' : 'Target' });
      }
    } catch (e) { lastError = e; notes.push(`${i === 0 ? 'As actor' : 'As target'}: ${describeError(e)}`); }
  }
  if (notes.length === filters.length) throw lastError;
  return { rows: [...seen.values()].sort((a, b) => String(b.time).localeCompare(String(a.time))), notes, days };
}

// Provisioning logs: for a user, events about that user; for an app, events of its provisioning job.
export async function provisioning(api, id, type, { days = 7, now = Date.now() } = {}) {
  const since = new Date(now - days * 86400000).toISOString();
  const who = type === 'user' ? `(sourceIdentity/id eq '${odata(id)}' or targetIdentity/id eq '${odata(id)}')` : `servicePrincipal/id eq '${odata(id)}'`;
  const r = await api.pages(queryUrl('/v1.0/auditLogs/provisioning', { '$filter': `activityDateTime ge ${since} and ${who}`, '$top': '100' }));
  return { rows: r.rows.map(p => ({ id: p.id, time: p.activityDateTime, app: p.servicePrincipal?.displayName || 'Unknown', action: p.provisioningAction || p.action || 'Not returned', status: PROV_STATUS[p.provisioningStatusInfo?.status] || p.provisioningStatusInfo?.status || 'Not returned', error: p.provisioningStatusInfo?.errorInformation?.reason || p.provisioningStatusInfo?.errorInformation?.errorCode || '', target: p.targetIdentity?.displayName || p.targetIdentity?.id || '' })), notes: [], days };
}

// App roles defined by the app, SSO mode and reply URLs (service principal plus its app registration when readable).
export async function appSso(api, id) {
  const sp = await api.request(`/v1.0/servicePrincipals/${id}?$select=id,appId,displayName,appRoles,preferredSingleSignOnMode,replyUrls,loginUrl,samlSingleSignOnSettings,servicePrincipalType`);
  const mode = { saml: 'SAML', oidc: 'OIDC', password: 'Password-based', notSupported: 'Not supported' }[sp.preferredSingleSignOnMode] || (sp.preferredSingleSignOnMode ? sp.preferredSingleSignOnMode : 'OIDC/OAuth (no preferred mode set)');
  const rows = (sp.appRoles || []).map(r => ({ id: r.id, role: r.displayName || r.value || r.id, value: r.value || '', members: (r.allowedMemberTypes || []).join(', '), enabled: r.isEnabled === false ? 'Disabled' : 'Enabled' }));
  return { rows, sso: { mode, replyUrls: sp.replyUrls || [], loginUrl: sp.loginUrl || '', relayState: sp.samlSingleSignOnSettings?.relayState || '' }, notes: [] };
}

// Entra (microsoft.aadiam) diagnostic settings via ARM with the user's Azure token. Needs Reader on the tenant-level aadiam provider.
export async function diagnostics(api) {
  const r = await api.request('/providers/microsoft.aadiam/diagnosticSettings?api-version=2017-04-01-preview', { origin: 'https://management.azure.com' });
  return { rows: (r.value || []).map(d => { const p = d.properties || {}; const dest = [p.workspaceId && `Log Analytics: ${p.workspaceId.split('/').pop()}`, p.storageAccountId && `Storage: ${p.storageAccountId.split('/').pop()}`, p.eventHubAuthorizationRuleId && `Event Hub: ${p.eventHubName || p.eventHubAuthorizationRuleId.split('/').slice(-3, -2)[0]}`].filter(Boolean); return { id: d.id, name: d.name, destinations: dest.join('; ') || 'None', categories: (p.logs || []).filter(l => l.enabled).map(l => l.category).join(', ') || 'None enabled' }; }), notes: [] };
}

export async function tabTable(api, table, { id, type = 'user', appId = '', days = 7, now } = {}) {
  if (!B3_TABLES.includes(table)) throw fail('Unknown table.');
  if (table !== 'diagnostics' && !GUID.test(String(id))) throw fail('Invalid entity identifier.');
  if (!['user', 'application', 'managedIdentity'].includes(type)) throw fail('Invalid entity type.');
  if (table === 'adminUnits') return adminUnits(api, id, type);
  if (table === 'pimRequests') return pimRequests(api, id);
  if (table === 'entraAudit') return entraAudit(api, id, type, appId, { days, now });
  if (table === 'provisioning') return provisioning(api, id, type, { days, now });
  if (table === 'appSso') { if (type === 'user') throw fail('App roles and SSO apply to applications only.'); return appSso(api, id); }
  return diagnostics(api);
}

// CA What If with user-supplied inputs; returns the policies that apply plus those still incomplete.
export async function whatIf(api, { id, type = 'user', input = {} } = {}) {
  const conditions = whatIfConditions(input);
  const listed = await api.pages('/v1.0/identity/conditionalAccess/policies').catch(() => null);
  const { rows, apps } = await evaluateConditionalAccess(api, { id, type: type === 'user' ? 'user' : 'servicePrincipal', policies: listed?.rows || null, conditions });
  return { conditions, apps: apps.map(a => a.name), rows: rows.map(p => ({ id: p.id, name: p.name, result: p.result, state: p.state, controls: caControls(p.evidence), missing: p.missing })) };
}
