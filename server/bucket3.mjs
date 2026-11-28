// Coverage bucket 3: new tables on existing pages. Delegated Graph and ARM reads only, loaded when a tab is opened.
import { GUID, fail, odata, describeError, queryUrl } from './model.mjs';
import { evaluateConditionalAccess, whatIfConditions, caControls } from './access.mjs';
import { forestGroups, mergeAdRows } from './ad-forest.mjs';

export const B3_TABLES = ['adminUnits', 'adGroups', 'pimRequests', 'entraAudit', 'provisioning', 'appSso', 'diagnostics'];
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

// On-premises Active Directory groups this user is in, direct and nested, as synced to Entra (GroupMember.Read.All,
// User.Read.All). Only groups in sync scope reach Entra: AD built-in groups (Domain Users, Domain Admins) never sync,
// and the primary group is not a memberOf link in AD either. "Through" walks group-in-group links back to a direct group.
export const AD_NESTED_LIMIT = 50;
const AD_GROUP_SELECT = 'id,displayName,description,securityEnabled,mailEnabled,onPremisesSyncEnabled,onPremisesSamAccountName,onPremisesNetBiosName,onPremisesDomainName,onPremisesSecurityIdentifier';
const groupLink = id => `https://entra.microsoft.com/#view/Microsoft_AAD_IAM/GroupDetailsMenuBlade/~/Overview/groupId/${id}`;
export async function adGroups(api, id, type, { ad = {} } = {}) {
  if (type !== 'user') return { rows: [], notes: ['Active Directory groups apply to users. Service principals are cloud-only.'], user: null };
  const u = await api.request(`/v1.0/users/${id}?$select=id,displayName,onPremisesSyncEnabled,onPremisesSamAccountName,onPremisesDomainName,onPremisesDistinguishedName,onPremisesSecurityIdentifier`);
  const user = { synced: u.onPremisesSyncEnabled === true, sam: u.onPremisesSamAccountName ? `${(u.onPremisesDomainName || '').split('.')[0].toUpperCase()}${u.onPremisesDomainName ? '\\' : ''}${u.onPremisesSamAccountName}` : '', dn: u.onPremisesDistinguishedName || '', sid: u.onPremisesSecurityIdentifier || '' };
  const all = (await api.pages(`/v1.0/users/${id}/transitiveMemberOf/microsoft.graph.group?$select=${AD_GROUP_SELECT}`)).rows;
  const direct = new Set((await api.pages(`/v1.0/users/${id}/memberOf/microsoft.graph.group?$select=id`)).rows.map(g => g.id));
  const mine = new Map(all.map(g => [g.id, g]));
  const onprem = all.filter(g => g.onPremisesSyncEnabled === true);
  const notes = [];
  // For each nested group, which of the user's own groups are its direct members. One read per nested group.
  const parents = new Map();
  const nested = onprem.filter(g => !direct.has(g.id));
  for (const g of nested.slice(0, AD_NESTED_LIMIT)) {
    try { parents.set(g.id, (await api.pages(`/v1.0/groups/${g.id}/members/microsoft.graph.group?$select=id`)).rows.map(m => m.id).filter(m => mine.has(m))); }
    catch (e) { notes.push(`Members of ${g.displayName}: ${describeError(e)}`); }
  }
  if (nested.length > AD_NESTED_LIMIT) notes.push(`The nesting path is shown for the first ${AD_NESTED_LIMIT} of ${nested.length} nested groups.`);
  // Shortest chain from a direct group down to g, as names: "SEC-Finance" or "SEC-A > SEC-B".
  const chain = (g, seen = new Set()) => {
    if (direct.has(g)) return [];
    if (seen.has(g)) return null;
    seen.add(g);
    let best = null;
    for (const p of parents.get(g) || []) {
      const c = direct.has(p) ? [] : parents.has(p) ? chain(p, seen) : null;
      if (c && (!best || c.length + 1 < best.length)) best = [...c, p];
    }
    return best;
  };
  const kind = g => [g.securityEnabled && 'Security', g.mailEnabled && (g.securityEnabled ? 'mail-enabled' : 'Distribution')].filter(Boolean).join(', ') || 'Not returned';
  const rows = onprem.map(g => {
    const isDirect = direct.has(g.id), c = isDirect ? [] : chain(g.id);
    return { id: g.id, name: g.displayName || g.onPremisesSamAccountName || g.id, sam: g.onPremisesSamAccountName ? `${g.onPremisesNetBiosName ? `${g.onPremisesNetBiosName}\\` : ''}${g.onPremisesSamAccountName}` : '', sid: g.onPremisesSecurityIdentifier || '', type: kind(g),
      membership: isDirect ? 'Direct' : 'Nested', via: isDirect ? '' : c ? c.map(x => mine.get(x)?.displayName || x).join(' > ') : 'Not returned', link: groupLink(g.id) };
  }).sort((a, b) => (a.membership === b.membership ? 0 : a.membership === 'Direct' ? -1 : 1) || a.name.localeCompare(b.name));
  if (!user.synced) {
    notes.push('This user is cloud-only (not synced from on-premises AD), so on-premises AD has no record of them.');
    return { rows, notes, user, cloudGroups: all.length - onprem.length, ad: { status: 'skipped' } };
  }
  // Live read from a domain controller: every security group in the forest, synced or not.
  const live = await forestGroups(user.sid, ad);
  const adStatus = { status: live.status, server: live.server || '', forest: live.forest || '', message: live.message || '', domains: live.domains || [] };
  if (live.status === 'live') {
    if (live.user?.dn) user.dn = live.user.dn;
    if (live.user?.sam) user.sam = live.user.sam;
    const merged = mergeAdRows(rows, live);
    return { rows: merged, notes: [...notes, ...live.notes], user, cloudGroups: all.length - onprem.length, ad: adStatus, source: 'ad' };
  }
  if (live.status !== 'cloud') notes.push('Only groups that sync to Entra are listed. AD built-in groups such as Domain Users and Domain Admins never sync, so Microsoft Graph cannot see them.');
  return { rows, notes, user, cloudGroups: all.length - onprem.length, ad: adStatus, source: 'graph' };
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

export async function tabTable(api, table, { id, type = 'user', appId = '', days = 7, now, ad } = {}) {
  if (!B3_TABLES.includes(table)) throw fail('Unknown table.');
  if (table !== 'diagnostics' && !GUID.test(String(id))) throw fail('Invalid entity identifier.');
  if (!['user', 'application', 'managedIdentity'].includes(type)) throw fail('Invalid entity type.');
  if (table === 'adminUnits') return adminUnits(api, id, type);
  if (table === 'adGroups') return adGroups(api, id, type, { ad });
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
