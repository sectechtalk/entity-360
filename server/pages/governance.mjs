// GOVERNANCE section: Entitlements, PIM (Entra roles), PIM Azure.
import { part, yesNo, day } from '../bucket5.mjs';
const E = 'https://entra.microsoft.com/#view/';
const ARM = { origin: 'https://management.azure.com' };
const EM = '/v1.0/identityGovernance/entitlementManagement';

async function entitlements(api, { notes }) {
  const cats = (await api.pages(`${EM}/catalogs?$select=id,displayName,catalogType,state,isExternallyVisible,createdDateTime`)).rows;
  const pkgs = await part(notes, 'Access packages', () => api.pages(`${EM}/accessPackages?$expand=catalog($select=id)&$select=id,displayName,isHidden,createdDateTime`).then(r => r.rows)) || [];
  const orgs = await part(notes, 'Connected organizations', () => api.pages(`${EM}/connectedOrganizations`).then(r => r.rows));
  const set = await part(notes, 'External user lifecycle', () => api.request(`${EM}/settings`));
  return [
    { title: 'Catalogs', link: `${E}Microsoft_AAD_ERM/DashboardBlade/~/elmCatalog`, columns: ['Catalog', 'Type', 'State', 'External users can request', 'Access packages', 'Created'],
      rows: cats.map(c => [c.displayName, c.catalogType === 'userManaged' ? 'User managed' : 'Built-in', c.state, yesNo(c.isExternallyVisible), String(pkgs.filter(p => p.catalog?.id === c.id).length), day(c.createdDateTime)]) },
    { title: 'Access packages', columns: ['Package', 'Catalog', 'Hidden', 'Created'], rows: pkgs.map(p => [p.displayName, cats.find(c => c.id === p.catalog?.id)?.displayName || '', yesNo(p.isHidden), day(p.createdDateTime)]) },
    orgs && { title: 'Connected organizations', columns: ['Organization', 'State', 'Identity sources', 'Created'], rows: orgs.map(o => [o.displayName, o.state, (o.identitySources || []).map(s => s.domainName || s.tenantId || s.displayName).join(', '), day(o.createdDateTime)]) },
    set && { title: 'External user lifecycle', columns: ['Setting', 'Value'], rows: [['When an external user loses their last assignment', set.externalUserLifecycleAction || 'Not returned'], ['Days before blocked users are removed', String(set.durationUntilExternalUserDeletedAfterBlocked || 'Not returned')]] },
  ];
}

const rule = (rules, id) => (rules || []).find(r => r.id === id) || {};
async function pim(api, { notes }) {
  const defs = Object.fromEntries((await api.pages('/v1.0/roleManagement/directory/roleDefinitions?$select=id,displayName')).rows.map(d => [d.id, d.displayName]));
  const used = new Set();
  await part(notes, 'Eligible and active assignments', async () => {
    for (const p of ['roleEligibilitySchedules', 'roleAssignments']) for (const a of (await api.pages(`/v1.0/roleManagement/directory/${p}?$select=roleDefinitionId`)).rows) used.add(a.roleDefinitionId);
  });
  const asg = await part(notes, 'Role settings', () => api.pages("/v1.0/policies/roleManagementPolicyAssignments?$filter=scopeId eq '/' and scopeType eq 'DirectoryRole'&$expand=policy($expand=rules)").then(r => r.rows));
  const audit = await part(notes, 'PIM audit', () => api.request("/v1.0/auditLogs/directoryAudits?$filter=loggedByService eq 'PIM'&$top=50").then(r => r.value || []));
  notes.push('PIM alerts need RoleManagementAlert.Read.Directory, which is not consented.');
  const settings = (asg || []).filter(a => used.has(a.roleDefinitionId)).map(a => {
    const r = a.policy?.rules || [];
    const en = rule(r, 'Enablement_EndUser_Assignment').enabledRules || [];
    return [defs[a.roleDefinitionId] || a.roleDefinitionId, rule(r, 'Expiration_EndUser_Assignment').maximumDuration || '', en.includes('MultiFactorAuthentication') ? 'Yes' : 'No', en.includes('Justification') ? 'Yes' : 'No', en.includes('Ticketing') ? 'Yes' : 'No', yesNo(rule(r, 'Approval_EndUser_Assignment').setting?.isApprovalRequired), yesNo(rule(r, 'Expiration_Admin_Eligibility').isExpirationRequired)];
  });
  return [
    asg && { title: 'Role settings for roles in use', note: 'Activation rules for every role with an eligible or active assignment.', link: `${E}Microsoft_Azure_PIMCommon/ResourceMenuBlade/~/roles/resourceId//resourceType/tenant/provider/aadroles`, columns: ['Role', 'Max activation', 'MFA', 'Justification', 'Ticket', 'Approval', 'Eligibility expires'], rows: settings },
    audit && { title: 'Recent PIM activity', columns: ['When', 'Activity', 'By', 'Target', 'Result'], rows: audit.map(a => [day(a.activityDateTime) + ' ' + String(a.activityDateTime || '').slice(11, 16) + ' UTC', a.activityDisplayName, a.initiatedBy?.user?.userPrincipalName || a.initiatedBy?.app?.displayName || '', (a.targetResources || []).map(t => t.displayName).filter(Boolean).join(', '), a.result]) },
  ];
}

async function pimAzure(api, { notes }) {
  const subs = ((await api.request('/subscriptions?api-version=2022-12-01', ARM)).value || []).slice(0, 10);
  const rows = [];
  for (const s of subs) for (const [kind, path] of [['Eligible', 'roleEligibilityScheduleInstances'], ['Active', 'roleAssignmentScheduleInstances']]) {
    const got = await part(notes, `${s.displayName} ${kind.toLowerCase()} roles`, () => api.request(`/subscriptions/${s.subscriptionId}/providers/Microsoft.Authorization/${path}?api-version=2020-10-01&$filter=atScope()`, ARM).then(r => r.value || []));
    for (const i of got || []) { const p = i.properties || {}, x = p.expandedProperties || {};
      rows.push([x.principal?.displayName || p.principalId, x.principal?.type || p.principalType || '', x.roleDefinition?.displayName || '', x.scope?.displayName || p.scope, kind, p.assignmentType || (kind === 'Eligible' ? 'Eligible' : ''), p.endDateTime ? day(p.endDateTime) : 'Permanent']); }
  }
  return [{ title: 'Azure resource role assignments', note: `${subs.length} subscriptions checked.`, link: `${E}Microsoft_Azure_PIMCommon/CommonMenuBlade/~/azurerbac`, columns: ['Principal', 'Type', 'Role', 'Scope', 'State', 'Assignment', 'Ends'], rows: rows.sort((a, b) => a[4].localeCompare(b[4])) }];
}

export const GOVERNANCE_PAGES = {
  'g-entitlements': { section: 'GOVERNANCE', title: 'Entitlements', load: entitlements },
  'g-pim': { section: 'GOVERNANCE', title: 'PIM', load: pim },
  'g-pim-azure': { section: 'GOVERNANCE', title: 'PIM Azure', azure: true, load: pimAzure },
};
