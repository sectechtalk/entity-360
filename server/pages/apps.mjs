// APPS section: Enterprise apps, App registrations, Consent settings.
import { part, yesNo, day } from '../bucket5.mjs';
const E = 'https://entra.microsoft.com/#view/';
const GRAPH_APP = '00000003-0000-0000-c000-000000000000';

async function enterprise(api, { notes }) {
  const sps = (await api.pages("/v1.0/servicePrincipals?$filter=tags/any(t:t eq 'WindowsAzureActiveDirectoryIntegratedApp')&$count=true&$top=999&$select=id,appId,displayName,accountEnabled,appRoleAssignmentRequired,tags,preferredSingleSignOnMode,appOwnerOrganizationId,createdDateTime&$expand=owners($select=displayName,userPrincipalName)")).rows;
  const auth = await part(notes, 'Tenant app settings', () => api.request('/v1.0/policies/authorizationPolicy'));
  const org = await part(notes, 'Tenant ID', () => api.request('/v1.0/organization?$select=id').then(r => r.value?.[0]?.id));
  return [
    auth && { title: 'Tenant app settings', columns: ['Setting', 'Value'], rows: [['Users can register applications', yesNo(auth.defaultUserRolePermissions?.allowedToCreateApps)], ['User consent policy', (auth.defaultUserRolePermissions?.permissionGrantPoliciesAssigned || []).join(', ') || 'Users cannot consent']] },
    { title: 'Enterprise applications', note: `${sps.length} apps. Apps with no assignment requirement are open to every user in the tenant.`, link: `${E}Microsoft_AAD_IAM/StartboardApplicationsMenuBlade/~/AppAppsPreview`, columns: ['App', 'Publisher', 'Enabled', 'Assignment required', 'Visible to users', 'SSO', 'Owners'],
      rows: sps.sort((a, b) => (a.appRoleAssignmentRequired === true) - (b.appRoleAssignmentRequired === true)).map(s => [{ text: s.displayName, link: `${E}Microsoft_AAD_IAM/ManagedAppMenuBlade/~/Overview/objectId/${s.id}/appId/${s.appId}` }, org && s.appOwnerOrganizationId === org ? 'This tenant' : 'External', yesNo(s.accountEnabled), yesNo(s.appRoleAssignmentRequired), (s.tags || []).includes('HideApp') ? 'No' : 'Yes', s.preferredSingleSignOnMode || 'None', (s.owners || []).map(o => o.userPrincipalName || o.displayName).join(', ') || 'None']) },
  ];
}

async function registrations(api, { notes }) {
  const apps = (await api.pages('/v1.0/applications?$top=999&$select=id,appId,displayName,signInAudience,createdDateTime,passwordCredentials,keyCredentials,requiredResourceAccess')).rows;
  const now = Date.now(), soon = now + 30 * 864e5;
  const creds = apps.flatMap(a => [...(a.passwordCredentials || []).map(c => [a, 'Secret', c]), ...(a.keyCredentials || []).map(c => [a, 'Certificate', c])]);
  const state = t => { const e = Date.parse(t); return e < now ? 'Expired' : e < soon ? 'Expires in 30 days' : 'Valid'; };
  const scopes = a => (a.requiredResourceAccess || []).reduce((n, r) => n + (r.resourceAccess || []).length, 0);
  return [
    { title: 'Summary', columns: ['Measure', 'Count'], rows: [['App registrations', String(apps.length)], ['Apps with no credential', String(apps.filter(a => !a.passwordCredentials?.length && !a.keyCredentials?.length).length)], ['Expired credentials', String(creds.filter(([, , c]) => state(c.endDateTime) === 'Expired').length)], ['Expiring in 30 days', String(creds.filter(([, , c]) => state(c.endDateTime) === 'Expires in 30 days').length)]] },
    { title: 'Credentials', note: 'Soonest expiry first.', link: `${E}Microsoft_AAD_RegisteredApps/ApplicationsListBlade`, columns: ['App', 'Type', 'Name', 'Expires', 'State'],
      rows: creds.sort((x, y) => Date.parse(x[2].endDateTime) - Date.parse(y[2].endDateTime)).map(([a, t, c]) => [{ text: a.displayName, link: `${E}Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/${a.appId}` }, t, c.displayName || '', day(c.endDateTime), state(c.endDateTime)]) },
    { title: 'API permissions requested', columns: ['App', 'Audience', 'Permissions', 'Microsoft Graph', 'Created'], rows: apps.map(a => [a.displayName, a.signInAudience || '', String(scopes(a)), yesNo((a.requiredResourceAccess || []).some(r => r.resourceAppId === GRAPH_APP)), day(a.createdDateTime)]) },
  ];
}

async function consent(api, { notes }) {
  const req = await part(notes, 'Admin consent workflow', () => api.request('/v1.0/policies/adminConsentRequestPolicy'));
  const auth = await part(notes, 'User consent settings', () => api.request('/v1.0/policies/authorizationPolicy'));
  const pols = await part(notes, 'Permission grant policies', () => api.pages('/v1.0/policies/permissionGrantPolicies?$select=id,displayName,description').then(r => r.rows));
  notes.push('Pending admin consent requests need ConsentRequest.Read.All, which is not consented. Settings below come from Policy.Read.All.');
  return [
    auth && { title: 'User consent', link: `${E}Microsoft_AAD_IAM/ConsentPoliciesMenuBlade/~/UserSettings`, columns: ['Setting', 'Value'], rows: [['Policies assigned to users', (auth.defaultUserRolePermissions?.permissionGrantPoliciesAssigned || []).join(', ') || 'Users cannot consent']] },
    req && { title: 'Admin consent workflow', link: `${E}Microsoft_AAD_IAM/ConsentPoliciesMenuBlade/~/AdminConsentSettings`, columns: ['Setting', 'Value'], rows: [['Users can request admin consent', yesNo(req.isEnabled)], ['Reviewers', String((req.reviewers || []).length)], ['Email reviewers', yesNo(req.notifyReviewers)], ['Reminders', yesNo(req.remindersEnabled)], ['Requests expire after (days)', String(req.requestDurationInDays ?? 'Not returned')]] },
    pols && { title: 'Permission grant policies', columns: ['Policy', 'Description'], rows: pols.map(p => [p.displayName || p.id, p.description || '']) },
  ];
}

export const APPS_PAGES = {
  'p-enterprise': { section: 'APPS', title: 'Enterprise apps', load: enterprise },
  'p-registrations': { section: 'APPS', title: 'App registrations', load: registrations },
  'p-consent': { section: 'APPS', title: 'Consent', load: consent },
};
