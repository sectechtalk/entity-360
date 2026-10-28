// EXTERNAL section: Guests, Cross-tenant access.
import { part, yesNo, day } from '../bucket5.mjs';
const E = 'https://entra.microsoft.com/#view/';

async function guests(api, { notes }) {
  const rows = (await api.pages("/v1.0/users?$filter=userType eq 'Guest'&$count=true&$top=999&$select=id,displayName,mail,userPrincipalName,externalUserState,externalUserStateChangeDateTime,createdDateTime,accountEnabled,signInActivity")).rows;
  const last = u => u.signInActivity?.lastSignInDateTime || u.signInActivity?.lastNonInteractiveSignInDateTime;
  const stale = u => !last(u) || Date.now() - Date.parse(last(u)) > 90 * 864e5;
  const domain = u => (u.mail || '').split('@')[1] || (u.userPrincipalName.split('#EXT#')[0].split('_').pop() || '');
  const byDomain = {}; for (const u of rows) byDomain[domain(u)] = (byDomain[domain(u)] || 0) + 1;
  return [
    { title: 'Summary', columns: ['Measure', 'Guests'], rows: [['Total', String(rows.length)], ['Invitation pending', String(rows.filter(u => u.externalUserState === 'PendingAcceptance').length)], ['Disabled', String(rows.filter(u => u.accountEnabled === false).length)], ['No sign-in in 90 days', String(rows.filter(stale).length)]] },
    { title: 'Guests', note: 'Oldest sign-in first, so stale guests are at the top.', link: `${E}Microsoft_AAD_UsersAndTenants/UserManagementMenuBlade/~/AllUsers`, columns: ['Guest', 'Email', 'Invitation', 'Created', 'Last sign-in', 'Enabled'],
      rows: rows.sort((a, b) => (Date.parse(last(a)) || 0) - (Date.parse(last(b)) || 0)).slice(0, 300).map(u => [{ text: u.displayName || u.userPrincipalName, link: `${E}Microsoft_AAD_UsersAndTenants/UserProfileMenuBlade/~/overview/userId/${u.id}` }, u.mail || '', u.externalUserState || 'Not returned', day(u.createdDateTime), day(last(u)) || 'Never', yesNo(u.accountEnabled)]) },
    { title: 'Guests by home domain', columns: ['Domain', 'Guests'], rows: Object.entries(byDomain).sort((a, b) => b[1] - a[1]).map(([d, n]) => [d || 'Unknown', String(n)]) },
  ];
}

async function crossTenant(api, { notes }) {
  const def = await part(notes, 'Default cross-tenant settings', () => api.request('/v1.0/policies/crossTenantAccessPolicy/default'));
  const partners = await part(notes, 'Organizational settings', () => api.pages('/v1.0/policies/crossTenantAccessPolicy/partners').then(r => r.rows));
  const auth = await part(notes, 'Guest invite settings', () => api.request('/v1.0/policies/authorizationPolicy'));
  const acc = s => s?.usersAndGroups?.accessType ? `${s.usersAndGroups.accessType === 'allowed' ? 'Allow' : 'Block'} (${(s.usersAndGroups.targets || []).map(t => t.target === 'AllUsers' ? 'all users' : t.target).join(', ')})` : 'Inherited';
  const trust = t => t ? [t.isMfaAccepted && 'MFA', t.isCompliantDeviceAccepted && 'Compliant device', t.isHybridAzureADJoinedDeviceAccepted && 'Hybrid joined'].filter(Boolean).join(', ') || 'None' : 'Inherited';
  const link = `${E}Microsoft_AAD_IAM/CompanyRelationshipsMenuBlade/~/CrossTenantAccessSettings`;
  return [
    auth && { title: 'External collaboration', columns: ['Setting', 'Value'], rows: [['Guest invites allowed from', auth.allowInvitesFrom || 'Not returned'], ['Email one-time passcode join', yesNo(auth.allowEmailVerifiedUsersToJoinOrganization)]] },
    def && { title: 'Default settings', link, columns: ['Direction', 'B2B collaboration', 'B2B direct connect', 'Trusted claims'], rows: [
      ['Inbound', acc(def.b2bCollaborationInbound), acc(def.b2bDirectConnectInbound), trust(def.inboundTrust)], ['Outbound', acc(def.b2bCollaborationOutbound), acc(def.b2bDirectConnectOutbound), '']] },
    partners && { title: 'Organizational settings', link, columns: ['Tenant ID', 'Inbound B2B', 'Outbound B2B', 'Trusted claims', 'Service provider'], rows: partners.map(p => [p.tenantId, acc(p.b2bCollaborationInbound), acc(p.b2bCollaborationOutbound), trust(p.inboundTrust), yesNo(p.isServiceProvider)]) },
  ];
}

export const EXTERNAL_PAGES = {
  'x-guests': { section: 'EXTERNAL', title: 'Guests', load: guests },
  'x-cross': { section: 'EXTERNAL', title: 'Cross-tenant', load: crossTenant },
};
