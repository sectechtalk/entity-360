// TENANT section: Settings, Domains, Roles, Hybrid.
import { part, yesNo, day } from '../bucket5.mjs';
const E = 'https://entra.microsoft.com/#view/';

async function settings(api, { notes }) {
  const auth = await part(notes, 'Authorization policy', () => api.request('/v1.0/policies/authorizationPolicy'));
  const dev = await part(notes, 'Device registration policy', () => api.request('/v1.0/policies/deviceRegistrationPolicy'));
  const sd = await part(notes, 'Security defaults', () => api.request('/v1.0/policies/identitySecurityDefaultsEnforcementPolicy'));
  const p = auth?.defaultUserRolePermissions || {};
  const GUEST = { 'a0b1b346-4d3e-4e8b-98f8-753987be4970': 'Same as members', '10dae51f-b6af-4016-8d66-8c2a99b929b3': 'Limited (default)', '2af84b1e-32c8-42b7-82bc-daa82404023b': 'Most restrictive' };
  return [
    auth && { title: 'User settings', columns: ['Setting', 'Value'], rows: [
      ['Users can register applications', yesNo(p.allowedToCreateApps)], ['Users can create security groups', yesNo(p.allowedToCreateSecurityGroups)],
      ['Users can create tenants', yesNo(p.allowedToCreateTenants)], ['Users can read other users', yesNo(p.allowedToReadOtherUsers)],
      ['Users can read BitLocker keys for their devices', yesNo(p.allowedToReadBitlockerKeysForOwnedDevice)],
      ['User consent policy', (p.permissionGrantPoliciesAssigned || []).join(', ') || 'Users cannot consent'],
      ['Guest user access', GUEST[auth.guestUserRoleId] || auth.guestUserRoleId || 'Not returned'], ['Guest invites allowed from', auth.allowInvitesFrom || 'Not returned'],
      ['Email-verified users can join', yesNo(auth.allowEmailVerifiedUsersToJoinOrganization)], ['Self-service password reset for admins', yesNo(auth.allowedToUseSSPR)],
      ['Block MSOnline PowerShell', yesNo(auth.blockMsolPowerShell)],
    ].map(([a, b]) => [a, { text: b }]) },
    dev && { title: 'Device settings', columns: ['Setting', 'Value'], rows: [
      ['Users can Entra join', dev.azureADJoin?.allowedToJoin?.['@odata.type']?.split('.').pop() || 'Not returned'],
      ['Users can register devices', dev.azureADRegistration?.allowedToRegister?.['@odata.type']?.split('.').pop() || 'Not returned'],
      ['MFA to register or join', yesNo(dev.multiFactorAuthConfiguration === 'required' ? true : dev.multiFactorAuthConfiguration === 'notRequired' ? false : undefined)],
      ['Max devices per user', String(dev.userDeviceQuota ?? 'Not returned')],
      ['Local admin password (LAPS)', yesNo(dev.localAdminPassword?.isEnabled)],
    ] },
    sd && { title: 'Security defaults', columns: ['Setting', 'Value'], rows: [['Security defaults enabled', yesNo(sd.isEnabled)]] },
  ];
}

async function domains(api, { notes }) {
  const org = (await api.request('/v1.0/organization?$select=id,displayName,verifiedDomains,countryLetterCode,preferredLanguage,technicalNotificationMails,tenantType')).value?.[0] || {};
  const brand = await part(notes, 'Company branding', () => api.request(`/v1.0/organization/${org.id}/branding`));
  notes.push('Federation settings and DNS records need Domain.Read.All, which is not consented. Domain names and types come from the organization object.');
  return [
    { title: 'Verified domains', columns: ['Domain', 'Type', 'Default', 'Initial', 'Services'], rows: (org.verifiedDomains || []).map(d => [d.name, d.type || '', yesNo(d.isDefault), yesNo(d.isInitial), d.capabilities || '']), link: `${E}Microsoft_AAD_IAM/DomainsManagementMenuBlade/~/CustomDomainNames` },
    { title: 'Organization', columns: ['Setting', 'Value'], rows: [['Name', org.displayName || ''], ['Tenant type', org.tenantType || ''], ['Country', org.countryLetterCode || ''], ['Preferred language', org.preferredLanguage || ''], ['Technical contacts', (org.technicalNotificationMails || []).join(', ')]] },
    brand && { title: 'Company branding', columns: ['Setting', 'Value'], rows: [['Sign-in page text', brand.signInPageText || 'Not set'], ['Username hint', brand.usernameHintText || 'Not set'], ['Background color', brand.backgroundColor || 'Not set'], ['Hide "Keep me signed in"', yesNo(brand.loginPageLayoutConfiguration?.isHideKeepMeSignedIn ?? brand.hideKeepMeSignedIn)], ['Custom sign-in assets', [brand.bannerLogoRelativeUrl && 'Banner logo', brand.backgroundImageRelativeUrl && 'Background image', brand.squareLogoRelativeUrl && 'Square logo'].filter(Boolean).join(', ') || 'None']] },
  ];
}

async function roles(api, { notes }) {
  const defs = (await api.pages('/v1.0/roleManagement/directory/roleDefinitions?$select=id,displayName,isBuiltIn,isEnabled,templateId')).rows;
  const counts = {};
  await part(notes, 'Role assignments', async () => { for (const a of (await api.pages('/v1.0/roleManagement/directory/roleAssignments?$select=roleDefinitionId')).rows) counts[a.roleDefinitionId] = (counts[a.roleDefinitionId] || 0) + 1; });
  const elig = {};
  await part(notes, 'Eligible assignments', async () => { for (const a of (await api.pages('/v1.0/roleManagement/directory/roleEligibilitySchedules?$select=roleDefinitionId')).rows) elig[a.roleDefinitionId] = (elig[a.roleDefinitionId] || 0) + 1; });
  const used = defs.filter(d => !d.isBuiltIn || counts[d.id] || counts[d.templateId] || elig[d.id] || elig[d.templateId]);
  const aus = await part(notes, 'Administrative units', async () => {
    const rows = [];
    for (const au of (await api.pages('/v1.0/directory/administrativeUnits?$select=id,displayName,membershipType,isMemberManagementRestricted')).rows.slice(0, 50)) {
      const sr = await api.pages(`/v1.0/directory/administrativeUnits/${au.id}/scopedRoleMembers`).catch(() => ({ rows: [] }));
      const mem = await api.pages(`/v1.0/directory/administrativeUnits/${au.id}/members?$select=id`).catch(() => ({ rows: [] }));
      rows.push([{ text: au.displayName, link: `${E}Microsoft_AAD_IAM/AdministrativeUnitMenuBlade/~/Overview/objectId/${au.id}` }, au.membershipType === 'Dynamic' ? 'Dynamic' : 'Assigned', au.isMemberManagementRestricted ? 'Restricted' : 'Standard', String(mem.rows.length), sr.rows.map(r => `${r.roleMemberInfo?.displayName || r.roleMemberInfo?.id} (${defs.find(d => d.id === r.roleId || d.templateId === r.roleId)?.displayName || r.roleId})`).join('; ') || 'None']);
    }
    return rows;
  });
  return [
    { title: 'Roles in use and custom roles', note: `${defs.length} role definitions; showing custom roles and built-in roles with at least one assignment.`, columns: ['Role', 'Type', 'Enabled', 'Active assignments', 'Eligible (PIM)'], rows: used.sort((a, b) => (counts[b.id] || 0) - (counts[a.id] || 0)).map(d => [{ text: d.displayName, link: `${E}Microsoft_Azure_PIMCommon/UserRolesViewModelMenuBlade/~/members/roleObjectId/${d.id}/roleId/${d.id}/roleTemplateId/${d.templateId || d.id}/roleName/${encodeURIComponent(d.displayName)}/isRoleCustom~/${!d.isBuiltIn}/resourceScopeId/%2F/resourceId/` }, d.isBuiltIn ? 'Built-in' : 'Custom', yesNo(d.isEnabled), String(counts[d.id] || counts[d.templateId] || 0), String(elig[d.id] || elig[d.templateId] || 0)]) },
    aus && { title: 'Administrative units', columns: ['Unit', 'Membership', 'Management', 'Members', 'Scoped admins'], rows: aus },
  ];
}

async function hybrid(api, { notes }) {
  const org = (await api.request('/v1.0/organization?$select=onPremisesSyncEnabled,onPremisesLastSyncDateTime,onPremisesLastPasswordSyncDateTime')).value?.[0] || {};
  const synced = await part(notes, 'Synced user count', () => api.request('/v1.0/users/$count?$filter=onPremisesSyncEnabled eq true').then(n => String(n?.value ?? n)));
  notes.push('Password hash sync, pass-through and seamless SSO feature flags need OnPremDirectorySynchronization.Read.All, which is not consented. Connect Health and Kerberos objects have no Graph read.');
  const ago = t => t ? `${Math.round((Date.now() - Date.parse(t)) / 36e5)} hours ago` : '';
  return [{ title: 'Directory synchronization', columns: ['Setting', 'Value'], link: `${E}Microsoft_AAD_IAM/DirectoriesADConnectBlade`, rows: [
    ['Sync enabled', yesNo(org.onPremisesSyncEnabled ?? false)], ['Last sync', org.onPremisesLastSyncDateTime ? `${day(org.onPremisesLastSyncDateTime)} (${ago(org.onPremisesLastSyncDateTime)})` : 'Never'],
    ['Last password hash sync', org.onPremisesLastPasswordSyncDateTime ? `${day(org.onPremisesLastPasswordSyncDateTime)} (${ago(org.onPremisesLastPasswordSyncDateTime)})` : 'Never'], ['Synced users', synced ?? 'Not returned'],
  ] }];
}

export const TENANT_PAGES = {
  't-settings': { section: 'TENANT', title: 'Settings', load: settings },
  't-domains': { section: 'TENANT', title: 'Domains', load: domains },
  't-roles': { section: 'TENANT', title: 'Roles', load: roles },
  't-hybrid': { section: 'TENANT', title: 'Hybrid', load: hybrid },
};
