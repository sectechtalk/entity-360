// "Where this lives in the portal" links for each Access tab. Static links only: nothing here calls a Microsoft API.
// Every link carries the tenant (#@<tenant>/) so the portal opens in the tenant Entity 360 is reading, not the
// browser's last-used tenant. Where the view is about one user or app, the link opens that object's own blade.
// Each link also names its menu path, so the place can be found by hand if Microsoft moves a blade.
import { PIM_ACTIVATION_LINKS } from './device-links.js';
// PIM activation links live only in device-links.js; reuse the Entra roles one ("My roles") here.
const PIM_MY_ROLES = PIM_ACTIVATION_LINKS[0][1].split('#')[1];
const ENTRA = 'https://entra.microsoft.com/', AZURE = 'https://portal.azure.com/', INTUNE = 'https://intune.microsoft.com/';
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const TENANT = /^[0-9a-z][0-9a-z.-]{0,253}$/i;

const hashFor = tenant => TENANT.test(String(tenant || '')) ? `#@${tenant}/` : '#';
const link = (host, tenant, blade) => `${host}${hashFor(tenant)}${blade}`;

// Every blade below was opened in a signed-in browser on 2026-11-14 and showed the named page.
// Blades shared by the Entra admin center and the Azure portal (both host the same Entra extensions).
const B = {
  caPolicies: 'view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies',
  userRoles: id => `view/Microsoft_AAD_UsersAndTenants/UserProfileMenuBlade/~/AdministrativeRole/userId/${id}`,
  userGroups: id => `view/Microsoft_AAD_UsersAndTenants/UserProfileMenuBlade/~/Groups/userId/${id}`,
  userApps: id => `view/Microsoft_AAD_UsersAndTenants/UserProfileMenuBlade/~/AssignedApplications/userId/${id}`,
  allRoles: 'view/Microsoft_AAD_IAM/AllRolesBlade',
  entitlements: 'view/Microsoft_AAD_ERM/DashboardBlade/~/elmEntitlement',
  allGroups: 'view/Microsoft_AAD_IAM/GroupsManagementMenuBlade/~/AllGroups',
  enterpriseApps: 'view/Microsoft_AAD_IAM/StartboardApplicationsMenuBlade/~/AppAppsPreview',
  appPermissions: (sp, app) => `view/Microsoft_AAD_IAM/ManagedAppMenuBlade/~/Permissions/objectId/${sp}/appId/${app}`,
  appSso: (sp, app) => `view/Microsoft_AAD_IAM/ManagedAppMenuBlade/~/SignOn/objectId/${sp}/appId/${app}`,
  appUsers: (sp, app) => `view/Microsoft_AAD_IAM/ManagedAppMenuBlade/~/Users/objectId/${sp}/appId/${app}`,
  appRoles: app => `view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/AppRoles/appId/${app}`,
  // Verified in a signed-in browser 2026-11-14: the two portals use different blades for admin units.
  adminUnitsEntra: 'view/Microsoft_AAD_IAM/RolesManagementMenuBlade/~/AdminUnits',
  adminUnitsAzure: 'view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/AdminUnit',
  // PIM > Microsoft Entra roles > Resource audit. The empty resourceId (//) is correct.
  pimEntraRolesAudit: 'view/Microsoft_Azure_PIMCommon/ResourceMenuBlade/~/Audit/resourceId//resourceType/tenant/provider/aadroles',
  audit: 'view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/Audit',
  provisioning: 'view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/ProvisioningEvents',
};

// Returns [{ portal, label, url, path }] for one Access tab. entity: { id, type, appId }.
export function accessPortalLinks(tab, { tenant, entity } = {}) {
  const id = GUID.test(String(entity?.id || '')) ? entity.id : '';
  const appId = GUID.test(String(entity?.appId || '')) ? entity.appId : '';
  const isUser = (entity?.type || 'user') === 'user' && id;
  const isApp = entity && entity.type !== 'user' && id;
  const E = (label, blade, path) => ({ portal: 'Microsoft Entra admin center', label, url: link(ENTRA, tenant, blade), path: `Entra admin center > ${path}` });
  const A = (label, blade, path) => ({ portal: 'Azure portal', label, url: link(AZURE, tenant, blade), path: `Azure portal > ${path}` });
  const I = (label, blade, path) => ({ portal: 'Microsoft Intune admin center', label, url: link(INTUNE, tenant, blade), path: `Intune admin center > ${path}` });
  const userNote = isUser ? ' > this user' : '';
  switch (tab) {
    case 'ca': return [
      E('Conditional Access policies', B.caPolicies, 'Entra ID > Conditional Access > Policies'),
      A('Conditional Access policies', B.caPolicies, 'Microsoft Entra ID > Security > Conditional Access > Policies'),
      I('Conditional Access policies', B.caPolicies, 'Endpoint security > Conditional access > Policies'),
    ];
    case 'roles': return [
      isUser ? E('Assigned roles (this user)', B.userRoles(id), 'Entra ID > Users > this user > Assigned roles') : E('Roles and administrators', B.allRoles, 'Entra ID > Roles & admins > All roles'),
      isUser ? A('Assigned roles (this user)', B.userRoles(id), 'Microsoft Entra ID > Users > this user > Assigned roles') : A('Roles and administrators', B.allRoles, 'Microsoft Entra ID > Roles and administrators'),
      E('PIM: My roles (your own, to activate)', PIM_MY_ROLES, 'ID Governance > Privileged Identity Management > My roles > Microsoft Entra roles'),
    ];
    case 'packages': return [
      E('Access packages', B.entitlements, 'ID Governance > Entitlement management > Access packages'),
      A('Access packages', B.entitlements, 'Microsoft Entra ID Governance > Entitlement management > Access packages'),
    ];
    case 'groups': return [
      isUser ? E('Groups (this user)', B.userGroups(id), 'Entra ID > Users > this user > Groups') : E('All groups', B.allGroups, 'Entra ID > Groups > All groups'),
      isUser ? A('Groups (this user)', B.userGroups(id), 'Microsoft Entra ID > Users > this user > Groups') : A('All groups', B.allGroups, 'Microsoft Entra ID > Groups > All groups'),
      I('All groups', B.allGroups, 'Groups > All groups'),
    ];
    case 'apps': return [
      isApp ? E('Permissions (this app)', B.appPermissions(id, appId), 'Entra ID > Enterprise apps > this app > Permissions') : isUser ? E('Applications (this user)', B.userApps(id), 'Entra ID > Users > this user > Applications') : E('Enterprise apps', B.enterpriseApps, 'Entra ID > Enterprise apps > All applications'),
      isApp ? A('Permissions (this app)', B.appPermissions(id, appId), 'Microsoft Entra ID > Enterprise applications > this app > Permissions') : isUser ? A('Applications (this user)', B.userApps(id), 'Microsoft Entra ID > Users > this user > Applications') : A('Enterprise applications', B.enterpriseApps, 'Microsoft Entra ID > Enterprise applications'),
    ];
    case 'au': return [
      E('Administrative units', B.adminUnitsEntra, 'Entra ID > Roles & admins > Admin units'),
      A('Administrative units', B.adminUnitsAzure, 'Microsoft Entra ID > Administrative units'),
    ];
    case 'pimreq': return [
      E('PIM Resource audit (Microsoft Entra roles)', B.pimEntraRolesAudit, 'ID Governance > Privileged Identity Management > Microsoft Entra roles > Resource audit'),
      E('Audit logs (filter Service = PIM)', B.audit, 'Entra ID > Monitoring & health > Audit logs, Service: PIM'),
      A('PIM Resource audit (Microsoft Entra roles)', B.pimEntraRolesAudit, 'Microsoft Entra Privileged Identity Management > Microsoft Entra roles > Resource audit'),
    ];
    case 'audit': return [
      E('Audit logs', B.audit, `Entra ID > Monitoring & health > Audit logs${userNote ? ' (filter by this user)' : ''}`),
      A('Audit logs', B.audit, `Microsoft Entra ID > Monitoring > Audit logs${userNote ? ' (filter by this user)' : ''}`),
    ];
    case 'prov': return [
      E('Provisioning logs', B.provisioning, 'Entra ID > Monitoring & health > Provisioning logs'),
      A('Provisioning logs', B.provisioning, 'Microsoft Entra ID > Monitoring > Provisioning logs'),
    ];
    case 'sso': return isApp ? [
      E('Single sign-on (this app)', B.appSso(id, appId), 'Entra ID > Enterprise apps > this app > Single sign-on'),
      E('Users and groups (this app)', B.appUsers(id, appId), 'Entra ID > Enterprise apps > this app > Users and groups'),
      ...(appId ? [E('App roles (this app registration)', B.appRoles(appId), 'Entra ID > App registrations > this app > App roles')] : []),
      A('Single sign-on (this app)', B.appSso(id, appId), 'Microsoft Entra ID > Enterprise applications > this app > Single sign-on'),
    ] : [];
    default: return [];
  }
}

// The sentence shown above each tab's links: what the links open and whether they are the same thing.
// Worded per tab so it stays true; where links open different pages, it says so.
export function accessPortalNote(tab, entity) {
  const isUser = (entity?.type || 'user') === 'user', isApp = entity && entity.type !== 'user';
  switch (tab) {
    case 'ca': return 'All three links open the same Conditional Access policies. There is one set, stored in Entra ID; the Entra, Azure and Intune portals each have their own menu entry for it. Use whichever portal you already have open.';
    case 'roles': return isUser
      ? 'Assigned roles is the same page in two portals: this user\'s Entra roles, eligible and active. PIM My roles is a different page: your own PIM roles, where you activate an eligible role. PIM has no page for another person\'s roles.'
      : 'Roles and administrators is the same list of Entra roles in two portals. PIM My roles is a different page: your own PIM roles, where you activate an eligible role.';
    case 'packages': return 'Both links open the same access packages, stored in Entra ID Governance, through two portals.';
    case 'groups': return isUser
      ? 'Groups (this user) is the same page in Entra and the Azure portal: this user\'s memberships. All groups in Intune opens the full list of the same Entra groups.'
      : 'All three links open the same Entra groups list, through three portals.';
    case 'apps': return isApp
      ? 'Both links open the same Permissions page for this app, through two portals.'
      : isUser ? 'Both links open the same page: the apps assigned to this user, through two portals.' : 'Both links open the same enterprise applications list, through two portals.';
    case 'au': return 'Both links open the same administrative units, stored in Entra ID, through two portals. Intune has no administrative units page (it uses scope tags instead), so there is no Intune link.';
    case 'pimreq': return 'PIM resource audit is the same page in two portals and lists PIM requests and activations. The Entra audit log, filtered to Service = PIM, shows the same events inside the full audit log.';
    case 'audit': return 'Both links open the same Entra audit log, through two portals. Filter by this identity once it opens.';
    case 'prov': return 'Both links open the same Entra provisioning log, through two portals.';
    case 'sso': return 'Single sign-on is the same page for this app in both portals. Users and groups and App roles are other pages of the same app.';
    default: return '';
  }
}

// Stacked: a heading, the note, then one link per line with its portal name.
export function accessPortalLinksHtml(tab, ctx, { esc }) {
  const links = accessPortalLinks(tab, ctx);
  if (!links.length) return '';
  const note = accessPortalNote(tab, ctx?.entity);
  const rows = links.map(l => `<li><span class="portal-where-name">${esc(l.portal)}</span><a href="${esc(l.url)}" target="_blank" rel="noopener noreferrer">${esc(l.label)}</a>${l.path ? ` <small class="portal-where-path">${esc(l.path)}</small>` : ''}</li>`).join('');
  return `<div class="portal-where"><p class="portal-where-label">Open in the portal</p>${note ? `<p class="portal-where-note">${esc(note)}</p>` : ''}<ul class="portal-where-list">${rows}</ul></div>`;
}
