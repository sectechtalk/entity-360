// Classifies Graph memberOf / transitiveMemberOf objects for My access > Group memberships. Shared by server and browser.
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export const GROUP_SELECT = 'id,displayName,groupTypes,mailEnabled,securityEnabled,membershipRule,isAssignableToRole,onPremisesSyncEnabled';
export const GROUP_KINDS = ['Security', 'Microsoft 365', 'Mail-enabled security', 'Distribution', 'Administrative unit', 'Other'];
export const ALL_GROUPS_URL = 'https://entra.microsoft.com/#view/Microsoft_AAD_IAM/GroupsManagementMenuBlade/~/AllGroups';
export const ADMIN_UNITS_URL = 'https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/AdminUnit';
const odata = o => String(o?.['@odata.type'] || '').replace('#microsoft.graph.', '');
export function groupKind(g) {
  const t = odata(g);
  if (t === 'administrativeUnit') return 'Administrative unit';
  if (t === 'directoryRole') return 'Directory role';
  if (t && t !== 'group') return 'Other';
  if ((g.groupTypes || []).includes('Unified')) return 'Microsoft 365';
  if (g.securityEnabled && g.mailEnabled) return 'Mail-enabled security';
  if (g.securityEnabled) return 'Security';
  if (g.mailEnabled) return 'Distribution';
  return 'Other';
}
// memberOf gives direct rows, transitiveMemberOf gives all; anything only in the transitive list is inherited via a nested group.
export function classifyMemberships(direct = [], transitive = []) {
  const directIds = new Set(direct.map(o => o.id)), seen = new Set(), rows = [];
  let roles = 0;
  for (const o of [...direct, ...transitive]) {
    if (!o?.id || seen.has(o.id)) continue; seen.add(o.id);
    const kind = groupKind(o);
    if (kind === 'Directory role') { roles++; continue; } // shown on Access > Admin roles; not repeated here
    const group = odata(o) === 'group' || !odata(o);
    rows.push({
      id: o.id, name: o.displayName || o.id, kind,
      membershipType: group ? ((o.groupTypes || []).includes('DynamicMembership') || o.membershipRule ? 'Dynamic' : 'Assigned') : 'n/a',
      roleAssignable: o.isAssignableToRole === true,
      membership: directIds.has(o.id) ? 'Direct' : 'Transitive',
      source: group ? (o.onPremisesSyncEnabled ? 'Synced from on-premises AD' : 'Cloud (Entra ID)') : 'Cloud (Entra ID)',
    });
  }
  rows.sort((a, b) => a.name.localeCompare(b.name));
  return { rows, directoryRoles: roles };
}
export function typeLabel(r) {
  return [r.kind, r.membershipType !== 'n/a' && r.membershipType, r.roleAssignable && 'Role-assignable'].filter(Boolean).join(' · ');
}
export function groupLink(r) {
  if (r.kind === 'Administrative unit') return ADMIN_UNITS_URL;
  return GUID.test(r.id || '') ? `https://entra.microsoft.com/#view/Microsoft_AAD_IAM/GroupDetailsMenuBlade/~/Overview/groupId/${r.id}` : ALL_GROUPS_URL;
}
// My access merges admin roles into the memberships table ("Group memberships and Role assignments").
export const ROLE_KINDS = ['Directory role', 'Azure role'];
export const ACCESS_MEMBERSHIPS = ['Direct', 'Transitive', 'Active', 'Eligible', 'Permanent'];
const fmtDuration = ms => { const m = Math.round(Math.abs(ms) / 60000), d = Math.floor(m / 1440), h = Math.floor((m % 1440) / 60), mm = m % 60; return d ? `${d}d ${h}h` : h ? `${h}h ${mm}m` : `${mm}m`; };
const fmtTime = t => `${new Date(t).toLocaleString('en-GB', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', timeZone: 'UTC' })} UTC`;
export const isRoleRow = r => ROLE_KINDS.includes(r.kind);
export function roleTiming(r) {
  if (!isRoleRow(r)) return { granted: '', remaining: '' };
  const granted = r.granted ? fmtTime(r.granted) : r.membership === 'Permanent' ? 'Not returned' : 'Not returned';
  const remaining = Number.isFinite(r.remaining) ? (r.remaining > 0 ? fmtDuration(r.remaining) : 'Expired') : r.membership === 'Permanent' ? 'No end date' : 'Not returned';
  return { granted, remaining };
}
export function accessRows(groups = [], roles = []) { return [...roles, ...groups]; }
export const accessLink = r => (isRoleRow(r) ? r.link : groupLink(r));
export const accessType = r => (isRoleRow(r) ? r.kind : typeLabel(r));
