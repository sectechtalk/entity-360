import { queryUrl } from './model.mjs';
// Entitlement management (read-only, delegated EntitlementManagement.Read.All). Packages held by one user,
// their catalog, policy, schedule and the resources each package grants, plus that user's pending requests.
export const ELM_URL = 'https://entra.microsoft.com/#view/Microsoft_AAD_ERM/DashboardBlade/~/elmEntitlement';
const EM = '/v1.0/identityGovernance/entitlementManagement';
export const MAX_PACKAGES = 25;
const PENDING = new Set(['pendingApproval', 'pending', 'accepted', 'scheduled', 'delivering', 'partiallyDelivered']);
export function packageRow(a, pkg) {
  return {
    id: a.id, packageId: a.accessPackage?.id || pkg?.id, name: pkg?.displayName || a.accessPackage?.displayName || a.accessPackage?.id || 'Unknown package',
    catalog: pkg?.catalog?.displayName || 'Not returned', policy: a.assignmentPolicy?.displayName || 'Not returned',
    assigned: a.schedule?.startDateTime || null, expires: a.schedule?.expiration?.endDateTime || a.expiredDateTime || null,
    state: a.state || 'unknown', status: a.status || '',
    resources: (pkg?.resourceRoleScopes || []).map(s => ({ name: s.role?.resource?.displayName || s.scope?.displayName || s.role?.originId || 'Resource', role: s.role?.displayName || 'Not returned', type: s.role?.originSystem || s.scope?.originSystem || '' })),
  };
}
export function requestRow(q) {
  return { id: q.id, name: q.accessPackage?.displayName || 'Unknown package', type: q.requestType, state: q.state, status: q.status || '', created: q.createdDateTime || null };
}
export async function accessPackages(api, userId) {
  const assigned = await api.pages(queryUrl(`${EM}/assignments`, { '$filter': `target/objectId eq '${userId}'`, '$expand': 'accessPackage,assignmentPolicy' }));
  const live = assigned.rows.filter(a => a.state !== 'expired');
  const ids = [...new Set(live.map(a => a.accessPackage?.id).filter(Boolean))];
  const pkgs = new Map();
  await Promise.all(ids.slice(0, MAX_PACKAGES).map(id => api.request(`${EM}/accessPackages/${id}?$expand=catalog,resourceRoleScopes($expand=role($expand=resource),scope)`).then(p => pkgs.set(id, p), () => null)));
  let requests = [], requestsNote = null;
  try {
    const q = await api.pages(queryUrl(`${EM}/assignmentRequests`, { '$expand': 'accessPackage,target' }));
    requests = q.rows.filter(r => r.target?.objectId === userId && PENDING.has(r.state)).map(requestRow);
  } catch (e) { requestsNote = e; }
  return { rows: live.map(a => packageRow(a, pkgs.get(a.accessPackage?.id))), requests, requestsNote, truncated: assigned.truncated || ids.length > MAX_PACKAGES, limit: ids.length > MAX_PACKAGES ? `resources read for the first ${MAX_PACKAGES} packages` : undefined };
}
