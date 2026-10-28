// Coverage bucket 2: helpers for account state, license assignment path, role permissions and PIM activation rules.
// Delegated scopes only; anything the viewer cannot read is reported as unavailable, never guessed.
import { queryUrl } from './model.mjs';

export const ACCOUNT_SELECT = 'id,accountEnabled,userType,createdDateTime,signInSessionsValidFromDateTime,onPremisesSyncEnabled,onPremisesLastSyncDateTime';
// Investigate > Summary: account state and the last "revoke sessions" point (User.Read.All).
export function accountState(u = {}) {
  return {
    enabled: typeof u.accountEnabled === 'boolean' ? u.accountEnabled : null,
    userType: u.userType || null,
    created: u.createdDateTime || null,
    sessionsValidFrom: u.signInSessionsValidFromDateTime || null,
    synced: u.onPremisesSyncEnabled === true ? 'Synced from on-premises AD' : 'Cloud only',
    lastSync: u.onPremisesLastSyncDateTime || null,
  };
}

// My access > Licenses: how each SKU is assigned (Direct or via a group) and any group-licensing error (User.Read on /me).
export async function licensePaths(states = [], groupName = async id => id) {
  const bySku = new Map();
  for (const s of states || []) {
    if (!s?.skuId) continue;
    const via = s.assignedByGroup ? `Group: ${await groupName(s.assignedByGroup)}` : 'Direct';
    const error = s.error && s.error !== 'None' ? s.error : null;
    if (!bySku.has(s.skuId)) bySku.set(s.skuId, []);
    bySku.get(s.skuId).push({ via, state: s.state || null, error, disabledPlans: (s.disabledPlans || []).length });
  }
  return bySku;
}

// Access > Admin roles: the actions a role definition allows (RoleManagement.Read.Directory, via $expand=roleDefinition).
export function rolePermissions(def) {
  const actions = (def?.rolePermissions || []).flatMap(p => p.allowedResourceActions || []);
  return [...new Set(actions)];
}
export function permissionSummary(actions) {
  if (!Array.isArray(actions)) return '';
  if (!actions.length) return 'None returned';
  const shown = actions.slice(0, 3).join(', ');
  return actions.length > 3 ? `${actions.length} actions: ${shown}, …` : shown;
}

// PIM activation rules for Entra roles (RoleManagement.Read.Directory covers policy reads; viewer needs a reader role such as Global Reader).
const isoDuration = d => { const m = String(d || '').match(/^P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?)?$/); if (!m) return d || ''; const [, D, H, M] = m; return [D && `${D}d`, H && `${H}h`, M && `${M}m`].filter(Boolean).join(' ') || d; };
export function activationSummary(policy) {
  const rules = policy?.rules || [];
  const end = id => rules.find(r => r.id === id);
  const exp = end('Expiration_EndUser_Assignment'), en = end('Enablement_EndUser_Assignment'), ap = end('Approval_EndUser_Assignment'), ac = end('AuthenticationContext_EndUser_Assignment');
  if (!exp && !en && !ap) return null;
  const parts = [];
  if (exp?.maximumDuration) parts.push(`Max ${isoDuration(exp.maximumDuration)}`);
  const names = { MultiFactorAuthentication: 'MFA', Justification: 'Justification', Ticketing: 'Ticket' };
  for (const r of en?.enabledRules || []) parts.push(names[r] || r);
  if (ac?.isEnabled) parts.push(`Auth context ${ac.claimValue || ''}`.trim());
  parts.push(ap?.setting?.isApprovalRequired ? 'Approval required' : 'No approval');
  return parts.join(', ');
}
export async function activationRules(api) {
  const r = await api.pages(queryUrl('/v1.0/policies/roleManagementPolicyAssignments', { '$filter': "scopeId eq '/' and scopeType eq 'DirectoryRole'", '$expand': 'policy($expand=rules)' }));
  const map = new Map();
  for (const a of r.rows) { const s = activationSummary(a.policy); if (a.roleDefinitionId && s) map.set(a.roleDefinitionId, s); }
  return map;
}
