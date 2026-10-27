// My access: the signed-in user's own Entra directory roles (active + eligible, PIM timing) and Azure roles.
// Access > Admin roles points here when the selected entity is the signed-in user, so the rows are not repeated.
import { queryUrl, describeError } from './model.mjs';
import { withFallback, azurePim } from './live.mjs';
import { resourceGraph, roleAssignmentQuery, SUBSCRIPTIONS_QUERY, pimTiming } from './access.mjs';

export const entraRoleLink = (id, name) => `https://entra.microsoft.com/#view/Microsoft_AAD_IAM/RoleMenuBlade/~/RoleMembers/objectId/${encodeURIComponent(id)}/roleName/${encodeURIComponent(name || '')}/roleTemplateId/${encodeURIComponent(id)}/adminUnitObjectId//customRole~/false/resourceScope/%2F`;
export const azureScopeLink = (tenant, scope) => `https://portal.azure.com/#@${tenant || ''}/resource${scope}/users`;
const membershipOf = (eligible, t) => eligible ? 'Eligible' : t.permanent ? 'Permanent' : 'Active';
const timing = t => ({ granted: t.granted ?? null, remaining: Number.isFinite(t.remaining) ? t.remaining : null });

export async function myRoles(api, me, groups = [], { tenant, maxSubscriptions = 25 } = {}) {
  let ok = false; const rows = [], problems = { partial: [], unavailable: [] }, notes = [];
  const fail = (src, e) => ([401, 403, 404].includes(e.status) ? problems.unavailable : problems.partial).push({ source: src, reason: describeError(e) });
  const nameOf = new Map(groups.map(g => [g.id, g.name]));
  // Entra roles can only be held through role-assignable groups.
  const entraPrincipals = [me.id, ...groups.filter(g => g.roleAssignable).map(g => g.id)].slice(0, 25);
  const via = p => p === me.id ? 'Direct' : `Group: ${nameOf.get(p) || p}`;
  const report = { notes };
  for (const p of entraPrincipals) {
    for (const [eligible, primary, fallback] of [[false, 'roleAssignmentScheduleInstances', 'roleAssignments'], [true, 'roleEligibilityScheduleInstances', 'roleEligibilitySchedules']]) {
      const q = path => queryUrl(`/v1.0/roleManagement/directory/${path}`, { '$filter': `principalId eq '${p}'`, '$expand': 'roleDefinition' });
      try {
        const r = await withFallback(api, q(primary), q(fallback), report, 'My Entra roles'); ok = true;
        for (const x of r.rows) {
          const t = pimTiming(x.startDateTime, x.endDateTime), name = x.roleDefinition?.displayName || x.roleDefinitionId || 'Unnamed role';
          rows.push({ id: `${x.id}`, name, kind: 'Directory role', membershipType: 'n/a', roleAssignable: false, membership: membershipOf(eligible, t), source: via(p), scope: x.directoryScopeId || '/', ...timing(t), link: entraRoleLink(x.roleDefinitionId, name) });
        }
      } catch (e) { fail('My Entra roles', e); }
    }
  }
  // Azure: permanent/current assignments from Resource Graph (user + every group), PIM eligibility and time-bound grants per subscription.
  const azPrincipals = [me.id, ...groups.filter(g => !['Administrative unit', 'Directory role'].includes(g.kind)).map(g => g.id)].slice(0, 500);
  try {
    const r = await resourceGraph(api, roleAssignmentQuery(azPrincipals));
    for (const x of r.rows) rows.push({ id: x.id, name: x.roleName || x.roleGuid || 'Unnamed role', kind: 'Azure role', membershipType: 'n/a', roleAssignable: false, membership: 'Permanent', source: x.principalId === me.id.toLowerCase() ? 'Direct' : `Group: ${nameOf.get(groups.find(g => g.id.toLowerCase() === x.principalId)?.id) || x.principalId}`, scope: x.scope, granted: null, remaining: null, link: azureScopeLink(tenant, x.scope) });
  } catch (e) { fail('My Azure roles', e); }
  try {
    const subs = (await resourceGraph(api, SUBSCRIPTIONS_QUERY)).rows.slice(0, maxSubscriptions);
    const seen = new Set();
    for (const s of subs) for (const kind of ['roleAssignmentScheduleInstances', 'roleEligibilityScheduleInstances']) {
      try {
        const r = await azurePim(api, s.subscriptionId, kind, me.id, { self: true });
        for (const x of r.rows) {
          const p = x.properties || {}, eligible = kind === 'roleEligibilityScheduleInstances';
          if (!eligible && !p.endDateTime) continue; // permanent active rows already come from Resource Graph
          if (seen.has(x.id)) continue; seen.add(x.id);
          const t = pimTiming(p.startDateTime, p.endDateTime);
          rows.push({ id: x.id, name: p.expandedProperties?.roleDefinition?.displayName || String(p.roleDefinitionId || '').split('/').pop() || 'Unnamed role', kind: 'Azure role', membershipType: 'n/a', roleAssignable: false, membership: membershipOf(eligible, t), source: p.memberType === 'Group' ? 'Group membership' : 'Direct', scope: p.scope, ...timing(t), link: azureScopeLink(tenant, p.scope) });
        }
      } catch (e) { fail('My Azure PIM', e); }
    }
  } catch (e) { fail('My Azure PIM', e); }
  const dedupe = (list, key) => [...new Map(list.map(x => [key(x), x])).values()];
  return { ok: ok || rows.length > 0, rows: dedupe(rows, x => `${x.kind}|${x.id}|${x.membership}`), problems: { partial: dedupe(problems.partial, x => x.source + x.reason), unavailable: dedupe(problems.unavailable, x => x.source + x.reason) }, notes };
}
