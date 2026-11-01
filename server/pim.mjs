// Unified PIM table: Entra roles, PIM for Groups and Azure roles in one list.
// Self (MY ACCOUNT > PIM): filterByCurrentUser / asTarget(), with activate and deactivate through selfActivate,
// selfDeactivate and ARM roleAssignmentScheduleRequests. Another user (INVESTIGATE > PIM): principalId / assignedTo, read-only.
// Every call uses the viewer's own delegated token; Microsoft enforces each PIM policy (approval, MFA, ticket, duration).
import { randomUUID } from 'node:crypto';
import { queryUrl, describeError, fail, GUID } from './model.mjs';
import { azurePim, resolveScopes } from './live.mjs';
import { resourceGraph, SUBSCRIPTIONS_QUERY } from './access.mjs';
import { mergeRows } from '../public/pim.js';

const ARM = 'https://management.azure.com';
const ARM_VERSION = '2020-10-01';
const DIR = '/v1.0/roleManagement/directory';
const GRP = '/v1.0/identityGovernance/privilegedAccess/group';
export const PIM_TYPES = ['Entra role', 'Group', 'Azure role'];
export const PIM_SCOPES = {
  'Entra role': 'RoleEligibilitySchedule.Read.Directory, RoleAssignmentSchedule.ReadWrite.Directory',
  Group: 'PrivilegedEligibilitySchedule.Read.AzureADGroup, PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup',
  'Azure role': 'Azure Resource Manager user_impersonation',
};
export const DEFAULT_POLICY = { maxMinutes: 480, justification: true, ticket: false, mfa: false, approval: false, source: 'default' };
const MAX_SUBSCRIPTIONS = 25;

// ISO 8601 duration (PT8H, PT30M, P1D, P1DT2H) -> minutes; null when not a positive duration.
export function isoMinutes(value) {
  const m = /^P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:\d+(?:\.\d+)?S)?)?$/.exec(String(value || ''));
  if (!m) return null;
  const n = (Number(m[1]) || 0) * 1440 + (Number(m[2]) || 0) * 60 + (Number(m[3]) || 0);
  return n > 0 ? n : null;
}
export const minutesIso = n => { const h = Math.floor(n / 60), m = n % 60; return `PT${h ? `${h}H` : ''}${m ? `${m}M` : ''}`; };

export function stateOf(eligible, x) {
  if (eligible) return 'Eligible';
  // Graph PIM for Groups returns 'activated' (lowercase); directory roles return 'Activated'. Compare without case.
  if (String(x.assignmentType || '').toLowerCase() === 'activated') return 'Active (activated)';
  return x.endDateTime ? 'Active (time-bound)' : 'Active (permanent)';
}
const deny = e => [401, 403].includes(e?.status);
// Directory roles Microsoft accepts for reading ANOTHER user's PIM data (Graph docs, least privilege first).
export const PIM_OTHER_ROLES = {
  'Entra role': 'Global Reader, Security Reader or Privileged Role Administrator',
  Group: 'Global Reader, Privileged Role Administrator, Groups Administrator, Identity Governance Administrator or User Administrator (or be an owner or member of the group)',
};
// One entry per source and reason (eligibility and assignment usually fail the same way). A refusal says what
// Microsoft answered: a missing consented scope needs an admin consent; otherwise, for another user, the viewer's role.
function problem(problems, type, e, self = true) {
  let reason;
  if (deny(e)) {
    const said = [e.upstreamCode, e.upstreamMessage].filter(Boolean).join(': ').replace(/\s+/g, ' ').slice(0, 240);
    const scope = /PermissionScopeNotGranted|missing permission scope|scope/i.test(said);
    reason = scope ? `the app's sign-in is missing a delegated scope (${PIM_SCOPES[type]}); an admin must consent it for Entity 360`
      : !self && PIM_OTHER_ROLES[type] ? `Microsoft refused to show another user's ${type === 'Group' ? 'PIM group' : 'PIM role'} assignments to your sign-in. The scopes are consented; Microsoft also requires your account to hold an active ${PIM_OTHER_ROLES[type]} role at directory scope`
      : `not readable with your sign-in (uses ${PIM_SCOPES[type]})`;
    if (said) reason += `. Microsoft said: ${said}`;
  } else reason = describeError(e);
  if (!problems.some(p => p.source === type && p.reason === reason)) problems.push({ source: type, status: e?.status || null, reason });
}
// filterByCurrentUser first; a tenant that rejects the function falls back to principalId eq <me>.
async function listFor(api, base, kind, who, extra = {}) {
  const filtered = queryUrl(`${base}/${kind}`, { '$filter': `principalId eq '${who.id}'`, ...extra });
  if (!who.self) return api.pages(filtered);
  const fn = `${base}/${kind}/filterByCurrentUser(on='principal')`;
  try { return await api.pages(Object.keys(extra).length ? queryUrl(fn, extra) : fn); }
  catch (e) { if (![400, 404, 501].includes(e.status)) throw e; return api.pages(filtered); }
}

async function entraRows(api, who, problems) {
  const rows = [], names = new Map();
  const roleName = async id => {
    if (!names.has(id)) { let n = id; try { n = (await api.request(`${DIR}/roleDefinitions/${encodeURIComponent(id)}?$select=displayName`)).displayName || id; } catch { /* keep id */ } names.set(id, n); }
    return names.get(id);
  };
  for (const [eligible, kind] of [[true, 'roleEligibilityScheduleInstances'], [false, 'roleAssignmentScheduleInstances']]) {
    try {
      const r = await listFor(api, DIR, kind, who, { '$expand': 'roleDefinition' });
      for (const x of r.rows) {
        const scope = x.directoryScopeId || '/';
        rows.push({ id: x.id, type: 'Entra role', name: x.roleDefinition?.displayName || await roleName(x.roleDefinitionId), scope, scopeLabel: scope === '/' ? 'Directory (tenant-wide)' : scope, state: stateOf(eligible, x), memberType: x.memberType || null, start: x.startDateTime || null, end: x.endDateTime || null, key: `entra|${x.roleDefinitionId}|${scope}`.toLowerCase(), target: { roleDefinitionId: x.roleDefinitionId, directoryScopeId: scope } });
      }
    } catch (e) { problem(problems, 'Entra role', e, who.self); }
  }
  const au = rows.filter(r => r.scope !== '/');
  if (au.length) { const pols = au.map(r => ({ evidence: { directoryScopeId: r.scope } })); try { await resolveScopes(api, pols, null); au.forEach((r, i) => { r.scopeLabel = pols[i].scopeName || r.scope; }); } catch { /* keep raw ids */ } }
  return rows;
}

const GROUP_KINDS = [[true, 'eligibilityScheduleInstances'], [false, 'assignmentScheduleInstances']];
const groupRow = (eligible, x, name) => {
  const access = x.accessId === 'owner' ? 'owner' : 'member';
  return { id: x.id, type: 'Group', name, scope: x.groupId, scopeLabel: `Group ${access}`, state: stateOf(eligible, x), memberType: x.memberType || null, start: x.startDateTime || null, end: x.endDateTime || null, key: `group|${x.groupId}|${access}`.toLowerCase(), target: { groupId: x.groupId, accessId: access } };
};
async function groupRows(api, who, problems, notes = []) {
  const rows = [], names = new Map(), refused = [];
  for (const [eligible, kind] of GROUP_KINDS) {
    try {
      const r = await listFor(api, GRP, kind, who);
      for (const x of r.rows) {
        if (!x.groupId) continue;
        if (!names.has(x.groupId)) { let n = x.groupId; try { n = (await api.request(`/v1.0/groups/${x.groupId}?$select=id,displayName`)).displayName || n; } catch { /* keep id */ } names.set(x.groupId, n); }
        rows.push(groupRow(eligible, x, names.get(x.groupId)));
      }
    } catch (e) { if (!who.self && deny(e)) refused.push(e); else problem(problems, 'Group', e, who.self); }
  }
  // Another user: Microsoft's PIM service refuses principalId eq '<other user>' (UnauthorizedAccessException) even for
  // Global Reader. The groupId form is the documented admin view, so read group by group and keep this user's rows.
  if (refused.length) rows.push(...await groupRowsByGroup(api, who, problems, notes, refused[0]));
  return rows;
}

export const MAX_PIM_GROUPS = 100, GROUP_CONCURRENCY = 6;
// Candidate groups: the user's transitive group memberships plus every security group the viewer can list (capped).
// A PIM group only matters if it is a security group, so this covers eligible-only groups too, up to the cap.
async function candidateGroups(api, who) {
  const found = new Map(); let total = 0, truncated = false;
  const add = list => { for (const g of list || []) if (g?.id && GUID.test(g.id) && !found.has(g.id)) found.set(g.id, g.displayName || g.id); };
  try { add((await api.pages(queryUrl(`/v1.0/users/${who.id}/transitiveMemberOf/microsoft.graph.group`, { '$select': 'id,displayName' }))).rows); } catch { /* membership unreadable: the security group list still runs */ }
  const member = found.size;
  try {
    const all = (await api.pages(queryUrl('/v1.0/groups', { '$filter': 'securityEnabled eq true', '$select': 'id,displayName', '$top': '999' }))).rows || [];
    total = all.length; add(all);
  } catch { /* keep memberships only */ }
  const ids = [...found.keys()];
  if (ids.length > MAX_PIM_GROUPS) { truncated = true; ids.length = MAX_PIM_GROUPS; }
  return { ids, names: found, member, total, truncated };
}
// Microsoft answers 400 ResourceTypeNotSupported for groups PIM cannot manage (for example dynamic or Microsoft 365 groups): not an error.
const notPim = e => e?.status === 400 && /ResourceTypeNotSupported/i.test(`${e.upstreamCode || ''} ${e.upstreamMessage || ''}`);
async function pool(items, n, fn) { const out = []; let i = 0; await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => { while (i < items.length) { const k = i++; out[k] = await fn(items[k]); } })); return out; }

async function groupRowsByGroup(api, who, problems, notes, first) {
  const c = await candidateGroups(api, who), rows = [], fails = [], unsupported = new Set();
  await pool(c.ids, GROUP_CONCURRENCY, async gid => {
    for (const [eligible, kind] of GROUP_KINDS) {
      const url = queryUrl(`${GRP}/${kind}`, { '$filter': `groupId eq '${gid}'` });
      try { for (const x of (await api.pages(url)).rows) if (String(x.principalId || '').toLowerCase() === who.id.toLowerCase()) rows.push(groupRow(eligible, { ...x, groupId: x.groupId || gid }, c.names.get(gid) || gid)); }
      catch (e) { if (notPim(e)) { unsupported.add(gid); return; } fails.push({ e, url }); }
    }
  });
  const calls = (c.ids.length - unsupported.size) * 2;
  if (!c.ids.length) { problem(problems, 'Group', first, false); return rows; }
  if (fails.length === calls) {
    // Refused by group too: report the exact request and Microsoft's answer.
    const f = fails[0], said = [f.e.upstreamCode, f.e.upstreamMessage].filter(Boolean).join(': ') || describeError(f.e);
    problems.push({ source: 'Group', status: f.e.status || null, reason: `Microsoft refused both the per-user query and the per-group query (GET ${decodeURIComponent(f.url)}). Microsoft said: ${said}` });
    return rows;
  }
  if (fails.length) problems.push({ source: 'Group', status: fails[0].e.status || null, reason: `${fails.length} of ${calls} group PIM reads failed (${describeError(fails[0].e)}); those groups may be missing.` });
  const pim = c.ids.length - unsupported.size;
  notes.push(`PIM groups: Microsoft does not allow listing another user's PIM groups in one query, so each group was checked. Checked ${c.ids.length} groups (${pim} PIM-enabled): the ${c.member} groups this user belongs to and the security groups you can see${c.truncated ? ` (first ${MAX_PIM_GROUPS} of ${c.total})` : ''}. A PIM group outside these is not shown.`);
  return rows;
}

async function azureRows(api, who, problems, notes) {
  const rows = [], seen = new Set();
  let subs;
  try { subs = (await resourceGraph(api, SUBSCRIPTIONS_QUERY)).rows; } catch (e) { problem(problems, 'Azure role', e); return rows; }
  if (subs.length > MAX_SUBSCRIPTIONS) notes.push(`Azure roles cover the first ${MAX_SUBSCRIPTIONS} of ${subs.length} subscriptions you can see.`);
  for (const s of subs.slice(0, MAX_SUBSCRIPTIONS)) for (const [eligible, kind] of [[true, 'roleEligibilityScheduleInstances'], [false, 'roleAssignmentScheduleInstances']]) {
    try {
      const r = await azurePim(api, s.subscriptionId, kind, who.id, { self: who.self });
      for (const x of r.rows) {
        if (seen.has(x.id)) continue; seen.add(x.id);
        const p = x.properties || {}, e = p.expandedProperties || {};
        rows.push({ id: x.id, type: 'Azure role', name: e.roleDefinition?.displayName || String(p.roleDefinitionId || '').split('/').pop() || 'Unnamed role', scope: p.scope, scopeLabel: e.scope?.displayName ? `${e.scope.displayName} (${e.scope.type || 'scope'})` : p.scope, state: stateOf(eligible, p), memberType: p.memberType || null, start: p.startDateTime || null, end: p.endDateTime || null, key: `azure|${p.roleDefinitionId}|${p.scope}`.toLowerCase(), target: { scope: p.scope, roleDefinitionId: p.roleDefinitionId, eligibilityScheduleId: eligible ? p.roleEligibilityScheduleId || null : p.linkedRoleEligibilityScheduleId || null } });
      }
    } catch (e) { problem(problems, 'Azure role', e); }
  }
  return rows;
}

// One row per group/role/scope: an activation absorbs its eligibility (Eligibility column); Activate on Eligible rows,
// Deactivate on Activated rows (self only). Standing assignments (for example a permanent group owner) stay separate rows.
export function withActions(rows, self) { return mergeRows(rows, self); }
const order = { Eligible: 1, 'Active (activated)': 0, 'Active (time-bound)': 2, 'Active (permanent)': 3 };
export async function pimTable(api, who, { azure = false } = {}) {
  if (!who?.id || !GUID.test(who.id)) throw fail('No user object id for the PIM lookup.', 400);
  const problems = [], notes = [];
  const lists = await Promise.all([entraRows(api, who, problems), groupRows(api, who, problems, notes), azure ? azureRows(api, who, problems, notes) : Promise.resolve([])]);
  if (!azure) notes.push('Azure roles are not included: connect Azure to list them.');
  if (!who.self) notes.push('Read-only. Lists assignments made to this user directly; roles reached only through a group are listed under that group.');
  const rows = withActions(lists.flat(), who.self).sort((a, b) => PIM_TYPES.indexOf(a.type) - PIM_TYPES.indexOf(b.type) || (order[a.state] ?? 9) - (order[b.state] ?? 9) || String(a.name).localeCompare(String(b.name)));
  return { rows, problems, notes, self: Boolean(who.self), azure, readAt: new Date().toISOString() };
}

// ---- Validation of a row target sent back by the browser ----
const AZ_SCOPE = /^\/(subscriptions\/[0-9a-f-]{36}|providers\/Microsoft\.Management\/managementGroups\/[\w.()-]{1,90})(\/[\w.()\-/]{1,400})?$/i;
const AZ_ROLE = /^(\/subscriptions\/[0-9a-f-]{36})?\/providers\/Microsoft\.Authorization\/roleDefinitions\/[0-9a-f-]{36}$/i;
const AZ_ELIG = /^\/[\w.()\-/]{1,600}\/providers\/Microsoft\.Authorization\/roleEligibilitySchedules\/[0-9a-f-]{36}$/i;
const DIR_SCOPE = /^\/((administrativeUnits\/)?[0-9a-f-]{36})?$/i;
export function checkTarget(type, t = {}) {
  const bad = what => { throw fail(`Invalid ${what}.`, 400); };
  if (type === 'Entra role') { if (!GUID.test(String(t.roleDefinitionId || ''))) bad('role'); if (!DIR_SCOPE.test(String(t.directoryScopeId || ''))) bad('directory scope'); return { roleDefinitionId: t.roleDefinitionId, directoryScopeId: t.directoryScopeId }; }
  if (type === 'Group') { if (!GUID.test(String(t.groupId || ''))) bad('group'); if (!['member', 'owner'].includes(t.accessId)) bad('group access'); return { groupId: t.groupId, accessId: t.accessId }; }
  if (type === 'Azure role') {
    const scope = String(t.scope || ''), role = String(t.roleDefinitionId || ''), elig = t.eligibilityScheduleId ? String(t.eligibilityScheduleId) : null;
    if (!AZ_SCOPE.test(scope) || scope.includes('..')) bad('Azure scope'); if (!AZ_ROLE.test(role)) bad('Azure role'); if (elig && (!AZ_ELIG.test(elig) || elig.includes('..'))) bad('eligibility schedule');
    return { scope, roleDefinitionId: role, eligibilityScheduleId: elig };
  }
  return bad('type');
}

export function policyFrom(rules) {
  if (!Array.isArray(rules) || !rules.length) return { ...DEFAULT_POLICY };
  const exp = rules.find(r => r.id === 'Expiration_EndUser_Assignment'), en = rules.find(r => r.id === 'Enablement_EndUser_Assignment'), ap = rules.find(r => r.id === 'Approval_EndUser_Assignment');
  const enabled = (en?.enabledRules || []).map(String);
  return { maxMinutes: isoMinutes(exp?.maximumDuration) || DEFAULT_POLICY.maxMinutes, justification: enabled.includes('Justification'), ticket: enabled.includes('Ticketing'), mfa: enabled.includes('MultiFactorAuthentication'), approval: Boolean(ap?.setting?.isApprovalRequired), source: 'policy' };
}
// The activation policy for one row. Unreadable policy -> defaults plus the reason; Microsoft still enforces the real one.
export async function pimPolicy(api, type, rawTarget) {
  const t = checkTarget(type, rawTarget);
  try {
    if (type === 'Azure role') {
      const r = await api.pages(queryUrl(`${t.scope}/providers/Microsoft.Authorization/roleManagementPolicyAssignments`, { 'api-version': ARM_VERSION }), { origin: ARM });
      const guid = t.roleDefinitionId.split('/').pop().toLowerCase();
      const hit = r.rows.find(x => String(x.properties?.roleDefinitionId || '').split('/').pop().toLowerCase() === guid);
      return hit ? policyFrom(hit.properties?.effectiveRules) : { ...DEFAULT_POLICY, reason: 'No policy assignment returned for this role and scope.' };
    }
    const filter = type === 'Group' ? `scopeId eq '${t.groupId}' and scopeType eq 'Group' and roleDefinitionId eq '${t.accessId}'` : `scopeId eq '/' and scopeType eq 'DirectoryRole' and roleDefinitionId eq '${t.roleDefinitionId}'`;
    const r = await api.pages(queryUrl('/v1.0/policies/roleManagementPolicyAssignments', { '$filter': filter, '$expand': 'policy($expand=rules)' }));
    const rules = r.rows[0]?.policy?.rules;
    return rules ? policyFrom(rules) : { ...DEFAULT_POLICY, reason: 'No policy returned for this role.' };
  } catch (e) { return { ...DEFAULT_POLICY, reason: `Policy not readable (${describeError(e)}). Microsoft applies the real policy when you submit.` }; }
}

export function checkRequest(body = {}) {
  const action = body.action;
  if (!['activate', 'deactivate'].includes(action)) throw fail('Invalid action.', 400);
  if (!PIM_TYPES.includes(body.type)) throw fail('Invalid type.', 400);
  const target = checkTarget(body.type, body.target);
  if (action === 'deactivate') return { type: body.type, action, target };
  const reason = String(body.reason || '').trim();
  if (!reason) throw fail('Enter a reason for the activation.', 400);
  if (reason.length > 500) throw fail('Keep the reason under 500 characters.', 400);
  const minutes = Number(body.minutes);
  if (!Number.isInteger(minutes) || minutes < 5 || minutes > 43200) throw fail('Choose a duration.', 400);
  const tn = String(body.ticket?.number || '').trim().slice(0, 100), ts = String(body.ticket?.system || '').trim().slice(0, 100);
  return { type: body.type, action, target, reason, minutes, ticket: tn ? { ticketNumber: tn, ticketSystem: ts || 'Entity 360' } : null };
}

// Submit a self-activation or self-deactivation. Returns Microsoft's request id and status (Provisioned, PendingApproval, ...).
export async function pimRequest(api, me, raw) {
  if (!me?.id || !GUID.test(me.id)) throw fail('No signed-in user object id.', 400);
  const q = checkRequest(raw), on = q.action === 'activate', t = q.target;
  const schedule = on ? { startDateTime: new Date().toISOString(), expiration: { type: 'afterDuration', duration: minutesIso(q.minutes) } } : null;
  const extra = on ? { justification: q.reason, scheduleInfo: schedule, ...(q.ticket ? { ticketInfo: q.ticket } : {}) } : {};
  try {
    if (q.type === 'Entra role') {
      const r = await api.request(`${DIR}/roleAssignmentScheduleRequests`, { method: 'POST', body: { action: on ? 'selfActivate' : 'selfDeactivate', principalId: me.id, roleDefinitionId: t.roleDefinitionId, directoryScopeId: t.directoryScopeId, ...extra } });
      return { id: r?.id || null, status: r?.status || 'Submitted', request: q };
    }
    if (q.type === 'Group') {
      const r = await api.request(`${GRP}/assignmentScheduleRequests`, { method: 'POST', body: { action: on ? 'selfActivate' : 'selfDeactivate', principalId: me.id, groupId: t.groupId, accessId: t.accessId, ...extra } });
      return { id: r?.id || null, status: r?.status || 'Submitted', request: q };
    }
    const props = { principalId: me.id, roleDefinitionId: t.roleDefinitionId, requestType: on ? 'SelfActivate' : 'SelfDeactivate', ...(on ? { justification: q.reason, scheduleInfo: { ...schedule, expiration: { type: 'AfterDuration', duration: minutesIso(q.minutes) } }, ...(t.eligibilityScheduleId ? { linkedRoleEligibilityScheduleId: t.eligibilityScheduleId } : {}), ...(q.ticket ? { ticketInfo: q.ticket } : {}) } : {}) };
    const r = await api.request(`${t.scope}/providers/Microsoft.Authorization/roleAssignmentScheduleRequests/${randomUUID()}?api-version=${ARM_VERSION}`, { origin: ARM, method: 'PUT', body: { properties: props } });
    return { id: r?.name || null, status: r?.properties?.status || 'Submitted', request: q };
  } catch (e) {
    throw Object.assign(fail(`Microsoft did not accept the ${q.action === 'activate' ? 'activation' : 'deactivation'}: ${describeError(e)}`, e.status === 401 ? 403 : e.status || 502), { pimRequest: q });
  }
}
