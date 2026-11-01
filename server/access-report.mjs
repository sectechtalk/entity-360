// On-demand access report (GOVERNANCE > Access report). For one group, one directory role or one user it reads, at
// run time and with the signed-in viewer's delegated token: group members, directory role assignments, PIM
// eligibility and activations, and last sign-in. Nothing is stored: the rows go back in the response, the browser
// builds the CSV. Not Entra Access Reviews. Read-only. One E360_AUDIT line per run (no user data in it).
import { queryUrl, describeError, fail, GUID } from './model.mjs';
import { pimTable } from './pim.mjs';

export const REPORT_KINDS = ['group', 'role', 'user'];
export const REPORT_COLUMNS = [['name', 'User'], ['upn', 'UPN'], ['objectType', 'Object type'], ['source', 'Source'], ['via', 'Group or role'], ['end', 'End date'], ['lastSignIn', 'Last sign-in (UTC)']];
export const SOURCES = { member: 'Group member', nested: 'Group member (nested)', role: 'Directory role', eligible: 'PIM eligible', active: 'PIM active' };
export const MAX_SIGNIN_LOOKUPS = 500, SIGNIN_CONCURRENCY = 6;
const DIR = '/v1.0/roleManagement/directory';
const GRP = '/v1.0/identityGovernance/privilegedAccess/group';
const typeOf = o => String(o?.['@odata.type'] || '').replace('#microsoft.graph.', '') || (o?.userPrincipalName ? 'user' : 'unknown');
const typeLabel = t => ({ user: 'User', group: 'Group', servicePrincipal: 'Service principal', device: 'Device', orgContact: 'Contact' })[t] || t;
const row = (p, source, via, end = null) => ({ id: p.id, name: p.displayName || p.id, upn: p.userPrincipalName || '', objectType: typeLabel(typeOf(p)), source, via, end: end || null, lastSignIn: null });
async function pool(items, n, fn) { let i = 0; await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => { while (i < items.length) { const k = i++; await fn(items[k]); } })); }
const sel = 'id,displayName,userPrincipalName';

// Search box: the first 20 groups, directory roles or users whose name (or UPN) starts with the text.
export async function searchScope(api, kind, raw) {
  if (!REPORT_KINDS.includes(kind)) throw fail('Pick group, role or user.');
  const q = String(raw || '').trim().replace(/'/g, "''").slice(0, 64);
  if (!q) throw fail('Type the start of a name.');
  if (kind === 'role') {
    const r = await api.pages(queryUrl(`${DIR}/roleDefinitions`, { '$select': 'id,displayName,isBuiltIn' }), { maxPages: 2 });
    return r.rows.filter(x => String(x.displayName || '').toLowerCase().startsWith(q.toLowerCase().replace(/''/g, "'"))).slice(0, 20).map(x => ({ id: x.id, name: x.displayName, detail: x.isBuiltIn ? 'Built-in role' : 'Custom role' }));
  }
  if (kind === 'group') {
    const r = await api.pages(queryUrl('/v1.0/groups', { '$filter': `startswith(displayName,'${q}')`, '$select': 'id,displayName,securityEnabled,mailEnabled', '$top': '20' }), { maxPages: 1 });
    return r.rows.slice(0, 20).map(x => ({ id: x.id, name: x.displayName, detail: x.securityEnabled ? 'Security group' : 'Microsoft 365 group' }));
  }
  const r = await api.pages(queryUrl('/v1.0/users', { '$filter': `startswith(displayName,'${q}') or startswith(userPrincipalName,'${q}')`, '$select': sel, '$top': '20' }), { maxPages: 1 });
  return r.rows.slice(0, 20).map(x => ({ id: x.id, name: x.displayName, detail: x.userPrincipalName }));
}

async function groupScope(api, id, out, problems) {
  const g = await api.request(`/v1.0/groups/${id}?$select=id,displayName`);
  const via = g.displayName || id, direct = new Set();
  try { for (const m of (await api.pages(queryUrl(`/v1.0/groups/${id}/members`, { '$select': sel }))).rows) { direct.add(m.id); out.push(row(m, SOURCES.member, via)); } }
  catch (e) { problems.push(`Group members: ${describeError(e)}`); }
  try { for (const m of (await api.pages(queryUrl(`/v1.0/groups/${id}/transitiveMembers`, { '$select': sel }))).rows) if (!direct.has(m.id) && typeOf(m) !== 'group') out.push(row(m, SOURCES.nested, via)); }
  catch (e) { problems.push(`Nested members: ${describeError(e)}`); }
  for (const [kind, eligible] of [['eligibilityScheduleInstances', true], ['assignmentScheduleInstances', false]]) {
    try {
      const r = await api.pages(queryUrl(`${GRP}/${kind}`, { '$filter': `groupId eq '${id}'`, '$expand': 'principal' }));
      for (const x of r.rows) {
        if (!eligible && String(x.assignmentType || '').toLowerCase() !== 'activated') continue; // standing members are listed above
        out.push(row(x.principal || { id: x.principalId }, eligible ? SOURCES.eligible : SOURCES.active, `${via} (${x.accessId === 'owner' ? 'owner' : 'member'})`, x.endDateTime));
      }
    } catch (e) { if (!(e.status === 400 && /ResourceTypeNotSupported/i.test(`${e.upstreamCode} ${e.upstreamMessage}`))) problems.push(`PIM for this group: ${describeError(e)}`); }
  }
  return { kind: 'group', id, name: via };
}

async function roleScope(api, id, out, problems) {
  const d = await api.request(`${DIR}/roleDefinitions/${id}?$select=id,displayName`);
  const via = d.displayName || id;
  for (const [kind, eligible] of [['roleEligibilityScheduleInstances', true], ['roleAssignmentScheduleInstances', false]]) {
    try {
      const r = await api.pages(queryUrl(`${DIR}/${kind}`, { '$filter': `roleDefinitionId eq '${id}'`, '$expand': 'principal' }));
      for (const x of r.rows) {
        const scope = x.directoryScopeId && x.directoryScopeId !== '/' ? ` (scope ${x.directoryScopeId})` : '';
        const source = eligible ? SOURCES.eligible : String(x.assignmentType || '').toLowerCase() === 'activated' ? SOURCES.active : SOURCES.role;
        out.push(row(x.principal || { id: x.principalId }, source, via + scope, x.endDateTime));
      }
    } catch (e) { problems.push(`${eligible ? 'Role eligibility' : 'Role assignments'}: ${describeError(e)}`); }
  }
  return { kind: 'role', id, name: via };
}

async function userScope(api, id, out, problems, notes) {
  const u = await api.request(`/v1.0/users/${id}?$select=${sel}`);
  try {
    const direct = new Set((await api.pages(queryUrl(`/v1.0/users/${id}/memberOf/microsoft.graph.group`, { '$select': 'id' }))).rows.map(g => g.id));
    for (const g of (await api.pages(queryUrl(`/v1.0/users/${id}/transitiveMemberOf/microsoft.graph.group`, { '$select': 'id,displayName' }))).rows) out.push(row(u, direct.has(g.id) ? SOURCES.member : SOURCES.nested, g.displayName || g.id));
  } catch (e) { problems.push(`Group memberships: ${describeError(e)}`); }
  // Directory roles and PIM: the same reads as INVESTIGATE > PIM (per-group for PIM groups).
  const p = await pimTable(api, { id, self: false });
  for (const r of p.rows) {
    if (r.type === 'Group' && r.state !== 'Eligible' && r.state !== 'Active (activated)') continue; // standing membership is listed above
    const source = r.state === 'Eligible' ? SOURCES.eligible : r.state === 'Active (activated)' ? SOURCES.active : SOURCES.role;
    out.push(row(u, source, r.type === 'Group' ? `${r.name} (${r.target?.accessId || 'member'})` : r.name + (r.scope && r.scope !== '/' ? ` (scope ${r.scopeLabel || r.scope})` : ''), r.end));
  }
  problems.push(...p.problems.map(x => `${x.source}: ${x.reason}`));
  notes.push(...p.notes.filter(n => n.startsWith('PIM groups:')));
  return { kind: 'user', id, name: u.displayName || id };
}

// Last sign-in per user (signInActivity: AuditLog.Read.All + User.Read.All, consented; the viewer also needs
// Reports Reader, Security Reader, Global Reader or similar). One GET per user, 6 at a time, capped.
async function addSignIns(api, rows, problems, notes) {
  const ids = [...new Set(rows.filter(r => r.objectType === 'User' && GUID.test(r.id)).map(r => r.id))];
  const take = ids.slice(0, MAX_SIGNIN_LOOKUPS), seen = new Map(); let refused = null;
  await pool(take, SIGNIN_CONCURRENCY, async id => {
    if (refused) return;
    try { const u = await api.request(`/v1.0/users/${id}?$select=id,signInActivity`); seen.set(id, u.signInActivity?.lastSignInDateTime || u.signInActivity?.lastNonInteractiveSignInDateTime || ''); }
    catch (e) { if ([401, 403].includes(e.status)) refused = e; else seen.set(id, ''); }
  });
  if (refused) problems.push(`Last sign-in: ${describeError(refused)}. It needs AuditLog.Read.All (consented) and a role such as Reports Reader or Global Reader on your account.`);
  for (const r of rows) if (seen.has(r.id)) r.lastSignIn = seen.get(r.id) || 'Never';
  if (ids.length > take.length) notes.push(`Last sign-in read for the first ${take.length} of ${ids.length} users.`);
}

export async function accessReport(api, rawKind, rawId) {
  const kind = String(rawKind || ''), id = String(rawId || '');
  if (!REPORT_KINDS.includes(kind)) throw fail('Pick group, role or user.');
  if (!GUID.test(id)) throw fail('Pick a group, role or user from the search results.');
  const rows = [], problems = [], notes = [], started = Date.now();
  let scope;
  try { scope = await (kind === 'group' ? groupScope(api, id, rows, problems) : kind === 'role' ? roleScope(api, id, rows, problems) : userScope(api, id, rows, problems, notes)); }
  catch (e) { throw fail(`Could not read the ${kind}: ${describeError(e)}`, e.status === 404 ? 404 : 502); }
  await addSignIns(api, rows, problems, notes);
  const order = Object.values(SOURCES);
  rows.sort((a, b) => String(a.name).localeCompare(String(b.name), undefined, { sensitivity: 'base' }) || order.indexOf(a.source) - order.indexOf(b.source) || String(a.via).localeCompare(String(b.via)));
  return { scope, rows, problems: [...new Set(problems)], notes, readAt: new Date().toISOString(), ms: Date.now() - started };
}

// The audit line: who ran it, the kind of scope, the group or role id (never a user's id), row count, outcome.
export function auditLine({ requester, kind, scopeId, rows, outcome, ms, error }) {
  return 'E360_AUDIT ' + JSON.stringify({ type: 'access-report', time: new Date().toISOString(), requester: { upn: requester?.upn || null, objectId: requester?.objectId || null }, scope: kind, scopeId: kind === 'user' ? null : scopeId || null, rows: rows ?? null, outcome, ms: ms ?? null, error: error ? String(error).slice(0, 300) : null });
}
