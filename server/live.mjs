import { SOURCE, GUID, fail, describeError, odata, queryUrl, entityLink, policyLink, finishReport } from './model.mjs';
import { evaluateConditionalAccess, caApps, resourceGraph, roleAssignmentQuery, SUBSCRIPTIONS_QUERY, pimTiming } from './access.mjs';

const GRAPH = 'https://graph.microsoft.com';
const ARM = 'https://management.azure.com';
const LOGS = 'https://api.loganalytics.azure.com';
const REQUEST_ORIGINS = new Set([GRAPH, ARM, LOGS]);
import { claimsChallenge } from './authflow.mjs';
import { accessPackages } from './entitlements.mjs';
// Graph wraps some errors (PIM UnknownError) as JSON inside error.message; surface the inner code and text.
const innerError = err => { try { const j = JSON.parse(err?.message); return j?.error || j; } catch { return null; } };
export const innerCode = err => { const i = innerError(err); return i?.code && err?.code === 'UnknownError' ? `${err.code}: ${i.code}` : err?.code; };
export const upstreamText = err => { const i = innerError(err); return String(i?.message || err?.message || '').slice(0, 300) || undefined; };
// Node's fetch (undici) sends "Accept-Language: *" by default. Graph roleManagement (PIM) and some ARM providers parse it as a
// .NET culture and fail with HTTP 400 CultureNotFoundException, so every Graph/ARM/Logs call sends an explicit culture.
export const requestHeaders = token => ({ Authorization: `Bearer ${token}`, Accept: 'application/json', 'Accept-Language': 'en-US', 'Content-Type': 'application/json', ConsistencyLevel: 'eventual' });
// Error bodies: JSON when possible; otherwise keep the raw text so a bare 400 still says why.
export async function readBody(response) {
  if (typeof response.text !== 'function') return response.json().catch(() => ({}));
  const text = await response.text().catch(() => '');
  if (!text) return {};
  try { return JSON.parse(text); } catch { return response.ok ? {} : { error: { code: `HTTP${response.status}`, message: text.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 300) } }; }
}
export class MicrosoftApi {
  constructor(tokenFor, { fetcher = fetch, maxPages = 10 } = {}) { this.tokenFor = tokenFor; this.fetcher = fetcher; this.maxPages = maxPages; this.claimsChallenged = false; }
  async request(path, { method = 'GET', body, origin = GRAPH } = {}) {
    const url = new URL(path, origin);
    if (!REQUEST_ORIGINS.has(url.origin) || url.username || url.password) throw fail('Unsupported upstream URL.', 502);
    const token = await this.tokenFor(url.origin === ARM ? 'azure' : url.origin === LOGS ? 'logs' : 'graph');
    for (let attempt = 0; attempt < 3; attempt++) {
      let response;
      try {
        response = await this.fetcher(url, { method, redirect: 'error', signal: AbortSignal.timeout(25000), headers: requestHeaders(token), ...(body ? { body: JSON.stringify(body) } : {}) });
      } catch (e) { throw Object.assign(fail('The source could not be reached. Try again.', 502), { reason: e?.name === 'TimeoutError' ? 'timed out after 25 seconds' : 'the service could not be reached' }); }
      // Honor Retry-After up to 60 seconds; at most two retries keep the total wait bounded.
      if ((response.status === 429 || response.status === 503) && attempt < 2) {
        const delay = Math.min(60, Math.max(1, Number(response.headers.get('retry-after')) || 1));
        await new Promise(resolve => setTimeout(resolve, delay * 1000));
        continue;
      }
      const data = await readBody(response);
      if (!response.ok) {
        const upstreamMessage = upstreamText(data.error);
        const claims = response.status === 401 ? claimsChallenge(response.headers.get('www-authenticate')) : null;
        if (claims) this.claimsChallenged = true;
        // Azure or Log Analytics rejecting a token is not a sign-out: report it as a reconnect (403), so the app keeps the session.
        if (response.status === 401 && url.origin !== GRAPH) throw Object.assign(fail(`${url.origin === LOGS ? 'Log Analytics' : 'Azure'} rejected the access token. Reconnect Azure${claims ? ' to complete the extra verification' : ''}.`, 403), { upstreamCode: data.error?.code, upstreamMessage, claims, reconnect: true });
        throw Object.assign(fail(response.status === 403 ? 'Access not granted.' : claims ? 'Additional sign-in verification is required.' : 'The source query could not be completed.', response.status), { upstreamCode: innerCode(data.error), upstreamMessage, claims });
      }
      if (data.error) throw fail('The source returned an incomplete result.', 502);
      return data;
    }
  }
  async pages(path, options) {
    let url = path, rows = [], page = 0;
    while (url && page < this.maxPages) {
      const data = await this.request(url, options);
      rows.push(...(data.value || []));
      url = data['@odata.nextLink'] || data.nextLink;
      page++;
    }
    return { rows, truncated: Boolean(url) };
  }
}
export function normalizeEntity(row, tenant) {
  const type = row.userPrincipalName ? 'user' : row.servicePrincipalType === 'ManagedIdentity' ? 'managedIdentity' : 'application';
  const entity = { id: row.id, name: row.displayName || row.userPrincipalName || row.id, type, subtitle: row.userPrincipalName || row.appId || row.id, appId: row.appId, enabled: row.accountEnabled, department: row.department, tenant, credentials: [...(row.passwordCredentials || []), ...(row.keyCredentials || [])].map(c => ({ id: c.keyId, name: c.displayName || c.type || 'Credential', expires: c.endDateTime })) };
  entity.link = entityLink(entity);
  return entity;
}
export async function searchLive(api, query, tenant) {
  const q = odata(query.trim());
  if (q.length < 2) return { entities: [], partial: false };
  const userFilter = GUID.test(query) ? `id eq '${q}'` : `startsWith(displayName,'${q}') or startsWith(userPrincipalName,'${q}')`;
  const appFilter = GUID.test(query) ? `id eq '${q}' or appId eq '${q}'` : `startsWith(displayName,'${q}')`;
  const results = await Promise.allSettled([
    api.request(queryUrl('/v1.0/users', { '$filter': userFilter, '$select': 'id,displayName,userPrincipalName,accountEnabled,department', '$top': '25' })),
    api.request(queryUrl('/v1.0/servicePrincipals', { '$filter': appFilter, '$select': 'id,displayName,appId,servicePrincipalType,accountEnabled', '$top': '25' })),
  ]);
  const available = results.filter(r => r.status === 'fulfilled');
  if (!available.length) throw fail('No authorized entity search is available. Check your sign-in and delegated directory permissions.', 403);
  return { entities: available.flatMap(r => r.value.value || []).map(e => normalizeEntity(e, tenant)), partial: results.some(r => r.status === 'rejected' && ![401, 403].includes(r.reason.status)) || available.some(r => r.value['@odata.nextLink']) };
}


const ZERO = '00000000-0000-0000-0000-000000000000';
export const appRoleName = (sp, roleId) => !roleId || roleId === ZERO ? 'Default Access' : (sp?.appRoles || []).find(r => r.id === roleId)?.displayName || `App role ${roleId} (name not readable)`;
export const assignmentLink = a => `https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AssignmentDetailBlade/objectId/${a.principalId}/isUser~/${a.principalType === 'User'}/assignmentObjectId/${a.id}/spObjectId/${a.resourceId}/principalId/${a.principalId}`;
export const permissionsLink = (spId, appId) => `https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ManagedAppMenuBlade/~/Permissions/objectId/${spId}/appId/${appId || ''}`;
// Directory role scopes: '/' is tenant-wide, '/administrativeUnits/{id}' an AU, '/{objectId}' a single app registration or service principal.
export async function resolveScopes(api, policies, report) {
  const names = new Map();
  const lookup = scope => {
    if (names.has(scope)) return names.get(scope);
    let p;
    const au = scope.match(/^\/administrativeUnits\/([0-9a-f-]{36})$/i), obj = scope.match(/^\/([0-9a-f-]{36})$/i);
    if (!scope || scope === '/') p = Promise.resolve({ name: 'Directory (tenant-wide)' });
    else if (au) p = api.request(`/v1.0/directory/administrativeUnits/${au[1]}?$select=displayName`).then(x => ({ name: `Administrative unit: ${x.displayName}`, link: `https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AdministrativeUnitMenuBlade/~/Overview/objectId/${au[1]}` }), e => ({ name: `Administrative unit ${au[1]}`, note: e.status === 403 ? 'name needs AdministrativeUnit.Read.All' : null }));
    else if (obj) p = api.request(`/v1.0/directoryObjects/${obj[1]}?$select=id,displayName`).then(x => ({ name: `${String(x['@odata.type'] || '').includes('application') ? 'App registration' : 'Object'}: ${x.displayName}` }), () => ({ name: `Object ${obj[1]}` }));
    else p = Promise.resolve({ name: scope });
    names.set(scope, p); return p;
  };
  for (const pol of policies) {
    const scope = pol.evidence?.directoryScopeId || '/';
    const r = await lookup(scope);
    pol.scopeName = r.name; if (r.link) pol.scopeLink = r.link;
    if (r.note && report && !report.unavailable.some(u => u.reason === r.note)) report.unavailable.push({ source: 'Entra roles & PIM', reason: r.note });
  }
}
// PIM schedule instances can fail with HTTP 400 (Graph UnknownError) for some principals; the plain assignment
// or schedule list needs the same RoleManagement.Read.Directory scope, so fall back to it instead of losing the roles.
export async function withFallback(api, primary, fallback, report, label) {
  try { return await api.pages(primary); }
  catch (error) {
    if (error.status !== 400) throw error;
    const result = await api.pages(fallback);
    const note = `${label}: Microsoft rejected the PIM schedule query (${describeError(error)}); used the standard role list instead, so PIM start and end times may be missing.`;
    if (report && !report.notes.includes(note)) report.notes.push(note);
    return result;
  }
}
export async function liveReport(api, id, type, range, { tenant, beta = false, azure = false, logs = false, workspaceIds = [], telemetryRoles = {} } = {}) {
  if (!GUID.test(id) || !['user', 'application', 'managedIdentity'].includes(type)) throw fail('Invalid entity identifier.');
  const collection = type === 'user' ? 'users' : 'servicePrincipals';
  const rawEntity = await api.request(`/v1.0/${collection}/${id}`);
  const entity = normalizeEntity(rawEntity, tenant);
  const report = { mode: 'live', entity, range, sources: [], events: [], policies: [], relationships: [], notes: [], partial: false, partialReasons: [], unavailable: [] };
  const flag = (source, reason) => { report.partial = true; if (!report.partialReasons.some(r => r.source === source && r.reason === reason)) report.partialReasons.push({ source, reason }); };
  report.flag = flag;
  const sourceMap = new Map();
  const addSource = sourceId => {
    if (!sourceMap.has(sourceId)) sourceMap.set(sourceId, { ...SOURCE[sourceId], status: 'Connected', count: 0, scope: 'Current viewer’s authorized scope', coverage: `${range.from} → ${range.to}`, freshness: new Date().toISOString(), note: 'Only retained, collected records are available. An empty result does not prove no activity.' });
    return sourceMap.get(sourceId);
  };
  const run = async (sourceId, operation, consume, label) => {
    try {
      const result = await operation();
      const source = addSource(sourceId);
      if (result.truncated) { flag(source.name, result.limit || 'page limit reached (1,000 records); narrow the timeframe'); source.status = 'Partial'; source.note = 'Page limit reached. Narrow the timeframe to retrieve the remaining records.'; }
      await consume(result.rows ?? result, source);
      return result;
    } catch (error) {
      // label names the exact call, so the banner says which directory query failed and which scope it needs.
      const name = `${SOURCE[sourceId]?.name || sourceId}${label ? ` (${label})` : ''}`;
      if (![401, 403, 404].includes(error.status)) {
        flag(name, describeError(error));
        if (sourceMap.has(sourceId)) { sourceMap.get(sourceId).status = 'Partial'; sourceMap.get(sourceId).note = `One query failed: ${describeError(error)}. These results are incomplete; try again.`; }
      } else if (!report.unavailable.some(u => u.source === name)) report.unavailable.push({ source: name, reason: describeError(error) });
      return null;
    }
  };
  addSource('directory').coverage = 'Current configuration snapshot';
  const groupIds = new Set();
  const directGroupIds = new Set();
  const groupNames = new Map();
  await run('directory', () => api.pages(`/v1.0/${collection}/${id}/transitiveMemberOf/microsoft.graph.group?$select=id,displayName`), rows => {
    for (const g of rows) { groupIds.add(g.id); groupNames.set(g.id, g.displayName || g.id); report.relationships.push({ name: g.displayName || g.id, kind: 'Group', relation: 'Transitive membership', source: 'directory', objectId: g.id }); }
  }, 'group memberships');
  await run('directory', () => api.pages(`/v1.0/${collection}/${id}/memberOf/microsoft.graph.group?$select=id,displayName`), rows => rows.forEach(g => directGroupIds.add(g.id)), 'direct groups');
  const startEnd = `createdDateTime ge ${range.from} and createdDateTime le ${range.to}`;
  const signInFilter = type === 'user'
    ? `${startEnd} and userId eq '${id}'${beta ? " and signInEventTypes/any(t:t eq 'interactiveUser' or t eq 'nonInteractiveUser')" : ''}`
    : `${startEnd} and servicePrincipalId eq '${id}' and signInEventTypes/any(t:t eq '${type === 'managedIdentity' ? 'managedIdentity' : 'servicePrincipal'}')`;
  const tasks = [];
  if (type === 'user' || beta) tasks.push(run('signin', () => api.pages(queryUrl(`/${beta ? 'beta' : 'v1.0'}/auditLogs/signIns`, { '$filter': signInFilter, '$top': '100' })), (rows, source) => {
    source.note = beta ? 'Includes requested sign-in event types through Microsoft Graph beta (preview).' : 'Microsoft Graph v1.0 interactive user sign-ins. Noninteractive and workload sign-ins require the optional beta connector.';
    report.events.push(...rows.map(s => ({
      id: s.id, time: s.createdDateTime, category: 'Sign-ins', title: `${s.appDisplayName || s.resourceDisplayName || 'Application'} sign-in`, result: s.status?.errorCode === 0 ? 'Success' : s.conditionalAccessStatus === 'failure' ? 'Blocked' : 'Failed', source: 'signin', actor: entity.name, target: s.resourceDisplayName || s.appDisplayName, direction: 'Actor', ip: s.ipAddress, correlationId: s.correlationId, explanation: s.status?.failureReason || 'See the recorded sign-in result and policy evaluations.',
      link: SOURCE.signin.url, linkLabel: 'Open sign-in logs', query: `Record ID: ${s.id}\nCorrelation ID: ${s.correlationId || 'Unavailable'}\nTime: ${s.createdDateTime}\nEntity: ${id}`,
      evaluatedPolicies: (s.appliedConditionalAccessPolicies || []).map(p => ({ id: p.id, name: p.displayName, status: p.result, detail: (p.enforcedGrantControls || []).join(', '), link: policyLink(p.id), linkLabel: 'Open policy' })),
      policyEvidence: s.appliedConditionalAccessPolicies === undefined ? 'Policy evaluation details were not supplied by the source.' : undefined,
      evidence: s,
    })));
  }));
  else report.notes.push('Workload sign-in collection is disabled. Enable the optional Graph beta connector to query these records.');
  const auditTime = `activityDateTime ge ${range.from} and activityDateTime le ${range.to}`;
  const actorFilter = type === 'user' ? `initiatedBy/user/id eq '${id}'` : `initiatedBy/app/appId eq '${odata(entity.appId || '')}'`;
  for (const [direction, filter] of [['Actor', actorFilter], ['Target', `targetResources/any(t:t/id eq '${id}')`]]) {
    tasks.push(run('audit', () => api.pages(queryUrl('/v1.0/auditLogs/directoryAudits', { '$filter': `${auditTime} and ${filter}`, '$top': '100' })), rows => {
      for (const a of rows) {
        const existing = report.events.find(e => e.source === 'audit' && e.id === a.id);
        if (existing) { existing.direction = 'Actor & Target'; continue; }
        report.events.push({ id: a.id, time: a.activityDateTime, category: 'Changes', service: a.loggedByService || 'Core Directory', auditCategory: a.category, title: a.activityDisplayName, result: a.result === 'success' ? 'Success' : a.result === 'failure' ? 'Failed' : 'Observed', source: 'audit', actor: a.initiatedBy?.user?.displayName || a.initiatedBy?.app?.displayName || 'Unknown', target: (a.targetResources || []).map(t => t.displayName || t.id).join(', '), direction, explanation: a.resultReason || 'Directory audit evidence.', correlationId: a.correlationId, link: SOURCE.audit.url, linkLabel: 'Open directory audit', query: `Record ID: ${a.id}\nTime: ${a.activityDateTime}`, evaluatedPolicies: [], evidence: a });
      }
    }));
  }
  tasks.push((async () => {
    // The policy list is used only for names, deep links and spotting policies whose inputs e360 cannot supply.
    const listed = await api.pages('/v1.0/identity/conditionalAccess/policies').catch(() => null);
    await run('policies', async () => ({ rows: (await evaluateConditionalAccess(api, { id, type: type === 'user' ? 'user' : 'servicePrincipal', policies: listed?.rows || null })).rows, truncated: Boolean(listed?.truncated) }), (rows, source) => {
      source.coverage = `Microsoft What If evaluation for: ${caApps().map(a => a.name).join(', ')}`;
      source.note = `Evaluated by Microsoft (Conditional Access What If), not by e360. Device platform, location, device state, client app and risk are not supplied, so a policy that depends on them is shown as Incomplete instead of not applying.${listed ? '' : ' The policy list was not readable, so Incomplete policies cannot be shown.'}`;
      for (const p of rows) report.policies.push({ id: p.id, name: p.name, kind: 'Conditional Access', result: p.result, state: p.state, status: p.result === 'Incomplete' ? 'Incomplete' : p.state, assignment: p.result === 'Incomplete' ? `Incomplete: ${p.missing.join(', ')} unknown` : `Applies to ${p.apps.join(', ')}`, detail: `Grant controls: ${p.grant.join(', ') || 'See policy'}.${p.result === 'Applies' && p.missing.length ? ` Also depends on ${p.missing.join(', ')}, which were not supplied.` : ''}`, source: 'policies', link: policyLink(p.id), linkLabel: 'Open policy', evidence: p.evidence });
      // Enabled policies Microsoft did not return for these apps are listed as Does not apply so the Access page shows the full set.
      const seenCa = new Set(rows.map(p => p.id));
      for (const p of listed?.rows || []) if (p && p.state !== 'disabled' && !seenCa.has(p.id)) report.policies.push({ id: p.id, name: p.displayName || p.id, kind: 'Conditional Access', result: 'Does not apply', state: p.state, status: p.state, assignment: `Does not apply to ${caApps().map(a => a.name).join(', ')} for this identity (Microsoft What If)`, detail: '', source: 'policies', link: policyLink(p.id), linkLabel: 'Open policy', evidence: p });
    });
  })());
  const principals = [id, ...directGroupIds].slice(0, 25);
  if (directGroupIds.size > 24) { flag('Entra roles & PIM', `role inheritance checked for the first 24 of ${directGroupIds.size} direct groups`); report.notes.push('Role inheritance checks are limited to the first 24 direct groups.'); }
  tasks.push((async () => {
    // Active roles come from schedule instances so PIM elevations show their granted duration and time remaining.
    for (const principal of principals) {
      const group = principal === id ? null : groupNames.get(principal) || principal;
      await run('roles', () => withFallback(api, queryUrl('/v1.0/roleManagement/directory/roleAssignmentScheduleInstances', { '$filter': `principalId eq '${principal}'`, '$expand': 'roleDefinition' }), queryUrl('/v1.0/roleManagement/directory/roleAssignments', { '$filter': `principalId eq '${principal}'`, '$expand': 'roleDefinition' }), report, 'Entra roles & PIM'), rows => {
        for (const r of rows) { const t = pimTiming(r.startDateTime, r.endDateTime); report.policies.push({ id: r.id, name: r.roleDefinition?.displayName || r.roleDefinitionId, kind: 'Role', status: r.assignmentType === 'Activated' ? 'Active (PIM elevation)' : 'Active', assignment: group ? `Through ${group}` : 'Direct directory role', detail: `Directory scope: ${r.directoryScopeId || '/'}. ${t.text}.`, timing: t, source: 'roles', link: SOURCE.roles.url, linkLabel: 'Open Entra roles', evidence: r }); }
      });
      await run('roles', () => withFallback(api, queryUrl('/v1.0/roleManagement/directory/roleEligibilityScheduleInstances', { '$filter': `principalId eq '${principal}'`, '$expand': 'roleDefinition' }), queryUrl('/v1.0/roleManagement/directory/roleEligibilitySchedules', { '$filter': `principalId eq '${principal}'`, '$expand': 'roleDefinition' }), report, 'Entra roles & PIM'), rows => {
        for (const r of rows) report.policies.push({ id: r.id, name: r.roleDefinition?.displayName || r.roleDefinitionId, kind: 'Role', status: 'Eligible', assignment: group ? `PIM eligibility through ${group}` : 'Direct PIM eligibility', detail: `Scope: ${r.directoryScopeId || '/'}. ${r.endDateTime ? `Eligibility ends ${r.endDateTime}` : 'Permanent eligibility'}.`, source: 'roles', link: SOURCE.roles.url, linkLabel: 'Open PIM', evidence: r });
      });
    }
    await resolveScopes(api, report.policies.filter(p => p.source === 'roles'), report);
  })());
  // Access packages (entitlement management): read-only, user identities only.
  if (type === 'user') tasks.push(run('governance', () => accessPackages(api, id), (rows, source) => {
    source.coverage = 'Current assignments snapshot';
    report.accessPackages = { packages: rows, requests: [] };
  }, 'access packages').then(r => { if (r && report.accessPackages) { report.accessPackages.requests = r.requests; if (r.requestsNote) report.unavailable.push({ source: 'Entitlement management (requests)', reason: describeError(r.requestsNote) }); } }));
  // App role assignments: direct, plus through direct groups (Entra does not honour nested groups for app roles).
  const spCache = new Map();
  const resourceSp = rid => { if (!spCache.has(rid)) spCache.set(rid, api.request(`/v1.0/servicePrincipals/${rid}?$select=id,appId,displayName,appRoles`).catch(() => null)); return spCache.get(rid); };
  const assignmentRows = async (rows, viaGroup) => {
    for (const a of rows) {
      const sp = await resourceSp(a.resourceId);
      const role = appRoleName(sp, a.appRoleId);
      const isUser = a.principalType === 'User';
      const link = type === 'user' ? assignmentLink(a) : `https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ManagedAppMenuBlade/~/Permissions/objectId/${id}/appId/${entity.appId || ''}`;
      report.policies.push({ id: a.id, name: a.resourceDisplayName || sp?.displayName || a.resourceId, kind: type === 'user' ? 'Application assignment' : 'API permission', status: type === 'user' ? 'Assigned' : 'Granted', role, assignment: type === 'user' ? (viaGroup ? `Through ${viaGroup}` : (isUser ? 'Direct' : `Through ${a.principalDisplayName}`)) : 'Application permission (app-only)', date: a.createdDateTime || null, detail: `Resource app: ${sp?.displayName || a.resourceId}`, source: 'directory', link, linkLabel: type === 'user' ? 'Open assignment' : 'Open app permissions', evidence: a });
    }
  };
  tasks.push(run('directory', () => api.pages(`/v1.0/${collection}/${id}/appRoleAssignments`), rows => assignmentRows(rows, null), 'app role assignments'));
  if (type === 'user') {
    for (const gid of [...directGroupIds].slice(0, 24)) tasks.push(run('directory', () => api.pages(`/v1.0/groups/${gid}/appRoleAssignments`), rows => assignmentRows(rows, groupNames.get(gid) || gid), 'group app role assignments'));
    // Delegated consents this user gave (or that an admin gave on their behalf). Tenant-wide admin consents are on each app's Permissions blade.
    tasks.push(run('directory', () => api.pages(queryUrl('/v1.0/oauth2PermissionGrants', { '$filter': `principalId eq '${id}'` })), async rows => {
      for (const g of rows) {
        const [client, res] = await Promise.all([resourceSp(g.clientId), resourceSp(g.resourceId)]);
        report.policies.push({ id: g.id, name: client?.displayName || g.clientId, kind: 'Delegated permission', status: 'Consented', role: (g.scope || '').trim() || 'No scopes', assignment: 'Consent for this user only', date: null, detail: `To ${res?.displayName || g.resourceId}. Microsoft Graph does not record when a delegated consent was granted.`, source: 'directory', link: permissionsLink(g.clientId, client?.appId), linkLabel: 'Open app permissions', evidence: g });
      }
    }, 'delegated consents'));
  }
  if (type !== 'user') {
    tasks.push(run('directory', () => api.pages(`/v1.0/servicePrincipals/${id}/owners?$select=id,displayName`), rows => {
      for (const o of rows) report.relationships.push({ name: o.displayName || o.id, kind: 'Owner', relation: 'Owns this application', objectId: o.id, source: 'directory' });
    }, 'owners'));
    tasks.push(run('directory', () => api.pages(queryUrl('/v1.0/oauth2PermissionGrants', { '$filter': `clientId eq '${id}'` })), rows => {
      for (const g of rows) report.policies.push({ id: g.id, name: g.scope || 'Delegated consent', kind: 'Delegated permission', status: 'Consented', role: (g.scope || '').trim() || 'No scopes', assignment: g.consentType === 'AllPrincipals' ? 'Admin consent for all users' : `Consent for one user (${g.principalId})`, date: null, detail: `Resource service principal: ${g.resourceId}. Microsoft Graph does not record when a delegated consent was granted.`, source: 'directory', link: permissionsLink(id, entity.appId), linkLabel: 'Open app permissions', evidence: g });
    }, 'delegated consents'));
    if (entity.appId) tasks.push(run('directory', () => api.pages(queryUrl('/v1.0/applications', { '$filter': `appId eq '${odata(entity.appId)}'`, '$select': 'id,displayName,passwordCredentials,keyCredentials' })), rows => {
      for (const app of rows) for (const c of [...(app.passwordCredentials || []), ...(app.keyCredentials || [])]) report.policies.push({ id: c.keyId, name: c.displayName || c.type || 'Application credential', kind: 'Credential', status: new Date(c.endDateTime) < new Date() ? 'Expired' : 'Configured', role: c.type === 'AsymmetricX509Cert' || c.usage ? 'Certificate' : 'Client secret', date: c.startDateTime || null, assignment: 'App registration credential metadata', detail: `Expires ${c.endDateTime}. Registration object: ${app.id}`, source: 'directory', link: `https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/${entity.appId}`, linkLabel: 'Open credentials' });
    }, 'app registration credentials'));
  }
  if (type === 'user') {
    tasks.push(run('intune', () => api.pages(queryUrl(`/v1.0/users/${id}/managedDevices`, { '$select': 'id,deviceName,complianceState,operatingSystem,lastSyncDateTime,azureADDeviceId' })), async (rows, source) => {
      source.coverage = 'Current managed device results';
      source.note = 'Devices associated with the user. Per-device compliance and configuration states load only when you open a device (Load policy states).';
      for (const d of rows) {
        const link = `https://intune.microsoft.com/#view/Microsoft_Intune_Devices/DeviceSettingsMenuBlade/~/overview/mdmDeviceId/${d.id}`;
        report.relationships.push({ name: d.deviceName, kind: d.operatingSystem, relation: `Device · ${d.complianceState}`, source: 'intune', link });
        report.policies.push({ id: d.id, name: d.deviceName, kind: 'Device', status: d.complianceState, assignment: 'Managed device associated with user', detail: `Last synchronized: ${d.lastSyncDateTime}`, source: 'intune', link, linkLabel: 'Open device', evidence: d, deviceId: d.id, lazyStates: true });
      }
    }));
    // Defender process events load on the Defender tab only (GET /api/defender), so they are not part of this report.
  }
  if (azure) tasks.push(collectAzure(api, entity, groupIds, range, run, report));
  if (logs) tasks.push(collectWorkspaceLogs(api, entity, range, workspaceIds, telemetryRoles, run, report));
  await Promise.all(tasks);
  delete report.flag;
  report.sources = [...sourceMap.values()];
  for (const source of report.sources) source.count = report.events.filter(e => e.source === source.id).length;
  if (report.partial) report.notes.push('Some queries are incomplete. Coverage details describe known limits; no complete activity claim is made.');
  report.notes.push('Live coverage is limited to the connectors and scopes listed here. This release does not collect every monitoring or configuration surface. The setup guide lists implementation coverage separately.');
  return finishReport(report);
}

export function workspaceQueries(entity, range, roleNames = []) {
  const literal = value => JSON.stringify(String(value));
  const time = `| where TimeGenerated between (datetime(${range.from}) .. datetime(${range.to}))`;
  const cap = '| order by TimeGenerated desc | take 1000';
  const entityFilter = entity.type === 'user' ? `UserId == ${literal(entity.id)}` : `ServicePrincipalId == ${literal(entity.id)}${entity.appId ? ` or AppId == ${literal(entity.appId)}` : ''}`;
  const result = [{ source: 'graphLogs', table: 'MicrosoftGraphActivityLogs', category: 'API', query: `MicrosoftGraphActivityLogs\n${time}\n| where ${entityFilter}\n${cap}` }];
  if (entity.type === 'user') result.push({ source: 'office', table: 'OfficeActivity', category: 'Data access', query: `OfficeActivity\n${time}\n| where UserId =~ ${literal(entity.subtitle)} or UserKey == ${literal(entity.id)}\n${cap}` });
  const traceFilter = entity.type === 'user' ? `UserAuthenticatedId == ${literal(entity.id)} or UserAuthenticatedId =~ ${literal(entity.subtitle)}` : roleNames.length ? `AppRoleName in (${roleNames.map(literal).join(', ')})` : null;
  if (traceFilter) for (const table of ['AppRequests', 'AppDependencies']) result.push({ source: 'insights', table, category: 'API', query: `${table}\n${time}\n| where ${traceFilter}\n${cap}` });
  return result;
}

async function collectWorkspaceLogs(api, entity, range, workspaceIds, telemetryRoles, run, report) {
  const roles = Array.isArray(telemetryRoles[entity.id]) ? telemetryRoles[entity.id].filter(r => typeof r === 'string').slice(0, 20) : [];
  const queries = workspaceQueries(entity, range, roles);
  for (const workspace of workspaceIds.filter(id => GUID.test(id)).slice(0, 5)) {
    // Each table query establishes its own access; a workspace listing alone is insufficient.
    await Promise.all(queries.map(item => run(item.source, async () => {
      const data = await api.request(`/v1/workspaces/${workspace}/query`, { origin: LOGS, method: 'POST', body: { query: item.query, timespan: `${range.from}/${range.to}` } });
      const table = data.tables?.find(t => t.name === 'PrimaryResult');
      if (!table) throw fail('No primary query result.', 502);
      const rows = table.rows.map(row => Object.fromEntries(table.columns.map((col, i) => [col.name, row[i]])));
      return { rows, truncated: rows.length >= 1000 };
    }, (rows, source) => {
      source.note = 'Configured workspaces only; maximum 1,000 records per table and workspace. Identity matches depend on fields populated by the originating service.';
      source.scope = 'Authorized tables in explicitly configured workspaces';
      for (let i = 0; i < rows.length; i++) {
        const r = rows[i];
        let title, result, target, explanation;
        if (item.source === 'graphLogs') {
          title = `${r.RequestMethod || 'Request'} ${r.RequestUri || 'Microsoft Graph'}`;
          result = Number(r.ResponseStatusCode) >= 400 ? 'Failed' : Number(r.ResponseStatusCode) >= 200 && Number(r.ResponseStatusCode) < 400 ? 'Success' : 'Observed';
          target = r.RequestUri;
          explanation = `Microsoft Graph request telemetry; HTTP ${r.ResponseStatusCode}.`;
        } else if (item.source === 'office') {
          title = r.Operation || 'Microsoft 365 operation'; target = r.OfficeObjectId || r.Site_Url || r.OfficeWorkload;
          const status = String(r.ResultStatus || '').toLowerCase();
          result = ['succeeded', 'success', 'true'].includes(status) ? 'Success' : ['failed', 'failure', 'false'].includes(status) ? 'Failed' : 'Observed';
          explanation = 'Microsoft 365 audit evidence ingested into the configured workspace. An absent result status remains Observed.';
        } else {
          title = `${item.table === 'AppDependencies' ? 'Dependency' : 'Request'}: ${r.Name || r.OperationName || 'Application call'}`;
          target = r.Target || r.Url || r.AppRoleName;
          result = r.Success === true || r.Success === 'True' ? 'Success' : r.Success === false || r.Success === 'False' ? 'Failed' : 'Observed';
          explanation = `Instrumented ${item.table === 'AppDependencies' ? 'downstream dependency' : 'request'}; ${r.DurationMs ?? 'unknown'} ms. ${entity.type === 'user' ? 'Matched by application-supplied authenticated-user field.' : 'Matched through the configured application-role mapping; this does not prove which credential executed the request.'}`;
        }
        report.events.push({ id: `${workspace}-${item.table}-${r.Id || r.RequestId || r.OfficeId || i}-${r.TimeGenerated}`, time: new Date(r.TimeGenerated).toISOString(), category: item.category, title, result, source: item.source, actor: r.UserId || r.AppRoleName || entity.name, target, direction: 'Actor', explanation, ip: r.IPAddress || r.ClientIP, correlationId: r.OperationId || r.RequestId, link: SOURCE[item.source].url, linkLabel: 'Open Log Analytics', query: `// Workspace ID: ${workspace}\n${item.query}`, evaluatedPolicies: [], evidence: r });
      }
    })));
  }
}

// assignedTo() includes group-based PIM; if a subscription rejects it (HTTP 400), retry with the direct principalId filter.
export async function azurePim(api, subscriptionId, kind, principal, { self = false } = {}) {
  const url = filter => queryUrl(`/subscriptions/${subscriptionId}/providers/Microsoft.Authorization/${kind}`, { 'api-version': '2020-10-01', '$filter': filter });
  // asTarget() = the signed-in caller (direct and group); works without directory read rights. assignedTo() is for other principals.
  try { return await api.pages(url(self ? 'asTarget()' : `assignedTo('${principal}')`), { origin: ARM }); }
  catch (error) { if (error.status !== 400) throw error; return api.pages(url(`principalId eq '${principal}'`), { origin: ARM }); }
}
async function collectAzure(api, entity, groupIds, range, run, report) {
  // One Azure Resource Graph query replaces the per-subscription IAM loop: every readable subscription and management group, no cap.
  const principals = [entity.id, ...groupIds];
  if (principals.length > 500) { report.flag('Azure Monitor & IAM', 'Azure role lookup capped at the entity and its first 499 groups'); report.notes.push('Azure role lookup covers the entity and its first 499 groups.'); }
  await run('azure', () => resourceGraph(api, roleAssignmentQuery(principals)), (rows, source) => {
    source.coverage = 'Current Azure RBAC assignments (Azure Resource Graph)';
    source.note = 'Current Azure role assignments for the entity and its groups across every subscription and management group you can read. The activity log is not loaded with the page; use Load activity log (on demand). Deny assignments and effective access are not evaluated.';
    for (const r of rows) report.policies.push({ id: r.id, name: r.roleName || r.roleGuid, kind: 'Role', status: 'Active', assignment: r.principalId === entity.id.toLowerCase() ? 'Direct Azure role assignment' : 'Through group membership', detail: `Scope: ${r.scope}${r.condition ? `; condition: ${r.condition}` : ''}.`, source: 'azure', link: `https://portal.azure.com/#@${entity.tenant}/resource${r.scope}/users`, linkLabel: 'Open scope IAM', evidence: r });
  });
  if (entity.type !== 'user') return;
  // Azure PIM has no tenant-wide query, so schedules are read per subscription with assignedTo(), which includes group-based access.
  let skipped = 0, failed = 0; const failures = [];
  await run('azure', async () => {
    const subs = (await resourceGraph(api, SUBSCRIPTIONS_QUERY)).rows;
    const capped = subs.slice(0, AZURE_PIM_SUBSCRIPTIONS);
    skipped = subs.length - capped.length;
    const rows = [];
    for (let i = 0; i < capped.length; i += 5) {
      await Promise.all(capped.slice(i, i + 5).flatMap(s => ['roleAssignmentScheduleInstances', 'roleEligibilityScheduleInstances'].map(kind =>
        azurePim(api, s.subscriptionId, kind, entity.id)
          .then(r => rows.push(...r.rows.map(x => ({ ...x, pimKind: kind }))), e => { if ([401, 403].includes(e.status)) { report.unavailable.push({ source: 'Azure PIM', reason: `${s.name || s.subscriptionId}: ${describeError(e)}` }); return; } failed++; failures.push(`${s.name || s.subscriptionId}: ${describeError(e)}`); }))));
    }
    return { rows, truncated: false };
  }, rows => {
    if (skipped) { report.flag('Azure PIM', `${skipped} subscriptions beyond the first ${AZURE_PIM_SUBSCRIPTIONS} were skipped`); report.notes.push(`Azure PIM schedules were read for the first ${AZURE_PIM_SUBSCRIPTIONS} subscriptions; ${skipped} more were skipped (set E360_AZURE_PIM_SUBSCRIPTIONS to raise the limit).`); }
    if (failed) { report.flag('Azure PIM', [...new Set(failures)].join('; ')); report.notes.push(`Azure PIM schedules could not be read for ${failed} subscription queries.`); }
    const seen = new Set();
    for (const r of rows) {
      const p = r.properties || {};
      const eligible = r.pimKind === 'roleEligibilityScheduleInstances';
      // Permanent direct assignments already come from Resource Graph above; show elevations, time-bound grants and eligibility.
      if (!eligible && p.assignmentType !== 'Activated' && !p.endDateTime) continue;
      if (seen.has(r.id)) continue; seen.add(r.id);
      const t = pimTiming(p.startDateTime, p.endDateTime);
      const via = p.memberType === 'Group' ? 'Through group membership' : 'Direct';
      report.policies.push({ id: r.id, name: p.expandedProperties?.roleDefinition?.displayName || p.roleDefinitionId, kind: 'Role', status: eligible ? 'Eligible (Azure PIM)' : p.assignmentType === 'Activated' ? 'Active (Azure PIM elevation)' : 'Active (time-bound)', assignment: `${via} Azure ${eligible ? 'PIM eligibility' : 'assignment'}`, detail: `Scope: ${p.scope}. ${eligible ? (t.permanent ? 'Permanent eligibility' : `Eligibility ends ${p.endDateTime}`) : t.text}.`, timing: t, source: 'azure', link: `https://portal.azure.com/#@${entity.tenant}/resource${p.scope}/users`, linkLabel: 'Open scope IAM', evidence: r });
    }
  });
}
const AZURE_PIM_SUBSCRIPTIONS = Math.min(200, Math.max(1, Number(process.env.E360_AZURE_PIM_SUBSCRIPTIONS) || 25));

// Azure activity log, only when the user clicks Load activity log (on demand). days is 1 to 90.
export async function activityReport(api, id, type, days, { tenant, now = Date.now() } = {}) {
  if (!GUID.test(id)) throw fail('Invalid entity identifier.');
  if (!Number.isInteger(days) || days < 1 || days > 90) throw fail('Lookback must be a whole number of days from 1 to 90.');
  const row = await api.request(type === 'user' ? `/v1.0/users/${id}?$select=id,displayName,userPrincipalName` : `/v1.0/servicePrincipals/${id}?$select=id,displayName,appId,servicePrincipalType`);
  const entity = normalizeEntity(row, tenant);
  const range = { from: new Date(now - days * 86400000).toISOString(), to: new Date(now).toISOString() };
  const subscriptions = (await api.pages('/subscriptions?api-version=2022-12-01', { origin: ARM })).rows;
  const filter = `eventTimestamp ge '${range.from}' and eventTimestamp le '${range.to}'`;
  const events = [], notes = [];
  let partial = false;
  for (let i = 0; i < subscriptions.length; i += 5) {
    const batch = subscriptions.slice(i, i + 5);
    const results = await Promise.allSettled(batch.map(sub => api.pages(queryUrl(`/subscriptions/${sub.subscriptionId}/providers/microsoft.insights/eventtypes/management/values`, { 'api-version': '2015-04-01', '$filter': filter }), { origin: ARM })));
    results.forEach((r, j) => {
      const name = batch[j].displayName || batch[j].subscriptionId;
      if (r.status === 'rejected') { partial = true; notes.push(`${name}: activity log not readable with your access.`); return; }
      if (r.value.truncated) { partial = true; notes.push(`${name}: page limit reached; open the activity log in Azure for the rest.`); }
      for (const ev of r.value.rows) {
        const claims = ev.claims || {};
        const actorIds = [ev.caller, claims['http://schemas.microsoft.com/identity/claims/objectidentifier'], claims.oid, claims.appid].filter(Boolean).map(v => String(v).toLowerCase());
        if (![entity.id, entity.subtitle, entity.appId].filter(Boolean).some(v => actorIds.includes(v.toLowerCase()))) continue;
        events.push({ id: ev.eventDataId, time: ev.eventTimestamp, category: 'Changes', service: ev.resourceProviderName?.localizedValue || ev.resourceProviderName?.value || 'Azure Resource Manager', auditCategory: ev.category?.localizedValue || ev.category?.value || 'Administrative', title: ev.operationName?.localizedValue || ev.operationName?.value || 'Azure operation', result: ev.status?.value === 'Succeeded' ? 'Success' : ev.status?.value === 'Failed' ? 'Failed' : 'Observed', source: 'azure', onDemand: true, actor: ev.caller, target: ev.resourceId, direction: 'Actor', explanation: ev.description || 'Azure management activity. The originating command is not recorded here.', correlationId: ev.correlationId, link: `https://portal.azure.com/#@${entity.tenant}/resource${ev.resourceId}/activityLog`, linkLabel: 'Open resource activity', query: `Event ID: ${ev.eventDataId}\nCorrelation ID: ${ev.correlationId}\nTime: ${ev.eventTimestamp}`, evaluatedPolicies: [], evidence: ev });
      }
    });
  }
  events.sort((a, b) => String(b.time).localeCompare(String(a.time)));
  return { events, days, range, partial, notes, subscriptions: subscriptions.length, source: { id: 'azure', ...SOURCE.azure, status: partial ? 'Partial' : 'Connected', count: events.length, coverage: `${range.from} to ${range.to}`, freshness: new Date(now).toISOString(), note: 'Azure management-plane activity, loaded on demand only. Filtered to the entity after retrieval. Data-plane events are not collected.' } };
}

// Defender process events for one user, loaded only on the Defender tab. A short default window (1 day) keeps
// most results under the 1,000-row cap of runHuntingQuery; the tab offers 1 to 30 days.
export const DEFENDER_DAYS = [1, 3, 7, 14, 30];
export const DEFENDER_CAP = 1000;
export function defenderQuery(upn, range) {
  // JSON string literals prevent the identity from escaping the fixed KQL template.
  const u = JSON.stringify(String(upn));
  return `DeviceProcessEvents\n| where Timestamp between (datetime(${range.from}) .. datetime(${range.to}))\n| where AccountUpn =~ ${u} or InitiatingProcessAccountUpn =~ ${u}\n| project Timestamp, DeviceName, DeviceId, FileName, ProcessCommandLine, AccountUpn, InitiatingProcessAccountUpn, ReportId\n| order by Timestamp desc\n| take ${DEFENDER_CAP}`;
}
export async function defenderReport(api, id, days, { now = Date.now(), tenant } = {}) {
  if (!GUID.test(id)) throw fail('Invalid entity identifier.');
  if (!DEFENDER_DAYS.includes(days)) throw fail(`Timeframe must be one of ${DEFENDER_DAYS.join(', ')} days.`);
  const user = await api.request(`/v1.0/users/${id}?$select=id,displayName,userPrincipalName`);
  const range = { from: new Date(now - days * 86400000).toISOString(), to: new Date(now).toISOString() };
  const query = defenderQuery(user.userPrincipalName, range);
  const base = { days, range, query, events: [], partial: false, partialReasons: [], unavailable: [], source: { id: 'defender', ...SOURCE.defender } };
  let data;
  try { data = await api.request('/v1.0/security/runHuntingQuery', { method: 'POST', body: { Query: query, Timespan: `P${days}D` } }); }
  catch (error) {
    if ([401, 403, 404].includes(error.status)) return { ...base, unavailable: [{ source: SOURCE.defender.name, reason: describeError(error) }] };
    return { ...base, partial: true, partialReasons: [{ source: SOURCE.defender.name, reason: describeError(error) }] };
  }
  const rows = (data.results || []).map(r => r || {});
  const capped = rows.length >= DEFENDER_CAP;
  return { ...base, partial: capped, partialReasons: capped ? [{ source: SOURCE.defender.name, reason: `Defender returns at most ${DEFENDER_CAP} process events per query; choose a shorter timeframe to see the rest` }] : [],
    events: rows.map(r => ({ id: `${r.DeviceId}-${r.ReportId}-${r.Timestamp}`, time: new Date(r.Timestamp).toISOString(), title: `${r.FileName} launched`, device: r.DeviceName, account: r.AccountUpn || r.InitiatingProcessAccountUpn, command: r.ProcessCommandLine, link: SOURCE.defender.url, evidence: r })) };
}
