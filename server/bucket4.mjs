// Coverage bucket 4: new pages. Delegated Graph and ARM reads only. Nothing here writes to Microsoft.
import { GUID, fail, odata, describeError } from './model.mjs';

const ARM = { origin: 'https://management.azure.com' };
const GLOBAL_ADMIN = '62e90394-69f5-4237-9190-012177145e10';
const NAME_HINT = /break.?glass|emergency|globaladmin\d/i;
// Rows of bucket 4 that stay deferred until their scope is consented. Microsoft only lists PIM requests
// awaiting your approval under a write scope, which e360 will not request.
export const B4_DEFERRED = [
  ['My approvals', 'AccessReview.Read.All, RoleAssignmentSchedule.ReadWrite.Directory (Microsoft requires a write scope to list PIM approvals; e360 stays read-only)'],
];

// Emergency access: accounts that look like break-glass (excluded from Conditional Access or named for it),
// with CA exclusion coverage, last sign-in, roles, and alert rules that watch them.
export async function breakGlass(api, { azure = false, now = Date.now() } = {}) {
  const notes = [];
  const policies = (await api.pages('/v1.0/identity/conditionalAccess/policies')).rows.filter(p => p.state !== 'disabled');
  let gaIds = new Set();
  try { gaIds = new Set((await api.pages(`/v1.0/roleManagement/directory/roleAssignments?$filter=roleDefinitionId eq '${GLOBAL_ADMIN}'`)).rows.map(a => a.principalId)); }
  catch (e) { notes.push(`Global Administrator assignments: ${describeError(e)}`); }
  const excluded = new Set(policies.flatMap(p => p.conditions?.users?.excludeUsers || []).filter(id => GUID.test(id)));
  const candidates = new Map();
  for (const id of new Set([...excluded, ...gaIds])) {
    let u;
    try { u = await api.request(`/v1.0/users/${id}?$select=id,displayName,userPrincipalName,accountEnabled,signInActivity`); } catch { continue; } // not a user (service principal or group)
    if (excluded.has(id) || NAME_HINT.test(`${u.displayName} ${u.userPrincipalName}`)) candidates.set(id, u);
  }
  let rules = null;
  if (azure) {
    try {
      rules = [];
      for (const s of ((await api.request('/subscriptions?api-version=2022-12-01', ARM)).value || []).slice(0, 10)) {
        const r = await api.request(`/subscriptions/${s.subscriptionId}/providers/Microsoft.Insights/scheduledQueryRules?api-version=2023-03-15-preview`, ARM).catch(() => ({ value: [] }));
        rules.push(...(r.value || []));
      }
    } catch (e) { rules = null; notes.push(`Alert rules: ${describeError(e)}`); }
  } else notes.push('Connect Azure to check for alert rules that watch these accounts.');
  const rows = [];
  for (const u of candidates.values()) {
    let groups = new Set(), roles = [];
    try { groups = new Set((await api.pages(`/v1.0/users/${u.id}/transitiveMemberOf?$select=id`)).rows.map(g => g.id)); } catch (e) { notes.push(`Groups of ${u.userPrincipalName}: ${describeError(e)}`); }
    try { roles = (await api.pages(`/v1.0/roleManagement/directory/roleAssignments?$filter=principalId eq '${odata(u.id)}'&$expand=roleDefinition`)).rows.map(a => a.roleDefinition?.displayName || a.roleDefinitionId); } catch (e) { notes.push(`Roles of ${u.userPrincipalName}: ${describeError(e)}`); }
    const isExcluded = p => (p.conditions?.users?.excludeUsers || []).includes(u.id) || (p.conditions?.users?.excludeGroups || []).some(g => groups.has(g));
    const notExcluded = policies.filter(p => !isExcluded(p)).map(p => p.displayName);
    const last = u.signInActivity ? [u.signInActivity.lastSignInDateTime, u.signInActivity.lastNonInteractiveSignInDateTime].filter(Boolean).sort().pop() || null : undefined;
    const upn = String(u.userPrincipalName || '').toLowerCase();
    const alerts = rules === null ? null : rules.filter(r => (r.properties?.criteria?.allOf || []).some(c => { const q = String(c.query || '').toLowerCase(); return (upn && q.includes(upn)) || q.includes(u.id); }))
      .map(r => ({ name: r.name, enabled: r.properties?.enabled !== false, link: `https://portal.azure.com/#@/resource${r.id}` }));
    const findings = [];
    if (notExcluded.length) findings.push(`Not excluded from ${notExcluded.length} active policies`);
    if (!roles.includes('Global Administrator')) findings.push('No active Global Administrator role');
    if (u.accountEnabled === false) findings.push('Account disabled');
    if (alerts && !alerts.some(a => a.enabled)) findings.push('No enabled alert rule watches this account');
    if (last && now - Date.parse(last) < 7 * 864e5) findings.push('Signed in within the last 7 days: confirm it was a planned test');
    rows.push({ id: u.id, name: u.displayName, upn: u.userPrincipalName, enabled: u.accountEnabled !== false, excludedFrom: policies.length - notExcluded.length, policies: policies.length, notExcluded, lastSignIn: last, roles, alerts, findings, link: `https://entra.microsoft.com/#view/Microsoft_AAD_UsersAndTenants/UserProfileMenuBlade/~/overview/userId/${u.id}` });
  }
  return { rows, notes };
}

// Logs: Log Analytics workspaces visible through ARM, and saved KQL run through the ARM query proxy.
export const SAVED_QUERIES = {
  tables: { title: 'Tables with data', kql: 'union withsource=Table * | summarize Rows=count(), Last=max(TimeGenerated) by Table | order by Rows desc' },
  signinFailures: { title: 'Failed interactive sign-ins by user and error', kql: 'SigninLogs | where ResultType != "0" | summarize Failures=count(), Last=max(TimeGenerated) by UserPrincipalName, ResultType, ResultDescription | order by Failures desc | take 50' },
  caFailures: { title: 'Conditional Access failures by policy', kql: 'SigninLogs | where ConditionalAccessStatus == "failure" | mv-expand P=ConditionalAccessPolicies | where P.result == "failure" | summarize Count=count() by Policy=tostring(P.displayName), UserPrincipalName | order by Count desc | take 50' },
  reportOnly: { title: 'Report-only Conditional Access outcomes', kql: 'SigninLogs | mv-expand P=ConditionalAccessPolicies | where tostring(P.result) startswith "reportOnly" | summarize Count=count() by Policy=tostring(P.displayName), Result=tostring(P.result) | order by Count desc | take 50' },
  nonInteractive: { title: 'Non-interactive sign-ins by app', kql: 'AADNonInteractiveUserSignInLogs | summarize SignIns=count(), Users=dcount(UserPrincipalName), Failures=countif(ResultType != "0") by AppDisplayName | order by SignIns desc | take 50' },
  legacyAuth: { title: 'Legacy authentication sign-ins', kql: 'SigninLogs | where ClientAppUsed !in ("Browser", "Mobile Apps and Desktop clients") | summarize Count=count() by UserPrincipalName, ClientAppUsed | order by Count desc | take 50' },
  breakGlass: { title: 'Sign-ins by break-glass accounts', kql: 'union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs | where UserPrincipalName matches regex @"(?i)break.?glass|emergency|globaladmin\\d" | project TimeGenerated, UserPrincipalName, IPAddress, ResultType, AppDisplayName | order by TimeGenerated desc | take 50' },
  audit: { title: 'Directory changes by initiator', kql: 'AuditLogs | summarize Changes=count() by Initiator=coalesce(tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName)), OperationName | order by Changes desc | take 50' },
};
const WS_ID = /^\/subscriptions\/[0-9a-f-]{36}\/resourcegroups\/[\w.()-]{1,90}\/providers\/microsoft\.operationalinsights\/workspaces\/[\w-]{4,63}$/i;

export async function workspaces(api) {
  const out = [], notes = [], workbooks = [];
  const subs = ((await api.request('/subscriptions?api-version=2022-12-01', ARM)).value || []).slice(0, 10);
  for (const s of subs) {
    try {
      const r = await api.request(`/subscriptions/${s.subscriptionId}/providers/Microsoft.OperationalInsights/workspaces?api-version=2022-10-01`, ARM);
      for (const w of r.value || []) out.push({ id: w.id, name: w.name, subscription: s.displayName, location: w.location, sku: w.properties?.sku?.name || '', retention: w.properties?.retentionInDays ?? null, dailyCapGb: w.properties?.workspaceCapping?.dailyQuotaGb ?? null, link: `https://portal.azure.com/#@/resource${w.id}/logs` });
    } catch (e) { notes.push(`${s.displayName}: ${describeError(e)}`); }
  }
  for (const s of subs) {
    try { workbooks.push(...(((await api.request(`/subscriptions/${s.subscriptionId}/providers/Microsoft.Insights/workbooks?category=workbook&api-version=2022-04-01`, ARM)).value) || []).map(w => ({ name: w.properties?.displayName || w.name, link: `https://portal.azure.com/#@/resource${w.id}/workbook` }))); } catch { }
  }
  return { workspaces: out, workbooks, queries: Object.entries(SAVED_QUERIES).map(([key, q]) => ({ key, title: q.title, kql: q.kql })), notes };
}

const tableOf = data => { const t = (data.tables || data.Tables || [])[0] || {}; const cols = (t.columns || t.Columns || []).map(c => c.name || c.ColumnName); return { columns: cols, rows: (t.rows || t.Rows || []).slice(0, 200) }; };
export async function runSavedQuery(api, { workspace, query, days = 7 }) {
  if (!WS_ID.test(String(workspace || ''))) throw fail('Invalid workspace.');
  const q = SAVED_QUERIES[query]; if (!q) throw fail('Unknown saved query.');
  if (![1, 7, 30].includes(days)) throw fail('Invalid window.');
  try {
    const data = await api.request(`${workspace}/api/query?api-version=2020-08-01`, { ...ARM, method: 'POST', body: { query: q.kql, timespan: `P${days}D` } });
    return { title: q.title, kql: q.kql, days, ...tableOf(data) };
  } catch (e) {
    if (/Failed to resolve table|SemanticError/i.test(`${e.upstreamMessage || ''} ${e.upstreamCode || ''}`)) return { title: q.title, kql: q.kql, days, columns: [], rows: [], missing: 'This workspace has no such table yet. Send the Entra logs to it with a diagnostic setting (Health checks shows the current ones).' };
    throw e;
  }
}
