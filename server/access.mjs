import { GUID, fail, queryUrl } from './model.mjs';

const ARM = 'https://management.azure.com';

// Microsoft first-party apps used as What If targets. Override with E360_CA_EVAL_APPS (comma separated app IDs, max 10).
export const DEFAULT_CA_APPS = [
  { id: '00000003-0000-0ff1-ce00-000000000000', name: 'SharePoint Online' },
  { id: '00000002-0000-0ff1-ce00-000000000000', name: 'Exchange Online' },
  { id: '797f4846-ba00-4fd7-ba43-dac1f8f63013', name: 'Azure management' },
];
export function caApps(setting = process.env.E360_CA_EVAL_APPS) {
  const ids = String(setting || '').split(',').map(s => s.trim()).filter(s => GUID.test(s));
  return ids.length ? [...new Set(ids)].slice(0, 10).map(id => ({ id, name: DEFAULT_CA_APPS.find(a => a.id === id)?.name || id })) : DEFAULT_CA_APPS;
}

// Sign-in inputs e360 does not know, so it never sends them to What If. A policy that depends on one can be missed.
const UNKNOWN_INPUTS = [['platforms', 'device platform'], ['locations', 'location'], ['devices', 'device filter'], ['clientAppTypes', 'client app'], ['signInRiskLevels', 'sign-in risk'], ['userRiskLevels', 'user risk'], ['insiderRiskLevels', 'insider risk'], ['authenticationFlows', 'authentication flow']];
export function unknownInputs(policy) {
  const c = policy?.conditions || {};
  return UNKNOWN_INPUTS.filter(([k]) => {
    const v = c[k];
    if (v == null || v === '') return false;
    if (Array.isArray(v)) return v.length > 0 && !(k === 'clientAppTypes' && v.length === 1 && v[0] === 'all');
    return typeof v === 'object' ? Object.keys(v).length > 0 : true;
  }).map(([, label]) => label);
}

// Microsoft evaluates the policies (POST /v1.0/identity/conditionalAccess/evaluate, delegated, read only).
// The optional policy list is used only for names, links and to mark policies whose inputs are unknown as Incomplete.
export async function evaluateConditionalAccess(api, { id, type = 'user', apps = caApps(), policies = null } = {}) {
  if (!GUID.test(String(id))) throw fail('Invalid entity identifier.');
  const signInIdentity = type === 'user'
    ? { '@odata.type': '#microsoft.graph.userSignIn', userId: id }
    : { '@odata.type': '#microsoft.graph.servicePrincipalSignIn', servicePrincipalId: id };
  const applied = new Map();
  for (const app of apps) {
    const data = await api.request('/v1.0/identity/conditionalAccess/evaluate', { method: 'POST', body: { signInIdentity, signInContext: { '@odata.type': '#microsoft.graph.applicationContext', includeApplications: [app.id] }, signInConditions: {}, appliedPoliciesOnly: true } });
    for (const p of data.value || []) {
      const e = applied.get(p.id) || { id: p.id, name: p.displayName || p.id, state: p.state, apps: [], grant: p.grantControls?.builtInControls || [], session: p.sessionControls || null, missing: unknownInputs(p), result: 'Applies', evidence: p };
      e.apps.push(app.name);
      applied.set(p.id, e);
    }
  }
  const rows = [...applied.values()];
  for (const p of policies || []) {
    if (!p || p.state === 'disabled' || applied.has(p.id)) continue;
    const missing = unknownInputs(p);
    if (missing.length) rows.push({ id: p.id, name: p.displayName || p.id, state: p.state, apps: [], grant: p.grantControls?.builtInControls || [], session: p.sessionControls || null, missing, result: 'Incomplete', evidence: p });
  }
  return { rows, apps };
}

// Azure Resource Graph, following $skipToken. One query covers every subscription and management group the viewer can read.
export async function resourceGraph(api, query, { maxPages = 10 } = {}) {
  const rows = [];
  let skipToken, page = 0;
  do {
    const data = await api.request('/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01', { origin: ARM, method: 'POST', body: { query, options: { resultFormat: 'objectArray', $top: 1000, authorizationScopeFilter: 'AtScopeAboveAndBelow', ...(skipToken ? { $skipToken: skipToken } : {}) } } });
    rows.push(...(Array.isArray(data.data) ? data.data : []));
    skipToken = data.$skipToken;
    page++;
  } while (skipToken && page < maxPages);
  return { rows, truncated: Boolean(skipToken) };
}

// Only validated GUIDs reach the KQL text, so the list cannot break out of the query.
export function roleAssignmentQuery(principalIds) {
  const ids = [...new Set([...principalIds].map(v => String(v).toLowerCase()))].filter(v => GUID.test(v)).slice(0, 500);
  if (!ids.length) throw fail('No principal identifiers.');
  return `authorizationresources
| where type =~ 'microsoft.authorization/roleassignments'
| extend principalId = tolower(tostring(properties.principalId)), roleGuid = tolower(extract(@'roleDefinitions/([^/]+)$', 1, tostring(properties.roleDefinitionId))), scope = tostring(properties.scope), condition = tostring(properties.condition), createdOn = tostring(properties.createdOn)
| where principalId in (${ids.map(v => `'${v}'`).join(', ')})
| join kind=leftouter (authorizationresources | where type =~ 'microsoft.authorization/roledefinitions' | extend roleGuid = tolower(name), roleName = tostring(properties.roleName) | summarize roleName = any(roleName) by roleGuid) on roleGuid
| project id, principalId, roleGuid, roleName, scope, condition, createdOn, subscriptionId
| order by scope asc`;
}
export const SUBSCRIPTIONS_QUERY = "resourcecontainers | where type =~ 'microsoft.resources/subscriptions' | project subscriptionId, name | order by name asc";

export function fmtDuration(ms) {
  const m = Math.max(0, Math.round(ms / 60000));
  const d = Math.floor(m / 1440), h = Math.floor((m % 1440) / 60), mm = m % 60;
  return [d && `${d}d`, h && `${h}h`, (mm || (!d && !h)) && `${mm}m`].filter(Boolean).join(' ');
}
export function pimTiming(start, end, now = Date.now()) {
  if (!end) return { permanent: true, text: 'Permanent' };
  const s = Date.parse(start), e = Date.parse(end);
  if (!Number.isFinite(e)) return { permanent: false, text: 'End time not returned' };
  const granted = Number.isFinite(s) ? e - s : null, remaining = e - now;
  return { permanent: false, granted, remaining, text: `Granted ${granted == null ? 'unknown' : fmtDuration(granted)}; ${remaining > 0 ? `${fmtDuration(remaining)} remaining` : 'expired'}` };
}

// Per-device Intune policy states, loaded only when a device is opened.
export async function deviceStates(api, deviceId) {
  if (!GUID.test(String(deviceId))) throw fail('Invalid device identifier.');
  const states = [];
  let partial = false;
  for (const [path, kind] of [['deviceCompliancePolicyStates', 'Compliance'], ['deviceConfigurationStates', 'Configuration']]) {
    const r = await api.pages(`/v1.0/deviceManagement/managedDevices/${deviceId}/${path}`);
    partial ||= r.truncated;
    for (const p of r.rows) states.push({ id: p.id, name: p.displayName || p.id, kind, state: p.state || 'Unknown', settingCount: p.settingCount ?? null });
  }
  return { deviceId, states, partial, link: `https://intune.microsoft.com/#view/Microsoft_Intune_Devices/DeviceSettingsMenuBlade/~/overview/mdmDeviceId/${deviceId}` };
}
export { queryUrl };
