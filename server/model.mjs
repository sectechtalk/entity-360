export const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export const SOURCE = {
  directory: { id: 'directory', name: 'Entra directory', short: 'Entra', url: 'https://entra.microsoft.com/' },
  signin: { id: 'signin', name: 'Entra sign-ins', short: 'Entra', url: 'https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/SignIns' },
  audit: { id: 'audit', name: 'Entra audit', short: 'Entra', url: 'https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/Audit' },
  policies: { id: 'policies', name: 'Conditional Access', short: 'Entra', url: 'https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies' },
  roles: { id: 'roles', name: 'Entra roles & PIM', short: 'Entra', url: 'https://entra.microsoft.com/#view/Microsoft_Azure_PIMCommon/CommonMenuBlade/~/quickStart' },
  governance: { id: 'governance', name: 'Entitlement management', short: 'Entra', url: 'https://entra.microsoft.com/#view/Microsoft_AAD_ERM/DashboardBlade/~/elmEntitlement' },
  azure: { id: 'azure', name: 'Azure Monitor & IAM', short: 'Azure', url: 'https://portal.azure.com/#view/Microsoft_Azure_Monitoring/AzureMonitoringBrowseBlade/~/activityLog' },
  defender: { id: 'defender', name: 'Defender hunting', short: 'Defender', url: 'https://security.microsoft.com/v2/advanced-hunting' },
  intune: { id: 'intune', name: 'Intune devices', short: 'Intune', url: 'https://intune.microsoft.com/' },
  purview: { id: 'purview', name: 'Purview audit', short: 'Purview', url: 'https://purview.microsoft.com/audit/auditsearch' },
  insights: { id: 'insights', name: 'Application Insights', short: 'Azure', url: 'https://portal.azure.com/' },
  graphLogs: { id: 'graphLogs', name: 'Graph request logs', short: 'Graph logs', url: 'https://portal.azure.com/#view/Microsoft_Azure_Monitoring/AzureMonitoringBrowseBlade/~/logs' },
  office: { id: 'office', name: 'Microsoft 365 audit logs', short: 'M365 logs', url: 'https://portal.azure.com/#view/Microsoft_Azure_Monitoring/AzureMonitoringBrowseBlade/~/logs' },
};
export const fail = (message, status = 400) => Object.assign(new Error(message), { status });
// Plain-language reason for a failed upstream query, used in the Partial results banner.
export function describeError(error) {
  const s = error?.status, said = error?.upstreamMessage ? `: ${String(error.upstreamMessage).replace(/\s+/g, ' ').slice(0, 180)}` : '';
  const code = error?.upstreamCode ? ` (${error.upstreamCode}${said})` : said ? ` (${said.slice(2)})` : '';
  if (error?.reason) return error.reason;
  if (s === 429 || s === 503) return `Microsoft throttled the query (HTTP ${s}) after two retries`;
  if (s === 401) return 'your sign-in expired';
  if (s === 403) return `not granted to your account or to the app's delegated scopes${code}`;
  if (s === 404) return 'not found or not licensed in this tenant';
  if (s === 400) return `Microsoft rejected the query (HTTP 400${code})`;
  if (s >= 500) return `the service returned an error (HTTP ${s}${code})`;
  return error?.message || 'the query failed';
}
export function timeRange(from, to) {
  const start = new Date(from), end = new Date(to);
  if (!from || !to || !Number.isFinite(+start) || !Number.isFinite(+end) || start >= end) throw fail('Choose a valid start and end time.');
  if (+end - +start > 90 * 86400000) throw fail('Choose a range of 90 days or less.');
  return { from: start.toISOString(), to: end.toISOString() };
}
export const inRange = (date, range) => date >= range.from && date <= range.to;
export const odata = value => String(value).replaceAll("'", "''");
// Spaces are encoded as %20, never '+': Intune and the Graph PIM endpoints reject '+' in $filter with HTTP 400.
// '$' stays literal in parameter names so every API recognises $filter, $select and $expand.
export const queryUrl = (path, params) => `${path}?${Object.entries(params).map(([k, v]) => `${encodeURIComponent(k).replace(/^%24/, '$')}=${encodeURIComponent(v)}`).join('&')}`;
export const entityLink = entity => entity.type === 'user'
  ? `https://entra.microsoft.com/#view/Microsoft_AAD_UsersAndTenants/UserProfileMenuBlade/~/overview/userId/${encodeURIComponent(entity.id)}`
  : `https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ManagedAppMenuBlade/~/Overview/objectId/${encodeURIComponent(entity.id)}`;
export const policyLink = id => `https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/PolicyBlade/policyId/${encodeURIComponent(id)}`;

export function finishReport(report) {
  const allowed = new Set(report.sources.map(s => s.id));
  report.events = report.events.filter(e => allowed.has(e.source)).sort((a, b) => b.time.localeCompare(a.time));
  report.policies = report.policies.filter(p => allowed.has(p.source));
  report.relationships = report.relationships.filter(r => allowed.has(r.source));
  report.summary = {
    events: report.events.length,
    failed: report.events.filter(e => ['Failed', 'Blocked'].includes(e.result)).length,
    roles: report.policies.filter(p => p.kind === 'Role' && p.status === 'Active').length,
    policies: report.policies.filter(p => p.kind !== 'Role').length,
  };
  report.updatedAt = new Date().toISOString();
  return report;
}
