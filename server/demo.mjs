import { SOURCE, entityLink, finishReport, inRange } from './model.mjs';

export const entities = [
  { id: '8f210001-6b21-4818-83bc-fae28e1242ab', name: 'Alex Morgan', type: 'user', subtitle: 'alex.morgan@contoso.example', department: 'Platform Engineering', tenant: 'Contoso · Demo', enabled: true },
  { id: '8f210002-6b21-4818-83bc-fae28e1242ab', name: 'Jordan Lee', type: 'user', subtitle: 'jordan.lee@contoso.example', department: 'Finance', tenant: 'Contoso · Demo', enabled: true },
  { id: '8f210003-6b21-4818-83bc-fae28e1242ab', name: 'Finance API', type: 'application', subtitle: 'api.finance.contoso.example', appId: '31e50003-6b21-4818-83bc-fae28e1242ab', tenant: 'Contoso · Demo', enabled: true },
  { id: '8f210004-6b21-4818-83bc-fae28e1242ab', name: 'prod-sync-identity', type: 'managedIdentity', subtitle: 'Production synchronization service', appId: '31e50004-6b21-4818-83bc-fae28e1242ab', tenant: 'Contoso · Demo', enabled: true },
];
export const profiles = {
  analyst: { name: 'Morgan Lee', email: 'morgan.lee@contoso.example', role: 'Security analyst', allowed: Object.keys(SOURCE) },
  reader: { name: 'Casey Rivera', email: 'casey.rivera@contoso.example', role: 'Directory reader', allowed: ['directory', 'signin', 'audit'] },
};
export function searchDemo(q) {
  const needle = q.toLowerCase().trim();
  return entities.filter(e => [e.name, e.subtitle, e.id, e.appId].some(v => v?.toLowerCase().includes(needle)));
}
export function demoReport(id, range, profile = 'analyst', now = Date.now()) {
  const entity = entities.find(e => e.id === id);
  if (!entity) return null;
  const viewer = profiles[profile] || profiles.analyst;
  const isUser = entity.type === 'user';
  const allowed = new Set(viewer.allowed);
  const sourceIds = isUser ? ['directory', 'signin', 'audit', 'policies', 'roles', 'azure', 'defender', 'intune', 'purview'] : ['directory', 'signin', 'audit', 'roles', 'azure', 'insights'];
  const sources = sourceIds.filter(s => allowed.has(s)).map(id => ({ ...SOURCE[id], status: 'Demo', count: 0, scope: 'Fictional Contoso tenant', coverage: 'Generated examples · last 30 days', freshness: 'Simulated', note: 'Fictional data. Portal links open the real source portal; these record IDs do not exist.' }));
  const eventTemplates = isUser ? [
    ['CLI', 'Azure CLI: update virtual machine', 'Success', 'azure', 'vm-finance-01', 'The resource provider accepted the virtual machine update.', 'az vm update --name vm-finance-01 --resource-group rg-finance --set tags.owner=platform'],
    ['CLI', 'powershell.exe launched', 'Observed', 'defender', 'LAPTOP-AM-042', 'Endpoint process evidence; this does not prove the command completed.', 'powershell.exe -NoProfile -File deploy.ps1'],
    ['Data access', 'SharePoint file downloaded', 'Success', 'purview', 'Finance / Forecast.xlsx', 'A file download was recorded by the workload audit source.', null],
    ['Sign-ins', 'Finance app sign-in', 'Blocked', 'signin', 'Finance Portal', 'Require compliant device failed. The device reported noncompliant.', null],
    ['Governance', 'Privileged role activated', 'Success', 'roles', 'Privileged Role Administrator', 'A time-limited eligible role was activated.', null],
    ['Changes', 'Department attribute updated', 'Success', 'audit', entity.name, 'The selected entity was the target of this directory change.', null],
    ['Sign-ins', 'Microsoft 365 sign-in', 'Success', 'signin', 'Microsoft 365', 'Sign-in succeeded. MFA requirement satisfied.', null],
    ['API', 'Microsoft Graph: read profile', 'Success', 'azure', 'Microsoft Graph', 'A request was recorded in exported Graph activity telemetry.', null],
  ] : [
    ['Sign-ins', 'Workload identity sign-in', 'Success', 'signin', 'Azure Resource Manager', 'The workload authenticated to the resource.', null],
    ['API', 'GET /api/v1/invoices', 'Success', 'insights', 'Finance API', 'An instrumented request completed in 182 ms.', null],
    ['API', 'POST /payments/validate', 'Failed', 'insights', 'Payments API', 'An instrumented downstream dependency returned HTTP 503.', null],
    ['Data access', 'Key Vault: retrieve secret', 'Success', 'azure', 'kv-finance-prod', 'A data-plane operation was recorded in resource diagnostic logs.', null],
    ['Changes', 'Application credential added', 'Success', 'audit', entity.name, 'An administrator added a credential to the application.', null],
    ['API', 'Storage: read blob', 'Success', 'azure', 'stfinanceprod', 'A data-plane read was recorded by diagnostic logging.', null],
  ];
  const events = [];
  for (let day = 0; day < 30; day++) {
    eventTemplates.forEach((t, i) => {
      const time = new Date(now - (day * 1440 + 8 + i * 19) * 60000).toISOString();
      if (!inRange(time, range)) return;
      const [category, title, result, source, target, explanation, command] = t;
      const event = { id: `demo-${id.slice(0, 8)}-${day}-${i}`, time, category, title, result, source, target, actor: i === 5 || (!isUser && i === 4) ? 'Morgan Lee' : entity.name, direction: i === 5 || (!isUser && i === 4) ? 'Target' : 'Actor', explanation, command, ip: '192.0.2.42', correlationId: `demo-correlation-${day}-${i}`, link: SOURCE[source].url, linkLabel: 'Open source portal', evidence: { simulated: true, result, target }, evaluatedPolicies: [] };
      if (category === 'Sign-ins' && !allowed.has('policies')) {
        event.explanation = result === 'Blocked' ? 'The sign-in was blocked. Policy evaluation details are unavailable to this viewer.' : 'The sign-in succeeded.';
      }
      if (category === 'Sign-ins' && isUser && allowed.has('policies')) event.evaluatedPolicies = [
        { id: 'demo-mfa', name: 'Require MFA', status: 'success', detail: 'MFA requirement satisfied', link: SOURCE.policies.url, linkLabel: 'Open policy portal' },
        { id: 'demo-device', name: 'Require compliant device', status: result === 'Blocked' ? 'failure' : 'success', detail: result === 'Blocked' ? 'Device reported noncompliant' : 'Device compliance satisfied', link: SOURCE.policies.url, linkLabel: 'Open policy portal' },
      ];
      events.push(event);
    });
  }
  const policies = [
    ...(isUser ? [
      { id: 'demo-mfa', name: 'Require MFA', kind: 'Conditional Access', status: 'Enabled', assignment: 'Included through Employees group', detail: 'All cloud apps; grant control: MFA. Assignment does not establish enforcement at an event.', source: 'policies' },
      { id: 'demo-device', name: 'Require compliant device', kind: 'Conditional Access', status: 'Enabled', assignment: 'Included through Finance users group', detail: 'Finance Portal; grant control: compliant device.', source: 'policies' },
      { id: 'demo-role', name: 'Privileged Role Administrator', kind: 'Role', status: 'Active', assignment: 'Direct · time-limited activation', detail: 'Directory scope; example activation ends in 4 hours.', source: 'roles' },
      { id: 'demo-intune', name: 'Windows compliance baseline', kind: 'Device', status: 'Noncompliant', assignment: 'LAPTOP-AM-042', detail: 'Device compliance result. This is not a complete user policy assignment inventory.', source: 'intune' },
    ] : [
      { id: 'demo-perm', name: 'Microsoft Graph · User.Read.All', kind: 'API permission', status: 'Granted', assignment: 'Application permission', detail: 'Tenant-wide application consent in this fictional example.', source: 'directory' },
      { id: 'demo-credential', name: 'Signing certificate', kind: 'Credential', status: 'Configured', assignment: 'Application registration', detail: 'Metadata only; expires in 42 days.', source: 'directory' },
    ]),
    { id: 'demo-azure', name: 'Reader', kind: 'Role', status: 'Active', assignment: isUser ? 'Inherited through Platform Ops group' : 'Direct assignment', detail: '/subscriptions/demo-subscription/resourceGroups/rg-finance', source: 'azure' },
  ].map(p => ({ ...p, link: SOURCE[p.source].url, linkLabel: 'Open source portal' }));
  const relationships = isUser ? [
    { name: 'Platform Ops', kind: 'Group', relation: 'Member of', source: 'directory' },
    { name: 'Finance API', kind: 'Application', relation: 'Related demo entity', source: 'directory', entityId: entities[2].id, entityType: 'application' },
    { name: 'LAPTOP-AM-042', kind: 'Device', relation: 'Managed device', source: 'intune' },
    { name: 'vm-finance-01', kind: 'Virtual machine', relation: 'Observed target', source: 'azure' },
  ] : [
    { name: 'Alex Morgan', kind: 'User', relation: 'Owner', source: 'directory', entityId: entities[0].id, entityType: 'user' },
    { name: 'Microsoft Graph', kind: 'API', relation: 'Permission grant', source: 'directory' },
    { name: 'Payments API', kind: 'Application', relation: 'Observed dependency', source: 'insights' },
  ];
  for (const source of sources) source.count = events.filter(e => e.source === source.id).length;
  return finishReport({ mode: 'demo', entity: { ...entity, link: entityLink(entity) }, range, sources, events, policies, relationships, notes: ['Demo data is simulated. Source links open portal entry points, not fictional records.'], partial: false });
}
