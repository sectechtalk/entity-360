import { GUID } from './model.mjs';
const ARM = 'https://management.azure.com';
export function samePrincipalConnections(session) {
  const home = session.account?.homeAccountId;
  if (!home) return [];
  return [...session.connections.entries()].filter(([, c]) => c.account.homeAccountId === home).map(([key, c]) => ({ key, ...c, resources: new Set(c.resources) }));
}
export async function discoverTenants(api) {
  const result = await api.pages('/tenants?api-version=2022-12-01', { origin: ARM });
  return { tenants: result.rows.filter(t => GUID.test(t.tenantId)).map(t => ({ id: t.tenantId.toLowerCase(), name: t.displayName || t.defaultDomain || t.tenantId })), partial: result.truncated, source: 'Azure Resource Manager /tenants', complete: false, note: 'ARM-visible organizations only. This is not a universal directory of every Microsoft entitlement or relationship.' };
}
export async function aggregateContexts(connections, collect) {
  const contexts = [], sources = [];
  // Sequential contexts keep each API/token snapshot independent and bound load.
  for (const c of connections) {
    try {
      const report = await collect(c);
      contexts.push({ key: c.key, tenant: c.tenantId, account: c.account.username, status: report.partial ? 'partial' : 'queried', report });
      sources.push(...report.sources.map(s => ({ ...s, id: `${c.key}:${s.id}`, name: `${s.name} · ${c.mode === 'personal' ? 'Personal' : c.tenantId}` })));
    } catch { contexts.push({ key: c.key, tenant: c.tenantId, account: c.account.username, status: 'unavailable' }); }
  }
  return { contexts, sources, complete: false, updatedAt: new Date().toISOString(), partial: contexts.some(c => c.status !== 'queried'), note: 'Queried connected contexts sharing Microsoft’s home-account identifier. Other identities are not merged by email; unconnected or undiscovered tenants remain unknown.' };
}
