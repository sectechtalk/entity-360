import { GUID, fail } from './model.mjs';
export async function personalAccountReport(api) {
  const me = await api.request('/v1.0/me?$select=id,displayName,userPrincipalName,mail');
  if (typeof me.id !== 'string' || !me.id || me.id.length > 200) throw fail('Microsoft did not return a personal identity.', 502);
  return { mode: 'personal', identity: { id: me.id, name: me.displayName, upn: me.mail || me.userPrincipalName, mail: me.mail, tenant: 'Personal Microsoft account', userType: 'Personal' }, sources: [{ id: 'personal-identity', name: 'Personal Microsoft profile', url: 'https://account.microsoft.com/' }], sections: {}, partial: false, updatedAt: new Date().toISOString(), notes: ['Profile verified using the personal Microsoft sign-in. Personal/Family subscription ownership, sharing and billing are not established by this Graph profile.', 'A personal account and a tenant guest object remain distinct contexts.'] };
}
export async function licenseReport(api, { tenant, personal = false }) {
  if (personal) {
    const profile = await personalAccountReport(api);
    return { ...profile, levels: { account: { status: 'notQueried', kind: 'consumerSubscriptions', explanation: 'Personal/Family subscription details are not queried through this dashboard. Open Microsoft Services & subscriptions with this personal account.', portal: 'https://account.microsoft.com/services' }, parent: { status: 'notApplicable', explanation: 'There is no organizational tenant inventory above a personal subscription. Family sharing is managed in the personal subscription portal.' } } };
  }
  if (!GUID.test(tenant)) throw fail('Invalid tenant context.');
  const me = await api.request('/v1.0/me?$select=id,displayName,userPrincipalName,mail,userType');
  if (!GUID.test(me.id)) throw fail('Invalid signed-in directory identity.', 502);
  const report = { mode: 'live', identity: { id: me.id, name: me.displayName, upn: me.userPrincipalName, userType: me.userType, tenant }, sources: [{ id: 'license-identity', name: 'Signed-in directory identity', url: 'https://entra.microsoft.com/' }], levels: {}, partial: false, updatedAt: new Date().toISOString() };
  try {
    const r = await api.pages('/v1.0/me/licenseDetails');
    report.levels.account = { status: 'queried', kind: 'tenantAssignments', rows: r.rows.map(l => ({ skuId: l.skuId, sku: l.skuPartNumber, plans: (l.servicePlans || []).map(p => ({ name: p.servicePlanName, status: p.provisioningStatus, appliesTo: p.appliesTo })) })), partial: r.truncated };
    report.sources.push({ id: 'account-licenses', name: 'My license assignments', url: 'https://admin.microsoft.com/' });
    report.partial ||= r.truncated;
  } catch { report.levels.account = { status: 'unavailable', explanation: 'Account license evidence was not available under this sign-in; this is not proof of no licenses.' }; report.partial = true; }
  try {
    const r = await api.pages('/v1.0/subscribedSkus');
    report.levels.parent = { status: 'queried', rows: r.rows.map(s => ({ skuId: s.skuId, sku: s.skuPartNumber, status: s.capabilityStatus, enabled: s.prepaidUnits?.enabled ?? null, assigned: s.consumedUnits ?? null, unassigned: Number.isFinite(s.prepaidUnits?.enabled) && Number.isFinite(s.consumedUnits) ? Math.max(0, s.prepaidUnits.enabled - s.consumedUnits) : null, warning: s.prepaidUnits?.warning ?? null, suspended: s.prepaidUnits?.suspended ?? null })), partial: r.truncated };
    report.sources.push({ id: 'tenant-licenses', name: 'Current tenant license inventory', url: 'https://admin.microsoft.com/' });
    report.partial ||= r.truncated;
  } catch { report.partial = true; } // Omit inaccessible parent inventory entirely.
  return report;
}
export function demoLicenseReport(profile, personal = false) {
  if (personal) return { mode: 'demo-personal', identity: { id: 'DEMO-PERSONAL', upn: 'personal@outlook.example', name: 'Personal account (fictional)', tenant: 'Personal Microsoft account', userType: 'Personal' }, sources: [], levels: { account: { status: 'notQueried', kind: 'consumerSubscriptions', portal: 'https://account.microsoft.com/services', explanation: 'Demo identity only. No personal subscription details have been retrieved.' }, parent: { status: 'notApplicable', explanation: 'Personal subscriptions do not have a tenant inventory.' } }, updatedAt: new Date().toISOString() };
  return { mode: 'demo', identity: { id: 'DEMO', upn: profile === 'reader' ? 'casey.rivera@contoso.example' : 'morgan.lee@contoso.example', name: 'Demo viewer', tenant: 'Contoso · fictional', userType: 'Member' }, sources: [{ id: 'account-licenses', name: 'My license assignments', url: 'https://admin.microsoft.com/' }, ...(profile !== 'reader' ? [{ id: 'tenant-licenses', name: 'Current tenant license inventory', url: 'https://admin.microsoft.com/' }] : [])], levels: { account: { status: 'queried', rows: [{ sku: 'Business Premium (demo)', plans: [{ name: 'INTUNE_A', status: 'Success', appliesTo: 'User' }] }] }, ...(profile !== 'reader' ? { parent: { status: 'queried', rows: [{ sku: 'Business Premium (demo)', status: 'Enabled', enabled: 25, assigned: 20, unassigned: 5, warning: 0, suspended: 0 }] } } : {}) }, partial: profile === 'reader', updatedAt: new Date().toISOString() };
}
