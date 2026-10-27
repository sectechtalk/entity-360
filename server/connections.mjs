import { GUID, fail } from './model.mjs';
export const CONSUMER_TENANT = '9188040d-6c67-4c5b-b112-36a304b66dad';
export function connectionPlan(input = {}, config, active = {}) {
  const resource = ['azure', 'logs'].includes(input.resource) ? input.resource : 'graph';
  const personal = resource === 'graph' ? input.accountType === 'personal' : active.mode === 'personal';
  if (personal && resource !== 'graph') throw fail('Connect an organizational account for Azure or workspace access.', 409);
  if (personal) {
    if (!GUID.test(config.personalClientId)) throw fail('Configure PERSONAL_CLIENT_ID with a public-client registration supporting personal Microsoft accounts.', 409);
    return { resource, personal: true, tenant: CONSUMER_TENANT, authorityTenant: 'consumers', clientId: config.personalClientId };
  }
  const tenant = resource === 'graph' ? String(input.tenantId || config.defaultTenant).toLowerCase() : active.tenantId;
  if (!GUID.test(tenant) || !GUID.test(config.organizationClientId)) throw fail('Configure the organizational tenant/client IDs first.', 409);
  if (resource === 'graph' && tenant !== config.defaultTenant.toLowerCase() && !config.allowMultipleTenants) throw fail('Enable ALLOW_MULTI_TENANT and use a registration supporting multiple organizations before connecting another tenant.', 409);
  if (tenant === CONSUMER_TENANT) throw fail('Use the personal-account connection option.', 400);
  return { resource, personal: false, tenant, authorityTenant: tenant, clientId: config.organizationClientId };
}
export function connectionKey(account, tenant) {
  // Email is deliberately excluded: an address is not a directory identity key.
  if (!account?.homeAccountId || !account?.localAccountId || account.tenantId?.toLowerCase() !== tenant.toLowerCase()) throw fail('Microsoft account context did not match the requested directory.', 401);
  return `${tenant.toLowerCase()}:${account.localAccountId}`;
}
