import test from 'node:test';
import assert from 'node:assert/strict';
import { connectionPlan, connectionKey, CONSUMER_TENANT } from '../server/connections.mjs';
import { licenseReport } from '../server/licenses.mjs';
const a = '11111111-1111-1111-1111-111111111111', b = '22222222-2222-2222-2222-222222222222';
const config = { defaultTenant: a, organizationClientId: a, personalClientId: b, allowMultipleTenants: false };
test('organizational tenant boundaries are explicit; personal authority never comes from user URLs', () => {
  assert.equal(connectionPlan({}, config).tenant, a);
  assert.throws(() => connectionPlan({ tenantId: b }, config), /ALLOW_MULTI_TENANT/);
  assert.equal(connectionPlan({ tenantId: b }, { ...config, allowMultipleTenants: true }).tenant, b);
  assert.throws(() => connectionPlan({ tenantId: 'https://attacker.test' }, config));
  const p = connectionPlan({ accountType: 'personal', tenantId: b }, config);
  assert.equal(p.authorityTenant, 'consumers'); assert.equal(p.tenant, CONSUMER_TENANT);
  assert.throws(() => connectionPlan({ resource: 'azure' }, config, { mode: 'personal' }));
});
test('same email across tenants never merges directory identities', () => {
  const account = { username: 'same@example.test', homeAccountId: 'home', localAccountId: a, tenantId: a };
  assert.notEqual(connectionKey(account, a), connectionKey({ ...account, localAccountId: b, tenantId: b }, b));
  assert.throws(() => connectionKey(account, b));
});
test('user assignments and tenant inventory stay distinct; denied parent is omitted', async () => {
  const api = { async request() { return { id: a, userPrincipalName: 'me@example.test' }; }, async pages(path) {
    if (path.includes('licenseDetails')) return { rows: [{ skuPartNumber: 'P2', servicePlans: [{ servicePlanName: 'AAD_PREMIUM_P2', provisioningStatus: 'Disabled' }] }], truncated: false };
    throw Object.assign(new Error('forbidden billing data'), { status: 403 });
  } };
  const r = await licenseReport(api, { tenant: a });
  assert.equal(r.levels.account.rows[0].plans[0].status, 'Disabled');
  assert.equal(r.levels.parent, undefined);
  assert.ok(!r.sources.some(s => s.id === 'tenant-licenses'));
  assert.ok(!JSON.stringify(r).includes('forbidden billing'));
});
test('tenant counts retain unavailable and suspended information without inferring assigned user licenses', async () => {
  const api = { async request() { return { id: a }; }, async pages(path) { return path.includes('licenseDetails') ? { rows: [], truncated: false } : { rows: [{ skuPartNumber: 'Intune', capabilityStatus: 'Suspended', prepaidUnits: { enabled: 10, warning: 2, suspended: 3 }, consumedUnits: 7 }], truncated: true }; } };
  const r = await licenseReport(api, { tenant: a });
  assert.equal(r.levels.account.rows.length, 0);
  assert.equal(r.levels.parent.rows[0].unassigned, 3);
  assert.equal(r.levels.parent.rows[0].status, 'Suspended');
  assert.equal(r.partial, true);
});
test('personal profile does not claim subscription ownership or call tenant APIs', async () => {
  let calls = 0;
  const r = await licenseReport({ async request(path) { calls++; assert.match(path, /^\/v1.0\/me\?/); return { id: 'consumer-opaque-id', mail: 'me@outlook.test' }; }, async pages() { throw new Error('Tenant endpoint must not be called'); } }, { personal: true });
  assert.equal(calls, 1); assert.equal(r.levels.account.status, 'notQueried');
  assert.equal(r.levels.parent.status, 'notApplicable');
  assert.equal(r.identity.upn, 'me@outlook.test');
});
