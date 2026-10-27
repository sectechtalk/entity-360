import test from 'node:test';
import assert from 'node:assert/strict';
import { samePrincipalConnections, aggregateContexts, discoverTenants } from '../server/portfolio.mjs';
import { billingReport, billingWindow, costRows } from '../server/billing.mjs';
const a = '11111111-1111-1111-1111-111111111111', b = '22222222-2222-2222-2222-222222222222';
test('portfolio uses home principal identity, never same email, and freezes per-context resource sets', () => {
  const connections = new Map([['a', { account: { homeAccountId: 'same', username: 'me@test' }, resources: new Set(['graph']), tenantId: a }], ['b', { account: { homeAccountId: 'same', username: 'otherUPN@test' }, resources: new Set(['graph']), tenantId: b }], ['c', { account: { homeAccountId: 'different', username: 'me@test' }, resources: new Set(['graph']), tenantId: a }]]);
  const rows = samePrincipalConnections({ account: { homeAccountId: 'same' }, connections });
  assert.deepEqual(rows.map(r => r.key), ['a', 'b']);
  connections.get('a').resources.add('azure'); assert.equal(rows[0].resources.has('azure'), false);
});
test('multi-tenant failures remain unknown and successful sources retain tenant provenance', async () => {
  const r = await aggregateContexts([{ key: 'a', tenantId: a, account: { username: 'me@test' } }, { key: 'b', tenantId: b, account: { username: 'me@test' } }], async c => { if (c.key === 'b') throw new Error('secret'); return { sources: [{ id: 'licenses', name: 'Licenses' }], partial: false }; });
  assert.equal(r.complete, false); assert.equal(r.contexts[1].status, 'unavailable');
  assert.match(r.sources[0].name, new RegExp(a)); assert.ok(!JSON.stringify(r).includes('secret'));
});
test('ARM tenant discovery validates identifiers without claiming universal coverage', async () => {
  const r = await discoverTenants({ async pages(path, options) { assert.equal(options.origin, 'https://management.azure.com'); assert.match(path, /^\/tenants/); return { rows: [{ tenantId: a, displayName: 'A' }, { tenantId: 'malformed' }], truncated: true }; } });
  assert.equal(r.tenants.length, 1); assert.equal(r.partial, true); assert.equal(r.complete, false);
});
test('billing hides forbidden sources, preserves zero vs unavailable amounts, and does not combine currencies', async () => {
  const api = { async pages(path) { if (path.startsWith('/subscriptions?')) return { rows: [{ subscriptionId: a, displayName: 'Sub' }], truncated: false }; throw Object.assign(new Error('forbidden invoice secret'), { status: 403 }); }, async request(path, options) { assert.equal(options.method, 'POST'); assert.match(path, new RegExp(a)); assert.equal(options.body.type, 'Usage'); return { properties: { columns: [{ name: 'PreTaxCost' }, { name: 'Currency' }], rows: [[0, 'USD'], [12, 'EUR']] } }; } };
  const r = await billingReport(api, { tenant: a, azure: true });
  assert.equal(r.sections.costs[0].rows[0].amount, 0);
  assert.equal(r.sections.costs[0].rows[1].currency, 'EUR');
  assert.equal(r.sections.invoices, undefined); assert.equal(r.sections.billingAccounts, undefined);
  assert.equal(r.sources.some(s => s.id === 'billing-accounts'), false);
  assert.ok(!JSON.stringify(r).includes('forbidden invoice secret'));
});
test('billing validates window, flags cost truncation, and personal flow makes no ARM or Graph billing call', async () => {
  assert.throws(() => billingWindow(0)); assert.throws(() => billingWindow(91));
  assert.equal(costRows({ properties: { columns: [], rows: [[]], nextLink: 'next' } }).partial, true);
  assert.equal(costRows({ properties: { columns: [], rows: [[]] } }).rows[0].amount, null);
  const r = await billingReport({ pages() { throw new Error('must not query'); } }, { personal: true });
  assert.deepEqual(r.sections, {}); assert.equal(r.complete, false); assert.match(r.personalPortal, /account.microsoft.com/);
});
test('billing parent/profile/invoice scopes are normalized and unsupported names never create arbitrary API paths', async () => {
  const paths = [];
  const api = { async pages(path) { paths.push(path); if (path.includes('/billingAccounts?')) return { rows: [{ name: '123:456', properties: { displayName: 'Billing' } }, { name: '../../users' }] }; if (path.includes('/invoices?')) return { rows: [{ name: 'INV', properties: { totalAmount: { value: 12.50, currency: 'USD' } } }] }; if (path.includes('/billingProfiles?')) return { rows: [{ name: 'profile', properties: { displayName: 'Profile' } }] }; return { rows: [] }; }, async request(path) { paths.push(path); return { properties: { columns: [], rows: [] } }; } };
  const r = await billingReport(api, { tenant: a, azure: true });
  assert.equal(r.sections.invoices[0].amount, 12.5); assert.equal(r.sections.billingProfiles[0].account, '123:456');
  assert.ok(paths.some(p => p.includes('123%3A456'))); assert.ok(!paths.some(p => p.includes('../')));
  assert.equal(r.partial, true);
});
