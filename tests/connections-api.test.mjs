// These tests exercise demo routes; the hosted default is DEMO_MODE off.
process.env.DEMO_MODE ??= 'true';
import test from 'node:test';
import assert from 'node:assert/strict';
import { CONSUMER_TENANT } from '../server/connections.mjs';
const a = '11111111-1111-1111-1111-111111111111', b = '22222222-2222-2222-2222-222222222222';
process.env.ENTRA_TENANT_ID = a; process.env.ENTRA_CLIENT_ID = a;
process.env.PERSONAL_CLIENT_ID = b; process.env.ALLOW_MULTI_TENANT = 'true';
const { createApp } = await import('../server/index.mjs');
test('authenticated context switching isolates tenant/account resources and browser sessions', async t => {
  const scopes = [];
  const server = createApp({ port: 3624, createMsal(options) {
    const tenant = options.auth.authority.endsWith('/consumers') ? CONSUMER_TENANT : options.auth.authority.split('/').at(-1);
    return { getTokenCache() { return { serialize: () => '{}', deserialize() {} }; }, async acquireTokenByDeviceCode(request) { scopes.push(request.scopes); return { account: { tenantId: tenant, localAccountId: tenant, homeAccountId: 'same-home', username: 'same@example.test', name: 'Same name' } }; } };
  } }).listen(3624, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const base = 'http://127.0.0.1:3624'; const first = await fetch(base + '/api/session');
  const session = await first.json(); const headers = { Cookie: first.headers.get('set-cookie').split(';')[0], 'X-CSRF-Token': session.csrf, 'Content-Type': 'application/json' };
  const post = async (url, data) => fetch(base + url, { method: 'POST', headers, body: JSON.stringify(data) });
  await post('/api/auth/start', { tenantId: a });
  let state = await (await fetch(base + '/api/session', { headers })).json(); const keyA = state.activeConnection;
  await post('/api/auth/start', { tenantId: b });
  state = await (await fetch(base + '/api/session', { headers })).json();
  assert.equal(state.activeTenant, b); assert.equal(state.connections.length, 2);
  assert.equal(state.azureConnected, false);
  await post('/api/connections/switch', { key: keyA });
  state = await (await fetch(base + '/api/session', { headers })).json(); assert.equal(state.activeTenant, a);
  await post('/api/auth/start', { accountType: 'personal' });
  state = await (await fetch(base + '/api/session', { headers })).json(); assert.equal(state.mode, 'personal');
  assert.deepEqual(scopes.at(-1), ['https://graph.microsoft.com/User.Read']);
  assert.equal((await fetch(base + '/api/entities?q=me', { headers })).status, 409);
  assert.equal((await post('/api/auth/start', { resource: 'azure' })).status, 409);
  const separate = await fetch(base + '/api/session'); const other = await separate.json();
  assert.equal(other.connections.length, 0);
  assert.equal((await fetch(base + '/api/connections/switch', { method: 'POST', headers: { Cookie: separate.headers.get('set-cookie').split(';')[0], 'X-CSRF-Token': other.csrf, 'Content-Type': 'application/json' }, body: JSON.stringify({ key: keyA }) })).status, 404);
  await post('/api/demo', {}); state = await (await fetch(base + '/api/session', { headers })).json(); assert.equal(state.connections.length, 0);
});
test('tenant discovery silently connects only the same principal and collects licenses without switching the active tenant', async t => {
  const account = tenant => ({ tenantId: tenant, localAccountId: tenant, homeAccountId: 'same-home', username: 'same@example.test' });
  const requests = [];
  const server = createApp({ port: 3625, createMsal(options) {
    const tenant = options.auth.authority.split('/').at(-1);
    return { getTokenCache() { return { serialize: () => '{}', deserialize() {} }; }, async acquireTokenByDeviceCode() { return { account: account(tenant) }; }, async acquireTokenSilent() { return { account: account(tenant), accessToken: tenant }; } };
  }, apiFetcher: async (url, options) => {
    const tokenTenant = options.headers.Authorization.slice('Bearer '.length); requests.push({ url: String(url), tokenTenant });
    if (url.pathname === '/tenants') return Response.json({ value: [{ tenantId: a }, { tenantId: b }] });
    if (url.pathname === '/v1.0/me') return Response.json({ id: tokenTenant, userPrincipalName: 'same@example.test' });
    if (url.pathname.endsWith('/licenseDetails')) return Response.json({ value: [{ skuPartNumber: tokenTenant === a ? 'LICENSE-A' : 'LICENSE-B', servicePlans: [] }] });
    return Response.json({ value: [] });
  } }).listen(3625, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve)); t.after(() => new Promise(resolve => server.close(resolve)));
  const base = 'http://127.0.0.1:3625'; const first = await fetch(base + '/api/session'); const s = await first.json();
  const headers = { Cookie: first.headers.get('set-cookie').split(';')[0], 'X-CSRF-Token': s.csrf, 'Content-Type': 'application/json' };
  const post = (path, data) => fetch(base + path, { method: 'POST', headers, body: JSON.stringify(data) });
  await post('/api/auth/start', { tenantId: a }); await post('/api/auth/start', { resource: 'azure' });
  const discovered = await (await post('/api/portfolio/discover', {})).json();
  assert.equal(discovered.tenants[1].connectionStatus, 'connectedSilently');
  const state = await (await fetch(base + '/api/session', { headers })).json(); assert.equal(state.activeTenant, a); assert.equal(state.connections.length, 2);
  const r = await (await fetch(base + '/api/licenses?scope=all', { headers })).json();
  assert.deepEqual(r.contexts.map(c => c.report.levels.account.rows[0].sku), ['LICENSE-A', 'LICENSE-B']);
  assert.equal(r.complete, false);
  assert.ok(requests.filter(r => r.url.includes('/licenseDetails')).some(r => r.tokenTenant === b));
});
