import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { accessPackages, packageRow } from '../server/entitlements.mjs';

const U = '00000000-0000-4000-8000-0000000000a5';
const fakeApi = (fail = {}) => ({
  calls: [],
  async pages(url) {
    this.calls.push(url);
    if (url.includes('/assignmentRequests')) { if (fail.requests) throw Object.assign(new Error('x'), { status: 403 }); return { rows: [
      { id: 'q1', requestType: 'userAdd', state: 'pendingApproval', createdDateTime: '2026-10-26T10:00:00Z', accessPackage: { displayName: 'Other' }, target: { objectId: U } },
      { id: 'q2', requestType: 'adminAdd', state: 'delivered', target: { objectId: U } },
      { id: 'q3', requestType: 'userAdd', state: 'pendingApproval', target: { objectId: 'someone-else' } }] }; }
    return { rows: [
      { id: 'a1', state: 'delivered', status: 'Delivered', accessPackage: { id: 'p1', displayName: 'e360 Test Package' }, assignmentPolicy: { displayName: 'Admin direct' }, schedule: { startDateTime: '2026-10-26T20:00:00Z', expiration: { endDateTime: '2027-01-24T20:00:00Z' } } },
      { id: 'a2', state: 'expired', accessPackage: { id: 'p2' } }] };
  },
  async request(url) { this.calls.push(url); return { id: 'p1', displayName: 'e360 Test Package', catalog: { displayName: 'e360 Test Catalog' }, resourceRoleScopes: [{ role: { displayName: 'Member', originSystem: 'AadGroup', resource: { displayName: 'sg-e360-test-ap' } } }] }; },
});

test('access packages: held packages with catalog, policy, dates, state and resources; expired dropped', async () => {
  const api = fakeApi();
  const r = await accessPackages(api, U);
  assert.equal(r.rows.length, 1);
  assert.deepEqual({ ...r.rows[0], resources: undefined }, { id: 'a1', packageId: 'p1', name: 'e360 Test Package', catalog: 'e360 Test Catalog', policy: 'Admin direct', assigned: '2026-10-26T20:00:00Z', expires: '2027-01-24T20:00:00Z', state: 'delivered', status: 'Delivered', resources: undefined });
  assert.deepEqual(r.rows[0].resources, [{ name: 'sg-e360-test-ap', role: 'Member', type: 'AadGroup' }]);
  assert.deepEqual(r.requests.map(q => q.id), ['q1']);
  assert.ok(api.calls[0].startsWith('/v1.0/identityGovernance/entitlementManagement/assignments'));
  assert.ok(decodeURIComponent(api.calls[0]).includes(`target/objectId eq '${U}'`));
});

test('access packages: a request-list failure keeps the packages and reports the reason', async () => {
  const r = await accessPackages(fakeApi({ requests: true }), U);
  assert.equal(r.rows.length, 1); assert.equal(r.requests.length, 0); assert.equal(r.requestsNote.status, 403);
});

test('packageRow tolerates missing package details', () => {
  const p = packageRow({ id: 'a', accessPackage: { id: 'x' } }, undefined);
  assert.equal(p.catalog, 'Not returned'); assert.deepEqual(p.resources, []); assert.equal(p.expires, null);
});

test('Investigate has a read-only Access packages tab next to Admin roles, using .btn and delegated scope', async () => {
  const html = await readFile(new URL('../public/index.html', import.meta.url), 'utf8');
  assert.match(html, /data-tab="roles"[^>]*>Admin roles<\/button><button class="tab" role="tab" data-tab="packages"/);
  const app = await readFile(new URL('../public/app.js', import.meta.url), 'utf8');
  assert.match(app, /state\.tab === 'packages'/);
  assert.match(app, /data-table-id="access-packages"/);
  const idx = await readFile(new URL('../server/index.mjs', import.meta.url), 'utf8');
  assert.match(idx, /EntitlementManagement\.Read\.All/);
  assert.doesNotMatch(idx, /EntitlementManagement\.ReadWrite/);
  const live = await readFile(new URL('../server/live.mjs', import.meta.url), 'utf8');
  assert.match(live, /if \(type === 'user'\) tasks\.push\(run\('governance'/);
});
