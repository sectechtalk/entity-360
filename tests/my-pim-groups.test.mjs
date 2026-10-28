// My access: the signed-in user's own PIM for Groups eligibility (self-read).
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { myPimGroups, myRoles } from '../server/my-roles.mjs';
import { roleTiming } from '../public/group-types.js';
const read = p => readFileSync(new URL(`../${p}`, import.meta.url), 'utf8');
const end = new Date(Date.now() + 300 * 86400000).toISOString();

const graph = (fail = {}) => ({
  calls: [],
  async pages(p) {
    this.calls.push(p);
    for (const [k, st] of Object.entries(fail)) if (p.includes(k)) throw Object.assign(new Error('denied'), { status: st });
    if (p.includes("filterByCurrentUser(on='principal')") || p.includes('eligibilityScheduleInstances?')) return { rows: [{ id: 'e1', groupId: 'g1', accessId: 'member', startDateTime: new Date().toISOString(), endDateTime: end }] };
    if (p.includes('roleManagement/directory/roleAssignments')) return { rows: [{ id: 'r1', roleDefinitionId: 'rd', roleDefinition: { displayName: 'Reports Reader' }, directoryScopeId: '/' }] };
    return { rows: [] };
  },
  async request(p) { this.calls.push(p); if (p.startsWith('/v1.0/groups/g1')) return { displayName: 'sg-lab-pim-reportsreader', isAssignableToRole: true }; throw Object.assign(new Error('x'), { status: 404 }); },
});

test('self-read uses filterByCurrentUser and returns the group and its role as Eligible', async () => {
  const api = graph();
  const r = await myPimGroups(api, { id: 'me' });
  assert.ok(api.calls[0].endsWith("eligibilityScheduleInstances/filterByCurrentUser(on='principal')"));
  const [g, role] = r.rows;
  assert.equal(g.name, 'sg-lab-pim-reportsreader'); assert.equal(g.membershipType, 'Eligible (PIM)'); assert.equal(g.membership, 'Eligible');
  assert.ok(g.remaining > 0); assert.notEqual(roleTiming(g).remaining, '');
  assert.equal(role.name, 'Reports Reader'); assert.equal(role.kind, 'Directory role'); assert.equal(role.membership, 'Eligible');
  assert.equal(role.source, 'Eligible via PIM group sg-lab-pim-reportsreader');
});

test('falls back to principalId filter when the function is rejected', async () => {
  const api = graph({ filterByCurrentUser: 400 });
  const r = await myPimGroups(api, { id: 'me' });
  assert.ok(api.calls.some(c => c.includes('principalId')));
  assert.equal(r.rows.length, 2);
});

test('403 is reported as PIM for Groups not readable (Not available list in the banner/status)', async () => {
  const r = await myRoles(graph({ eligibilityScheduleInstances: 403, roleManagement: 403, resources: 403 }), { id: 'me' }, []);
  const p = r.problems.unavailable.find(x => x.source === 'PIM for Groups');
  assert.ok(p); assert.match(p.reason, /not readable/);
});

test('My access filters know the new values', () => {
  const a = read('public/account.js');
  assert.match(a, /'Eligible \(PIM\)'/); assert.match(a, /'PIM for Groups \(member\)'/);
});
