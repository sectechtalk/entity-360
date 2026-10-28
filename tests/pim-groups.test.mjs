// Bucket 1: PIM for Groups eligibility on Access > Admin roles > Source.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { pimGroupRoles, PIM_GROUP_SCOPE } from '../server/live.mjs';
const read = p => readFileSync(new URL(`../${p}`, import.meta.url), 'utf8');

test('scope requested (delegated) in .env.example and server default', () => {
  const env = read('.env.example').match(/^GRAPH_SCOPES=(.*)$/m)[1].trim().split(',');
  const def = read('server/index.mjs').match(/process\.env\.GRAPH_SCOPES \|\| '([^']+)'/)[1].split(',');
  assert.ok(env.includes(PIM_GROUP_SCOPE)); assert.ok(def.includes(PIM_GROUP_SCOPE));
});

test('roles held by an eligible PIM group show Eligible via PIM group <name>', async () => {
  const api = { async pages(p) {
    if (p.includes('privilegedAccess/group/eligibilityScheduleInstances')) return { rows: [{ id: 'e1', groupId: 'g1', accessId: 'member', group: { displayName: 'sg-pim-helpdesk' } }, { id: 'e2', groupId: 'g1', accessId: 'owner' }] };
    if (p.includes('roleAssignments')) return { rows: [{ id: 'r1', roleDefinitionId: 'x', roleDefinition: { displayName: 'Helpdesk Administrator', isBuiltIn: true }, directoryScopeId: '/' }] };
    throw new Error(p);
  } };
  const report = { unavailable: [] };
  const rows = await pimGroupRoles(api, 'u1', report);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].assignment, 'Eligible via PIM group sg-pim-helpdesk');
  assert.equal(rows[0].status, 'Eligible');
  assert.match(read('public/app.js'), /Eligible via PIM group \$\{pg\[1\]\}/);
});

test('403 shows scope not consented instead of failing', async () => {
  const report = { unavailable: [] };
  const rows = await pimGroupRoles({ async pages() { throw Object.assign(new Error('denied'), { status: 403 }); } }, 'u1', report);
  assert.deepEqual(rows, []);
  assert.deepEqual(report.unavailable, [{ source: 'PIM for Groups', reason: `scope not consented: ${PIM_GROUP_SCOPE}` }]);
});

test('PIM group memberships lists every eligibility, even groups with no role', async () => {
  const api = { async pages(p) {
    if (p.includes('eligibilityScheduleInstances')) return { rows: [{ id: 'e1', groupId: 'g2', accessId: 'member', endDateTime: '2027-10-23T00:00:00Z', group: { displayName: 'sg-e360-billing' } }, { id: 'e2', groupId: 'g1', accessId: 'owner', group: { displayName: 'sg-a' } }] };
    return { rows: [] };
  } };
  const report = { unavailable: [] };
  assert.deepEqual(await pimGroupRoles(api, 'u1', report), []);
  assert.equal(report.pimGroups.readable, true);
  assert.deepEqual(report.pimGroups.rows.map(r => [r.group, r.access, r.end]), [['sg-a', 'Owner', null], ['sg-e360-billing', 'Member', '2027-10-23T00:00:00Z']]);
});

test('PIM group memberships is "Not readable" on 403 and rendered under Admin roles', async () => {
  const report = { unavailable: [] };
  await pimGroupRoles({ async pages() { throw Object.assign(new Error('x'), { status: 403 }); } }, 'u1', report);
  assert.equal(report.pimGroups.readable, false);
  const app = read('public/app.js');
  assert.match(app, /PIM group memberships:/);
  assert.match(app, /Not readable \(/);
  assert.match(app, /pimGroupsLine\(r\.pimGroups\)/);
});
