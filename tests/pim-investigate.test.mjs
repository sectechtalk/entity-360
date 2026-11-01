// INVESTIGATE > PIM for another user: one Not available line per source, saying what Microsoft refused and why.
import test from 'node:test';
import assert from 'node:assert/strict';
import { pimTable, PIM_OTHER_ROLES } from '../server/pim.mjs';

const ME = '11111111-1111-1111-1111-111111111111';
// Every group PIM read is refused the same way; Entra and Azure return nothing (genuinely empty).
function fake(error) {
  return {
    calls: [],
    async pages(p) { this.calls.push(p); if (p.includes('privilegedAccess/group/')) throw Object.assign(new Error('denied'), error); return { rows: [] }; },
    async request(p, o = {}) { this.calls.push(p); if (o.method === 'POST' && p.includes('ResourceGraph')) return { data: [] }; throw Object.assign(new Error('nf'), { status: 404 }); },
  };
}

test('another user, 403 with the scopes consented: one Group line naming the directory roles Microsoft requires', async () => {
  const api = fake({ status: 403, upstreamCode: 'Forbidden', upstreamMessage: 'Insufficient privileges to complete the operation.' });
  const r = await pimTable(api, { id: ME, self: false });
  assert.equal(api.calls.filter(c => c.includes('privilegedAccess/group/')).length, 2, 'eligibility and assignment were both tried');
  const group = r.problems.filter(p => p.source === 'Group');
  assert.equal(group.length, 1, 'the two identical refusals are one line');
  assert.match(group[0].reason, /^Microsoft refused to show another user's PIM group assignments/);
  assert.match(group[0].reason, /The scopes are consented/);
  assert.ok(group[0].reason.includes(PIM_OTHER_ROLES.Group));
  assert.match(group[0].reason, /Microsoft said: Forbidden: Insufficient privileges/);
  assert.equal(r.problems.filter(p => p.source === 'Entra role').length, 0, 'Entra roles were read: empty, not failed');
  assert.deepEqual(r.rows, []);
});

test('a missing consented scope says an admin must consent it', async () => {
  const r = await pimTable(fake({ status: 403, upstreamCode: 'UnknownError', upstreamMessage: '{"errorCode":"PermissionScopeNotGranted","message":"Authorization failed due to missing permission scope PrivilegedEligibilitySchedule.Read.AzureADGroup"}' }), { id: ME, self: false });
  const group = r.problems.filter(p => p.source === 'Group');
  assert.equal(group.length, 1);
  assert.match(group[0].reason, /missing a delegated scope \(PrivilegedEligibilitySchedule\.Read\.AzureADGroup, .*\); an admin must consent it/);
});

test('My PIM (self) keeps the scope wording and different failures stay separate', async () => {
  let n = 0;
  const api = fake({ status: 403 });
  const pages = api.pages.bind(api);
  api.pages = async p => { if (p.includes('privilegedAccess/group/') && n++ >= 1) throw Object.assign(new Error('x'), { status: 400, upstreamCode: 'BadRequest', upstreamMessage: 'bad filter' }); return pages(p); };
  const r = await pimTable(api, { id: ME, self: true });
  const group = r.problems.filter(p => p.source === 'Group');
  assert.equal(group.length, 2);
  assert.match(group[0].reason, /^not readable with your sign-in \(uses PrivilegedEligibilitySchedule\.Read\.AzureADGroup/);
  assert.match(group[1].reason, /HTTP 400/);
});

// ---- Per-group fallback (Microsoft refuses principalId for another user even with Global Reader) ----
const U1 = '44444444-4444-4444-4444-444444444444', GA = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', GB = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', GC = 'aaaaaaaa-1111-2222-3333-444444444444';
function byGroupFake({ refuseGroups = false } = {}) {
  const unauth = { status: 403, upstreamCode: 'UnauthorizedAccessException', upstreamMessage: 'Attempted to perform an unauthorized operation.' };
  return {
    calls: [],
    async pages(p) {
      this.calls.push(decodeURIComponent(p));
      const d = decodeURIComponent(p);
      if (d.includes('privilegedAccess/group/') && d.includes('principalId eq')) throw Object.assign(new Error('denied'), unauth);
      if (d.includes('privilegedAccess/group/') && refuseGroups) throw Object.assign(new Error('denied'), unauth);
      if (d.includes(`/users/${U1}/transitiveMemberOf`)) return { rows: [{ id: GA, displayName: 'sg-e360-reader' }] };
      if (d.includes('/v1.0/groups?')) return { rows: [{ id: GA, displayName: 'sg-e360-reader' }, { id: GB, displayName: 'sg-e360-signins' }, { id: GC, displayName: 'sg-other' }] };
      if (d.includes(`eligibilityScheduleInstances?$filter=groupId eq '${GB}'`)) return { rows: [{ id: 'eB', groupId: GB, principalId: U1, accessId: 'member', memberType: 'Direct', startDateTime: '2026-10-30T00:00:00Z', endDateTime: '2027-10-30T00:00:00Z' }, { id: 'eX', groupId: GB, principalId: ME, accessId: 'member' }] };
      if (d.includes(`assignmentScheduleInstances?$filter=groupId eq '${GA}'`)) return { rows: [{ id: 'aA', groupId: GA, principalId: U1.toUpperCase(), accessId: 'member', assignmentType: 'Activated', memberType: 'Direct', startDateTime: '2026-10-31T05:00:00Z', endDateTime: '2026-10-31T06:00:00Z' }] };
      return { rows: [] };
    },
    async request(p, o = {}) { this.calls.push(p); if (o.method === 'POST' && p.includes('ResourceGraph')) return { data: [] }; throw Object.assign(new Error('nf'), { status: 404 }); },
  };
}

test('another user: refused per-user query falls back to per-group reads and keeps only that user', async () => {
  const api = byGroupFake();
  const r = await pimTable(api, { id: U1, self: false });
  assert.equal(r.problems.filter(p => p.source === 'Group').length, 0, 'no Not available line when the per-group read works');
  const g = r.rows.filter(x => x.type === 'Group');
  assert.deepEqual(g.map(x => [x.name, x.state]).sort(), [['sg-e360-reader', 'Active (activated)'], ['sg-e360-signins', 'Eligible']]);
  assert.ok(g.every(x => x.action === null), 'read-only');
  for (const id of [GA, GB, GC]) for (const k of ['eligibilityScheduleInstances', 'assignmentScheduleInstances']) assert.ok(api.calls.some(c => c.includes(`group/${k}?$filter=groupId eq '${id}'`)), `${k} ${id}`);
  const note = r.notes.find(n => n.startsWith('PIM groups:'));
  assert.match(note, /Checked 3 groups \(3 PIM-enabled\): the 1 groups this user belongs to and the security groups you can see\. A PIM group outside these is not shown\./);
});

test('another user: if the per-group read is refused too, report the exact request and Microsoft\'s answer', async () => {
  const r = await pimTable(byGroupFake({ refuseGroups: true }), { id: U1, self: false });
  const g = r.problems.filter(p => p.source === 'Group');
  assert.equal(g.length, 1);
  assert.match(g[0].reason, /refused both the per-user query and the per-group query \(GET \/v1\.0\/identityGovernance\/privilegedAccess\/group\/eligibilityScheduleInstances\?\$filter=groupId eq '/);
  assert.match(g[0].reason, /UnauthorizedAccessException: Attempted to perform an unauthorized operation\./);
});

test('groups PIM cannot manage (400 ResourceTypeNotSupported) are skipped and counted, not reported as failures', async () => {
  const GD = 'bbbbbbbb-1111-2222-3333-444444444444', api = byGroupFake(), pages = api.pages.bind(api);
  api.pages = async p => {
    const d = decodeURIComponent(p);
    if (d.includes('/v1.0/groups?')) return { rows: [{ id: GA, displayName: 'sg-e360-reader' }, { id: GB, displayName: 'sg-e360-signins' }, { id: GD, displayName: 'dynamic-all-users' }] };
    if (d.includes(`groupId eq '${GD}'`)) throw Object.assign(new Error('x'), { status: 400, upstreamCode: 'ResourceTypeNotSupported', upstreamMessage: 'Resource type not supported for onboarding' });
    return pages(p);
  };
  const r = await pimTable(api, { id: U1, self: false });
  assert.equal(r.problems.filter(p => p.source === 'Group').length, 0);
  assert.match(r.notes.find(n => n.startsWith('PIM groups:')), /Checked 3 groups \(2 PIM-enabled\)/);
  assert.equal(r.rows.filter(x => x.type === 'Group').length, 2);
});

test('a lowercase "direct" member type is not shown under the name', async () => {
  const { pimRowsHtml } = await import('../public/pim.js');
  const esc = v => String(v ?? '');
  const html = pimRowsHtml([{ id: 'x', type: 'Group', name: 'sg', memberType: 'direct', state: 'Eligible', key: 'k' }, { id: 'y', type: 'Group', name: 'sg2', memberType: 'group', state: 'Eligible', key: 'k2' }], { esc, self: false });
  assert.doesNotMatch(html, /<small>direct<\/small>/);
  assert.match(html, /<small>Through a group<\/small>/);
});