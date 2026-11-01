// Unified PIM tables: MY ACCOUNT > PIM (activate/deactivate) and INVESTIGATE > PIM (read-only).
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { pimTable, pimRequest, pimPolicy, policyFrom, isoMinutes, minutesIso, checkTarget, withActions } from '../server/pim.mjs';
import { pimTableHtml, durationOptions, settled, activateFormHtml } from '../public/pim.js';
import { roleForPath } from '../server/authflow.mjs';
import { VIEW_ROLES } from '../public/access-denied.js';
const read = p => readFileSync(new URL(`../${p}`, import.meta.url), 'utf8');
const ME = '11111111-1111-1111-1111-111111111111', RD = '62e90394-69f5-4237-9190-012177145e10', G = '22222222-2222-2222-2222-222222222222', SUB = '33333333-3333-3333-3333-333333333333';
const esc = v => String(v ?? '').replace(/[&<>"']/g, c => `&#${c.charCodeAt(0)};`);
const AZROLE = `/subscriptions/${SUB}/providers/Microsoft.Authorization/roleDefinitions/8f210002-6b21-4818-83bc-fae28e1242ab`;
const ELIG = `/subscriptions/${SUB}/providers/Microsoft.Authorization/roleEligibilitySchedules/44444444-4444-4444-4444-444444444444`;

function fake({ fail = {} } = {}) {
  return {
    calls: [], sent: [],
    async pages(p, o = {}) {
      this.calls.push(p);
      for (const [k, s] of Object.entries(fail)) if (p.includes(k)) throw Object.assign(new Error('denied'), { status: s });
      if (p.includes('roleEligibilityScheduleInstances') && p.includes('/v1.0/')) return { rows: [{ id: 'e1', roleDefinitionId: RD, roleDefinition: { displayName: 'Global Administrator' }, directoryScopeId: '/', memberType: 'Direct', startDateTime: '2026-10-01T00:00:00Z', endDateTime: null }] };
      if (p.includes('roleAssignmentScheduleInstances') && p.includes('/v1.0/')) return { rows: [{ id: 'a1', roleDefinitionId: RD, roleDefinition: { displayName: 'Global Administrator' }, directoryScopeId: '/', assignmentType: 'Activated', memberType: 'Direct', startDateTime: '2026-10-30T20:00:00Z', endDateTime: '2026-10-30T22:00:00Z' }] };
      if (p.includes('group/eligibilityScheduleInstances')) return { rows: [{ id: 'ge', groupId: G, accessId: 'member', memberType: 'Direct', startDateTime: '2026-10-01T00:00:00Z', endDateTime: '2027-10-01T00:00:00Z' }] };
      if (p.includes('group/assignmentScheduleInstances')) return { rows: [] };
      if (p.includes('roleEligibilityScheduleInstances')) return { rows: [{ id: 'azE', properties: { roleDefinitionId: AZROLE, scope: `/subscriptions/${SUB}`, roleEligibilityScheduleId: ELIG, memberType: 'Direct', startDateTime: '2026-10-01T00:00:00Z', expandedProperties: { roleDefinition: { displayName: 'Contributor' }, scope: { displayName: 'Lab', type: 'subscription' } } } }] };
      if (p.includes('roleAssignmentScheduleInstances')) return { rows: [] };
      if (p.includes('policies/roleManagementPolicyAssignments')) return { rows: [{ policy: { rules: [{ id: 'Expiration_EndUser_Assignment', maximumDuration: 'PT4H' }, { id: 'Enablement_EndUser_Assignment', enabledRules: ['Justification', 'Ticketing', 'MultiFactorAuthentication'] }] } }] };
      return { rows: [] };
    },
    async request(p, o = {}) {
      this.calls.push(p);
      if (o.method === 'POST' && p.includes('ResourceGraph')) return { data: [{ subscriptionId: SUB, name: 'Lab' }] };
      if (o.method === 'POST' || o.method === 'PUT') { this.sent.push({ p, ...o }); return o.method === 'PUT' ? { name: 'req1', properties: { status: 'Provisioned' } } : { id: 'req1', status: 'Provisioned' }; }
      if (p.startsWith(`/v1.0/groups/${G}`)) return { displayName: 'sg-e360-admin' };
      throw Object.assign(new Error('nf'), { status: 404 });
    },
  };
}

test('ISO durations convert both ways', () => {
  assert.equal(isoMinutes('PT8H'), 480); assert.equal(isoMinutes('PT30M'), 30); assert.equal(isoMinutes('P1D'), 1440); assert.equal(isoMinutes('P1DT2H'), 1560); assert.equal(isoMinutes('bogus'), null);
  assert.equal(minutesIso(90), 'PT1H30M'); assert.equal(minutesIso(60), 'PT1H'); assert.equal(minutesIso(30), 'PT30M');
});

test('self table uses filterByCurrentUser for roles and groups, one row per item, Activate/Deactivate actions', async () => {
  const api = fake();
  const r = await pimTable(api, { id: ME, self: true }, { azure: false });
  assert.ok(api.calls.some(c => c.includes("roleEligibilityScheduleInstances/filterByCurrentUser(on='principal')")));
  assert.ok(api.calls.some(c => c.includes("roleAssignmentScheduleInstances/filterByCurrentUser(on='principal')")));
  assert.ok(api.calls.some(c => c.includes("group/eligibilityScheduleInstances/filterByCurrentUser(on='principal')")));
  assert.ok(api.calls.some(c => c.includes("group/assignmentScheduleInstances/filterByCurrentUser(on='principal')")));
  const ga = r.rows.filter(x => x.name === 'Global Administrator');
  // Merged: the activation absorbs its eligibility, so Global Administrator is one row.
  assert.deepEqual(ga.map(x => [x.state, x.action, x.eligible]), [['Active (activated)', 'deactivate', true]]);
  const g = r.rows.find(x => x.type === 'Group');
  assert.equal(g.name, 'sg-e360-admin'); assert.equal(g.action, 'activate'); assert.deepEqual(g.target, { groupId: G, accessId: 'member' });
  assert.ok(r.notes.some(n => /connect Azure/i.test(n)));
});

test('Azure rows use asTarget() for self and assignedTo for another user', async () => {
  const api = fake();
  const r = await pimTable(api, { id: ME, self: true }, { azure: true });
  assert.ok(api.calls.some(c => c.includes(`/subscriptions/${SUB}/providers/Microsoft.Authorization/roleEligibilityScheduleInstances`) && c.includes('asTarget')));
  const az = r.rows.find(x => x.type === 'Azure role');
  assert.equal(az.name, 'Contributor'); assert.equal(az.scopeLabel, 'Lab (subscription)'); assert.equal(az.action, 'activate'); assert.equal(az.target.eligibilityScheduleId, ELIG);
  const api2 = fake();
  const o = await pimTable(api2, { id: ME, self: false }, { azure: true });
  assert.ok(api2.calls.some(c => c.includes('assignedTo')));
  assert.ok(!api2.calls.some(c => c.includes('filterByCurrentUser')));
  assert.ok(api2.calls.some(c => decodeURIComponent(c).includes(`principalId eq '${ME}'`)));
  assert.ok(o.rows.every(x => x.action === null), 'investigate is read-only');
});

test('403 on a source becomes a Not available problem with the scope it needs', async () => {
  const r = await pimTable(fake({ fail: { 'group/': 403 } }), { id: ME, self: true });
  assert.ok(r.problems.some(p => p.source === 'Group' && /PrivilegedAssignmentSchedule\.ReadWrite\.AzureADGroup/.test(p.reason)));
  assert.ok(r.rows.some(x => x.type === 'Entra role'));
});

test('policy: maximum duration, justification, ticket and MFA from the end-user rules', async () => {
  const p = await pimPolicy(fake(), 'Entra role', { roleDefinitionId: RD, directoryScopeId: '/' });
  assert.deepEqual([p.maxMinutes, p.justification, p.ticket, p.mfa], [240, true, true, true]);
  assert.equal(policyFrom(null).source, 'default');
  const bad = await pimPolicy(fake({ fail: { policies: 403 } }), 'Entra role', { roleDefinitionId: RD, directoryScopeId: '/' });
  assert.equal(bad.source, 'default'); assert.match(bad.reason, /Microsoft applies the real policy/);
});

test('activate and deactivate use selfActivate/selfDeactivate and ARM SelfActivate requests', async () => {
  const api = fake();
  await pimRequest(api, { id: ME }, { type: 'Entra role', action: 'activate', target: { roleDefinitionId: RD, directoryScopeId: '/' }, reason: 'Fix ticket', minutes: 60, ticket: { number: 'INC1' } });
  let s = api.sent.pop();
  assert.ok(s.p.endsWith('/roleManagement/directory/roleAssignmentScheduleRequests'));
  assert.equal(s.body.action, 'selfActivate'); assert.equal(s.body.principalId, ME); assert.equal(s.body.scheduleInfo.expiration.duration, 'PT1H'); assert.equal(s.body.ticketInfo.ticketNumber, 'INC1');
  await pimRequest(api, { id: ME }, { type: 'Group', action: 'deactivate', target: { groupId: G, accessId: 'member' } });
  s = api.sent.pop();
  assert.ok(s.p.endsWith('/privilegedAccess/group/assignmentScheduleRequests')); assert.equal(s.body.action, 'selfDeactivate'); assert.equal(s.body.justification, undefined);
  await pimRequest(api, { id: ME }, { type: 'Azure role', action: 'activate', target: { scope: `/subscriptions/${SUB}`, roleDefinitionId: AZROLE, eligibilityScheduleId: ELIG }, reason: 'deploy', minutes: 120 });
  s = api.sent.pop();
  assert.equal(s.method, 'PUT'); assert.equal(s.origin, 'https://management.azure.com');
  assert.match(s.p, new RegExp(`^/subscriptions/${SUB}/providers/Microsoft.Authorization/roleAssignmentScheduleRequests/[0-9a-f-]{36}\\?api-version=2020-10-01$`));
  assert.equal(s.body.properties.requestType, 'SelfActivate'); assert.equal(s.body.properties.linkedRoleEligibilityScheduleId, ELIG); assert.equal(s.body.properties.scheduleInfo.expiration.duration, 'PT2H');
});

test('requests are validated: reason required, targets cannot point anywhere else', async () => {
  const api = fake();
  await assert.rejects(pimRequest(api, { id: ME }, { type: 'Entra role', action: 'activate', target: { roleDefinitionId: RD, directoryScopeId: '/' }, minutes: 60 }), /reason/);
  assert.throws(() => checkTarget('Azure role', { scope: `/subscriptions/${SUB}/../x`, roleDefinitionId: AZROLE }), /Invalid Azure scope/);
  assert.throws(() => checkTarget('Azure role', { scope: 'https://evil.example/x', roleDefinitionId: AZROLE }), /Invalid/);
  assert.throws(() => checkTarget('Group', { groupId: G, accessId: 'admin' }), /Invalid group access/);
  assert.equal(api.sent.length, 0);
});

test('withActions offers no action when not self', () => {
  assert.equal(withActions([{ state: 'Eligible', key: 'k' }], false)[0].action, null);
});

test('UI: table columns, action buttons only on self, durations capped at policy max, poll settles', () => {
  const rows = [{ type: 'Group', name: 'sg-e360-admin', scope: G, scopeLabel: 'Group member', state: 'Eligible', start: '2026-10-01T00:00:00Z', end: null, action: 'activate', key: 'k' }];
  const mine = pimTableHtml(rows, { esc, self: true });
  for (const c of ['Type', 'Name', 'Scope', 'State', 'Eligibility', 'Start', 'End', 'Action']) assert.match(mine, new RegExp(`data-pim-sort="${c.toLowerCase()}"[^>]*>${c}<`));
  assert.match(mine, /class="btn" data-pim-action="activate"/);
  const other = pimTableHtml(rows, { esc, self: false });
  assert.doesNotMatch(other, /data-pim-action|data-pim-sort="action"/);
  assert.deepEqual(durationOptions(240), [30, 60, 120, 240]); assert.deepEqual(durationOptions(90), [30, 60, 90]);
  assert.match(activateFormHtml(rows[0], { maxMinutes: 240, ticket: true }, { esc }), /name="ticketNumber" required/);
  assert.doesNotMatch(activateFormHtml(rows[0], { maxMinutes: 240, ticket: false }, { esc }), /ticketNumber/);
  assert.equal(settled([{ key: 'k', state: 'Active (activated)' }], 'k', 'activate'), true);
  assert.equal(settled([{ key: 'k', state: 'Eligible' }], 'k', 'activate'), false);
  assert.equal(settled([{ key: 'k', state: 'Eligible' }], 'k', 'deactivate'), true);
});

test('wiring: nav items, routes gated by E360.Reader, server routes present, My access points to the PIM page', () => {
  const html = read('public/index.html'), app = read('public/app.js'), srv = read('server/index.mjs'), acct = read('public/account.js');
  assert.match(html, /data-view="pim"[^>]*>.*PIM<\/button>/); assert.match(html, /data-view="my-pim"[^>]*>.*My PIM<\/button>/); assert.match(app, /'my-pim': \['My PIM',/);
  assert.match(html, /id="pim-page"/); assert.match(html, /id="my-pim"/);
  assert.equal(roleForPath('/api/me/pim'), null); assert.equal(roleForPath('/api/me/pim/request'), null); assert.equal(roleForPath('/api/me/pim/policy'), null); assert.equal(roleForPath('/api/investigate/pim'), 'E360.Reader');
  assert.equal(VIEW_ROLES['my-pim'], undefined, 'My PIM needs no app role'); assert.equal(VIEW_ROLES.pim, 'E360.Reader');
  for (const r of ["app.get('/api/me/pim'", "app.post('/api/me/pim/policy'", "app.post('/api/me/pim/request'", "app.get('/api/investigate/pim'"]) assert.ok(srv.includes(r), r);
  assert.match(app, /createPimView\(/); assert.match(acct, /data-go="my-pim"/);
});

test('PIM scopes are in GRAPH_SCOPES (code default and .env.example)', () => {
  const env = read('.env.example').match(/^GRAPH_SCOPES=(.*)$/m)[1].split(',');
  const def = read('server/index.mjs').match(/process\.env\.GRAPH_SCOPES \|\| '([^']+)'/)[1].split(',');
  for (const s of ['RoleEligibilitySchedule.Read.Directory', 'RoleAssignmentSchedule.Read.Directory', 'RoleAssignmentSchedule.ReadWrite.Directory', 'PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup', 'PrivilegedEligibilitySchedule.Read.AzureADGroup', 'RoleManagementPolicy.Read.Directory', 'RoleManagementPolicy.Read.AzureADGroup']) { assert.ok(env.includes(s), `env ${s}`); assert.ok(def.includes(s), `default ${s}`); }
});

test('My PIM: no app role, but only ever the signed-in principal', async () => {
  const { groupNote } = await import('../public/pim.js');
  const api = fake();
  const OTHER = '8f210003-6b21-4818-83bc-fae28e1242ab';
  await pimRequest(api, { id: ME }, { type: 'Group', action: 'activate', principalId: OTHER, target: { groupId: G, accessId: 'member', principalId: OTHER }, reason: 'x', minutes: 60 });
  const s = api.sent.pop();
  assert.equal(s.body.principalId, ME); assert.equal(s.body.action, 'selfActivate');
  await assert.rejects(pimRequest(api, { id: '' }, { type: 'Group', action: 'activate', target: { groupId: G, accessId: 'member' }, reason: 'x', minutes: 60 }), /object id/);
  const srv = read('server/index.mjs');
  assert.match(srv, /const pimMe = s => \{ const id = s\.account\?\.idTokenClaims\?\.oid/);
  assert.match(srv, /app\.post\('\/api\/me\/pim\/request'[\s\S]{0,400}pimRequest\(api, me, req\.body\)/);
  assert.match(srv, /app\.get\('\/api\/me\/pim', async \(req, res\) => res\.json\(await pimTable\(pimApi\(req\.session\), pimMe\(req\.session\)/);
  assert.doesNotMatch(srv, /'\/api\/account\/pim/);
  assert.equal(roleForPath('/api/investigate/pim'), 'E360.Reader');
  assert.match(groupNote({ type: 'Group', name: 'sg-e360-reader' }), /grants E360\.Reader.*sign in again/);
  assert.match(groupNote({ type: 'Group', name: 'other' }), /sign in again/);
  assert.equal(groupNote({ type: 'Entra role', name: 'x' }), '');
});

test('createPimView renders into a root given as a function (how app.js wires My PIM), with Activate', async () => {
  // The in-browser render is covered by tests/pim-ux.test.mjs and tests/access-denied.test.mjs (function root, Activate shown).
  assert.match(read('public/pim.js'), /const el = \(\) => typeof root === 'function' \? root\(\) : \$\(root\)/);
  const app = read('public/app.js');
  assert.match(app, /\$\('#account-panel > \.account-controls'\)\.hidden = v === 'my-pim'/);
  assert.match(app, /accountView\.setActive\(my && v !== 'my-pim'/);
});
