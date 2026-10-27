import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { applyFilters, sortRows, sortOptions, multiSelectHtml } from '../public/multiselect.js';
import { accessRows, roleTiming, accessLink, accessType } from '../public/group-types.js';
import { myRoles, entraRoleLink, azureScopeLink } from '../server/my-roles.mjs';
import { demoAccountReport } from '../server/account.mjs';

const cols = [{ key: 'k', label: 'Kind', get: r => r.k }, { key: 'n', label: 'Num', get: r => r.n }];
const rows = [{ k: 'beta', n: 10 }, { k: 'Alpha', n: 2 }, { k: null, n: 1 }, { k: 'gamma', n: 3 }];

test('sortRows orders by column ascending/descending, missing values last, stable', () => {
  assert.deepEqual(sortRows(rows, cols, { key: 'k', dir: 'asc' }).map(r => r.k), ['Alpha', 'beta', 'gamma', null]);
  assert.deepEqual(sortRows(rows, cols, { key: 'k', dir: 'desc' }).map(r => r.k), ['gamma', 'beta', 'Alpha', null]);
  assert.deepEqual(sortRows(rows, cols, { key: 'n', dir: 'asc' }).map(r => r.n), [1, 2, 3, 10]);
  assert.equal(sortRows(rows, cols, null), rows);
  assert.deepEqual(applyFilters(rows, cols, { k: new Set(['beta']) }, { key: 'n', dir: 'desc' }).map(r => r.n), [3, 2, 1]);
});

test('dropdown has Sort A→Z / Z→A at the top, options alphabetical, n/a last, arrow when sorted', () => {
  assert.deepEqual(sortOptions([{ value: 'n/a', label: 'n/a' }, { value: 'b', label: 'b' }, { value: 'A', label: 'A' }]).map(o => o.value), ['A', 'b', 'n/a']);
  const html = multiSelectHtml({ key: 'k', label: 'Kind', options: ['zeta', 'n/a', 'alpha'], excluded: new Set(), sort: { key: 'k', dir: 'desc' } });
  assert.ok(html.indexOf('Sort A→Z') < html.indexOf('Select all'));
  assert.match(html, /data-msel-sort="desc" aria-pressed="true"/);
  assert.match(html, /data-msel-sorted="desc"/); assert.match(html, /Kind \(3 of 3\) ▼/);
  assert.ok(html.indexOf('alpha') < html.indexOf('zeta') && html.indexOf('zeta') < html.lastIndexOf('n/a'));
  assert.ok(!/data-msel-sorted/.test(multiSelectHtml({ key: 'x', label: 'X', options: ['a'], excluded: new Set(), sort: { key: 'k', dir: 'asc' } })));
});

test('every table passes its sort state through', async () => {
  const app = await readFile(new URL('../public/app.js', import.meta.url), 'utf8');
  const acct = await readFile(new URL('../public/account.js', import.meta.url), 'utf8');
  assert.match(app, /applyFilters\(rows, cols, state\.fx\.excluded, state\.fx\.sort\)/);
  assert.match(app, /sort: state\.fx\.sort/);
  assert.match(acct, /applyFilters\(all, GROUP_COLS, groupState\.fx\.excluded, groupState\.fx\.sort\)/);
});

const fakeApi = handlers => ({ calls: [], async pages(url, opts) { this.calls.push(url); for (const [re, fn] of handlers) if (re.test(url)) return fn(url, opts); return { rows: [] }; }, async request(url) { return this.pages(url); } });

test('myRoles returns Entra active/eligible with PIM timing and Azure roles with IAM links', async () => {
  const now = Date.now();
  const api = fakeApi([
    [/roleAssignmentScheduleInstances\?/, () => ({ rows: [{ id: 'a1', roleDefinitionId: 'r1', roleDefinition: { displayName: 'Security Administrator' }, startDateTime: new Date(now - 36e5).toISOString(), endDateTime: new Date(now + 2 * 36e5).toISOString(), directoryScopeId: '/' }] })],
    [/roleEligibilityScheduleInstances\?/, () => ({ rows: [{ id: 'e1', roleDefinitionId: 'r2', roleDefinition: { displayName: 'Global Administrator' }, startDateTime: new Date(now - 864e5).toISOString(), directoryScopeId: '/' }] })],
    [/resources|providers\/Microsoft.ResourceGraph/i, () => ({ rows: [] })],
  ]);
  const me = { id: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' };
  const r = await myRoles(api, me, [], { tenant: 't.example' });
  const sec = r.rows.find(x => x.name === 'Security Administrator'), ga = r.rows.find(x => x.name === 'Global Administrator');
  assert.equal(sec.kind, 'Directory role'); assert.equal(sec.membership, 'Active'); assert.equal(sec.source, 'Direct');
  assert.ok(sec.remaining > 0 && sec.remaining <= 2 * 36e5); assert.ok(sec.granted);
  assert.equal(ga.membership, 'Eligible');
  assert.match(sec.link, /^https:\/\/entra\.microsoft\.com\/#view\/Microsoft_AAD_IAM\/RoleMenuBlade\/~\/RoleMembers\/objectId\/r1\//);
  assert.ok(api.calls.some(u => u.includes(`principalId+eq+'${me.id}'`) || decodeURIComponent(u).includes(`principalId eq '${me.id}'`)));
});

test('myRoles never throws; failures are reported per source', async () => {
  const api = { async pages() { throw Object.assign(new Error('nope'), { status: 403 }); } };
  const r = await myRoles(api, { id: 'x' }, []);
  assert.deepEqual(r.rows, []); assert.ok(r.problems.unavailable.length >= 1);
});

test('My access table rows: roles first, timing text, links and type labels', () => {
  const d = demoAccountReport('full');
  const all = accessRows(d.sections.groups, d.sections.roles);
  assert.equal(all[0].kind, 'Directory role');
  const az = all.find(r => r.kind === 'Azure role');
  assert.equal(accessType(az), 'Azure role'); assert.equal(roleTiming(az).remaining, 'No end date');
  assert.equal(accessLink(az), azureScopeLink('contoso.onmicrosoft.com', '/subscriptions/00000000-0000-0000-0000-000000000000'));
  assert.match(accessLink(az), /portal\.azure\.com\/#@contoso\.onmicrosoft\.com\/resource\/subscriptions\/.+\/users$/);
  assert.equal(roleTiming(all[0]).remaining, '5h 0m');
  assert.equal(roleTiming(d.sections.groups[0]).remaining, '');
  assert.match(entraRoleLink('abc', 'X Y'), /objectId\/abc\/roleName\/X%20Y\/roleTemplateId\/abc\//);
});

test('Access > Admin roles points the signed-in user to My access instead of repeating the table', async () => {
  const app = await readFile(new URL('../public/app.js', import.meta.url), 'utf8');
  assert.match(app, /state\.tab === 'roles' && isSignedInUser\(\)/);
  assert.match(app, /data-go="my-access"/);
  assert.match(app, /state\.fx\.sort = null; loadEntity/);
});
