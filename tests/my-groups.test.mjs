import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { classifyMemberships, groupKind, typeLabel, groupLink, GROUP_SELECT, ALL_GROUPS_URL, ADMIN_UNITS_URL } from '../public/group-types.js';
import { accountReport } from '../server/account.mjs';

const G = n => `${n}${n}${n}${n}${n}${n}${n}${n}-${n}${n}${n}${n}-${n}${n}${n}${n}-${n}${n}${n}${n}-${n.repeat(12)}`;
const grp = (id, name, extra) => ({ '@odata.type': '#microsoft.graph.group', id, displayName: name, groupTypes: [], ...extra });

test('group types: Security, Microsoft 365, Mail-enabled security, Distribution; Dynamic vs Assigned; role-assignable; synced vs cloud', () => {
  assert.equal(groupKind(grp('a', 'x', { securityEnabled: true, mailEnabled: false })), 'Security');
  assert.equal(groupKind(grp('a', 'x', { groupTypes: ['Unified'], securityEnabled: false, mailEnabled: true })), 'Microsoft 365');
  assert.equal(groupKind(grp('a', 'x', { securityEnabled: true, mailEnabled: true })), 'Mail-enabled security');
  assert.equal(groupKind(grp('a', 'x', { securityEnabled: false, mailEnabled: true })), 'Distribution');
  const direct = [
    grp(G('1'), 'Sec', { securityEnabled: true, onPremisesSyncEnabled: true }),
    grp(G('2'), 'Admins', { securityEnabled: true, isAssignableToRole: true }),
    { '@odata.type': '#microsoft.graph.directoryRole', id: G('3'), displayName: 'Global Reader' },
    { '@odata.type': '#microsoft.graph.administrativeUnit', id: G('4'), displayName: 'West AU' },
  ];
  const transitive = [...direct, grp(G('5'), 'All staff', { groupTypes: ['Unified', 'DynamicMembership'], mailEnabled: true, membershipRule: 'user.accountEnabled -eq true' })];
  const { rows, directoryRoles } = classifyMemberships(direct, transitive);
  assert.equal(directoryRoles, 1);
  assert.ok(!rows.some(r => r.kind === 'Directory role'), 'directory-role memberships come from the role APIs, not memberOf');
  const by = Object.fromEntries(rows.map(r => [r.name, r]));
  assert.equal(typeLabel(by.Sec), 'Security · Assigned'); assert.equal(by.Sec.source, 'Synced from on-premises AD'); assert.equal(by.Sec.membership, 'Direct');
  assert.equal(typeLabel(by.Admins), 'Security · Assigned · Role-assignable'); assert.equal(by.Admins.source, 'Cloud (Entra ID)');
  assert.equal(typeLabel(by['All staff']), 'Microsoft 365 · Dynamic'); assert.equal(by['All staff'].membership, 'Transitive');
  assert.equal(typeLabel(by['West AU']), 'Administrative unit');
  assert.equal(groupLink(by.Sec), `https://entra.microsoft.com/#view/Microsoft_AAD_IAM/GroupDetailsMenuBlade/~/Overview/groupId/${G('1')}`);
  assert.equal(groupLink(by['West AU']), ADMIN_UNITS_URL);
  assert.equal(groupLink({ id: 'bad', kind: 'Security' }), ALL_GROUPS_URL);
});

test('My account reads memberOf and transitiveMemberOf with the group properties via $select', async () => {
  const urls = [];
  const api = { async request(p) { if (p.startsWith('/v1.0/me?')) return { id: G('9'), displayName: 'A', userPrincipalName: 'a@x.test' }; return { value: [] }; },
    async pages(p) { urls.push(p); if (p.startsWith('/v1.0/me/memberOf')) return { rows: [grp(G('1'), 'Sec', { securityEnabled: true })], truncated: false }; if (p.startsWith('/v1.0/me/transitiveMemberOf')) return { rows: [grp(G('1'), 'Sec', { securityEnabled: true }), grp(G('5'), 'Nested', { securityEnabled: true })], truncated: false }; return { rows: [], truncated: false }; } };
  const r = await accountReport(api, { tenant: G('9') });
  assert.ok(urls.includes(`/v1.0/me/memberOf?$select=${encodeURIComponent(GROUP_SELECT)}`));
  assert.ok(urls.some(u => u.startsWith('/v1.0/me/transitiveMemberOf?$select=id%2CdisplayName%2CgroupTypes%2CmailEnabled%2CsecurityEnabled%2CmembershipRule%2CisAssignableToRole%2ConPremisesSyncEnabled')));
  assert.deepEqual(r.sections.groups.map(g => [g.name, g.membership]), [['Nested', 'Transitive'], ['Sec', 'Direct']]);
});

test('Group memberships renders a paged, filterable table, not a dot-separated line', async () => {
  const js = await readFile(new URL('../public/account.js', import.meta.url), 'utf8');
  assert.ok(!/s\.groups\.map\(g => esc\(g\.name\)\)\.join\(' · '\)/.test(js));
  assert.match(js, /<th>Name<\/th><th>Type<\/th><th>Membership<\/th><th>Granted<\/th><th>Remaining<\/th><th>Source<\/th>/);
  assert.match(js, /table-scroll/); assert.match(js, /pagerHtml\('my-groups'/); assert.match(js, /multiSelectHtml/);
  assert.ok(!/Your admin roles are on Access/.test(js)); assert.match(js, /Group memberships and Role assignments/);
});
