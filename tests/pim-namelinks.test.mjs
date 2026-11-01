// PIM tables: Name is a link to the object (role, group, Azure scope) and a Sources line links where the data comes from.
import test from 'node:test';
import assert from 'node:assert/strict';
import { nameLink, safeLink, sourcesHtml, pimRowsHtml, shownRows, mergeRows } from '../public/pim.js';
const esc = v => String(v ?? '').replace(/[&<>"']/g, c => `&#${c.charCodeAt(0)};`);
const RD = '8f210001-6b21-4818-83bc-fae28e1242ab', GID = 'aaaaaaaa-1111-2222-3333-444444444444', SUB = '33333333-3333-3333-3333-333333333333';
const role = { id: 'r', type: 'Entra role', name: 'Global Reader', state: 'Eligible', key: 'k1', target: { roleDefinitionId: RD, directoryScopeId: '/' } };
const group = { id: 'g', type: 'Group', name: 'Contoso Finance', state: 'Eligible', key: 'k2', target: { groupId: GID, accessId: 'member' } };
const az = { id: 'a', type: 'Azure role', name: 'Reader', state: 'Active (permanent)', key: 'k3', scope: `/subscriptions/${SUB}/resourceGroups/rg-contoso`, target: { scope: `/subscriptions/${SUB}/resourceGroups/rg-contoso`, roleDefinitionId: 'x' } };

test('name links: Entra role blade, group overview, Azure scope; none for management groups or bad ids', () => {
  assert.equal(nameLink(role), `https://entra.microsoft.com/#view/Microsoft_AAD_IAM/RoleMenuBlade/~/RoleMembers/objectId/${RD}/roleName/Global%20Reader/roleTemplateId/${RD}/adminUnitObjectId//customRole~/false/resourceScope/%2F`);
  assert.equal(nameLink(group), `https://entra.microsoft.com/#view/Microsoft_AAD_IAM/GroupDetailsMenuBlade/~/Members/groupId/${GID}`);
  assert.equal(nameLink({ ...group, target: { groupId: GID, accessId: 'owner' } }), `https://entra.microsoft.com/#view/Microsoft_AAD_IAM/GroupDetailsMenuBlade/~/Owners/groupId/${GID}`);
  assert.equal(nameLink({ ...az, target: { scope: `/subscriptions/${SUB}` } }), `https://portal.azure.com/#@/resource/subscriptions/${SUB}/users`);
  assert.equal(nameLink(az), `https://portal.azure.com/#@/resource/subscriptions/${SUB}/resourceGroups/rg-contoso/users`);
  assert.equal(nameLink({ ...az, scope: '/providers/Microsoft.Management/managementGroups/contoso', target: { scope: '/providers/Microsoft.Management/managementGroups/contoso' } }), null);
  assert.equal(nameLink({ ...group, target: { groupId: 'x" onmouseover="alert(1)' } }), null);
  assert.equal(nameLink({ ...az, target: { scope: `/subscriptions/${SUB}/resourceGroups/a"b` } }), null);
  assert.equal(safeLink('javascript:alert(1)'), null); assert.equal(safeLink('https://evil.example/'), null);
  assert.equal(safeLink('https://portal.azure.com/x"y'), null);
});

test('rows: the name is an <a> in a new tab with noopener; sort and filter still use the plain name', () => {
  const html = pimRowsHtml([role, group], { esc, self: true });
  assert.match(html, /<a href="https:\/\/entra\.microsoft\.com\/#view\/Microsoft_AAD_IAM\/GroupDetailsMenuBlade\/~\/Members\/groupId\/aaaaaaaa-1111-2222-3333-444444444444" target="_blank" rel="noopener noreferrer">Contoso Finance<\/a>/);
  const plain = pimRowsHtml([{ ...group, target: {} }], { esc, self: true });
  assert.doesNotMatch(plain, /<a /); assert.match(plain, /<td>Contoso Finance/);
  const rows = mergeRows([role, group], true);
  assert.deepEqual(shownRows(rows, { self: true, filters: { name: 'contoso' } }).map(r => r.name), ['Contoso Finance']);
});

test('Sources: only the row types shown; My roles links only on My PIM', () => {
  const mine = sourcesHtml([role, group], true, esc);
  assert.match(mine, /^Sources: /);
  assert.match(mine, /ActivationMenuBlade\/~\/aadmigratedroles/); assert.match(mine, /RolesManagementMenuBlade\/~\/AllRoles/);
  assert.match(mine, /ActivationMenuBlade\/~\/aadgroup/); assert.match(mine, /GroupsManagementMenuBlade\/~\/AllGroups/);
  assert.doesNotMatch(mine, /azurerbac|subscriptions/);
  assert.equal((mine.match(/target="_blank" rel="noopener noreferrer"/g) || []).length, 4);
  const other = sourcesHtml([az], false, esc);
  assert.doesNotMatch(other, /My roles/); assert.match(other, /Microsoft\.Resources%2Fsubscriptions/); assert.match(other, /#browse\/resourcegroups/);
  assert.equal(sourcesHtml([], true, esc), '');
});

test('nav section labels are white and one weight bolder', async () => {
  const { readFileSync } = await import('node:fs');
  const css = readFileSync(new URL('../public/styles.css', import.meta.url), 'utf8');
  assert.match(css, /\.nav-label\{[^}]*color:#fff;font-weight:800\}/);
});