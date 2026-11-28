import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { accessPortalLinks, accessPortalLinksHtml, accessPortalNote } from '../public/access-portals.js';

const TENANT = '3a871f00-1111-2222-3333-444455556666';
const USER = { id: '8f210001-6b21-4818-83bc-fae28e1242ab', type: 'user' };
const APP = { id: '11111111-2222-3333-4444-555555555555', type: 'application', appId: '99999999-8888-7777-6666-555555555555' };
const TABS = ['ca', 'roles', 'packages', 'groups', 'apps', 'au', 'pimreq', 'audit', 'prov'];
const HOSTS = ['entra.microsoft.com', 'portal.azure.com', 'intune.microsoft.com'];

test('every Access tab links to at least two portals, all tenant-scoped https links on Microsoft portal hosts', () => {
  for (const tab of TABS) {
    const links = accessPortalLinks(tab, { tenant: TENANT, entity: USER });
    assert.ok(new Set(links.map(l => l.portal)).size >= 2, `${tab} covers more than one portal`);
    for (const l of links) {
      const u = new URL(l.url);
      assert.equal(u.protocol, 'https:');
      assert.ok(HOSTS.includes(u.host), `${tab}: ${u.host}`);
      assert.ok(u.hash.startsWith(`#@${TENANT}/view/`), `${tab}: ${l.url} carries the tenant`);
      assert.match(l.path, /> /, `${tab}: menu path given`);
    }
  }
});

test('Conditional Access lists the Entra, Azure and Intune locations', () => {
  const portals = accessPortalLinks('ca', { tenant: TENANT, entity: USER }).map(l => l.portal);
  assert.deepEqual(portals, ['Microsoft Entra admin center', 'Azure portal', 'Microsoft Intune admin center']);
});

test('user and app tabs open that object\'s own blade', () => {
  assert.ok(accessPortalLinks('roles', { tenant: TENANT, entity: USER })[0].url.endsWith(`/AdministrativeRole/userId/${USER.id}`));
  const roles = accessPortalLinks('roles', { tenant: TENANT, entity: USER });
  assert.ok(roles[2].url.endsWith('/ActivationMenuBlade/~/aadmigratedroles'));
  assert.ok(roles[1].url.startsWith('https://portal.azure.com/') && roles[1].url.endsWith(`/AdministrativeRole/userId/${USER.id}`));
  for (const l of accessPortalLinks('apps', { tenant: TENANT, entity: USER })) assert.ok(l.url.endsWith(`/AssignedApplications/userId/${USER.id}`), l.url);
  // Menu ids Aaron saw fall back to the user overview must not come back.
  for (const tab of TABS) for (const l of accessPortalLinks(tab, { tenant: TENANT, entity: USER })) assert.doesNotMatch(l.url, /~\/(Applications|AzureRoleAssignments)\//);
  assert.ok(accessPortalLinks('groups', { tenant: TENANT, entity: USER })[0].url.endsWith(`/Groups/userId/${USER.id}`));
  assert.ok(accessPortalLinks('apps', { tenant: TENANT, entity: APP })[0].url.endsWith(`/Permissions/objectId/${APP.id}/appId/${APP.appId}`));
  const sso = accessPortalLinks('sso', { tenant: TENANT, entity: APP }).map(l => l.url);
  assert.ok(sso.some(u => u.endsWith(`/SignOn/objectId/${APP.id}/appId/${APP.appId}`)));
  assert.ok(sso.some(u => u.endsWith(`/AppRoles/appId/${APP.appId}`)));
  assert.deepEqual(accessPortalLinks('sso', { tenant: TENANT, entity: USER }), []);
});

test('a missing or odd tenant or id never ends up in the link', () => {
  assert.ok(accessPortalLinks('ca', {})[0].url.startsWith('https://entra.microsoft.com/#view/'));
  assert.ok(accessPortalLinks('ca', { tenant: 'x"/><script>' })[0].url.startsWith('https://entra.microsoft.com/#view/'));
  assert.ok(accessPortalLinks('roles', { tenant: TENANT, entity: { id: '../evil', type: 'user' } })[0].url.endsWith('/AllRolesBlade'));
  const html = accessPortalLinksHtml('ca', { tenant: TENANT, entity: USER }, { esc: s => String(s).replace(/[&<>"']/g, c => `&#${c.charCodeAt(0)};`) });
  assert.match(html, /target="_blank" rel="noopener noreferrer"/);
  assert.match(html, /Open in the portal/);
});

test('Access page: tabs wrap, top bar grows, status text has no dot and uses the cell font size', async () => {
  const css = await readFile(new URL('../public/styles.css', import.meta.url), 'utf8');
  assert.match(css, /#access-page \.tabs\{flex-wrap:wrap/);
  assert.match(css, /#access-page \.tab\{white-space:nowrap\}/);
  assert.match(css, /\.topbar\{position:sticky[^}]*height:auto;min-height:76px/);
  assert.match(css, /\.result::before\{content:none/);
  assert.match(css, /\.event-table \.result[^{]*\{font-size:inherit\}/);
  const html = await readFile(new URL('../public/index.html', import.meta.url), 'utf8');
  assert.match(html, /<div id="access-portal-links"><\/div><section class="panel" id="access-tab-body">/);
});

test('Intune unreadable: the Devices page and Summary card send the reader to PIM', async () => {
  const app = await readFile(new URL('../public/app.js', import.meta.url), 'utf8');
  assert.doesNotMatch(app, /Intune source unavailable or permission missing/);
  assert.match(app, /function intuneMissingHtml[\s\S]*?INVESTIGATE &gt; PIM[\s\S]*?data-go="pim"/);
  assert.match(app, /go\('Open PIM', 'pim'\)/);
});

test('links stack one per line under a note that says what they open, on every tab', () => {
  const esc = s => String(s).replace(/[&<>"']/g, c => `&#${c.charCodeAt(0)};`);
  for (const tab of [...TABS, 'sso']) {
    const entity = tab === 'sso' ? APP : USER, links = accessPortalLinks(tab, { tenant: TENANT, entity });
    const html = accessPortalLinksHtml(tab, { tenant: TENANT, entity }, { esc });
    assert.equal((html.match(/<li>/g) || []).length, links.length, `${tab}: one line per link`);
    assert.ok(accessPortalNote(tab, entity).length > 40, `${tab}: has a note`);
    assert.match(html, /class="portal-where-note"/);
  }
  assert.match(accessPortalNote('ca', USER), /same Conditional Access policies/);
  assert.match(accessPortalNote('roles', USER), /different page: your own PIM roles/);
});

test('Access tabs are in alphabetical order with a | between them', async () => {
  const html = await readFile(new URL('../public/index.html', import.meta.url), 'utf8');
  const strip = html.match(/aria-label="Access">(.*?)<\/div>/)[1];
  const names = [...strip.matchAll(/>([^<]+)<\/button>/g)].map(m => m[1]);
  assert.deepEqual(names, [...names].sort((a, b) => a.toLowerCase().localeCompare(b.toLowerCase())));
  assert.equal(names.length, 11);
  const css = await readFile(new URL('../public/styles.css', import.meta.url), 'utf8');
  assert.match(css, /#access-page \.tab:not\(\[hidden\]\) ~ \.tab:not\(\[hidden\]\)::before\{content:'\|'/);
});

// Each of these was opened in a signed-in browser (2026-11-14) and showed the named page. Earlier guesses
// (AdminUnitsManagementMenuBlade, CommonMenuBlade quickStart, ~/Applications, ~/AzureRoleAssignments) failed.
test('portal links use the blades verified in a real browser', () => {
  const urls = tab => accessPortalLinks(tab, { tenant: TENANT, entity: USER }).map(l => l.url);
  assert.deepEqual(urls('au'), [
    `https://entra.microsoft.com/#@${TENANT}/view/Microsoft_AAD_IAM/RolesManagementMenuBlade/~/AdminUnits`,
    `https://portal.azure.com/#@${TENANT}/view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/AdminUnit`,
  ]);
  const pim = urls('pimreq').filter(u => u.includes('PIMCommon'));
  assert.deepEqual(pim, ['https://entra.microsoft.com/', 'https://portal.azure.com/'].map(h => `${h}#@${TENANT}/view/Microsoft_Azure_PIMCommon/ResourceMenuBlade/~/Audit/resourceId//resourceType/tenant/provider/aadroles`));
  for (const tab of [...TABS, 'sso']) for (const u of accessPortalLinks(tab, { tenant: TENANT, entity: tab === 'sso' ? APP : USER }).map(l => l.url))
    assert.doesNotMatch(u, /AdminUnitsManagementMenuBlade|CommonMenuBlade\/~\/quickStart|~\/(Applications|AzureRoleAssignments)\//, u);
});
