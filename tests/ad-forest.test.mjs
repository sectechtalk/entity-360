// INVESTIGATE > Access > AD groups, live from a domain controller: every security group in the forest, synced or not.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { forestGroups, parseAdResult, mergeAdRows, adConfig, cloudHosted } from '../server/ad-forest.mjs';
import { tabTable } from '../server/bucket3.mjs';
import { b3Panel } from '../public/tab-tables.js';
import { fakeApi } from './pages-bucket5.test.mjs';
const read = f => readFileSync(new URL(`../${f}`, import.meta.url), 'utf8');
const esc = v => String(v ?? '').replace(/[&<>"']/g, c => `&#${c.charCodeAt(0)};`);
const h = { esc, emptyBox: t => `<div class="inline-empty">${esc(t)}</div>`, fmtTime: x => x, resultBadge: x => `<b>${x}</b>`, linkBtn: (u, l) => `<a href="${u}">${l}</a>` };

// Fictional forest contoso.com with a child domain emea.contoso.com.
const DOM = 'S-1-5-21-1000-2000-3000';
const USER_SID = `${DOM}-1601`;
const U = '22222222-2222-2222-2222-222222222222';
const winOn = { enabled: true, server: 'dc01.contoso.com', credential: 'C:\\e360\\ad-reader.xml', platform: 'win32' };
const live = {
  status: 'live', server: 'dc01.contoso.com', forest: 'contoso.com',
  user: { dn: 'CN=Pat Lee,OU=Staff,DC=contoso,DC=com', sam: 'CONTOSO\\plee', domain: 'contoso.com' },
  domains: [{ name: 'contoso.com', netbios: 'CONTOSO', reachable: true }, { name: 'emea.contoso.com', netbios: 'EMEA', reachable: true }],
  groups: [
    { sid: `${DOM}-513`, dn: 'CN=Domain Users,CN=Users,DC=contoso,DC=com', name: 'Domain Users', sam: 'Domain Users', domain: 'contoso.com', netbios: 'CONTOSO', scope: 'Global', membership: 'Primary', via: [], pathKnown: true },
    { sid: `${DOM}-1700`, dn: 'CN=Finance,OU=Groups,DC=contoso,DC=com', name: 'Finance', sam: 'Finance', domain: 'contoso.com', netbios: 'CONTOSO', scope: 'Global', membership: 'Direct', via: [], pathKnown: true },
    { sid: `${DOM}-1701`, dn: 'CN=FS-Finance-RW,OU=Groups,DC=contoso,DC=com', name: 'FS-Finance-RW', sam: 'FS-Finance-RW', domain: 'contoso.com', netbios: 'CONTOSO', scope: 'Domain local', membership: 'Nested', via: ['Finance'], pathKnown: true },
    { sid: 'S-1-5-21-4000-5000-6000-1200', dn: 'CN=EMEA-Share-Read,DC=emea,DC=contoso,DC=com', name: 'EMEA-Share-Read', sam: 'EMEA-Share-Read', domain: 'emea.contoso.com', netbios: 'EMEA', scope: 'Domain local', membership: 'Nested', via: ['Finance'], pathKnown: true },
    { sid: 'S-1-5-32-555', dn: 'CN=Remote Desktop Users,CN=Builtin,DC=contoso,DC=com', name: 'Remote Desktop Users', sam: 'Remote Desktop Users', domain: 'contoso.com', netbios: 'CONTOSO', scope: 'Builtin', membership: 'Nested', via: [], pathKnown: false },
  ],
  notes: ['1 distribution group(s) left out: they grant no access.'],
};
const graphTenant = () => ({
  [`/users/${U}?`]: { id: U, onPremisesSyncEnabled: true, onPremisesSamAccountName: 'plee', onPremisesDomainName: 'contoso.com', onPremisesDistinguishedName: 'CN=Pat Lee,OU=Staff,DC=contoso,DC=com', onPremisesSecurityIdentifier: USER_SID },
  [`/users/${U}/transitiveMemberOf`]: [{ id: 'gFin', displayName: 'Finance', securityEnabled: true, onPremisesSyncEnabled: true, onPremisesSamAccountName: 'Finance', onPremisesNetBiosName: 'CONTOSO', onPremisesSecurityIdentifier: `${DOM}-1700` }],
  [`/users/${U}/memberOf`]: [{ id: 'gFin' }],
});

test('forest groups: arguments go to the script as an array, credential path included', async () => {
  let seen;
  const r = await forestGroups(USER_SID, { config: winOn, run: async a => { seen = a; return JSON.stringify(live); } });
  assert.deepEqual(seen, ['-UserSid', USER_SID, '-Server', 'dc01.contoso.com', '-CredentialPath', 'C:\\e360\\ad-reader.xml']);
  assert.equal(r.status, 'live');
  assert.equal(r.groups.length, 5);
});

test('forest groups: off on Linux, bad SID, timeouts and junk output never throw', async () => {
  assert.equal((await forestGroups(USER_SID, { config: adConfig({}, 'linux') })).status, 'off');
  assert.equal(adConfig({ E360_AD_ENABLED: 'false' }, 'win32').enabled, false);
  assert.equal((await forestGroups('S-1-5-21-1; calc', { config: winOn, run: async () => { throw new Error('should not run'); } })).status, 'error');
  const slow = await forestGroups(USER_SID, { config: winOn, run: async () => { throw Object.assign(new Error('t'), { killed: true }); } });
  assert.match(slow.message, /timed out/);
  assert.equal(parseAdResult('not json').status, 'error');
  assert.equal(parseAdResult(JSON.stringify({ status: 'unreachable', message: 'Could not connect' })).status, 'unreachable');
  assert.equal(parseAdResult(JSON.stringify({ status: 'pwned' })).status, 'error');
  assert.equal(parseAdResult(JSON.stringify({ status: 'live', groups: [{ sid: 'nope' }] })).groups.length, 0);
});

test('merge: synced groups keep their Entra link, AD-only groups are marked, primary group first after direct', () => {
  const graph = [{ id: 'gFin', name: 'Finance', sid: `${DOM}-1700`, sam: 'CONTOSO\\Finance', link: 'https://entra.example/gFin', membership: 'Direct' }, { id: 'gOld', name: 'Old', sid: `${DOM}-1999`, membership: 'Direct', link: 'x' }];
  const rows = mergeAdRows(graph, parseAdResult(JSON.stringify(live)));
  assert.deepEqual(rows.map(r => [r.name, r.membership, r.inEntra]), [
    ['Finance', 'Direct', 'Synced'], ['Old', 'Direct', 'Synced'], ['Domain Users', 'Primary', 'AD only'],
    ['EMEA-Share-Read', 'Nested', 'AD only'], ['FS-Finance-RW', 'Nested', 'AD only'], ['Remote Desktop Users', 'Nested', 'AD only']]);
  assert.equal(rows[0].link, 'https://entra.example/gFin');
  assert.equal(rows.find(r => r.name === 'Old').note, 'In Entra, not returned by AD');
  assert.equal(rows.find(r => r.name === 'FS-Finance-RW').via, 'Finance');
  assert.equal(rows.find(r => r.name === 'Remote Desktop Users').via, 'Path not returned');
  assert.equal(rows.find(r => r.name === 'Remote Desktop Users').type, 'Security, built-in');
  assert.equal(rows.find(r => r.name === 'Domain Users').sam, 'CONTOSO\\Domain Users');
});

test('AD groups tab: live read replaces the Graph-only list and says where it came from', async () => {
  const d = await tabTable(fakeApi(graphTenant()), 'adGroups', { id: U, type: 'user', ad: { config: winOn, run: async () => JSON.stringify(live) } });
  assert.equal(d.source, 'ad');
  assert.equal(d.rows.length, 5);
  assert.ok(!d.notes.some(n => /never sync, so Microsoft Graph cannot see them/.test(n)));
  const html = b3Panel('adgroups', { data: d }, h);
  assert.match(html, /Read live from domain controller <code>dc01\.contoso\.com<\/code> in forest <code>contoso\.com<\/code>/);
  assert.match(html, /<td>Domain Users<\/td><td><code>CONTOSO\\Domain Users<\/code><\/td><td><b>Primary<\/b><\/td>/);
  assert.match(html, /<td>Security, domain local<\/td><td>AD only<\/td>/);
  assert.match(html, /<th>In Entra<\/th>/);
});

test('AD groups tab: when AD cannot be reached it falls back to Graph and tells the user how to connect', async () => {
  const d = await tabTable(fakeApi(graphTenant()), 'adGroups', { id: U, type: 'user', ad: { config: winOn, run: async () => JSON.stringify({ status: 'unreachable', server: 'dc01.contoso.com', message: 'Could not connect to dc01.contoso.com over LDAP.' }) } });
  assert.equal(d.source, 'graph');
  assert.deepEqual(d.rows.map(r => r.name), ['Finance']);
  const html = b3Panel('adgroups', { data: d }, h);
  assert.match(html, /Only groups synced to Entra are shown\. Could not connect to dc01\.contoso\.com over LDAP\. To list every AD group, run Set-E360AdReader\.ps1/);
  const linux = await tabTable(fakeApi(graphTenant()), 'adGroups', { id: U, type: 'user', ad: { config: adConfig({}, 'linux') } });
  assert.match(b3Panel('adgroups', { data: linux }, h), /need Entity 360 running on Windows/);
});

test('AD query script only reads and never builds a filter from raw input', () => {
  const ps = read('server/ad/Get-E360AdGroups.ps1');
  assert.doesNotMatch(ps, /CommitChanges|\.Put\(|Set-AD|New-AD|Remove-AD|Add-ADGroupMember|Invoke-Expression/);
  assert.match(ps, /\$UserSid -notmatch '\^S-1-5-21-\\d\+-\\d\+-\\d\+-\\d\+\$'/, 'SID is validated before any LDAP filter uses it');
  assert.match(read('server/ad-forest.mjs'), /execFile\(exe, \[/, 'no shell');
});

test('AD reader setup never waits forever: timed binds, password asked with Read-Host, NTLM fallback', () => {
  const ps = read('Set-E360AdReader.ps1');
  assert.match(ps, /function Invoke-WithTimeout/);
  assert.match(ps, /Invoke-WithTimeout \$BindTest \(\$bindArgs \+ 'Negotiate'\) 20/);
  assert.match(ps, /Invoke-WithTimeout \$BindTest \(\$bindArgs \+ 'Ntlm'\) 20/);
  assert.match(ps, /WaitForExit\(60000\)/);
  assert.match(ps, /Read-Host -AsSecureString/);
  assert.doesNotMatch(ps, /Get-Credential/);
  assert.match(read('server/ad/Get-E360AdGroups.ps1'), /AuthenticationTypes\]::ServerBind/);
});

test('AD groups tab: a cloud-hosted copy warns that on-premises AD is out of reach by design', async () => {
  assert.equal(cloudHosted({ CONTAINER_APP_NAME: 'any-app' }), true, 'Azure Container Apps');
  assert.equal(cloudHosted({ WEBSITE_SITE_NAME: 'any-site' }), true, 'Azure App Service');
  assert.equal(cloudHosted({ E360_HOSTING: 'cloud' }), true);
  assert.equal(cloudHosted({ CONTAINER_APP_NAME: 'x', E360_HOSTING: 'local' }), false);
  assert.equal(cloudHosted({}), false, 'a local copy shows no warning');
  assert.equal(adConfig({ WEBSITE_SITE_NAME: 'x' }, 'win32').enabled, false, 'never tries LDAP from the cloud, even on Windows');
  const d = await tabTable(fakeApi(graphTenant()), 'adGroups', { id: U, type: 'user', ad: { config: adConfig({ CONTAINER_APP_NAME: 'any-app' }, 'linux') } });
  assert.equal(d.ad.status, 'cloud');
  assert.deepEqual(d.rows.map(r => r.name), ['Finance']);
  const html = b3Panel('adgroups', { data: d }, h);
  assert.match(html, /verdict-banner verdict-warn[^>]*><span class="verdict-status">Warning<\/span><div><strong>On-premises AD is out of reach from the cloud<\/strong>/);
  assert.match(html, /cannot reach on-premises Active Directory by design/);
  assert.doesNotMatch(html, /Set-E360AdReader/, 'no setup hint that cannot work in the cloud');
  const local = await tabTable(fakeApi(graphTenant()), 'adGroups', { id: U, type: 'user', ad: { config: winOn, run: async () => JSON.stringify(live) } });
  assert.doesNotMatch(b3Panel('adgroups', { data: local }, h), /verdict-warn/);
});
