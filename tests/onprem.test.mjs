// ON-PREM AD: Sync health verdict, the Sync health and Groups pages, the Findings entry and the sidebar section.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { syncHealth, ouPath, errorText, ONPREM_PAGES, SYNC_SCOPE, CLOUD_SYNC_SCOPE, CLOUD_SYNC_TEMPLATE, intervalMinutes, lastRun, jobCheck } from '../server/pages/onprem.mjs';
import { loadPage, B5_PAGES } from '../server/bucket5.mjs';
import { findingsOverview, syncFindings } from '../server/findings.mjs';
import { pageHtml, B5_VIEWS } from '../public/bucket5.js';
import { fakeApi } from './pages-bucket5.test.mjs';
import { tabTable } from '../server/bucket3.mjs';
import { B3_TABS, b3Panel } from '../public/tab-tables.js';
const read = f => readFileSync(new URL(`../${f}`, import.meta.url), 'utf8');
const esc = v => String(v ?? '').replace(/[&<>"']/g, c => `&#${c.charCodeAt(0)};`);
const h = { esc, external: (u, l) => `<a class="btn" href="${u}">${esc(l)}</a>`, emptyBox: t => `<div class="inline-empty">${esc(t)}</div>` };
const NOW = Date.parse('2026-11-14T21:30:00Z');
const minsAgo = m => new Date(NOW - m * 6e4).toISOString();
const status = (v, name) => v.checks.find(c => c.check === name)?.status;
const denied = () => Object.assign(new Error('denied'), { status: 403 });

// Shaped like contoso.com on 2026-11-14: pilot user in OU=SyncPilot, two DNS groups, PHS on, no last password sync time.
const tenant = (over = {}) => ({
  '/organization?': { value: [{ id: 'o1', onPremisesSyncEnabled: true, onPremisesLastSyncDateTime: minsAgo(10), ...over.org }] },
  '/directory/onPremisesSynchronization': over.sync ?? { value: [{ features: { passwordSyncEnabled: true, softMatchOnUpnEnabled: true, passwordWritebackEnabled: false }, configuration: { accidentalDeletionPrevention: { synchronizationPreventionType: 'enabledForCount', alertThreshold: 500 }, anchorAttribute: 'mS-DS-ConsistencyGuid', synchronizationClientVersion: '2.6.92.0', currentExportData: { clientMachineName: 'SYNCSERVER01', pendingObjectsAddition: 0, pendingObjectsUpdate: 0, pendingObjectsDeletion: 0, totalConnectorSpaceObjects: 3 } } }] },
  'onPremisesSyncEnabled eq true&$count=true&$top=999&$select=id,displayName,userPrincipalName': over.users ?? [{ id: 'u1', displayName: 'SEC Sync Pilot', userPrincipalName: 'sec-syncpilot@contoso.com', accountEnabled: true, onPremisesSamAccountName: 'sec-syncpilot', onPremisesDomainName: 'corp.contoso.com', onPremisesDistinguishedName: 'CN=SEC Sync Pilot,OU=SyncPilot,DC=corp,DC=contoso,DC=com', onPremisesLastSyncDateTime: '2026-10-31T01:00:00Z' }],
  'onPremisesSyncEnabled eq true&$count=true&$top=999&$select=id,displayName,description': over.groups ?? [
    { id: 'g2', displayName: 'DnsUpdateProxy', securityEnabled: true, mailEnabled: false, onPremisesSamAccountName: 'DnsUpdateProxy', onPremisesNetBiosName: 'SEC', onPremisesSecurityIdentifier: 'S-1-5-21-1-1102' },
    { id: 'g1', displayName: 'DnsAdmins', securityEnabled: true, mailEnabled: false, onPremisesSamAccountName: 'DnsAdmins', onPremisesNetBiosName: 'SEC', onPremisesSecurityIdentifier: 'S-1-5-21-1-1101' }],
  '/groups/g1/members': [{ id: 'u1', displayName: 'SEC Sync Pilot' }],
  '/groups/g2/members': [],
  '/appRoleAssignments': over.apps ?? [],
});

test('verdict: healthy, late, stalled and never synced', () => {
  const sync = { features: { passwordSyncEnabled: true } };
  const ok = syncHealth({ org: { onPremisesSyncEnabled: true, onPremisesLastSyncDateTime: minsAgo(20), onPremisesLastPasswordSyncDateTime: minsAgo(5) }, sync, errors: [], now: NOW });
  assert.equal(ok.status, 'Healthy');
  assert.equal(status(syncHealth({ org: { onPremisesSyncEnabled: true, onPremisesLastSyncDateTime: minsAgo(90) }, errors: [], now: NOW }), 'Last sync cycle'), 'Warning');
  const stalled = syncHealth({ org: { onPremisesSyncEnabled: true, onPremisesLastSyncDateTime: minsAgo(200) }, errors: [], now: NOW });
  assert.equal(status(stalled, 'Last sync cycle'), 'Failed');
  assert.equal(stalled.status, 'Failing');
  assert.equal(syncHealth({ org: {}, now: NOW }).status, 'Not set up');
  assert.match(syncHealth({ org: { onPremisesSyncEnabled: false }, now: NOW }).checks[0].detail, /now off/);
});

test('verdict: password hash sync with no last time (Graph v1.0 never returns it) says check on server, not a warning', () => {
  const v = syncHealth({ org: { onPremisesSyncEnabled: true, onPremisesLastSyncDateTime: minsAgo(5) }, sync: { features: { passwordSyncEnabled: true } }, errors: [], now: NOW });
  assert.equal(status(v, 'Password hash sync'), 'Check on server');
  assert.equal(v.status, 'Healthy');
  assert.match(v.checks.find(c => c.check === 'Password hash sync').detail, /event 654/);
  assert.equal(status(syncHealth({ org: { onPremisesSyncEnabled: true, onPremisesLastSyncDateTime: minsAgo(5) }, sync: { features: { passwordSyncEnabled: false } }, errors: [], now: NOW }), 'Password hash sync'), 'Off');
  assert.equal(status(syncHealth({ org: { onPremisesSyncEnabled: true, onPremisesLastSyncDateTime: minsAgo(5), onPremisesLastPasswordSyncDateTime: minsAgo(300) }, sync: { features: { passwordSyncEnabled: true } }, errors: [], now: NOW }), 'Password hash sync'), 'Failed');
});

test('verdict: sync errors, pending exports and accidental delete protection', () => {
  const org = { onPremisesSyncEnabled: true, onPremisesLastSyncDateTime: minsAgo(5), onPremisesLastPasswordSyncDateTime: minsAgo(5) };
  const v = syncHealth({ org, errors: [{ kind: 'User' }], sync: { features: { passwordSyncEnabled: true }, configuration: { currentExportData: { pendingObjectsUpdate: 4 }, accidentalDeletionPrevention: { synchronizationPreventionType: 'disabled' } } }, now: NOW });
  assert.equal(status(v, 'Objects with sync errors'), 'Failed');
  assert.equal(status(v, 'Changes waiting to export'), 'Warning');
  assert.equal(status(v, 'Accidental delete protection'), 'Warning');
  assert.equal(status(syncHealth({ org, errors: null, now: NOW }), 'Objects with sync errors'), 'Unknown');
});

test('helpers: OU path and error text', () => {
  assert.equal(ouPath('CN=SEC Sync Pilot,OU=SyncPilot,DC=corp,DC=contoso,DC=com'), 'OU=SyncPilot,DC=corp,DC=contoso,DC=com');
  assert.equal(ouPath('CN=Smith\\, Ann,OU=Staff,DC=corp,DC=contoso,DC=com'), 'OU=Staff,DC=corp,DC=contoso,DC=com');
  assert.equal(errorText([{ category: 'PropertyConflict', propertyCausingError: 'UserPrincipalName', value: 'a@x.com', occurredDateTime: '2026-11-01T00:00:00Z' }]), 'PropertyConflict: UserPrincipalName = a@x.com (since 2026-11-01)');
});

test('Sync health page with the live tenant shape', async () => {
  const d = await loadPage(fakeApi(tenant()), 'h-sync', { now: NOW });
  const [health, connect, features, users] = d.tables;
  assert.equal(health.title, 'Sync health: Healthy');
  assert.match(health.link, /AADConnectMenuBlade\/~\/ConnectSync$/);
  const conn = Object.fromEntries(connect.rows);
  assert.equal(conn['Connect server'], 'SYNCSERVER01');
  assert.equal(conn['Connect version'], '2.6.92.0');
  assert.equal(conn['Synced groups'], '2');
  assert.deepEqual(features.rows.find(r => r[0] === 'Accidental delete threshold'), ['Accidental delete threshold', '500']);
  assert.equal(users.rows[0][3], 'OU=SyncPilot,DC=corp,DC=contoso,DC=com');
  assert.match(pageHtml('h-sync', { data: d }, h), /Open in Entra/);
});

test('Sync health without the new scope still runs the checks and says which permission is missing', async () => {
  const api = fakeApi(tenant({ sync: denied() }));
  const d = await loadPage(api, 'h-sync', { now: NOW });
  assert.match(d.tables[0].title, /Sync health/);
  assert.ok(d.notes.some(n => n.includes(SYNC_SCOPE)));
  assert.ok(!d.tables.some(t => t.title === 'Sync features'));
  assert.ok(!api.calls.some(u => u.startsWith('/beta/')), 'beta is only read when allowed');
});

test('Sync health reads Graph beta only when allowed', async () => {
  const api = fakeApi(tenant());
  await loadPage(api, 'h-sync', { now: NOW, beta: true });
  assert.ok(api.calls.includes('/beta/directory/onPremisesSynchronization'));
});

test('Sync health on a cloud-only tenant shows Not set up and reads nothing else', async () => {
  const api = fakeApi({ '/organization?': { value: [{ id: 'o1' }] } });
  const d = await loadPage(api, 'h-sync', { now: NOW });
  assert.equal(d.tables.length, 1);
  assert.deepEqual(d.tables[0].rows[0][2], { text: 'Not set up', badge: true });
  assert.equal(d.verdict.status, 'Not set up');
  assert.equal(api.calls.length, 1);
});

test('Groups page lists synced groups A to Z with SAM name, SID, members and app access', async () => {
  const d = await loadPage(fakeApi(tenant({ apps: [{ resourceDisplayName: 'Entity 360' }, { resourceDisplayName: 'Entity 360' }] })), 'h-groups', { now: NOW });
  const t = d.tables[0];
  assert.deepEqual(t.rows.map(r => r[0].text), ['DnsAdmins', 'DnsUpdateProxy']);
  assert.deepEqual(t.rows[0].slice(1, 5), ['Security', 'DnsAdmins', 'SEC', 'S-1-5-21-1-1101']);
  assert.equal(t.rows[0][5].text, '1');
  assert.match(t.rows[0][5].link, /GroupDetailsMenuBlade\/~\/Members\/groupId\/g1$/);
  assert.equal(t.rows[0][6], 'SEC Sync Pilot');
  assert.equal(t.rows[0][7], 'Entity 360');
  assert.equal(t.rows[1][6], 'No members');
});

test('Groups page: a denied app-access read is asked once and becomes a note', async () => {
  const api = fakeApi(tenant({ apps: denied() }));
  const d = await loadPage(api, 'h-groups', { now: NOW });
  assert.equal(api.calls.filter(u => u.includes('appRoleAssignments')).length, 1);
  assert.ok(d.notes.some(n => n.includes('App access')));
});

test('Findings: stalled sync is an open finding; a cloud-only tenant passes', async () => {
  const stale = syncFindings({ org: { onPremisesSyncEnabled: true, onPremisesLastSyncDateTime: minsAgo(400) }, errors: [{ kind: 'User', id: 'u9', displayName: 'Ann', onPremisesProvisioningErrors: [{ category: 'PropertyConflict', propertyCausingError: 'ProxyAddresses' }] }] }, NOW);
  assert.ok(stale.items.some(i => i.text === 'Last sync cycle: Failed'));
  assert.ok(stale.items.some(i => i.text === 'Ann' && /ProxyAddresses/.test(i.detail)));
  assert.equal(syncFindings({ org: {} }, NOW).count, 0);
  const all = await findingsOverview(fakeApi(tenant({ org: { onPremisesLastSyncDateTime: minsAgo(400) } })), { now: NOW });
  const f = all.findings.find(x => x.id === 'hybrid-sync');
  assert.equal(f.status, 'open');
  assert.equal(f.playbook.view.key, 'h-sync');
});

test('sidebar: ON-PREM AD section holds Sync health and Groups; TENANT > Hybrid is gone', () => {
  const html = read('public/index.html');
  assert.match(html, /data-section="on-prem-ad"><span>ON-PREM AD<\/span>[\s\S]*?data-view="h-sync"[\s\S]*?data-view="h-groups"/);
  assert.doesNotMatch(html, /t-hybrid/);
  assert.ok(!('t-hybrid' in B5_PAGES));
  for (const k of Object.keys(ONPREM_PAGES)) assert.ok(B5_VIEWS[k], k);
});

// Cloud Sync, shaped like the live tenant on 2026-11-15 after the move from Connect Sync (v1.0 and beta returned the same).
const SP = { id: 'sp1', appId: 'bfd32892', displayName: 'corp.contoso.com' };
const exec = (end, over = {}) => ({ state: 'Succeeded', timeBegan: end, timeEnded: end, countExported: 0, error: null, ...over });
const provJob = (over = {}) => ({ id: 'AD2AADProvisioning.x', templateId: 'AD2AADProvisioning', schedule: { interval: 'PT20M', state: 'Active' },
  status: { code: 'Active', countSuccessiveCompleteFailures: 0, quarantine: null, lastSuccessfulExecution: null, steadyStateLastAchievedTime: minsAgo(15),
    lastExecution: exec(minsAgo(15), { countExported: 14 }), synchronizedEntryCountByType: [{ key: 'user to User', value: 4 }, { key: 'group to Group', value: 6 }], ...over.status }, ...over.job });
const phsJob = () => ({ id: 'AD2AADPasswordHash.x', templateId: 'AD2AADPasswordHash', schedule: { interval: 'PT5M', state: 'Active' },
  status: { code: 'Active', countSuccessiveCompleteFailures: 0, quarantine: null, lastExecution: exec(minsAgo(3)), lastSuccessfulExecution: { state: 'Succeeded', timeBegan: '0001-01-01T00:00:00Z', timeEnded: minsAgo(13) }, synchronizedEntryCountByType: [] } });
const cloudTenant = (jobs = [phsJob(), provJob()]) => ({ ...tenant(), '/servicePrincipals?': [SP], '/synchronization/jobs': jobs });

test('Cloud Sync helpers: interval, last good run with a null lastSuccessfulExecution', () => {
  assert.equal(intervalMinutes('PT20M'), 20);
  assert.equal(intervalMinutes('PT2H'), 120);
  assert.equal(intervalMinutes('P10675199DT2H48M5.4775807S') > 0, true);
  assert.equal(intervalMinutes(''), null);
  assert.equal(lastRun(provJob().status), minsAgo(15));
  assert.equal(lastRun(phsJob().status), minsAgo(3));
  assert.equal(lastRun({ lastSuccessfulExecution: { timeBegan: '0001-01-01T00:00:00Z', timeEnded: '0001-01-01T00:00:00Z' } }), null);
});

test('Cloud Sync job checks: healthy, quarantined, failed, paused, stale', () => {
  assert.equal(jobCheck(SP, provJob(), NOW).status, 'OK');
  assert.match(jobCheck(SP, provJob(), NOW).detail, /every 20 minutes.*10 objects/);
  const q = jobCheck(SP, provJob({ status: { quarantine: { reason: 'EncounteredQuarantineException', since: minsAgo(60), error: { message: 'Agent unreachable' } } } }), NOW);
  assert.equal(q.status, 'Failed');
  assert.match(q.detail, /quarantine.*Agent unreachable/);
  assert.equal(jobCheck(SP, provJob({ status: { countSuccessiveCompleteFailures: 2, lastExecution: exec(minsAgo(5), { state: 'Failed', error: { message: 'boom' } }) } }), NOW).status, 'Failed');
  assert.equal(jobCheck(SP, provJob({ job: { schedule: { interval: 'PT20M', state: 'Disabled' } } }), NOW).status, 'Warning');
  assert.equal(jobCheck(SP, provJob({ status: { steadyStateLastAchievedTime: minsAgo(300), lastExecution: exec(minsAgo(300)) } }), NOW).status, 'Failed');
  assert.equal(jobCheck(SP, provJob(), NOW).check, 'Cloud Sync: Users and groups');
});

test('Sync health with Cloud Sync active: job checks, Cloud Sync table, stale Connect data labelled, no Connect export check', async () => {
  const api = fakeApi(cloudTenant());
  const d = await loadPage(api, 'h-sync', { now: NOW, beta: true });
  const [health, cloud, connect] = d.tables;
  assert.ok(api.calls.some(u => u.includes(`applicationTemplateId eq '${CLOUD_SYNC_TEMPLATE}'`)));
  assert.ok(api.calls.includes('/v1.0/servicePrincipals/sp1/synchronization/jobs'));
  assert.equal(health.title, 'Sync health: Healthy');
  assert.match(health.link, /~\/CloudSync$/);
  const checks = health.rows.map(r => r[0]);
  assert.ok(checks.includes('Cloud Sync: Users and groups'));
  assert.ok(checks.includes('Cloud Sync: Password hash sync'));
  assert.ok(!checks.includes('Password hash sync'), 'the Cloud Sync job replaces the check-on-server row');
  assert.ok(!checks.includes('Changes waiting to export'), 'Connect export counts are stale after the move');
  assert.equal(cloud.title, 'Cloud Sync');
  const prov = cloud.rows.find(r => r[1] === 'Users and groups');
  assert.equal(prov[3], '20 minutes');
  assert.equal(prov[6], '10 (4 users, 6 groups)');
  assert.equal(prov[7], 'No');
  assert.equal(connect.title, 'Entra Connect Sync (replaced by Cloud Sync)');
  assert.match(connect.note, /not current/);
});

test('Sync health with Cloud Sync but without Synchronization.Read.All: asked once, Partly checked, names the permission', async () => {
  const api = fakeApi({ ...cloudTenant(), '/synchronization/jobs': denied() });
  const d = await loadPage(api, 'h-sync', { now: NOW });
  assert.equal(api.calls.filter(u => u.includes('/synchronization/jobs')).length, 1);
  assert.equal(d.tables[0].title, 'Sync health: Partly checked');
  assert.ok(d.tables[0].rows.some(r => r[0] === 'Cloud Sync jobs' && r[1].includes(CLOUD_SYNC_SCOPE)));
  assert.ok(d.notes.some(n => n.includes(CLOUD_SYNC_SCOPE)));
  assert.ok(!d.tables.some(t => t.title === 'Cloud Sync'));
});

test('Findings: a quarantined Cloud Sync job is an open finding', async () => {
  const q = provJob({ status: { quarantine: { reason: 'EncounteredQuarantineException' } } });
  const all = await findingsOverview(fakeApi(cloudTenant([q])), { now: NOW });
  const f = all.findings.find(x => x.id === 'hybrid-sync');
  assert.equal(f.status, 'open');
  assert.ok(f.items.some(i => i.text === 'Cloud Sync: Users and groups: Failed'));
  assert.ok(f.playbook.steps.some(s => s.includes('AADConnectProvisioningAgent')));
});

test('Sync health: a big verdict banner on top, status badges, Connect leftovers collapsed after the move', async () => {
  const d = await loadPage(fakeApi(cloudTenant()), 'h-sync', { now: NOW, beta: true });
  assert.equal(d.verdict.status, 'Healthy');
  assert.match(d.verdict.headline, /syncing to Entra\. All \d+ checks passed/);
  assert.deepEqual(d.tables[0].rows[0][2], { text: 'OK', badge: true });
  assert.ok(d.tables.find(t => t.title === 'Entra Connect Sync (replaced by Cloud Sync)').collapsed);
  assert.ok(d.tables.find(t => t.title === 'Sync features').collapsed);
  const html = pageHtml('h-sync', { data: d }, h);
  assert.ok(html.indexOf('verdict-banner verdict-pass') < html.indexOf('<h3>'), 'banner sits above the first table');
  assert.match(html, /<span class="verdict-status">Healthy<\/span>/);
  assert.match(html, /health-badge health-pass">OK</);
  assert.match(html, /<details class="b5-collapsed"><summary><h3>Entra Connect Sync \(replaced by Cloud Sync\)/);
  const bad = await loadPage(fakeApi(cloudTenant([provJob({ status: { quarantine: { reason: 'EncounteredQuarantineException' } } })])), 'h-sync', { now: NOW });
  assert.equal(bad.verdict.status, 'Failing');
  assert.match(bad.verdict.headline, /1 check needs attention: Cloud Sync: Users and groups/);
  assert.match(pageHtml('h-sync', { data: bad }, h), /verdict-banner verdict-fail/);
});

// INVESTIGATE > Access > AD groups, shaped like corp.contoso.com: E360 Test 1 is in SEC-Finance, which is in SEC-FS-Finance-RW.
const U1 = '11111111-1111-1111-1111-111111111111';
const adTenant = (over = {}) => ({
  [`/users/${U1}?`]: over.user ?? { id: U1, onPremisesSyncEnabled: true, onPremisesSamAccountName: 'e360-test1', onPremisesDomainName: 'corp.contoso.com', onPremisesDistinguishedName: 'CN=E360 Test 1,OU=Users,OU=SyncPilot,DC=corp,DC=contoso,DC=com' },
  [`/users/${U1}/transitiveMemberOf`]: over.all ?? [
    { id: 'gFin', displayName: 'SEC-Finance', securityEnabled: true, onPremisesSyncEnabled: true, onPremisesSamAccountName: 'SEC-Finance', onPremisesNetBiosName: 'SEC', onPremisesSecurityIdentifier: 'S-1-5-21-2799850457-1661112821-634973895-1109' },
    { id: 'gRW', displayName: 'SEC-FS-Finance-RW', securityEnabled: true, onPremisesSyncEnabled: true, onPremisesSamAccountName: 'SEC-FS-Finance-RW', onPremisesNetBiosName: 'SEC', onPremisesSecurityIdentifier: 'S-1-5-21-2799850457-1661112821-634973895-1111' },
    { id: 'gCloud', displayName: 'All staff (cloud)', securityEnabled: true }],
  [`/users/${U1}/memberOf`]: over.direct ?? [{ id: 'gFin' }, { id: 'gCloud' }],
  '/groups/gRW/members': over.rwMembers ?? [{ id: 'gFin' }],
  ...over.extra,
});

test('AD groups: direct and nested on-prem groups with SAM, SID and the group it comes through; cloud groups left out', async () => {
  const api = fakeApi(adTenant());
  const d = await tabTable(api, 'adGroups', { id: U1, type: 'user' });
  assert.equal(d.user.sam, 'CORP\\e360-test1');
  assert.deepEqual(d.rows.map(r => [r.name, r.membership, r.via, r.sam]), [
    ['SEC-Finance', 'Direct', '', 'SEC\\SEC-Finance'],
    ['SEC-FS-Finance-RW', 'Nested', 'SEC-Finance', 'SEC\\SEC-FS-Finance-RW'],
  ]);
  assert.equal(d.rows[1].sid, 'S-1-5-21-2799850457-1661112821-634973895-1111');
  assert.match(d.rows[0].link, /GroupDetailsMenuBlade\/~\/Overview\/groupId\/gFin$/);
  assert.equal(d.cloudGroups, 1);
  assert.equal(api.calls.filter(u => u.includes('/groups/')).length, 1, 'only nested groups need a members read');
  assert.ok(d.notes.some(n => /Domain Users/.test(n)));
  const html = b3Panel('adgroups', { data: d }, { ...h, fmtTime: x => x, resultBadge: x => `<b>${x}</b>`, linkBtn: (u, l) => `<a href="${u}">${l}</a>` });
  assert.match(html, /Active Directory groups <span class="count">2<\/span>/);
  assert.match(html, /<code>CORP\\e360-test1<\/code>/);
  assert.match(html, /2 from on-premises AD \(1 direct, 1 nested\), plus 1 cloud group/);
  assert.match(html, /<td>SEC-Finance<\/td><td>Security<\/td>/);
});

test('AD groups: two levels of nesting show the whole path', async () => {
  const all = [
    { id: 'gA', displayName: 'SEC-A', onPremisesSyncEnabled: true }, { id: 'gB', displayName: 'SEC-B', onPremisesSyncEnabled: true }, { id: 'gC', displayName: 'SEC-C', onPremisesSyncEnabled: true }];
  const d = await tabTable(fakeApi(adTenant({ all, direct: [{ id: 'gA' }], extra: { '/groups/gB/members': [{ id: 'gA' }], '/groups/gC/members': [{ id: 'gB' }] } })), 'adGroups', { id: U1, type: 'user' });
  assert.equal(d.rows.find(r => r.name === 'SEC-C').via, 'SEC-A > SEC-B');
});

test('AD groups: cloud-only user and service principals say why the list is empty', async () => {
  const cloud = await tabTable(fakeApi(adTenant({ user: { id: U1, onPremisesSyncEnabled: null }, all: [{ id: 'gCloud', displayName: 'Cloud' }], direct: [{ id: 'gCloud' }] })), 'adGroups', { id: U1, type: 'user' });
  assert.equal(cloud.rows.length, 0);
  const hh = { ...h, fmtTime: x => x, resultBadge: x => x, linkBtn: () => '' };
  assert.match(b3Panel('adgroups', { data: cloud }, hh), /cloud-only/);
  const sp = await tabTable(fakeApi({}), 'adGroups', { id: U1, type: 'application' });
  assert.match(b3Panel('adgroups', { data: sp }, hh), /apply to users only/);
});

test('AD groups tab sits on INVESTIGATE > Access', () => {
  assert.match(read('public/index.html'), /data-tab="packages"[^>]*>Access packages<\/button><button class="tab" role="tab" data-tab="adgroups" aria-selected="false">AD groups<\/button>/);
  assert.equal(B3_TABS.adgroups.table, 'adGroups');
});

test('ON-PREM AD pages only read', () => {
  assert.doesNotMatch(read('server/pages/onprem.mjs'), /method:\s*'(POST|PATCH|PUT|DELETE)'/);
});

test('sync finding counts every object with a sync error, even past the listing limit', () => {
  const errors = Array.from({ length: 60 }, (_, i) => ({ kind: 'User', id: `u${i}`, displayName: `User ${i}`, onPremisesProvisioningErrors: [{ category: 'PropertyConflict', propertyCausingError: 'ProxyAddresses' }] }));
  const r = syncFindings({ org: { onPremisesSyncEnabled: true, onPremisesLastSyncDateTime: minsAgo(5) }, errors }, NOW);
  assert.ok(r.count >= 60, `count ${r.count} should include all 60 errored objects`);
  assert.equal(r.count, r.items.length);
});
