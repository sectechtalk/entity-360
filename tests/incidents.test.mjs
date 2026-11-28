// Incident queue: shaping Defender XDR and Identity Protection rows, per-source failures, correlation, and the page.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { incidentQueue, evidenceEntities, incidentItems, riskItems, rankItems, sourceError, demoQueueApi, SOURCES, QUEUE_SCOPES, ITEM_LIMIT } from '../server/incidents.mjs';
import { roleForPath } from '../server/authflow.mjs';
import { VIEW_ROLES } from '../public/access-denied.js';
import { incidentsHtml, filterItems, itemHtml } from '../public/incidents.js';

const read = f => readFileSync(new URL(`../${f}`, import.meta.url), 'utf8');
const esc = v => String(v ?? '').replace(/[&<>"']/g, c => `&#${c.charCodeAt(0)};`);
const h = { esc, external: (u, l, c = 'btn') => `<a class="${c}" href="${u}">${esc(l)}</a>`, emptyBox: t => `<div class="inline-empty">${esc(t)}</div>` };
const NOW = Date.parse('2026-11-20T18:00:00Z');
const U1 = '11111111-1111-4111-8111-111111111111', D1 = '22222222-2222-4222-8222-222222222222';
const denied = () => Object.assign(new Error('Access not granted.'), { status: 403, upstreamCode: 'Forbidden' });
function fakeApi(fixtures) {
  const calls = [];
  const hit = u => Object.entries(fixtures).find(([k]) => u.includes(k))?.[1];
  return { calls, request: async () => ({}), pages: async u => { calls.push(u); const f = hit(u); if (f instanceof Error) throw f; return { rows: f || [] }; } };
}

test('route and nav item need E360.Reader; page and grant script exist', () => {
  assert.equal(roleForPath('/api/incidents'), 'E360.Reader');
  assert.equal(VIEW_ROLES.incidents, 'E360.Reader');
  assert.match(read('public/index.html'), /data-view="incidents"/);
  assert.match(read('public/index.html'), /id="incidents-panel"/);
  const ps = read('Grant-E360IncidentScopes.ps1');
  for (const s of QUEUE_SCOPES) assert.ok(ps.includes(`'${s}'`), s);
  assert.match(ps, /oauth2PermissionScopes/, 'permission ids are read from Graph, not typed in');
  assert.doesNotMatch(ps, /^\s*az ad app permission admin-consent/m, 'never consents every declared scope at once');
});

test('reads are GET-only, read-only scopes, bounded to the window', async () => {
  const api = fakeApi({});
  await incidentQueue(api, { now: NOW, days: 30 });
  assert.equal(api.calls.length, 4);
  assert.ok(api.calls.every(u => u.startsWith('/v1.0/')));
  assert.ok(api.calls.some(u => u.includes('/security/incidents') && decodeURIComponent(u).includes('lastUpdateDateTime ge 2026-10-21T18:00:00Z')));
  assert.ok(api.calls.some(u => u.includes('/identityProtection/riskDetections') && decodeURIComponent(u).includes('detectedDateTime ge 2026-10-21T18:00:00Z')));
  assert.ok(QUEUE_SCOPES.every(s => /\.Read\.All$/.test(s)));
  assert.doesNotMatch(read('server/incidents.mjs'), /method:\s*'(POST|PATCH|DELETE)'/);
});

test('evidence: Entra users and devices open in Entity 360; local accounts and link-local IPs do not', () => {
  const e = evidenceEntities([
    { '@odata.type': '#microsoft.graph.security.userEvidence', userAccount: { azureAdUserId: U1, displayName: 'Megan', userPrincipalName: 'm@contoso.example' } },
    { '@odata.type': '#microsoft.graph.security.userEvidence', userAccount: { accountName: 'adminlocal', domainName: 'PC1' } },
    { '@odata.type': '#microsoft.graph.security.deviceEvidence', deviceDnsName: 'pc1', azureAdDeviceId: D1, osPlatform: 'Windows11' },
    { '@odata.type': '#microsoft.graph.security.deviceEvidence', deviceDnsName: 'pc1', azureAdDeviceId: D1 },
    { '@odata.type': '#microsoft.graph.security.ipEvidence', ipAddress: 'fe80::1' },
    { '@odata.type': '#microsoft.graph.security.ipEvidence', ipAddress: '203.0.113.9' },
  ]);
  assert.deepEqual(e.users.map(u => [u.name, u.id]), [['Megan', U1], ['PC1\\adminlocal', null]]);
  assert.equal(e.devices.length, 1);
  assert.equal(e.devices[0].entraId, D1);
  assert.deepEqual(e.ips, ['203.0.113.9']);
});

test('alerts nest under their incident; orphan alerts stay visible as their own item', () => {
  const items = incidentItems(
    [{ id: '7', displayName: 'Inc', severity: 'medium', status: 'active', lastUpdateDateTime: '2026-11-20T00:00:00Z' }],
    [{ id: 'a', incidentId: '7', title: 'A', severity: 'high', mitreTechniques: ['T1078'], evidence: [] }, { id: 'b', incidentId: '99', title: 'Orphan', severity: 'low', status: 'new', evidence: [] }]);
  assert.equal(items.length, 2);
  assert.deepEqual(items[0].mitre, ['T1078']);
  assert.equal(items[0].alerts.length, 1);
  assert.equal(items[1].kind, 'alert');
  assert.equal(items[1].incidentId, '99');
});

test('risk: at-risk users carry their detections; remediated detections are dropped; orphan detections still show', () => {
  const items = riskItems(
    [{ id: U1, userDisplayName: 'Megan', riskLevel: 'high', riskState: 'atRisk' }, { id: 'x', riskState: 'remediated', riskLevel: 'high' }],
    [{ id: 'd1', userId: U1, riskEventType: 'anomalousToken', riskLevel: 'high', riskState: 'atRisk', detectedDateTime: '2026-11-20T10:00:00Z' },
      { id: 'd2', userId: 'other', userDisplayName: 'Lee', riskEventType: 'impossibleTravel', riskLevel: 'medium', riskState: 'atRisk', detectedDateTime: '2026-11-19T10:00:00Z' },
      { id: 'd3', userId: 'gone', riskEventType: 'unlikelyTravel', riskLevel: 'low', riskState: 'dismissed' }]);
  assert.deepEqual(items.map(i => i.kind), ['risky-user', 'risk-detection']);
  assert.equal(items[0].detections[0].type, 'Anomalous Token');
  assert.equal(items[1].users[0].id, null, 'a non-GUID user id never becomes an Open button');
});

test('ranking: open before resolved, then severity, then most recent', () => {
  const r = rankItems([{ id: 1, active: false, severity: 'high', updated: '3' }, { id: 2, active: true, severity: 'low', updated: '9' }, { id: 3, active: true, severity: 'high', updated: '1' }, { id: 4, active: true, severity: 'high', updated: '5' }]);
  assert.deepEqual(r.map(i => i.id), [4, 3, 2, 1]);
});

test('one refused source names scope, role and license; the other sources still load', async () => {
  const q = await incidentQueue(fakeApi({ '/security/incidents': denied(), '/security/alerts_v2': [], riskyUsers: [{ id: U1, userDisplayName: 'M', riskLevel: 'high', riskState: 'atRisk' }], riskDetections: [] }), { now: NOW });
  const inc = q.sources.find(s => s.id === 'incidents');
  assert.equal(inc.status, 'denied');
  assert.match(inc.needs, /SecurityIncident\.Read\.All/);
  assert.match(inc.needs, /Security Reader/);
  assert.match(inc.needs, /Grant-E360IncidentScopes\.ps1/);
  assert.equal(q.sources.find(s => s.id === 'riskyUsers').status, 'ok');
  assert.equal(q.items.length, 1);
  assert.equal(sourceError(SOURCES[2], Object.assign(new Error('x'), { status: 404 })).status, 'unavailable');
});

test('correlation: an incident and a risky user for the same person point at each other', async () => {
  const q = await incidentQueue(demoQueueApi(), { now: NOW });
  const inc = q.items.find(i => i.id === 'incident:41'), risky = q.items.find(i => i.kind === 'risky-user' && i.users[0].name === 'Megan Bowen');
  assert.ok(inc.related.some(r => r.id === risky.id));
  assert.ok(risky.related.some(r => r.id === inc.id));
  assert.equal(q.tally.high, 2);
  assert.ok(q.items.length <= ITEM_LIMIT);
});

test('page: chips, sources table, Open person/device buttons, Defender link, filter', async () => {
  const data = await incidentQueue(demoQueueApi(), { now: NOW });
  const html = incidentsHtml({ data }, 'open', h);
  assert.match(html, /2 High/);
  assert.match(html, /Sources: 4 of 4 read/);
  assert.match(html, /data-incident-user="\d+:0"/);
  assert.match(html, /data-incident-device="\d+:0"/);
  assert.match(html, /Open in Defender/);
  assert.match(html, /T1539/);
  assert.doesNotMatch(html, /Password spray against several accounts/, 'resolved items are hidden by default');
  assert.match(incidentsHtml({ data }, 'all', h), /Password spray against several accounts/);
  assert.equal(filterItems(data.items, 'identity').every(i => i.source === 'Identity Protection'), true);
  const local = itemHtml({ kind: 'alert', id: 'x', title: 'T', severity: 'low', status: 'New', active: true, source: 'Defender', mitre: [], users: [{ id: null, name: 'PC\\admin' }], devices: [], ips: [] }, 0, h);
  assert.match(local, /Not an Entra account/);
  assert.doesNotMatch(local, /data-incident-user/);
});

test('page: every source refused shows the one-time setup step', async () => {
  const data = await incidentQueue(fakeApi({ security: denied(), identityProtection: denied() }), { now: NOW });
  const html = incidentsHtml({ data }, 'open', h);
  assert.match(html, /None of the four sources could be read/);
  assert.match(html, /Grant-E360IncidentScopes\.ps1/);
  assert.match(html, /Security Reader/);
});
