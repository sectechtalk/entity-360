// These tests exercise demo routes; the hosted default is DEMO_MODE off.
process.env.DEMO_MODE ??= 'true';
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { demoReport, entities } from '../server/demo.mjs';
import { timeRange } from '../server/model.mjs';
import { MicrosoftApi, liveReport, workspaceQueries } from '../server/live.mjs';
import { evaluateConditionalAccess, resourceGraph, roleAssignmentQuery, pimTiming, unknownInputs } from '../server/access.mjs';
import { createApp } from '../server/index.mjs';

const now = Date.parse('2026-10-09T12:00:00Z');
const range = { from: '2026-10-02T12:00:00.000Z', to: '2026-10-09T12:00:00.000Z' };
test('restricted viewer receives no forbidden source, event, policy, relationship or evaluation', () => {
  const report = demoReport(entities[0].id, range, 'reader', now);
  const allowed = new Set(['directory', 'signin', 'audit']);
  assert.equal(report.sources.length, 3);
  for (const list of [report.events, report.policies, report.relationships]) for (const row of list) assert.ok(allowed.has(row.source));
  assert.ok(report.events.every(e => !e.evaluatedPolicies.length));
  assert.doesNotMatch(JSON.stringify(report), /Defender|Purview|Intune|vm-finance|Require MFA|Require compliant/);
});
test('date boundaries and invalid ranges are handled; configuration is independent of activity range', () => {
  assert.throws(() => timeRange('', 'bad'));
  assert.throws(() => timeRange(range.to, range.from));
  assert.throws(() => timeRange('2025-01-01', '2026-01-01'));
  const report = demoReport(entities[0].id, { from: '2027-01-01T00:00:00.000Z', to: '2027-01-02T00:00:00.000Z' }, 'analyst', now);
  assert.equal(report.events.length, 0);
  assert.ok(report.policies.length > 0);
  assert.ok(demoReport(entities[2].id, range, 'analyst', now).events.some(e => e.category === 'API'));
});
test('pagination follows trusted origins, reports truncation and rejects credential exfiltration', async () => {
  let calls = 0;
  const api = new MicrosoftApi(async () => 'test-token', { maxPages: 1, fetcher: async () => { calls++; return Response.json({ value: [{ id: 1 }], '@odata.nextLink': 'https://graph.microsoft.com/v1.0/users?$skiptoken=next' }); } });
  const data = await api.pages('/v1.0/users');
  assert.equal(data.rows.length, 1); assert.equal(data.truncated, true); assert.equal(calls, 1);
  await assert.rejects(api.request('https://attacker.example/collect'), /Unsupported/);
  assert.equal(calls, 1);
});
test('CA What If marks unknown inputs Incomplete instead of not applying', async () => {
  const bodies = [];
  const api = { async request(p, o) { assert.equal(p, '/v1.0/identity/conditionalAccess/evaluate'); bodies.push(o.body); return { value: [{ id: 'a', displayName: 'Require MFA', state: 'enabled', grantControls: { builtInControls: ['mfa'] }, conditions: {} }] }; } };
  const r = await evaluateConditionalAccess(api, { id: '11111111-1111-1111-1111-111111111111', apps: [{ id: '00000003-0000-0ff1-ce00-000000000000', name: 'SharePoint' }], policies: [{ id: 'a', state: 'enabled' }, { id: 'b', displayName: 'Block platforms', state: 'enabled', conditions: { platforms: { includePlatforms: ['all'] } } }, { id: 'c', state: 'disabled', conditions: { locations: { includeLocations: ['All'] } } }] });
  assert.equal(bodies[0].appliedPoliciesOnly, true);
  assert.equal(bodies[0].signInIdentity.userId, '11111111-1111-1111-1111-111111111111');
  assert.equal(r.rows.find(p => p.id === 'a').result, 'Applies');
  assert.equal(r.rows.find(p => p.id === 'b').result, 'Incomplete');
  assert.deepEqual(unknownInputs({ conditions: { platforms: { includePlatforms: ['all'] } } }), ['device platform']);
  assert.ok(!r.rows.some(p => p.id === 'c'));
  await assert.rejects(evaluateConditionalAccess(api, { id: "x' or 1" }));
});
test('Resource Graph role query pages with $skipToken and only embeds GUIDs; PIM timing is reported', async () => {
  const q = roleAssignmentQuery(['11111111-1111-1111-1111-111111111111', "x') or 1==1 //"]);
  assert.match(q, /in \('11111111-1111-1111-1111-111111111111'\)/);
  assert.ok(!q.includes('1==1'));
  const tokens = [];
  const api = { async request(p, o) { tokens.push(o.body.options.$skipToken); return tokens.length === 1 ? { data: [{ id: 1 }], $skipToken: 'next' } : { data: [{ id: 2 }] }; } };
  const r = await resourceGraph(api, q);
  assert.deepEqual(r.rows.map(x => x.id), [1, 2]);
  assert.deepEqual(tokens, [undefined, 'next']);
  assert.equal(pimTiming('2026-10-24T00:00:00Z', '2026-10-24T08:00:00Z', Date.parse('2026-10-24T05:00:00Z')).text, 'Granted 8h; 3h remaining');
  assert.equal(pimTiming('2026-10-24T00:00:00Z', null).text, 'Permanent');
});
test('workload telemetry requires explicit role mapping and escapes injected KQL strings', () => {
  const app = { id: entities[2].id, type: 'application', appId: entities[2].appId };
  const withoutMapping = workspaceQueries(app, range);
  assert.ok(!withoutMapping.some(q => q.table === 'AppDependencies'));
  const withMapping = workspaceQueries(app, range, ['finance-api', 'a" | take 99999 //']);
  assert.equal(withMapping.length, 3);
  assert.ok(withMapping[1].query.includes(JSON.stringify('a" | take 99999 //')));
  assert.ok(withMapping.every(q => q.query.includes('| take 1000')));
});
test('workspace rows are normalized, unauthorized tables hidden, operation correlation preserved', async () => {
  const id = entities[0].id;
  const denied = () => { throw Object.assign(new Error('denied'), { status: 403 }); };
  const api = {
    async request(url, options) {
      if (url === `/v1.0/users/${id}`) return { id, displayName: 'Alex', userPrincipalName: 'alex@example.test' };
      if (options?.origin === 'https://api.loganalytics.azure.com' && options.body.query.startsWith('AppDependencies')) return { tables: [{ name: 'PrimaryResult', columns: ['TimeGenerated', 'Name', 'Target', 'Success', 'OperationId', 'Id'].map(name => ({ name })), rows: [[range.to, 'GET /finance', 'payments.example.test', false, 'operation-123', 'dependency-123']] }] };
      return denied();
    },
    async pages() { return denied(); },
  };
  const report = await liveReport(api, id, 'user', range, { tenant: 'test', logs: true, workspaceIds: ['11111111-1111-1111-1111-111111111111'] });
  assert.deepEqual(report.sources.map(s => s.id).sort(), ['directory', 'insights']);
  assert.equal(report.events[0].result, 'Failed'); assert.equal(report.events[0].correlationId, 'operation-123');
  assert.match(report.events[0].query, /Workspace ID/);
});
test('live aggregation hides forbidden connectors and deduplicates actor/target audit records', async () => {
  const id = entities[0].id;
  const denied = () => { throw Object.assign(new Error('denied'), { status: 403 }); };
  const audit = { id: 'audit-1', activityDateTime: range.to, activityDisplayName: 'Update user', result: 'success', initiatedBy: { user: { displayName: 'Alex' } }, targetResources: [{ id, displayName: 'Alex' }] };
  const api = {
    async request(url) { if (url === `/v1.0/users/${id}`) return { id, displayName: 'Alex', userPrincipalName: 'alex@example.test' }; return denied(); },
    async pages(url) { if (url.includes('/directoryAudits')) return { rows: [audit], truncated: false }; if (url.includes('memberOf') || url.includes('transitiveMemberOf')) return { rows: [], truncated: false }; return denied(); },
  };
  const report = await liveReport(api, id, 'user', range, { tenant: 'test' });
  assert.deepEqual(report.sources.map(s => s.id).sort(), ['audit', 'directory']);
  assert.equal(report.events.length, 1); assert.equal(report.events[0].direction, 'Actor & Target');
});
test('local API rejects foreign hosts, cross-origin mutations and missing CSRF; sessions are isolated', async t => {
  const port = 3619;
  const server = createApp({ port }).listen(port, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const base = `http://127.0.0.1:${port}`;
  const response = await fetch(`${base}/api/session`);
  const cookie = response.headers.get('set-cookie').split(';')[0], session = await response.json();
  assert.equal(response.status, 200); assert.equal(session.mode, 'demo');
  assert.equal((await fetch(`${base}/api/demo`, { method: 'POST', headers: { Cookie: cookie, 'Content-Type': 'application/json' }, body: '{}' })).status, 403);
  const foreignHostStatus = await new Promise((resolve, reject) => {
    http.get(`${base}/api/session`, { headers: { Host: 'attacker.example' } }, response => { response.resume(); resolve(response.statusCode); }).on('error', reject);
  });
  assert.equal(foreignHostStatus, 403);
  assert.equal((await fetch(`${base}/api/demo`, { method: 'POST', headers: { Cookie: cookie, 'X-CSRF-Token': session.csrf, Origin: 'https://attacker.example', 'Content-Type': 'application/json' }, body: '{}' })).status, 403);
  const changed = await fetch(`${base}/api/demo`, { method: 'POST', headers: { Cookie: cookie, 'X-CSRF-Token': session.csrf, 'Content-Type': 'application/json' }, body: JSON.stringify({ profile: 'reader' }) });
  assert.equal((await changed.json()).profile, 'reader');
  const separate = await fetch(`${base}/api/session`); assert.equal((await separate.json()).profile, 'analyst');
  const report = await fetch(`${base}/api/investigate?${new URLSearchParams({ id: entities[0].id, ...range })}`, { headers: { Cookie: cookie } });
  assert.equal((await report.json()).sources.length, 3);
});
