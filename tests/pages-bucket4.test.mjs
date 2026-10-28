// Coverage bucket 4: new pages (Emergency access, Logs). My approvals stays deferred.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { breakGlass, workspaces, runSavedQuery, SAVED_QUERIES, B4_DEFERRED } from '../server/bucket4.mjs';
import { emergencyHtml, logsHtml } from '../public/bucket4.js';
const read = f => readFileSync(new URL(`../${f}`, import.meta.url), 'utf8');
const esc = v => String(v ?? '').replace(/[&<>"']/g, c => `&#${c.charCodeAt(0)};`);
const h = { esc, fmtTime: t => `T(${t})`, resultBadge: v => `<b>${esc(v)}</b>`, external: (u, l) => `<a class="btn" href="${u}">${l}</a>`, emptyBox: t => `<div class="inline-empty">${esc(t)}</div>` };
const fakeId = n => `00000000-0000-0000-0000-${String(n).padStart(12, '0')}`;
const BG = fakeId(1), OTHER = fakeId(2), GRP = fakeId(3);
const WS = '/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-example/providers/Microsoft.OperationalInsights/workspaces/law-breakglass';

function graph({ azure = true } = {}) {
  const calls = [];
  const pages = async u => { calls.push(u);
    if (u.includes('conditionalAccess/policies')) return { rows: [
      { displayName: 'Require MFA', state: 'enabledForReportingButNotEnforced', conditions: { users: { excludeUsers: [BG] } } },
      { displayName: 'Block legacy', state: 'enabled', conditions: { users: { excludeGroups: [GRP] } } },
      { displayName: 'Old', state: 'disabled', conditions: { users: { excludeUsers: [OTHER] } } }] };
    if (u.includes(`roleDefinitionId eq '62e90394`)) return { rows: [{ principalId: BG }, { principalId: OTHER }] };
    if (u.includes('transitiveMemberOf')) return { rows: u.includes(BG) ? [{ id: GRP }] : [] };
    if (u.includes('principalId eq')) return { rows: [{ roleDefinition: { displayName: 'Global Administrator' } }] };
    return { rows: [] }; };
  const request = async (u, o = {}) => { calls.push(u);
    if (u.startsWith(`/v1.0/users/${BG}`)) return { id: BG, displayName: 'Break Glass 1', userPrincipalName: 'globaladmin01@x.onmicrosoft.com', accountEnabled: true, signInActivity: { lastSignInDateTime: '2026-09-01T00:00:00Z' } };
    if (u.startsWith(`/v1.0/users/${OTHER}`)) return { id: OTHER, displayName: 'Aaron', userPrincipalName: 'aaron@x.com', accountEnabled: true };
    if (u.startsWith('/subscriptions?')) { assert.equal(o.origin, 'https://management.azure.com'); return { value: [{ subscriptionId: '11111111-2222-3333-4444-555555555555', displayName: 'Free Azure Trial' }] }; }
    if (u.includes('scheduledQueryRules')) return { value: [{ id: '/subscriptions/s/rg/r/breakglass-signin', name: 'breakglass-signin', properties: { enabled: true, criteria: { allOf: [{ query: 'SigninLogs | where UserPrincipalName in~ ("GlobalAdmin01@x.onmicrosoft.com")' }] } } }] };
    if (u.includes('/api/query')) { calls.push(JSON.stringify(o.body)); return { Tables: [{ Columns: [{ ColumnName: 'Table' }, { ColumnName: 'Rows' }], Rows: [['SigninLogs', 1483]] }] }; }
    if (u.includes('OperationalInsights/workspaces')) return { value: [{ id: WS, name: 'law-breakglass', location: 'westus3', properties: { sku: { name: 'PerGB2018' }, retentionInDays: 30, workspaceCapping: { dailyQuotaGb: -1 } } }] };
    if (u.includes('workbooks')) return { value: [] };
    throw Object.assign(new Error('not found'), { status: 404 }); };
  return { calls, pages, request };
}

test('emergency access: CA exclusions (direct and via group), roles, last sign-in, alert rules', async () => {
  const d = await breakGlass(graph(), { azure: true, now: Date.parse('2026-10-28T00:00:00Z') });
  assert.equal(d.rows.length, 1, 'a Global Admin not excluded and not named for break-glass is not a candidate');
  const r = d.rows[0];
  assert.equal(r.excludedFrom, 2); assert.equal(r.policies, 2, 'disabled policies are ignored');
  assert.deepEqual(r.roles, ['Global Administrator']);
  assert.equal(r.alerts[0].name, 'breakglass-signin', 'UPN matched case-insensitively');
  assert.deepEqual(r.findings, []);
  const html = emergencyHtml({ data: d }, h);
  assert.match(html, /Excluded from all/); assert.match(html, /T\(2026-09-01T00:00:00Z\)/); assert.match(html, /<b>OK<\/b>/);
});

test('emergency access: findings and no Azure', async () => {
  const api = graph(); const pages = api.pages;
  api.pages = async u => u.includes('transitiveMemberOf') ? { rows: [] } : pages(u);
  const d = await breakGlass(api, { azure: false, now: Date.parse('2026-09-03T00:00:00Z') });
  const r = d.rows[0];
  assert.equal(r.alerts, null); assert.match(d.notes.join(' '), /Connect Azure/);
  assert.deepEqual(r.notExcluded, ['Block legacy']);
  assert.match(r.findings.join('|'), /Not excluded from 1 active policies/); assert.match(r.findings.join('|'), /Signed in within the last 7 days/);
  assert.ok(!api.calls.some(c => c.includes('scheduledQueryRules')));
  assert.match(emergencyHtml({ data: d }, h), /Still applies: Block legacy/);
  assert.match(emergencyHtml(null, h), /id="emergency-run" type="button" class="btn"/);
});

test('logs: workspaces via ARM, saved queries only, ARM query proxy, missing table message', async () => {
  const api = graph();
  const d = await workspaces(api);
  assert.equal(d.workspaces[0].name, 'law-breakglass'); assert.equal(d.workspaces[0].retention, 30);
  assert.deepEqual(d.queries.map(q => q.key), Object.keys(SAVED_QUERIES));
  const r = await runSavedQuery(api, { workspace: WS, query: 'tables', days: 7 });
  assert.deepEqual(r.columns, ['Table', 'Rows']); assert.deepEqual(r.rows, [['SigninLogs', 1483]]);
  assert.ok(api.calls.includes(`${WS}/api/query?api-version=2020-08-01`));
  assert.match(api.calls.at(-1), /"timespan":"P7D"/);
  await assert.rejects(runSavedQuery(api, { workspace: WS, query: 'SigninLogs | take 1' }), /Unknown saved query/);
  await assert.rejects(runSavedQuery(api, { workspace: 'https://evil/x', query: 'tables' }), /Invalid workspace/);
  await assert.rejects(runSavedQuery(api, { workspace: WS, query: 'tables', days: 365 }), /Invalid window/);
  const miss = await runSavedQuery({ request: async () => { throw Object.assign(new Error('x'), { upstreamMessage: "Failed to resolve table expression named 'AuditLogs'" }); } }, { workspace: WS, query: 'audit', days: 7 });
  assert.match(miss.missing, /diagnostic setting/);
  const html = logsHtml({ data: d }, { workspace: WS, query: 'tables', days: 7 }, { data: r }, h);
  assert.match(html, /<option value="tables" selected>/); assert.match(html, /<td>SigninLogs<\/td>/); assert.match(html, /PerGB2018, retention 30 days\./);
  assert.match(logsHtml(null, {}, null, h), /id="logs-load"/);
});

test('pages, routes and nav are wired; My approvals deferred with its scopes', () => {
  const html = read('public/index.html'), idx = read('server/index.mjs'), app = read('public/app.js');
  assert.match(html, /data-view="emergency"/); assert.match(html, /data-view="logs"/);
  assert.match(html, /id="emergency-panel"/); assert.match(html, /id="logs-panel"/);
  assert.match(app, /emergency: '#emergency-panel', logs: '#logs-panel'/);
  assert.match(idx, /app\.get\('\/api\/emergency-access'/); assert.match(idx, /app\.get\('\/api\/logs\/workspaces'/); assert.match(idx, /app\.post\('\/api\/logs\/query'/);
  assert.equal(B4_DEFERRED[0][0], 'My approvals'); assert.match(B4_DEFERRED[0][1], /AccessReview\.Read\.All/);
  assert.doesNotMatch(html, /data-view="my-approvals"/);
});

test('bucket 4 stays delegated and read-only, no demo, one .btn', () => {
  const src = ['server/bucket4.mjs', 'public/bucket4.js'].map(read).join('\n');
  assert.doesNotMatch(src, /demo|client_credentials|clientSecret/i);
  assert.doesNotMatch(src, /class="btn-|style="/);
  assert.doesNotMatch(read('server/bucket4.mjs'), /method: '(PUT|PATCH|DELETE)'/);
  for (const q of Object.values(SAVED_QUERIES)) assert.doesNotMatch(q.kql, /\.(set|append|drop|delete)/i);
});
