// These tests exercise demo routes; the hosted default is DEMO_MODE off.
process.env.DEMO_MODE ??= 'true';
import test from 'node:test';
import assert from 'node:assert/strict';
import { lookupOptions, signInLookup, demoSignInLookup, normalizeSignIn, groupSignIns } from '../server/signins.mjs';
import { createApp } from '../server/index.mjs';

const now = Date.parse('2026-10-10T12:00:00Z');
const user = 'alex.morgan@contoso.example';
const options = extra => lookupOptions({ users: user, hours: 3, ...extra }, now);
const row = (id, extra = {}) => ({ id, createdDateTime: '2026-10-10T11:50:00Z', userPrincipalName: user, appDisplayName: 'Test app', isInteractive: true, status: { errorCode: 0 }, ...extra });

test('lookback validates users, bounds, booleans and captures a fixed UTC window', () => {
  const o = options({ users: `${user.toUpperCase()}, ${user}\nother@example.test`, nonInteractive: true });
  assert.equal(o.users.length, 2); assert.equal(o.beta, true);
  assert.equal(o.range.from, '2026-10-10T09:00:00.000Z'); assert.equal(o.range.to, '2026-10-10T12:00:00.000Z');
  assert.throws(() => options({ hours: -1 })); assert.throws(() => options({ hours: 2161 })); assert.throws(() => options({ hours: '3' }));
  assert.throws(() => options({ users: '' })); assert.throws(() => options({ users: Array.from({ length: 11 }, (_, i) => `user${i}@example.test`) }));
  assert.throws(() => options({ beta: 'true' })); assert.throws(() => options({ users: 'bad\u0000@example.test' }));
});
test('default 3-hour demo filters events and preserves every grouped record', () => {
  const report = demoSignInLookup(options());
  assert.equal(report.totalEvents, 4); assert.equal(report.groups.length, 2);
  assert.equal(report.groups[0].count, 3); assert.equal(report.groups[0].events.length, 3);
  assert.ok(report.groups.every(g => g.first >= report.range.from && g.last <= report.range.to));
  assert.equal(demoSignInLookup(options({ detail: true })).groups.length, 4);
  assert.equal(demoSignInLookup(options({ hours: 0.25 })).totalEvents, 3);
  assert.equal(demoSignInLookup(options({ hours: 6, nonInteractive: true })).totalEvents, 6);
});
test('beta details are optional and restricted viewers do not receive policy configuration', () => {
  const normal = demoSignInLookup(options()).groups[0].event;
  assert.equal(normal.methods.length, 0); assert.equal(normal.sessions.length, 0);
  const preview = demoSignInLookup(options({ beta: true })).groups[0].event;
  assert.ok(preview.methods.length); assert.ok(preview.sessions.length);
  assert.ok(preview.policies.some(p => p.status === 'notApplied'));
  const restricted = demoSignInLookup(options({ beta: true }), 'reader');
  assert.ok(restricted.groups.every(g => !g.event.policiesReturned && !g.event.policies.length));
  assert.doesNotMatch(JSON.stringify(restricted), /Require MFA|Restrict outside trusted/);
});
test('missing result and type remain unknown; distinct reasons are not collapsed', () => {
  const a = normalizeSignIn(row('a', { status: {}, isInteractive: undefined }), user, 'v1.0');
  assert.equal(a.code, null); assert.equal(a.result, 'Not returned'); assert.equal(a.kind, 'Not returned');
  const b = normalizeSignIn(row('b', { status: { errorCode: 1, failureReason: 'Reason one' } }), user, 'v1.0');
  const c = normalizeSignIn(row('c', { status: { errorCode: 1, failureReason: 'Reason two' } }), user, 'v1.0');
  assert.equal(groupSignIns([b, c]).length, 2);
});
test('live beta fallback, noninteractive query, deduplication and UTC filters', async () => {
  const calls = [];
  const api = { async pages(url) {
    calls.push(url);
    const parsed = new URL(url, 'https://graph.microsoft.com'), filter = parsed.searchParams.get('$filter');
    assert.match(filter, /createdDateTime ge 2026-10-10T09:00:00.000Z and createdDateTime le 2026-10-10T12:00:00.000Z/);
    if (url.startsWith('/v1.0')) return { rows: [row('interactive')], truncated: false };
    if (filter.includes("'nonInteractiveUser'")) return { rows: [row('interactive'), row('refresh', { isInteractive: false })], truncated: false };
    return { rows: [], truncated: false };
  } };
  const report = await signInLookup(api, options({ nonInteractive: true }));
  assert.equal(calls.length, 3); assert.equal(report.totalEvents, 2); assert.equal(report.partial, false);
  assert.ok(report.groups.some(g => g.event.version === 'v1.0'));
  assert.ok(report.groups.some(g => g.event.kind === 'Noninteractive'));
  assert.match(report.users[0].notes.join(' '), /fallback/);
});
test('denied lookups hide the source and are never reported as successful empty results', async () => {
  const api = { async pages() { throw Object.assign(new Error('Denied'), { status: 403 }); } };
  const report = await signInLookup(api, options());
  assert.equal(report.sources.length, 0); assert.equal(report.users[0].status, 'unavailable'); assert.equal(report.partial, true);
  assert.doesNotMatch(report.users[0].notes.join(' '), /No observed sign-ins/);
});
test('partial collection and upstream user/time mismatches are not silently accepted', async () => {
  const api = { async pages() { return { rows: [row('valid'), row('wrong-user', { userPrincipalName: 'different@example.test' }), row('too-old', { createdDateTime: '2026-10-01T00:00:00Z' })], truncated: true }; } };
  const report = await signInLookup(api, options());
  assert.equal(report.totalEvents, 1); assert.equal(report.partial, true); assert.equal(report.users[0].status, 'partial');
  assert.match(report.users[0].notes.join(' '), /Page limit/);
});
test('UPN apostrophes are escaped in OData; the endpoint is fixed', async () => {
  let captured;
  const api = { async pages(url) { captured = new URL(url, 'https://graph.microsoft.com'); return { rows: [], truncated: false }; } };
  await signInLookup(api, options({ users: "o'brien@example.test" }));
  assert.equal(captured.pathname, '/v1.0/auditLogs/signIns');
  assert.match(captured.searchParams.get('$filter'), /userPrincipalName eq 'o''brien@example.test'/);
});
test('sign-in lookup API enforces CSRF and validates lookback', async t => {
  const port = 3620, app = createApp({ port }), server = app.listen(port, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const base = `http://127.0.0.1:${port}`;
  const response = await fetch(`${base}/api/session`), cookie = response.headers.get('set-cookie').split(';')[0], session = await response.json();
  const headers = { Cookie: cookie, 'Content-Type': 'application/json' };
  assert.equal((await fetch(`${base}/api/signins/lookup`, { method: 'POST', headers, body: JSON.stringify({ users: user, hours: 3 }) })).status, 403);
  headers['X-CSRF-Token'] = session.csrf;
  assert.equal((await fetch(`${base}/api/signins/lookup`, { method: 'POST', headers, body: JSON.stringify({ users: user, hours: -3 }) })).status, 400);
  const result = await fetch(`${base}/api/signins/lookup`, { method: 'POST', headers, body: JSON.stringify({ users: user, hours: 3 }) });
  assert.equal(result.status, 200); const report = await result.json(); assert.equal(report.totalEvents, 4); assert.equal(report.options.hours, 3);
});
