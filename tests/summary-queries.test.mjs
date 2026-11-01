import test from 'node:test';
import assert from 'node:assert/strict';
import { MicrosoftApi, liveReport, SIGNIN_PAGING, CONSENTS_NEEDED } from '../server/live.mjs';
import { accessPackages } from '../server/entitlements.mjs';

const U = '00000000-0000-4000-8000-0000000000a5';
const range = { from: '2026-10-24T00:00:00.000Z', to: '2026-10-25T00:00:00.000Z' };
const err = (status, extra = {}) => Object.assign(new Error('x'), { status, ...extra });
const timeoutError = () => Object.assign(new Error('timeout'), { name: 'TimeoutError' });

test('sign-ins: userId filter first, $top 50, bounded paging and timeout', async () => {
  const calls = [];
  const api = {
    async request(url) { if (url === `/v1.0/users/${U}`) return { id: U, displayName: 'A', userPrincipalName: 'a@x.test' }; throw err(403); },
    async pages(url, opts) { calls.push({ url, opts }); return { rows: [], truncated: false }; },
  };
  await liveReport(api, U, 'user', range, { tenant: 't' });
  const s = calls.find(c => c.url.includes('auditLogs/signIns'));
  const q = new URL(s.url, 'https://graph.microsoft.com').searchParams;
  assert.equal(q.get('$top'), '50');
  assert.ok(q.get('$filter').startsWith(`userId eq '${U}' and createdDateTime ge ${range.from}`));
  assert.equal(q.get('$select'), null, 'signIns does not support $select');
  assert.deepEqual(s.opts, SIGNIN_PAGING);
  assert.ok(SIGNIN_PAGING.timeoutMs < 25000 && SIGNIN_PAGING.budgetMs < 25000);
});

test('pages keepPartial: a timeout after page one returns rows so far flagged slow', async () => {
  let n = 0;
  const api = new MicrosoftApi(async () => 't', { fetcher: async (url, init) => { assert.ok(init.signal); if (++n === 1) return Response.json({ value: [{ id: 's1' }], '@odata.nextLink': 'https://graph.microsoft.com/v1.0/auditLogs/signIns?$skiptoken=x' }); throw timeoutError(); } });
  const r = await api.pages('/v1.0/auditLogs/signIns', { ...SIGNIN_PAGING });
  assert.equal(r.rows.length, 1); assert.equal(r.truncated, true); assert.equal(r.slow, true);
  assert.match(r.limit, /^slow: Microsoft did not finish within \d+ seconds; showing the 1 most recent/);
  const strict = new MicrosoftApi(async () => 't', { fetcher: async () => { throw timeoutError(); } });
  const e = await strict.pages('/v1.0/x', { timeoutMs: 15000 }).catch(x => x);
  assert.equal(e.status, 502); assert.equal(e.reason, 'timed out after 15 seconds');
});

test('live report: a slow sign-in query is Partial (slow) and the rest of the summary still loads', async () => {
  const api = {
    async request(url) { if (url === `/v1.0/users/${U}`) return { id: U, displayName: 'A', userPrincipalName: 'a@x.test' }; throw err(403); },
    async pages(url) {
      if (url.includes('auditLogs/signIns')) return { rows: [{ id: 's1', createdDateTime: range.from, status: { errorCode: 0 } }], truncated: true, slow: true, limit: 'slow: Microsoft did not finish within 20 seconds; showing the 1 most recent records. Narrow the timeframe for the rest' };
      if (url.includes('memberOf')) return { rows: [{ id: 'g1', displayName: 'G' }], truncated: false };
      return { rows: [], truncated: false };
    },
  };
  const r = await liveReport(api, U, 'user', range, { tenant: 't' });
  const src = r.sources.find(s => s.id === 'signin' || /sign-in/i.test(s.name));
  assert.equal(src.status, 'Partial'); assert.match(src.note, /Slow: Microsoft did not answer in time/);
  assert.ok(r.partialReasons.some(p => /^slow:/.test(p.reason)));
  assert.equal(r.events.filter(e => e.category === 'Sign-ins').length, 1);
  assert.ok(r.sources.some(s => s !== src && s.status === 'Connected'), 'other sources still load');
});

test('consents 403: the message names the scope and directory roles needed', async () => {
  const api = {
    async request(url) { if (url === `/v1.0/users/${U}`) return { id: U, displayName: 'A', userPrincipalName: 'a@x.test' }; throw err(403); },
    async pages(url) { if (url.includes('oauth2PermissionGrants')) throw err(403, { upstreamCode: 'Authorization_RequestDenied' }); return { rows: [], truncated: false }; },
  };
  const r = await liveReport(api, U, 'user', range, { tenant: 't' });
  const u = r.unavailable.find(x => x.source === 'Entra directory (delegated consents)');
  assert.match(u.reason, /Directory\.Read\.All/); assert.match(u.reason, /Directory Readers or Global Reader/);
  assert.ok(u.reason.startsWith(CONSENTS_NEEDED)); assert.match(u.reason, /Authorization_RequestDenied/);
  assert.ok(!/\u2014/.test(CONSENTS_NEEDED));
});

test('entitlement requests: no target property; requestor and assignment target match the user', async () => {
  const urls = [];
  const api = {
    async request() { return {}; },
    async pages(url) {
      urls.push(url);
      if (url.includes('/assignmentRequests')) return { rows: [
        { id: 'q1', requestType: 'userAdd', state: 'pendingApproval', accessPackage: { displayName: 'P1' }, requestor: { objectId: U } },
        { id: 'q2', requestType: 'adminAdd', state: 'pendingApproval', accessPackage: { displayName: 'P2' }, requestor: { objectId: 'admin' }, assignment: { target: { objectId: U } } },
        { id: 'q3', requestType: 'userAdd', state: 'pendingApproval', requestor: { objectId: 'other' } },
        { id: 'q4', requestType: 'userAdd', state: 'delivered', requestor: { objectId: U } }], truncated: false };
      return { rows: [], truncated: false };
    },
  };
  const r = await accessPackages(api, U);
  const q = decodeURIComponent(urls.find(u => u.includes('assignmentRequests')));
  assert.ok(!/target/.test(q)); assert.match(q, /\$expand=accessPackage,requestor,assignment/);
  assert.deepEqual(r.requests.map(x => x.id), ['q1', 'q2']);
  assert.equal(r.requestsNote, null);
  const mine = []; await accessPackages({ async request() { return {}; }, async pages(u) { mine.push(u); return { rows: [{ id: 'm1', state: 'pendingApproval' }] }; } }, U, { self: true });
  assert.ok(decodeURIComponent(mine.at(-1)).includes("assignmentRequests/filterByCurrentUser(on='target')"));
});
