// Authorization log page: nav entry under Investigate, pure helpers, CSV guard, and the server route it reads.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { AUTHZ_COLUMNS, AUTHZ_HELP, filterDecisions, sortDecisions, decisionsCsv, tableHtml } from '../public/authz-log.js';
import { DecisionLog } from '../server/authflow.mjs';
const read = f => readFileSync(new URL(`../${f}`, import.meta.url), 'utf8');
const esc = v => String(v ?? '').replace(/[&<>"']/g, c => `&#${c.charCodeAt(0)};`);
const rows = [
  { time: '2026-10-29T03:00:00.000Z', user: 'b@x', path: '/api/billing', role: 'E360.Billing', outcome: 'denied', reason: 'role missing', tenant: 't', source: 'entity360' },
  { time: '2026-10-29T02:00:00.000Z', user: 'a@x', path: '/api/signins', role: 'E360.SignIns', outcome: 'allowed', reason: 'role present', tenant: 't', source: 'entity360' },
  { time: '2026-10-29T01:00:00.000Z', user: '=cmd', path: '/api/intune', role: 'E360.Intune', outcome: 'allowed', reason: 'role present', tenant: null, source: 'entity360' },
];

test('nav item sits in the Investigate group and the page is registered', () => {
  const html = read('public/index.html'), app = read('public/app.js');
  const nav = html.slice(html.indexOf('>INVESTIGATE<'), html.indexOf('>MY ACCOUNT<'));
  assert.match(nav, /data-view="authz"[^>]*>.*Authorization log<\/button>/);
  for (const id of ['authz-panel', 'authz-filter', 'authz-refresh', 'authz-export', 'authz-table', 'authz-help']) assert.match(html, new RegExp(`id="${id}"`));
  assert.match(app, /authz: \['Authorization log'/);
  assert.match(app, /authz: '#authz-panel'/);
  assert.match(app, /authz: '#authz-export'/);
  assert.match(app, /authzView\.setActive\(a?v === 'authz'\)/);
});

test('page uses only the shared .btn style, no em dashes, no demo data', () => {
  const html = read('public/index.html'), seg = html.slice(html.indexOf('id="authz-panel"'), html.indexOf('id="logs-panel"'));
  for (const m of seg.matchAll(/<button[^>]*class="([^"]*)"/g)) assert.equal(m[1], 'btn');
  const js = read('public/authz-log.js');
  assert.doesNotMatch(seg + js, /\u2014/);
  assert.doesNotMatch(js, /demo|fixture/i);
  assert.match(AUTHZ_HELP, /in memory/); assert.match(AUTHZ_HELP, /last 100/); assert.match(AUTHZ_HELP, /app starts/);
});

test('filter keeps allowed, denied or all', () => {
  assert.equal(filterDecisions(rows, 'all').length, 3);
  assert.deepEqual(filterDecisions(rows, 'denied').map(r => r.user), ['b@x']);
  assert.deepEqual(filterDecisions(rows, 'allowed').map(r => r.user), ['a@x', '=cmd']);
  assert.deepEqual(filterDecisions(null, 'all'), []);
});

test('default sort is newest first; columns sort both ways; empties last', () => {
  const shuffled = [rows[2], rows[0], rows[1]];
  assert.deepEqual(sortDecisions(shuffled).map(r => r.time), rows.map(r => r.time));
  assert.deepEqual(sortDecisions(rows, { key: 'user', dir: 'asc' }).map(r => r.user), ['=cmd', 'a@x', 'b@x']);
  assert.deepEqual(sortDecisions(rows, { key: 'user', dir: 'desc' }).map(r => r.user), ['b@x', 'a@x', '=cmd']);
  assert.equal(sortDecisions(rows, { key: 'tenant', dir: 'asc' }).at(-1).tenant, null);
});

test('CSV has every column header and guards formula cells', () => {
  const csv = decisionsCsv(rows);
  assert.ok(csv.startsWith('\ufeff"Time (UTC)"'));
  assert.equal(csv.split('\r\n').length, 4);
  assert.match(csv, /"'=cmd"/);
  for (const [, label] of AUTHZ_COLUMNS) assert.ok(csv.includes(`"${label}"`), label);
});

test('table marks the sorted column, labels decisions and escapes values', () => {
  const html = tableHtml([{ ...rows[0], user: '<b>' }], { key: 'time', dir: 'desc' }, esc);
  assert.match(html, /aria-sort="descending"/);
  assert.match(html, /class="result blocked">Denied/);
  assert.doesNotMatch(html, /<b>/);
  assert.equal((html.match(/data-authz-sort=/g) || []).length, AUTHZ_COLUMNS.length);
});

test('log rows carry every column the page shows, newest first', () => {
  const log = new DecisionLog(3);
  log.add({ user: 'u1', path: '/api/billing', outcome: 'denied', reason: 'role missing', needed: 'E360.Billing' });
  log.add({ user: 'u2', path: '/api/intune', outcome: 'allowed', reason: 'role present', needed: 'E360.Intune' });
  const [first] = log.list(100);
  assert.equal(first.user, 'u2');
  for (const [k] of AUTHZ_COLUMNS) assert.ok(k in first, k);
});

test('server route is unchanged: the page reads /api/authz/log as it is guarded today', () => {
  const idx = read('server/index.mjs');
  assert.match(idx, /app\.get\('\/api\/authz\/log'/);
  assert.match(read('public/authz-log.js'), /api\('\/api\/authz\/log'\)/);
});