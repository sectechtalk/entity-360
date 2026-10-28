import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { SIGNIN_HEADERS, signInColumns, signInCells, signInStatus, caLabel } from '../public/signin-columns.js';
import { applyFilters } from '../public/multiselect.js';
import { MIN_COL_WIDTH, storageKey, clampWidth, loadWidths, saveWidths, clearWidths, tableId } from '../public/col-resize.js';
import { normalizeSignIn } from '../server/signins.mjs';

const read = p => readFileSync(new URL(`../${p}`, import.meta.url), 'utf8');
const ths = (html, marker) => [...html.slice(html.indexOf(marker)).match(/<thead><tr>(.*?)<\/tr><\/thead>/)[1].matchAll(/<th[^>]*>(.*?)<\/th>/g)].map(m => m[1].replace(/<span[^>]*>.*?<\/span>/g, '').trim());

test('sign-ins table has the Entra Sign-in logs default columns in order', () => {
  assert.deepEqual(SIGNIN_HEADERS, ['Date', 'Request ID', 'Application', 'Status', 'Sign-in error code', 'IP address', 'Location', 'Conditional Access', 'Risk', 'Agent type', 'Authentication requirement', 'Tenant', 'Sign-in type', 'Session']);
  assert.deepEqual(ths(read('public/index.html'), 'class="signin-table"'), SIGNIN_HEADERS);
  assert.deepEqual(signInColumns().map(c => c.label), SIGNIN_HEADERS);
});

test('signIn resource fields map into the columns', () => {
  const e = normalizeSignIn({ id: 'req-1', createdDateTime: '2026-10-25T10:00:00Z', userDisplayName: 'Aaron Brooks', appDisplayName: 'Azure Portal', status: { errorCode: 50074 }, ipAddress: '203.0.113.5', location: { city: 'Seattle', state: 'Washington', countryOrRegion: 'US' }, conditionalAccessStatus: 'notApplied' }, 'aaron@contoso.com', 'v1.0');
  assert.deepEqual(signInCells(e), { requestId: 'req-1', user: 'Aaron Brooks', app: 'Azure Portal', status: 'Interrupted', ip: '203.0.113.5', location: 'Seattle, Washington, US', ca: 'Not Applied', code: '50074', risk: 'n/a', agent: '\u2014', authReq: '\u2014', tenant: 'n/a', type: '\u2014', session: '\u2014' });
  assert.equal(signInStatus(0), 'Success');
  assert.equal(signInStatus(50126), 'Failure');
  assert.equal(signInStatus(null), 'n/a');
  assert.equal(caLabel('failure'), 'Failure');
});

test('sign-in filters and sort work over groups; Date sorts by time', () => {
  const g = (t, code, ip) => ({ last: t, event: { code, ip, app: 'A', user: 'u', conditionalAccess: 'success' } });
  const rows = [g('2026-10-24T01:00:00Z', 0, '1.1.1.1'), g('2026-10-25T01:00:00Z', 50126, '2.2.2.2')];
  const cols = signInColumns();
  assert.equal(applyFilters(rows, cols, { 'si.status': new Set(['Failure']) }).length, 1);
  assert.equal(applyFilters(rows, cols, {}, { key: 'si.date', dir: 'desc' })[0].event.ip, '2.2.2.2');
  assert.equal(applyFilters(rows, cols, {}, { key: 'si.ip', dir: 'asc' })[0].event.ip, '1.1.1.1');
});

test('Defender: Evidence is the first column and Command line the last, single line', () => {
  const js = read('public/defender.js');
  const head = js.match(/<thead><tr>(.*?)<\/tr><\/thead>/)[1];
  const cells = [...head.matchAll(/<th[^>]*>(.*?)<\/th>/g)].map(m => m[1]);
  assert.match(cells[0], /Evidence/);
  assert.equal(cells.at(-1), 'Command line');
  assert.match(js, /<tr><td class="col-action"><button[^>]*data-defender-evidence/);
  assert.match(js, /<td class="col-cmd"><code>\$\{esc\(r\.command \|\| ''\)\}<\/code><\/td><\/tr>/);
  assert.match(read('public/styles.css'), /\.table-wrap td\.col-cmd\{white-space:nowrap!important;max-width:none!important\}/);
});

function memStore() { const m = new Map(); return { m, getItem: k => m.get(k) ?? null, setItem: (k, v) => m.set(k, String(v)), removeItem: k => m.delete(k) }; }

test('column widths clamp to a minimum, persist per table and reset', () => {
  const s = memStore();
  assert.equal(clampWidth(5), MIN_COL_WIDTH);
  saveWidths(s, 'defender', [10, 200.4, 90]);
  assert.equal(s.m.get(storageKey('defender')), JSON.stringify([MIN_COL_WIDTH, 200, 90]));
  assert.deepEqual(loadWidths(s, 'defender', 3), [MIN_COL_WIDTH, 200, 90]);
  assert.equal(loadWidths(s, 'defender', 4), null, 'column count changed: ignore stored widths');
  assert.equal(loadWidths(s, 'signins', 3), null, 'separate per table');
  clearWidths(s, 'defender');
  assert.equal(loadWidths(s, 'defender', 3), null);
  s.setItem(storageKey('x'), '{bad'); assert.equal(loadWidths(s, 'x', 1), null);
});

test('table ids come from data-table-id, then tbody id', () => {
  assert.equal(tableId({ dataset: { tableId: 'signins' }, querySelector: () => null }), 'signins');
  assert.equal(tableId({ dataset: {}, querySelector: () => ({ id: 'event-rows' }) }), 'event-rows');
});

test('resize is installed for every table with a header row with sticky-safe handles', () => {
  assert.match(read('public/app.js'), /installColumnResize\(document,/);
  const css = read('public/styles.css');
  assert.match(css, /(^|[\s},])thead th \.col-resizer\{position:absolute/);
  assert.match(read('public/col-resize.js'), /dblclick/);
});
