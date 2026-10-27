import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { createDefenderEvents } from '../public/defender.js';
import { enhanceTable, TABLE_SELECTOR } from '../public/col-resize.js';

const read = p => readFileSync(new URL(`../${p}`, import.meta.url), 'utf8');
const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

test('Defender renders Evidence as the first column and Command line last (rendered output)', async () => {
  const root = { innerHTML: '', querySelector: () => null, querySelectorAll: () => [] };
  globalThis.document = { querySelector: s => (s === '#defender-events' ? root : null) };
  const ev = { id: '1', time: '2026-10-25T20:42:01Z', title: 'cmd.exe launched', account: 'a@b.c', device: 'DEVICE02', command: '"cmd.exe" /c echo hi', link: '#' };
  const view = createDefenderEvents({ api: async () => ({ events: [ev], query: 'q' }), esc, external: (u, t) => `<a href="${u}">${t}</a>`, entity: () => ({ id: 'u1', type: 'user' }), session: () => ({ mode: 'live' }), showEvidence() {} });
  view.setActive(true);
  await new Promise(r => setTimeout(r, 10));
  const html = root.innerHTML;
  const heads = [...html.match(/<thead><tr>(.*?)<\/tr><\/thead>/)[1].matchAll(/<th[^>]*>(.*?)<\/th>/g)].map(m => m[1].replace(/<[^>]+>/g, '').trim());
  assert.deepEqual(heads, ['Evidence', 'Time UTC', 'Process', 'Device', 'Command line']);
  const cells = [...html.match(/<tbody>(.*?)<\/tbody>/)[1].matchAll(/<td[^>]*>(.*?)<\/td>/g)].map(m => m[1]);
  assert.match(cells[0], /data-defender-evidence="0"[^>]*>Evidence</);
  assert.match(cells.at(-1), /cmd\.exe/);
  delete globalThis.document;
});

// Minimal DOM stand-in for enhanceTable.
function fakeTable(n) {
  const ths = Array.from({ length: n }, (_, i) => ({ textContent: `H${i}`, style: {}, children: [], querySelector(s) { return this.children.find(c => s === '.col-resizer' && c.className === 'col-resizer') || null; }, appendChild(c) { this.children.push(c); }, getBoundingClientRect: () => ({ width: 100 }) }));
  const doc = { createElement: () => ({ className: '', attrs: {}, setAttribute(k, v) { this.attrs[k] = v; }, addEventListener() {} }), defaultView: { getComputedStyle: () => ({ position: 'static' }) } };
  return { ths, table: { dataset: {}, style: { removeProperty() {}, setProperty() {} }, classList: { add() {}, remove() {} }, ownerDocument: doc, closest: () => ({ id: 'account-access' }), querySelector: () => null, querySelectorAll: s => (s.includes('th') ? ths : []) } };
}

test('every table rendered by account.js gets resize handles', () => {
  const src = read('public/account.js');
  const tables = src.match(/<table[^>]*>/g) || [];
  assert.ok(tables.length >= 1);
  // The resizer targets every table that has header cells, app-wide (not only .table-scroll).
  assert.equal(TABLE_SELECTOR, 'table:has(> thead th)');
  assert.match(src, /<table class="account-table"><thead><tr><th>Name<\/th>/, 'Group memberships and role assignments table has a header row');
  const { ths, table } = fakeTable(6);
  const store = { getItem: () => null, setItem() {}, removeItem() {} };
  enhanceTable(table, store);
  assert.equal(ths.filter(th => th.children.some(c => c.className === 'col-resizer')).length, 6);
  assert.equal(ths[0].style.position, 'relative', 'non-sticky headers get a positioning context');
  enhanceTable(table, store);
  assert.equal(ths[0].children.length, 1, 'idempotent');
});

test('app wires the resizer and ships the module; static assets are no-cache', () => {
  assert.ok(existsSync(new URL('../public/col-resize.js', import.meta.url)), 'col-resize.js must exist in public/ (it is imported by app.js)');
  assert.match(read('public/app.js'), /import \{ installColumnResize \} from '\.\/col-resize\.js'/);
  assert.match(read('server/index.mjs'), /Cache-Control', 'no-cache'/);
});
