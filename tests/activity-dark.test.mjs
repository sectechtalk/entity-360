import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { ACTIVITY_HEADERS, activityColumns, activityService, activityCategory, activityStatus, activityActor } from '../public/activity-columns.js';

const read = p => readFileSync(new URL(`../${p}`, import.meta.url), 'utf8');

test('activity table uses the Entra Audit logs default columns', () => {
  assert.deepEqual(ACTIVITY_HEADERS, ['Date', 'Service', 'Category', 'Activity', 'Status', 'Initiated by (actor)']);
  const head = read('public/index.html').match(/<thead><tr>(.*?)<\/tr><\/thead><tbody id="event-rows">/)[1];
  const ths = [...head.matchAll(/<th>(.*?)<\/th>/g)].map(m => m[1].replace(/<[^>]+>.*?<\/[^>]+>/g, '').trim());
  assert.deepEqual(ths, ACTIVITY_HEADERS);
});

test('Entra audit and Azure activity events map into the columns', () => {
  const audit = { source: 'audit', service: 'Core Directory', auditCategory: 'RoleManagement', category: 'Changes', title: 'Add member to role', result: 'Success', actor: 'admin@contoso.com' };
  const azure = { source: 'azure', category: 'Changes', title: 'Write role assignment', result: 'Failure', actor: 'ops@contoso.com' };
  assert.equal(activityService(audit), 'Core Directory');
  assert.equal(activityCategory(audit), 'RoleManagement');
  assert.equal(activityService(azure), 'Azure Resource Manager');
  assert.equal(activityCategory(azure), 'Changes');
  assert.equal(activityStatus(azure), 'Failure');
  assert.equal(activityActor(azure), 'ops@contoso.com');
  assert.equal(activityActor({}), 'n/a');
});

test('each column except Date has a multiselect filter with all options', () => {
  const ev = [{ source: 'azure', title: 'b', result: 'Success', actor: 'x' }, { source: 'audit', title: 'a', result: 'Failure', actor: 'y' }];
  const cols = activityColumns([], ev, (known, vals) => [...new Set([...known, ...vals])].sort());
  assert.deepEqual(cols.map(c => c.label), ['Service', 'Category', 'Activity', 'Status', 'Initiated by']);
  assert.deepEqual(cols.find(c => c.label === 'Status').options, ['Failure', 'Success']);
});

test('live events carry service and audit category', () => {
  const live = read('server/live.mjs');
  assert.match(live, /service: a\.loggedByService/);
  assert.match(live, /auditCategory: ev\.category\?\.localizedValue/);
});

function themeEnv(stored, osDark = false) {
  const store = new Map(stored ? [['e360-theme', stored]] : []);
  const listeners = {};
  const btn = { attrs: {}, title: '', setAttribute(k, v) { this.attrs[k] = v; }, querySelector: () => btn.label, label: { textContent: '' }, addEventListener: (e, f) => { btn.click = f; } };
  const document = { documentElement: { dataset: {} }, getElementById: id => (id === 'theme-toggle' ? btn : null), addEventListener: (e, f) => { listeners[e] = f; } };
  const localStorage = { getItem: k => store.get(k) ?? null, setItem: (k, v) => store.set(k, v) };
  const matchMedia = q => ({ matches: osDark && /dark/.test(q), addEventListener() {} });
  vm.runInNewContext(read('public/theme.js'), { window: { document, localStorage, matchMedia }, module: undefined });
  listeners.DOMContentLoaded();
  return { document, btn, store };
}

test('with no stored choice the theme follows the OS, and the toggle persists', () => {
  assert.equal(themeEnv(null, false).document.documentElement.dataset.theme, 'light');
  const { document, btn, store } = themeEnv(null, true);
  assert.equal(document.documentElement.dataset.theme, 'dark');
  assert.equal(btn.label.textContent, 'Light mode');
  btn.click();
  assert.equal(document.documentElement.dataset.theme, 'light');
  assert.equal(store.get('e360-theme'), 'light');
  assert.equal(btn.attrs['aria-pressed'], 'false');
});

test('a stored light choice is respected', () => {
  assert.equal(themeEnv('light').document.documentElement.dataset.theme, 'light');
  assert.equal(themeEnv('light', true).document.documentElement.dataset.theme, 'light');
  assert.equal(themeEnv('bogus', true).document.documentElement.dataset.theme, 'dark');
  assert.equal(themeEnv('bogus', false).document.documentElement.dataset.theme, 'light');
});

test('styles define a dark palette with contrast fixes', () => {
  const css = read('public/styles.css'), base = read('public/360-base.css');
  assert.match(base, /:root\[data-theme="dark"\]\{color-scheme:dark;\s*--bg:/);
  assert.match(base, /prefers-color-scheme:dark/);
  assert.match(css, /html\[data-theme="dark"\] \.btn:disabled/);
  assert.match(css, /html\[data-theme="dark"\] a:not\(\.btn\)/);
  assert.match(read('public/index.html'), /<button id="theme-toggle" class="btn"/);
});
