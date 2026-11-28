// 360 rail standard (2026-11-15): collapsible uppercase section headers one step larger than their page links, and a
// unique icon for every page. The rules live in 360-base.css and the shared 360-icons.js so every 360 app gets them.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { ICONS_360, iconSvg } from '../public/360-icons.js';
import { readCollapsed } from '../public/nav-sections.js';

const read = f => readFileSync(new URL(`../public/${f}`, import.meta.url), 'utf8');
const html = read('index.html');
const nav = html.slice(html.indexOf('<nav id="navigation"'), html.indexOf('</nav>'));

test('every page in the rail has its own icon, and every icon exists in the shared set', () => {
  const pages = [...nav.matchAll(/data-view="([^"]+)" class="nav-item[^"]*"><span data-nav-icon="([^"]+)">/g)];
  assert.ok(pages.length >= 40, `found ${pages.length} pages`);
  const icons = pages.map(m => m[2]);
  assert.deepEqual(icons.filter((n, i) => icons.indexOf(n) !== i), [], 'no icon is used twice');
  for (const n of icons) assert.ok(ICONS_360[n], `icon ${n} exists`);
  assert.doesNotMatch(nav, /data-icon=/, 'rail icons come from the shared set');
});

test('section headers are buttons with a chevron; 360-base.css makes them one step larger than the links', () => {
  const labels = [...nav.matchAll(/<button type="button" class="nav-label" aria-expanded="false" data-section="[a-z-]+"><span>[A-Z -]+<\/span><span class="nav-chevron" aria-hidden="true"><\/span><\/button>/g)];
  assert.ok(labels.length >= 10);
  const base = read('360-base.css');
  assert.match(base, /\.nav-label\{[^}]*font-size:var\(--text-base\)[^}]*text-transform:uppercase/);
  assert.match(base, /\.nav-item\{[^}]*font-size:var\(--text-sm\)/);
  assert.match(base, /\.nav-label\[aria-expanded="false"\] \.nav-chevron\{transform:rotate\(-45deg\)\}/);
  assert.doesNotMatch(read('styles.css'), /\.nav-label[^{]*\{[^}]*font-size:var\(--text-(xs|sm)\)/, 'e-360 does not shrink the headers back');
});

test('iconSvg returns a decorative inline SVG and falls back for unknown names', () => {
  assert.match(iconSvg('crown'), /^<svg class="icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false">.+<\/svg>$/);
  assert.match(iconSvg('nope'), /<circle cx="12" cy="12" r="3"\/>/);
  for (const body of Object.values(ICONS_360)) assert.doesNotMatch(body, /<script|on[a-z]+=|href=/i);
});

test('collapsed sections are remembered per app under the key the app passes', () => {
  const store = { getItem: k => (k === 'hm360.nav.collapsed' ? '["tools"]' : null) };
  assert.deepEqual(readCollapsed(store, 'hm360.nav.collapsed'), ['tools']);
  assert.deepEqual(readCollapsed(store), []);
});
