// Static UI checks: every action button uses the one shared .btn class, and no inline scripts or styles break the CSP.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';

const dir = new URL('../public/', import.meta.url);
const files = readdirSync(dir).filter(f => /\.(html|js)$/.test(f)).map(f => [f, readFileSync(new URL(f, dir), 'utf8')]);
// Navigation controls are not action buttons: sidebar items, tabs and search suggestions.
const NAV = new Set(['nav-item', 'tab', 'search-option']);

test('every <button> carries the shared btn class (or is a navigation control)', () => {
  const bad = [];
  for (const [f, src] of files) {
    for (const m of src.matchAll(/<button\b[^>]*>/g)) {
      const cls = (m[0].match(/class="([^"]*)"/) || [])[1];
      const list = (cls || '').split(/\s+/).filter(Boolean);
      if (!list.includes('btn') && !list.some(c => NAV.has(c))) bad.push(`${f}: ${m[0].slice(0, 120)}`);
    }
  }
  assert.deepEqual(bad, []);
});

test('no legacy button or link-styled action classes remain', () => {
  const legacy = /\b(button primary|button secondary|button text|link-button|icon-button)\b/;
  for (const [f, src] of files) assert.ok(!legacy.test(src), `${f} still uses a legacy button class`);
});

test('links rendered as actions use btn', () => {
  for (const [f, src] of files) for (const m of src.matchAll(/<a\b[^>]*class="([^"]*)"/g)) {
    if (/\b(source-link|guide-link|skip|brand)\b/.test(m[1]) || m[1].includes('${')) continue;
    assert.ok(m[1].split(/\s+/).includes('btn'), `${f}: <a class="${m[1]}">`);
  }
});

test('index.html has no inline scripts, styles or handlers', () => {
  const html = readFileSync(new URL('index.html', dir), 'utf8');
  assert.ok(!/<script(?![^>]*\bsrc=)[^>]*>/.test(html), 'inline <script>');
  assert.ok(!/<style\b/.test(html), 'inline <style>');
  assert.ok(!/\sstyle="/.test(html), 'style attribute');
  assert.ok(!/\son[a-z]+="/.test(html), 'inline event handler');
});

test('UI text has no em dashes', () => {
  for (const [f, src] of files) assert.ok(!src.includes('\u2014'), `${f} contains an em dash`);
});
