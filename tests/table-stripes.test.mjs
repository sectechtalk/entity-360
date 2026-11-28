// Every table body alternates two row shades (Aaron, 2026-11-23: "Everywhere there is a table in e360 do this").
// One shared rule in 360-base.css covers every table; both shades must differ from the page and panel in light and dark.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const read = f => readFileSync(new URL(`../public/${f}`, import.meta.url), 'utf8');
const base = read('360-base.css'), styles = read('styles.css'), guide = read('guide.css');
const hex = h => [1, 3, 5].map(i => parseInt(h.slice(i, i + 2), 16) / 255).map(c => c <= .03928 ? c / 12.92 : ((c + .055) / 1.055) ** 2.4);
const lum = h => { const [r, g, b] = hex(h); return .2126 * r + .7152 * g + .0722 * b; };
const ratio = (a, b) => { const [x, y] = [lum(a), lum(b)].sort((m, n) => n - m); return (x + .05) / (y + .05); };
const tokens = block => Object.fromEntries([...block.matchAll(/--([a-z0-9-]+):(#[0-9a-f]{6})/g)].map(m => [m[1], m[2]]));

test('360-base.css stripes every table body with odd/even rows', () => {
  assert.match(base, /tbody>tr:nth-child\(odd\)\{background:var\(--row-odd\)\}/);
  assert.match(base, /tbody>tr:nth-child\(even\)\{background:var\(--row-even\)\}/);
  assert.match(base, /tbody>tr\.selected\{background:var\(--row-selected\)\}/);
});

test('no per-table zebra rule in styles.css fights the shared one', () => {
  assert.doesNotMatch(styles, /tr:nth-child\((even|odd)\)\{background/);
});

test('both stripe shades differ from page and panel, and muted text stays 4.5:1, in light and dark', () => {
  const light = { ...tokens(base.match(/:root\{\s*--bg:[^}]*\}/)[0]), ...tokens(base.match(/:root\{--row-odd[^}]*\}/)[0]) };
  const dark = { ...tokens(base.match(/:root\[data-theme="dark"\]\{color-scheme:dark;[^}]*\}/)[0]), ...tokens(base.match(/:root\[data-theme="dark"\]\{--row-odd[^}]*\}/)[0]) };
  for (const [name, t] of Object.entries({ light, dark })) {
    for (const row of ['row-odd', 'row-even']) {
      assert.ok(ratio(t[row], t.bg) >= 1.06, `${name} ${row} vs page`);
      assert.ok(ratio(t[row], t.surface) >= 1.08, `${name} ${row} vs panel`);
      assert.ok(ratio(t.muted, t[row]) >= 4.5, `${name} muted text on ${row}`);
    }
    assert.ok(ratio(t['row-odd'], t['row-even']) >= 1.07, `${name} stripes distinct from each other`);
  }
});

test('setup guide (light-only page) pins light stripes so OS dark mode cannot darken its rows', () => {
  assert.match(guide, /table\{[^}]*--row-odd:#e9eff6;--row-even:#dfe7f1/);
});
