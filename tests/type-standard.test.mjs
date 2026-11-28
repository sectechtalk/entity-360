// 360 look-and-feel standard (2026-11-15): one font, one type scale in rem, nothing under 12px, weights 400/500/600.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const read = f => readFileSync(new URL(`../public/${f}`, import.meta.url), 'utf8');
const base = read('360-base.css');

test('360-base.css defines the seven-step type scale with a 12px floor', () => {
  const steps = { xs: '.75rem', sm: '.8125rem', base: '.875rem', md: '1rem', lg: '1.25rem', xl: '1.5rem', '2xl': '1.875rem' };
  for (const [name, size] of Object.entries(steps)) assert.match(base, new RegExp(`--text-${name}:${size.replace('.', '\\.')};`));
  assert.match(base, /--font-sans:Inter,/);
  assert.match(base, /@font-face\{font-family:Inter;/);
});

for (const file of ['styles.css', 'guide.css']) {
  test(`${file} imports 360-base.css and uses only the type tokens`, () => {
    const css = read(file);
    assert.match(css, /^@import url\('\/360-base\.css'\);/);
    assert.deepEqual(css.match(/font(?:-size)?:[^;}]*\d(?:px|pt)\b/g) || [], [], 'font sizes in px or pt');
    assert.doesNotMatch(css, /Segoe UI|Consolas,monospace|IBM Plex|Sora/, 'only Inter and the shared mono stack');
    assert.deepEqual((css.match(/font-weight:(\d+)/g) || []).filter(w => !/:(400|500|600)$/.test(w)), [], 'weights 400/500/600 only');
  });
}

test('no page script or page sets its own font size inline', () => {
  for (const f of ['index.html', 'setup.html', 'app.js']) assert.doesNotMatch(read(f), /font-size:\s*\d/);
});

test('colour: e-360 uses the shared semantic tokens; no numbered --t colours are left, shadows are named by role', () => {
  const css = read('styles.css');
  assert.deepEqual(css.match(/--t\d+\b/g), null);
  for (const t of ['--shadow-sm', '--shadow-md', '--shadow-lg', '--backdrop']) assert.match(css, new RegExp(`${t}:#`), t);
  assert.match(css, /@media \(forced-colors:active\)\{/);
  for (const t of ['--bg', '--surface', '--surface-2', '--line', '--fg', '--muted', '--ok', '--ok-soft', '--warn', '--warn-soft', '--crit', '--crit-soft']) assert.match(base, new RegExp(`${t}:#`), t);
  assert.match(css, /:root\{--accent:#[0-9a-f]{6};--accent-strong:#[0-9a-f]{6};--accent-soft:#[0-9a-f]{6};--accent-ink:#fff\}/);
});
