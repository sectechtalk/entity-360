import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

test('no single-element $() result is iterated with forEach', () => {
  const src = readFileSync(new URL('../public/app.js', import.meta.url), 'utf8');
  const bad = src.split('\n').map((l, i) => [i + 1, l]).filter(([, l]) => /(^|[^$\w])\$\([^)]*\)\.forEach/.test(l));
  assert.deepEqual(bad, []);
});
