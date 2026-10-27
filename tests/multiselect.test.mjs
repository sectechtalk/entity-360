// Multi-select filter logic: AND across columns, OR within a column, default everything checked.
import test from 'node:test';
import assert from 'node:assert/strict';
import { filterOptions, applyFilters, passes, remainingBucket, grantedBucket, multiSelectHtml } from '../public/multiselect.js';

test('options merge known values with data values, no duplicates', () => {
  assert.deepEqual(filterOptions(['Applies', 'Incomplete'], ['Incomplete', 'Other', '']), ['Applies', 'Incomplete', 'Other', 'n/a']);
});
test('AND across columns, OR within a column', () => {
  const rows = [{ k: 'A', s: 'x' }, { k: 'B', s: 'x' }, { k: 'C', s: 'y' }];
  const cols = [{ key: 'k', get: r => r.k }, { key: 's', get: r => r.s }];
  assert.equal(applyFilters(rows, cols, {}).length, 3);
  assert.deepEqual(applyFilters(rows, cols, { k: new Set(['C']) }).map(r => r.k), ['A', 'B']);
  assert.deepEqual(applyFilters(rows, cols, { k: new Set(['C']), s: new Set(['x']) }), []);
  assert.ok(passes(['Actor', 'Target'], new Set(['Actor'])));
  assert.ok(!passes(['Actor'], new Set(['Actor'])));
});
test('duration buckets', () => {
  assert.equal(remainingBucket(null, true), 'Permanent');
  assert.equal(remainingBucket(null, false), 'n/a');
  assert.equal(remainingBucket(-1), 'Expired');
  assert.equal(remainingBucket(30 * 60000), '<1h');
  assert.equal(remainingBucket(4 * 3600000), '1-8h');
  assert.equal(remainingBucket(9 * 3600000), '>8h');
  const now = Date.parse('2026-10-24T12:00:00Z');
  assert.equal(grantedBucket('2026-10-24T11:30:00Z', now), '<1h');
  assert.equal(grantedBucket('2026-10-20T12:00:00Z', now), '1-7d');
  assert.equal(grantedBucket(undefined, now), 'n/a');
});
test('trigger shows count and uses btn, no inline handlers', () => {
  const html = multiSelectHtml({ key: 'ca.result', label: 'Result', options: ['A', 'B', 'C'], excluded: new Set(['B']) });
  assert.match(html, /Result \(2 of 3\)/);
  assert.match(html, /class="btn msel-trigger"/);
  assert.doesNotMatch(html, /\son[a-z]+=/);
});
