// My PIM usability: merged rows, per-row busy, polling that stops when the state changes, scroll kept across updates,
// sortable and filterable columns, and click-only (press and release on the button) actions.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { mergeRows, stateLabel, eligibilityLabel, shownRows, pimRowsHtml, pimHeadHtml, settled, PIM_COLUMNS } from '../public/pim.js';
import { stateOf } from '../server/pim.mjs';
import { startHarness } from './e360-browser-harness.mjs';
const esc = v => String(v ?? '').replace(/[&<>"']/g, c => `&#${c.charCodeAt(0)};`);
const G = n => `4444444${n}-4444-4444-4444-444444444444`;
const elig = (n, extra = {}) => ({ id: `e${n}`, type: 'Group', name: `sg-e360-g${String(n).padStart(2, '0')}`, scope: G(n % 10), scopeLabel: 'Group member', state: 'Eligible', start: '2026-10-30T16:17:00Z', end: '2027-10-30T16:17:00Z', key: `group|g${n}|member`, target: { groupId: G(n % 10), accessId: 'member' }, ...extra });

test('Graph PIM for Groups "activated" (lowercase) is an activation, not a time-bound assignment', () => {
  assert.equal(stateOf(false, { assignmentType: 'activated', endDateTime: '2026-10-31T03:06:00Z' }), 'Active (activated)');
  assert.equal(stateOf(false, { assignmentType: 'Activated', endDateTime: 'x' }), 'Active (activated)');
  assert.equal(stateOf(false, { assignmentType: 'assigned', endDateTime: null }), 'Active (permanent)');
  assert.equal(stateOf(false, { assignmentType: 'assigned', endDateTime: '2027-01-01T00:00:00Z' }), 'Active (time-bound)');
});

test('eligibility and activation for the same group merge into one row; owner standing assignments stay, labelled', () => {
  const rows = mergeRows([
    { ...elig(1), state: 'Active (activated)', id: 'a1', start: '2026-10-31T02:06:00Z', end: '2026-10-31T03:06:00Z' }, elig(1), elig(2),
    { id: 'o1', type: 'Group', name: 'sg-e360-g01', scopeLabel: 'Group owner', state: 'Active (permanent)', start: '2026-10-01T00:00:00Z', end: null, key: 'group|g1|owner', target: { accessId: 'owner' } },
  ], true);
  assert.equal(rows.filter(r => r.key === 'group|g1|member').length, 1);
  const a = rows.find(r => r.key === 'group|g1|member');
  assert.equal(a.action, 'deactivate'); assert.equal(a.eligible, true); assert.equal(a.eligibleEnd, '2027-10-30T16:17:00Z');
  assert.match(stateLabel(a), /^Active until /); assert.match(eligibilityLabel(a), /^Eligible until /);
  const e = rows.find(r => r.key === 'group|g2|member');
  assert.equal(e.action, 'activate'); assert.equal(e.start, null); assert.match(eligibilityLabel(e), /^Eligible until .*2027/);
  const o = rows.find(r => r.key === 'group|g1|owner');
  assert.equal(o.action, null); assert.equal(stateLabel(o), 'Assigned (permanent)'); assert.equal(eligibilityLabel(o), 'Standing owner assignment, no activation needed');
  assert.deepEqual(mergeRows(rows, true), rows, 'merging is idempotent');
  assert.equal(settled(rows, 'group|g1|member', 'activate'), true);
  assert.equal(mergeRows([elig(3)], false)[0].action, null);
});

test('only the pending row is busy; every other Activate stays clickable', () => {
  const rows = mergeRows([elig(1), elig(2), elig(3)], true), pending = new Map([['group|g2|member', { action: 'activate' }]]);
  const html = pimRowsHtml(rows, { esc, self: true, pending });
  assert.equal((html.match(/ disabled/g) || []).length, 1);
  assert.match(html, /data-pim-row="e2" disabled aria-busy="true">Activating\u2026</);
  assert.match(html, /Activation pending/);
  assert.equal((html.match(/data-pim-action="activate" data-pim-row="e\d">Activate</g) || []).length, 2);
});

test('every column sorts (header) and filters (menu with a text box and checkboxes)', () => {
  const head = pimHeadHtml({ esc, self: true, sort: { key: 'name', dir: 'desc' } });
  for (const c of PIM_COLUMNS) {
    const k = c.toLowerCase();
    assert.match(head, new RegExp(`data-pim-sort="${k}"`));
    assert.match(head, new RegExp(`<details class="msel msel-th pim-menu" data-msel="pim-${k}" data-pim-menu="${k}">`));
    assert.match(head, new RegExp(`<input class="pim-filter" data-pim-filter="${k}" type="search"`));
    assert.match(head, new RegExp(`data-pim-opts="${k}"`));
  }
  assert.doesNotMatch(head, /<select/);
  for (const o of ['Entra role', 'Group', 'Azure role', 'Active', 'Eligible', 'Assigned', 'Pending', 'Activate', 'Deactivate', 'None']) assert.match(head, new RegExp(`data-pim-check value="${o}" checked`));
  assert.match(head, /aria-sort="descending"[^>]*>Name<span class="sort-mark"> \u25bc/);
  const rows = mergeRows([elig(1), elig(2), { ...elig(3), state: 'Active (activated)', id: 'a3', end: '2026-10-31T03:06:00Z' }, elig(3)], true);
  assert.deepEqual(shownRows(rows, { self: true, sort: { key: 'name', dir: 'desc' } }).map(r => r.name), ['sg-e360-g03', 'sg-e360-g02', 'sg-e360-g01']);
  assert.deepEqual(shownRows(rows, { self: true, filters: { state: 'Active' } }).map(r => r.name), ['sg-e360-g03']);
  assert.deepEqual(shownRows(rows, { self: true, filters: { action: 'Activate', name: 'g02' } }).map(r => r.name), ['sg-e360-g02']);
  assert.deepEqual(shownRows(rows, { self: true, filters: { state: 'Pending' }, pending: new Map([['group|g1|member', { action: 'activate' }]]) }).map(r => r.name), ['sg-e360-g01']);
  assert.equal(shownRows(rows, { self: true, filters: { type: 'Entra role' } }).length, 0);
});

test('pim.js has no global busy: no table-wide disable, and polling stops per row when settled', () => {
  const src = readFileSync(new URL('../public/pim.js', import.meta.url), 'utf8');
  assert.doesNotMatch(src, /busy: st\.poll|\$\{busy \? ' disabled'/);
  assert.match(src, /settled\(st\.rows, key, p\.action\)\) \{ st\.pending\.delete\(key\)/);
  assert.match(src, /if \(html === st\.lastBody\) return;/);
});

test('browser: My PIM keeps scroll, per-row pending, merged row after activation, polling stops, sort and filter, click-only', async t => {
  const h = await startHarness(t, { port: 3691, roles: [] }); if (!h) return;
  let rows = [...Array.from({ length: 30 }, (_, i) => elig(i + 1)),
    { id: 'o1', type: 'Group', name: 'sg-e360-g01', scope: G(1), scopeLabel: 'Group owner', state: 'Active (permanent)', start: '2026-10-01T00:00:00Z', end: null, key: 'group|g1|owner', target: { groupId: G(1), accessId: 'owner' } }];
  let reads = 0, policyCalls = 0, requests = [];
  try {
    const { ctx, page, errors } = await h.open({ before: async p => {
      await p.route('**/api/me/pim', r => { reads++; r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ rows, problems: [], notes: [] }) }); });
      await p.route('**/api/me/pim/policy', async r => { policyCalls++; await new Promise(x => setTimeout(x, 400)); r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ maxMinutes: 480, justification: true }) }); });
      await p.route('**/api/me/pim/request', async r => {
        requests.push(JSON.parse(r.request().postData())); await new Promise(x => setTimeout(x, 1500));
        // Microsoft shows the activation one read later, as Graph PIM for Groups does (server would label it Active (activated)).
        rows = [{ ...elig(5), id: 'a5', state: 'Active (activated)', start: '2026-10-31T02:06:00Z', end: '2026-10-31T03:06:00Z' }, ...rows];
        r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ id: 'req1', status: 'Provisioned' }) });
      });
    } });
    await page.click('#navigation [data-view="my-pim"]');
    await page.waitForSelector('#my-pim [data-pim-action="activate"]', { timeout: 10000 });
    assert.equal(await page.locator('#my-pim [data-pim-action="activate"]').count(), 30);
    // Owner standing assignment is labelled clearly.
    const owner = page.locator('#my-pim tr[data-pim-key="group|g1|owner"]');
    assert.match(await owner.textContent(), /Group owner.*Assigned \(permanent\).*Standing owner assignment/);

    // Click-only: press on Activate, release elsewhere: nothing happens.
    const b7 = page.locator('#my-pim button[data-pim-row="e7"]');
    await b7.hover(); await page.mouse.down(); await page.locator('#my-pim [data-pim-title]').hover(); await page.mouse.up();
    await page.waitForTimeout(300);
    assert.equal(policyCalls, 0); assert.equal(await page.locator('#my-pim [data-pim-form]').count(), 0);

    // Activate gives immediate feedback on its own row.
    const b5 = page.locator('#my-pim button[data-pim-row="e5"]');
    await b5.click();
    assert.equal(await b5.getAttribute('aria-busy'), 'true');
    await page.waitForSelector('#my-pim [data-pim-form] input[name="reason"]');
    await page.fill('#my-pim [data-pim-form] input[name="reason"]', 'Testing My PIM');
    await page.click('#my-pim [data-pim-confirm]');
    // Immediately: confirm button busy, the row shows pending, other rows stay clickable.
    assert.equal(await page.getAttribute('#my-pim [data-pim-confirm]', 'aria-busy'), 'true');
    assert.match(await page.textContent('#my-pim [data-pim-confirm]'), /Activating/);
    assert.match(await page.textContent('#my-pim tr[data-pim-key="group|g5|member"]'), /Activation pending/);
    assert.equal(await page.locator('#my-pim [data-pim-action="activate"]:not([disabled])').count(), 29);
    // Scroll down while waiting; updates must not move it.
    await page.evaluate(() => { window.scrollTo(0, 600); const w = document.querySelector('#my-pim [data-pim-scroll]'); if (w) w.scrollTop = 100; });
    const view = () => page.evaluate(() => [Math.round(document.querySelector('#my-pim tr[data-pim-key="group|g20|member"]').getBoundingClientRect().top), document.querySelector('#my-pim [data-pim-scroll]')?.scrollTop, window.scrollY]);
    const before = await view();
    assert.ok(before[2] > 0 || before[1] > 0, 'page or table is scrollable in the test');
    await page.waitForFunction(() => /Active until/.test(document.querySelector('#my-pim tr[data-pim-key="group|g5|member"]')?.textContent || ''), null, { timeout: 15000 });
    const after = await view();
    // The rows under the reader stay where they were (the closing form is above them; scroll anchoring compensates).
    assert.ok(Math.abs(after[0] - before[0]) <= 2 && after[1] === before[1], `rows kept their place: ${before} -> ${after}`);
    assert.equal(requests.length, 1); assert.equal(requests[0].reason, 'Testing My PIM');
    // One row for sg-e360-g05 member, with Deactivate and the eligibility shown.
    const g5 = page.locator('#my-pim tr[data-pim-key="group|g5|member"]');
    assert.equal(await g5.count(), 1);
    assert.match(await g5.textContent(), /Eligible until/);
    assert.equal(await g5.locator('[data-pim-action="deactivate"]').count(), 1);
    assert.match(await page.textContent('#my-pim [data-pim-status]'), /sg-e360-g05 is active/);
    assert.equal(await page.locator('#my-pim [data-pim-form]').count(), 0);
    // Polling stopped once the state changed.
    const settledReads = reads; await page.waitForTimeout(6500); assert.equal(reads, settledReads, 'no polling after the change');
    // Sort and filter.
    await page.click('#my-pim th[data-pim-sort="name"]'); await page.click('#my-pim th[data-pim-sort="name"]');
    assert.equal(await page.getAttribute('#my-pim th[data-pim-sort="name"]', 'aria-sort'), 'descending');
    assert.match(await page.locator('#my-pim tbody.pim-rows tr').first().textContent(), /sg-e360-g30/);
    // Text filter inside the Name menu.
    await page.click('#my-pim [data-pim-menu="name"] > summary');
    await page.fill('#my-pim [data-pim-filter="name"]', 'g07');
    assert.equal(await page.locator('#my-pim tbody.pim-rows tr').count(), 1);
    assert.equal(await page.textContent('#my-pim [data-pim-menu="name"] > summary'), 'Filtered');
    await page.fill('#my-pim [data-pim-filter="name"]', '');
    // Checkboxes inside the State menu: Clear, then tick Active only.
    await page.click('#my-pim [data-pim-menu="state"] > summary');
    await page.waitForFunction(() => !document.querySelector('#my-pim [data-pim-menu="name"][open]'), null, { timeout: 3000 }); // one menu open at a time
    await page.click('#my-pim [data-pim-menu="state"] [data-pim-none]');
    assert.equal(await page.locator('#my-pim tbody.pim-rows tr').count(), 0);
    await page.check('#my-pim [data-pim-menu="state"] input[data-pim-check][value="Active"]');
    assert.equal(await page.locator('#my-pim tbody.pim-rows tr').count(), 1);
    await page.click('#my-pim [data-pim-menu="state"] [data-pim-all]');
    await page.uncheck('#my-pim [data-pim-menu="state"] input[data-pim-check][value="Eligible"]');
    await page.uncheck('#my-pim [data-pim-menu="state"] input[data-pim-check][value="Active"]');
    assert.match(await page.locator('#my-pim tbody.pim-rows tr').first().textContent(), /Group owner/);
    // Name menu lists the names as checkboxes too.
    assert.ok(await page.locator('#my-pim [data-pim-menu="name"] input[data-pim-check][value="sg-e360-g05"]').count() === 1);
    assert.deepEqual(errors, []); await ctx.close();
  } finally { await h.close(); }
});
