// UI round 2: column menus with a text filter and checkboxes, working Deactivate (5-minute rule and visible errors),
// activate form spacing, Export always enabled, larger nav section labels, and a TOOLS section with Error code lookup.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { mergeRows, shownRows, menuOptions, pimColumns, deactivateWait, friendlyError, MIN_ACTIVE_MS, BLANK } from '../public/pim.js';
import { startHarness } from './e360-browser-harness.mjs';

const css = readFileSync(new URL('../public/styles.css', import.meta.url), 'utf8');
const html = readFileSync(new URL('../public/index.html', import.meta.url), 'utf8');
const app = readFileSync(new URL('../public/app.js', import.meta.url), 'utf8');
const G = n => `5555555${n}-5555-5555-5555-555555555555`;
const row = (n, extra = {}) => ({ id: `e${n}`, type: 'Group', name: `sg-e360-r${n}`, scope: G(n), scopeLabel: 'Group member', state: 'Eligible', start: '2026-10-30T16:17:00Z', end: '2027-10-30T16:17:00Z', key: `group|r${n}|member`, target: { groupId: G(n), accessId: 'member' }, ...extra });
const json = body => ({ status: 200, contentType: 'application/json', body: JSON.stringify(body) });

test('deactivation waits for Microsoft\'s 5-minute minimum and explains ActiveDurationTooShort', () => {
  const now = Date.parse('2026-10-31T05:00:00Z');
  assert.equal(deactivateWait({ start: '2026-10-31T04:58:00Z' }, now), 3 * 60000);
  assert.equal(deactivateWait({ start: '2026-10-31T04:50:00Z' }, now), 0);
  assert.equal(deactivateWait({ start: null }, now), 0);
  assert.equal(MIN_ACTIVE_MS, 300000);
  assert.match(friendlyError('Microsoft did not accept the deactivation: HTTP 400 (ActiveDurationTooShort: The Active duration is too short.)'), /only after the assignment has been active for 5 minutes/);
  assert.equal(friendlyError('Other failure'), 'Other failure');
});

test('column menus: unchecked values hide rows, text matches a substring, values come from the rows', () => {
  const rows = mergeRows([row(1), row(2), { ...row(3), state: 'Active (activated)', id: 'a3', start: '2026-10-31T02:06:00Z', end: '2026-10-31T03:06:00Z' }, row(3)], true);
  const name = pimColumns(true).find(c => c.key === 'name'), state = pimColumns(true).find(c => c.key === 'state');
  assert.deepEqual(menuOptions(rows, name), ['sg-e360-r1', 'sg-e360-r2', 'sg-e360-r3']);
  assert.deepEqual(menuOptions(rows, state), ['Active', 'Eligible', 'Assigned', 'Pending']);
  assert.deepEqual(shownRows(rows, { self: true, excluded: { state: new Set(['Eligible']) } }).map(r => r.name), ['sg-e360-r3']);
  assert.deepEqual(shownRows(rows, { self: true, excluded: { name: new Set(['sg-e360-r1']) }, filters: { name: 'r' } }).map(r => r.name), ['sg-e360-r2', 'sg-e360-r3']);
  assert.deepEqual(shownRows(rows, { self: true, filters: { action: 'deact' } }).map(r => r.name), ['sg-e360-r3']);
  const scope = pimColumns(true).find(c => c.key === 'end');
  assert.ok(menuOptions([{ ...row(4), end: null }], scope).includes(BLANK));
});

test('static: TOOLS section holds Error code lookup, nav labels are 13px, form fields are spaced, Export never disabled', () => {
  const tools = html.indexOf('data-section="tools"'), lookup = html.indexOf('id="error-lookup-open"'), navEnd = html.indexOf('</nav>');
  assert.ok(tools > 0 && lookup > tools && lookup < navEnd, 'Error code lookup sits under TOOLS inside the nav');
  assert.equal(html.match(/id="error-lookup-open"/g).length, 1);
  assert.match(html, /data-section="tools"><span>TOOLS<\/span>/);
  assert.match(css, /\.nav-label\{display:block;padding:14px 18px 4px;font-size:13px;/);
  assert.match(css, /\.pim-form label\{display:inline-flex;align-items:center;gap:14px;margin:0 28px 10px 0\}/);
  assert.doesNotMatch(app, /function exportReason\(/);
  assert.match(app, /toast\('Nothing on this page to export yet\. Load or run the page first\.'\)/);
});

test('browser: Deactivate sends selfDeactivate after 5 minutes, refuses early with a message, and shows API errors', async t => {
  const h = await startHarness(t, { port: 3702, roles: [] }); if (!h) return;
  const ago = m => new Date(Date.now() - m * 60000).toISOString(), soon = new Date(Date.now() + 3600000).toISOString();
  let rows = [row(1), { ...row(1), id: 'a1', state: 'Active (activated)', start: ago(10), end: soon }, row(2), { ...row(2), id: 'a2', state: 'Active (activated)', start: ago(1), end: soon }, row(3), { ...row(3), id: 'a3', state: 'Active (activated)', start: ago(20), end: soon }];
  const requests = [];
  try {
    const { ctx, page, errors } = await h.open({ before: async p => {
      await p.route('**/api/me/pim', r => r.fulfill(json({ rows, problems: [], notes: [] })));
      await p.route('**/api/me/pim/request', r => {
        const body = JSON.parse(r.request().postData()); requests.push(body);
        if (body.target.groupId === G(3)) return r.fulfill({ status: 502, contentType: 'application/json', body: JSON.stringify({ error: 'Microsoft did not accept the deactivation: HTTP 400 (ActiveDurationTooShort: The Active duration is too short.)' }) });
        rows = rows.filter(x => !(x.target.groupId === body.target.groupId && x.state === 'Active (activated)'));
        r.fulfill(json({ id: 'req-d', status: 'Revoked' }));
      });
    } });
    page.on('dialog', d => d.accept());
    await page.click('#navigation [data-view="my-pim"]');
    await page.waitForSelector('#my-pim button[data-pim-row="a1"][data-pim-action="deactivate"]', { timeout: 10000 });

    // Activated 1 minute ago: no request, a visible error saying when it can be deactivated.
    await page.click('#my-pim button[data-pim-row="a2"]');
    await page.waitForFunction(() => /only after 5 minutes of active time/.test(document.querySelector('#my-pim [data-pim-status]')?.textContent || ''));
    assert.equal(requests.length, 0);
    assert.equal(await page.locator('#my-pim [data-pim-status].pim-status-error').count(), 1);

    // Activated 10 minutes ago: selfDeactivate request, then the row goes back to Activate.
    await page.click('#my-pim button[data-pim-row="a1"]');
    await page.waitForFunction(() => document.querySelector('#my-pim tr[data-pim-key="group|r1|member"] [data-pim-action="activate"]'), null, { timeout: 15000 });
    assert.equal(requests.length, 1); assert.equal(requests[0].action, 'deactivate'); assert.equal(requests[0].type, 'Group');
    assert.deepEqual(requests[0].target, { groupId: G(1), accessId: 'member' });
    assert.match(await page.textContent('#my-pim [data-pim-status]'), /sg-e360-r1 is deactivated/);
    assert.equal(await page.locator('#my-pim [data-pim-status].pim-status-error').count(), 0);

    // Microsoft refuses: the friendly reason is shown as an error and the row is usable again.
    await page.click('#my-pim button[data-pim-row="a3"]');
    await page.waitForFunction(() => document.querySelector('#my-pim [data-pim-status].pim-status-error'));
    assert.match(await page.textContent('#my-pim [data-pim-status]'), /active for 5 minutes/);
    assert.equal(await page.locator('#my-pim button[data-pim-row="a3"]:not([disabled])').count(), 1);
    assert.deepEqual(errors, []); await ctx.close();
  } finally { await h.close(); }
});

test('browser: Export is enabled everywhere and exports the shown table; activate form, nav labels, TOOLS and menu text filter', async t => {
  const h = await startHarness(t, { port: 3703, roles: [] }); if (!h) return;
  const rows = [row(1), row(2), row(3)];
  try {
    const { ctx, page, errors } = await h.open({ before: async p => {
      await p.route('**/api/me/pim', r => r.fulfill(json({ rows, problems: [], notes: [] })));
      await p.route('**/api/me/pim/policy', r => r.fulfill(json({ maxMinutes: 480, justification: true })));
    } });
    // Export enabled on every nav page.
    for (const view of await page.$$eval('#navigation [data-view]', bs => bs.filter(b => !b.hidden).map(b => b.dataset.view))) {
      await page.click(`#navigation [data-view="${view}"]`);
      if (await page.isHidden('#header-export')) continue; // the role-denied page hides the header actions
      assert.equal(await page.isDisabled('#header-export'), false, `Export enabled on ${view}`);
    }
    await page.click('#navigation [data-view="my-pim"]');
    await page.waitForSelector('#my-pim [data-pim-action="activate"]');
    // Filter to one row, then Export writes only that row.
    await page.click('#my-pim [data-pim-menu="name"] > summary');
    await page.fill('#my-pim [data-pim-filter="name"]', 'r2');
    await page.click('#my-pim [data-pim-title]');
    const [download] = await Promise.all([page.waitForEvent('download'), page.click('#header-export')]);
    const csv = readFileSync(await download.path(), 'utf8');
    const lines = csv.replace(/^﻿/, '').trim().split('\r\n');
    assert.equal(lines.length, 2, csv); assert.match(lines[0], /^"Type","Name","Scope","State"/); assert.match(lines[1], /"sg-e360-r2"/);
    // A page with nothing loaded says so instead of being greyed out.
    await page.click('#navigation [data-view="t-domains"]');
    if (!(await page.isHidden('#header-export'))) {
      await page.evaluate(() => { document.querySelectorAll('#main table').forEach(t => t.remove()); });
      await page.click('#header-export');
      await page.waitForFunction(() => /Nothing on this page to export yet/.test(document.querySelector('#toast')?.textContent || ''));
    }

    // Activate form: clear gaps between Reason, its box, Duration and the dropdown.
    await page.click('#navigation [data-view="my-pim"]');
    await page.click('#my-pim button[data-pim-row="e2"]'); // r2 is the row the Name filter left shown
    await page.waitForSelector('#my-pim [data-pim-form] input[name="reason"]');
    const gaps = await page.evaluate(() => {
      const f = document.querySelector('#my-pim [data-pim-form]'), labels = [...f.querySelectorAll('label')].slice(0, 2);
      const textRight = l => { const r = document.createRange(); r.selectNodeContents(l.firstChild); return r.getBoundingClientRect().right; };
      const [reason, duration] = labels, input = reason.querySelector('input'), select = duration.querySelector('select');
      return [input.getBoundingClientRect().left - textRight(reason), duration.getBoundingClientRect().left - input.getBoundingClientRect().right, select.getBoundingClientRect().left - textRight(duration)];
    });
    for (const g of gaps) assert.ok(g >= 12, `gap ${g}px`);

    // Nav section labels: 13px, one line each; TOOLS holds Error code lookup, which opens its dialog.
    const nav = await page.$$eval('#navigation .nav-label', ls => ls.map(l => [l.textContent.trim(), getComputedStyle(l).fontSize, Math.round(l.querySelector('span').getBoundingClientRect().height)]));
    assert.ok(nav.some(([t]) => t === 'TOOLS'));
    for (const [t, size, hgt] of nav) { assert.equal(size, '13px', t); assert.ok(hgt <= 24, `${t} fits on one line (${hgt}px)`); }
    await page.click('#navigation #error-lookup-open');
    assert.equal(await page.evaluate(() => document.querySelector('#error-lookup-dialog').open), true);
    await page.click('#error-lookup-close');

    // Shared checkbox menus get a text box under the sort buttons; typing keeps only matching values checked.
    const result = await page.evaluate(async () => {
      const m = await import('/multiselect.js');
      const host = document.createElement('div'); document.body.append(host);
      const store = { excluded: {}, open: null }; let changes = 0;
      const draw = () => { host.innerHTML = m.multiSelectHtml({ key: 'k', label: 'Result', options: ['Success', 'Failure', 'Interrupted'], excluded: store.excluded.k, open: store.open === 'k' }); m.wireMultiSelects(host, store, () => { changes++; draw(); }); };
      draw(); host.querySelector('summary').click();
      const box = host.querySelector('input[data-msel-text]');
      const order = [...host.querySelector('.msel-menu').children].map(c => c.className || c.tagName);
      box.value = 'fail'; box.dispatchEvent(new Event('input'));
      await new Promise(r => setTimeout(r, 400));
      const checked = [...host.querySelectorAll('input[type=checkbox]:checked')].map(i => i.value);
      const after = host.querySelector('input[data-msel-text]');
      const out = { order, checked, text: after.value, focused: document.activeElement === after, changes };
      host.remove(); return out;
    });
    assert.equal(result.order[0], 'msel-actions msel-sort'); assert.equal(result.order[1], 'msel-text');
    assert.deepEqual(result.checked, ['Failure']); assert.equal(result.text, 'fail'); assert.equal(result.focused, true); assert.equal(result.changes, 1);
    assert.deepEqual(errors, []); await ctx.close();
  } finally { await h.close(); }
});
