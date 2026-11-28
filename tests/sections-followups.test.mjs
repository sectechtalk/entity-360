// Follow-ups to the collapsed-sections rule (Aaron, 2026-11-27: "On EVERY page I want the default of collapsible
// sections to be collapsed" and "EVERY button on every page ... MUST give feedback"): rail groups start collapsed,
// the page heading has Expand all, Export still finds tables in collapsed sections, and presses that start no request
// still show feedback.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { ROLE_GROUPS } from '../public/access-denied.js';
import { startHarness } from './e360-browser-harness.mjs';

const read = f => readFileSync(new URL(`../public/${f}`, import.meta.url), 'utf8');

test('static: rail sections start collapsed; AD posture folds on its own; Expand all exists', () => {
  const labels = [...read('index.html').matchAll(/class="nav-label" aria-expanded="(\w+)"/g)].map(m => m[1]);
  assert.ok(labels.length >= 10); assert.deepEqual([...new Set(labels)], ['false']);
  assert.match(read('sections.js'), /const SECTION = '\.panel, \.posture-section'/);
  assert.match(read('sections.js'), /id = 'sections-toggle'/);
  assert.match(read('index.html'), /id="theme-toggle"[^>]*data-busy="none"/);
});

const BASE = 3751;
// The harness opens every section for most tests; these check the real default.
const realDefault = p => p.addInitScript(() => { Object.defineProperty(window, '__e360SectionsOpen', { get: () => false, set() {}, configurable: false }); });

test('browser: Expand all / Collapse all; header Export finds the table inside a collapsed section', async t => {
  const h = await startHarness(t, { port: BASE, roles: Object.keys(ROLE_GROUPS) }); if (!h) return;
  try {
    const { ctx, page, errors } = await h.open({ before: realDefault });
    await page.click('#navigation [data-view="g-access-report"]'); await page.waitForTimeout(900);
    const folded = () => page.$$eval('#access-report-panel .sec-panel', els => els.map(e => e.classList.contains('sec-folded')));
    assert.ok((await folded()).length >= 1); assert.ok((await folded()).every(Boolean));
    assert.equal((await page.textContent('#sections-toggle')).trim(), 'Expand all');
    await page.click('#sections-toggle');
    assert.ok((await folded()).every(f => !f)); assert.equal((await page.textContent('#sections-toggle')).trim(), 'Collapse all');
    await page.click('#sections-toggle');
    assert.ok((await folded()).every(Boolean));
    // A page with no sections hides the button.
    await page.click('#navigation [data-view="device"]'); await page.waitForTimeout(700);
    const shown = await page.$$eval('#access-report-panel', () => getComputedStyle(document.querySelector('#sections-toggle')).display);
    assert.equal(shown === 'none' || (await page.$$('#device-lookup-panel .sec-panel')).length > 0, true);
    // Start here: its tables sit in collapsed sections; header Export still exports the first one.
    await page.click('#navigation [data-view="start"]'); await page.waitForTimeout(700);
    assert.ok((await page.$$eval('#start-panel .sec-panel', els => els.map(e => e.classList.contains('sec-folded')))).every(Boolean));
    const [download] = await Promise.all([page.waitForEvent('download', { timeout: 5000 }), page.click('#header-export')]);
    assert.match(download.suggestedFilename(), /^entity-360-start-.*\.csv$/);
    const csv = readFileSync(await download.path(), 'utf8');
    assert.match(csv, /When someone says/);
    assert.deepEqual(errors, []);
    await ctx.close();
  } finally { await h.close(); }
});

test('browser: presses that start no request still show busy words or a spinner', async t => {
  const h = await startHarness(t, { port: BASE + 1, roles: Object.keys(ROLE_GROUPS) }); if (!h) return;
  try {
    const { ctx, page, errors } = await h.open();
    // Header Export with nothing to export: no request, no file. It still says what it is doing.
    await page.click('#navigation [data-view="device"]'); await page.waitForTimeout(800);
    await page.click('#header-export'); await page.waitForTimeout(60);
    const ex = await page.$eval('#header-export', el => ({ busy: el.hasAttribute('data-e360-busy'), aria: el.getAttribute('aria-busy') }));
    assert.deepEqual(ex, { busy: true, aria: 'true' });
    await page.waitForFunction(() => !document.querySelector('#header-export').hasAttribute('data-e360-busy'), null, { timeout: 3000 });
    // A quick second press is a new action, not ignored, once only local work was showing.
    await page.click('#header-export'); await page.waitForTimeout(60);
    assert.equal(await page.$eval('#header-export', el => el.hasAttribute('data-e360-busy')), true);
    // The theme switch shows its result instead (data-busy="none").
    await page.click('#theme-toggle'); await page.waitForTimeout(60);
    assert.equal(await page.$eval('#theme-toggle', el => el.hasAttribute('data-e360-busy')), false);
    assert.deepEqual(errors, []);
    await ctx.close();
  } finally { await h.close(); }
});
