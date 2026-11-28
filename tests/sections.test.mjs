// Aaron's rule (2026-11-27): every section on every page is collapsible and starts collapsed (public/sections.js).
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { ROLE_GROUPS } from '../public/access-denied.js';
import { readOpen, sectionKey, SECTIONS_OPEN_KEY } from '../public/sections.js';
import { startHarness } from './e360-browser-harness.mjs';

test('open sections are remembered per page and title; bad storage reads as nothing open', () => {
  const store = v => ({ getItem: () => v });
  assert.deepEqual(readOpen(store(JSON.stringify({ 'authz-panel::Authorization log #': true }))), { 'authz-panel::Authorization log #': true });
  for (const bad of [null, '', 'not json', '[1,2]', 'null']) assert.deepEqual(readOpen(store(bad)), {});
  assert.deepEqual(readOpen({ getItem() { throw new Error('blocked'); } }), {});
  assert.equal(sectionKey('', 'Sign-ins #'), 'summary::Sign-ins #');
  assert.equal(SECTIONS_OPEN_KEY, 'e360.sections.open');
});

test('styles: a folded panel shows only its heading row; the fold button is a filled button', () => {
  const css = readFileSync(new URL('../public/styles.css', import.meta.url), 'utf8');
  assert.match(css, /\.sec-folded>:not\(\.sec-head\)\{display:none!important\}/);
  assert.match(css, /\.btn\.sec-fold\{/);
  assert.match(readFileSync(new URL('../public/app.js', import.meta.url), 'utf8'), /installSections\(document\)/);
});

const folded = page => page.evaluate(() => {
  const vis = el => el.offsetParent !== null || el.getClientRects().length > 0;
  const panels = [...document.querySelectorAll('.sec-panel')].filter(vis);
  const details = [...document.querySelectorAll('details:not(.msel)')].filter(d => vis(d) && !d.closest('.sec-folded, [role="alert"], dialog'));
  const bare = [...document.querySelectorAll('.panel')].filter(p => vis(p) && p.tagName !== 'DETAILS' && !p.closest('.drawer, [role="alert"], dialog') && p.querySelector(':scope > .panel-heading, :scope > h2, :scope > h3') && !p.classList.contains('sec-panel'));
  return {
    panels: panels.length,
    open: panels.filter(p => !p.classList.contains('sec-folded')).map(p => p.dataset.secTitle),
    words: [...new Set(panels.map(p => p.querySelector('.sec-fold')?.textContent))],
    openDetails: details.filter(d => d.open).map(d => d.querySelector('summary')?.textContent.trim()),
    bare: bare.map(p => p.querySelector('h2, h3')?.textContent.trim()),
  };
});

test('browser: every section on every page starts collapsed; Expand opens it and it stays open on that page', async t => {
  const h = await startHarness(t, { roles: Object.keys(ROLE_GROUPS) }); if (!h) return;
  try {
    // This test checks the real default, so undo the harness's "open everything" switch for this page.
    const { ctx, page, errors } = await h.open({ before: p => p.addInitScript(() => { Object.defineProperty(window, '__e360SectionsOpen', { get: () => false, set() {}, configurable: false }); }) });
    const views = await page.$$eval('#navigation [data-view]', els => [...new Set(els.map(e => e.dataset.view))]);
    assert.ok(views.length > 30, `rail lists the pages (${views.length})`);
    let checked = 0;
    for (const v of views) {
      await page.evaluate(view => { location.hash = `#${view}`; }, v);
      await page.waitForTimeout(450);
      const s = await folded(page);
      assert.deepEqual(s.open, [], `${v}: every section starts collapsed`);
      assert.deepEqual(s.openDetails, [], `${v}: every details section starts closed`);
      assert.deepEqual(s.bare, [], `${v}: every section with a heading can fold`);
      if (s.panels) { assert.deepEqual(s.words, ['▸ Expand'], `${v}: fold button says Expand`); checked++; }
    }
    assert.ok(checked > 15, `sections found on ${checked} pages`);

    // Expand, refresh: still open. Collapse, refresh: collapsed again.
    await page.evaluate(() => { location.hash = '#authz'; }); await page.waitForTimeout(800);
    const fold = '#authz-panel .panel.sec-panel .sec-fold';
    await page.click(fold);
    assert.equal(await page.textContent(fold), '▾ Collapse');
    assert.equal(await page.$eval(fold, b => b.getAttribute('aria-expanded')), 'true');
    assert.ok(await page.isVisible('#authz-panel .table-wrap, #authz-panel table, #authz-panel .inline-empty, #authz-panel .loading'), 'content shows once expanded');
    await page.reload(); await page.waitForTimeout(1200);
    assert.equal(await page.textContent(fold), '▾ Collapse', 'an opened section stays open after a refresh');
    await page.click(fold);
    await page.reload(); await page.waitForTimeout(1200);
    assert.equal(await page.textContent(fold), '▸ Expand');
    assert.deepEqual(errors, []);
    await ctx.close();
  } finally { await h.close(); }
});

test('browser: with every section open, every heading on every page belongs to a section, and no section hides another', async t => {
  const h = await startHarness(t, { roles: Object.keys(ROLE_GROUPS) }); if (!h) return;
  try {
    const { ctx, page, errors } = await h.open(); // the harness opens every section, so nested ones show too
    const views = await page.$$eval('#navigation [data-view]', els => [...new Set(els.map(e => e.dataset.view))]);
    const problems = [];
    for (const v of views) {
      await page.evaluate(view => { location.hash = `#${view}`; }, v);
      await page.waitForTimeout(450);
      const r = await page.evaluate(() => {
        const main = document.querySelector('main');
        const vis = el => el.getClientRects().length > 0;
        const loose = [...main.querySelectorAll('h2, h3')].filter(vis)
          .filter(x => !x.closest('.sec-head, .page-heading, details, .summary-card, [role="alert"], .empty-state, .drawer, dialog'))
          .map(x => x.textContent.trim().slice(0, 40));
        // An h2 section inside another h2 section means one page part was swallowed by the part above it.
        const level = p => p.querySelector(':scope > .sec-head')?.matches('h2, h3') ? p.querySelector(':scope > .sec-head').tagName : p.querySelector(':scope > .sec-head :is(h2, h3)')?.tagName;
        const swallowed = [...main.querySelectorAll('.sec-panel')].filter(p => { const up = p.parentElement?.closest('.sec-panel'); return up && level(p) === 'H2' && level(up) === 'H2'; }).map(p => p.dataset.secTitle);
        return { loose, swallowed };
      });
      for (const x of r.loose) problems.push(`${v}: heading outside a section: ${x}`);
      for (const x of r.swallowed) problems.push(`${v}: section inside another section of the same level: ${x}`);
    }
    assert.deepEqual(problems, []);
    assert.deepEqual(errors, []);
    await ctx.close();
  } finally { await h.close(); }
});

test('browser: the Setup guide folds every section, starts collapsed, and a contents link opens its section', async t => {
  const h = await startHarness(t); if (!h) return;
  try {
    // Signed in first (the guide needs a session), with the real collapsed default rather than the harness's open switch.
    const { ctx, page, errors } = await h.open({ before: p => p.addInitScript(() => { Object.defineProperty(window, '__e360SectionsOpen', { get: () => false, set() {}, configurable: false }); }) });
    await page.goto(`http://127.0.0.1:${h.port}/setup.html`);
    await page.waitForSelector('main > section.sec-panel');
    const n = await page.locator('main > section').count();
    assert.ok(n >= 8, `guide sections (${n})`);
    assert.equal(await page.locator('main > section.sec-panel.sec-folded').count(), n, 'every guide section starts collapsed');
    await page.click('nav a[href="#limits"]');
    await page.waitForFunction(() => !document.querySelector('#limits').classList.contains('sec-folded'), null, { timeout: 3000 });
    assert.equal(await page.textContent('#limits .sec-fold'), '▾ Collapse');
    assert.deepEqual(errors, []);
    await ctx.close();
  } finally { await h.close(); }
});
