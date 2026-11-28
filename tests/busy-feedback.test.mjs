// Every button gives "doing something" feedback: a click that starts a request makes that control busy (spinner,
// "Refreshing…"-style wording, further clicks ignored) until the request finishes, a top progress bar shows while
// any request runs, and local-only actions such as exports say "Exported ✓".
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { ROLE_GROUPS } from '../public/access-denied.js';
import { busyLabel, doneLabel } from '../public/btn-feedback.js';
import { startHarness } from './e360-browser-harness.mjs';
import { freePort } from './free-port.mjs';

const fake = (text, data = {}, aria = null) => ({ textContent: text, dataset: data, getAttribute: n => (n === 'aria-label' ? aria : null) });

test('busy wording fits what each button does', () => {
  const cases = {
    'Look up sign-ins': 'Looking up…', 'Search': 'Searching…', 'Run report': 'Running…', 'Run Intune health': 'Running…',
    'Check my account': 'Checking…', 'Check my roles again': 'Re-checking…', 'Export CSV': 'Exporting…', 'Refresh': 'Refreshing…',
    'Load activity log': 'Loading…', 'Next': 'Loading…', 'Previous': 'Loading…', 'Connect Azure': 'Connecting…',
    'Microsoft connection & MFA': 'Connecting…', 'Discover other tenants': 'Discovering…', 'Collect server host': 'Collecting…',
    'Apply timeframe': 'Applying…', 'PDF report': 'Building PDF…', 'Sign in again': 'Signing in…', 'Sign in with Microsoft ↗': 'Signing in…',
    'Activate': 'Activating…', 'Deactivate': 'Deactivating…', 'Find device': 'Searching…', 'Open device page': 'Opening…',
    'Copy ID': 'Copying…', 'List workspaces': 'Loading…', 'Reload': 'Reloading…', 'Confirm run': 'Running…', 'Something new': 'Working…',
  };
  for (const [label, want] of Object.entries(cases)) assert.equal(busyLabel(fake(label)), want, label);
  assert.equal(busyLabel(fake('x', { busyLabel: 'Building PDF…' })), 'Building PDF…');
  assert.equal(busyLabel(fake('✕', {}, 'Close')), 'Working…');
  assert.equal(doneLabel(fake('Export CSV')), 'Exported ✓');
  assert.equal(doneLabel(fake('Copy record ID')), 'Copied ✓');
  assert.equal(doneLabel(fake('Run report')), '');
});

test('styles: busy controls, spinner, progress bar, pressed flash on every control', () => {
  const css = readFileSync(new URL('../public/styles.css', import.meta.url), 'utf8');
  for (const re of [/\[data-e360-busy\]\{cursor:progress/, /\.e360-spin\{[^}]*animation:btn-spin/, /\.e360-busy-bar\{position:fixed/, /a\.nav-item\.btn-clicked/, /\[role="tab"\]\.btn-clicked/])
    assert.match(css, re);
});

async function slowApi(page, ms = 1200) {
  const hits = [];
  await page.route('**/api/**', async r => { hits.push(new URL(r.request().url()).pathname); await new Promise(x => setTimeout(x, ms)); await r.continue(); });
  return hits;
}
const state = (page, sel) => page.$eval(sel, el => ({ busy: el.hasAttribute('data-e360-busy'), aria: el.getAttribute('aria-busy'), text: el.textContent.replace(/\s+/g, ' ').trim(), bar: !document.querySelector('.e360-busy-bar')?.hidden }));

test('browser: a clicked button is busy with fitting words until its request ends, and ignores double clicks', async t => {
  const h = await startHarness(t, { roles: Object.keys(ROLE_GROUPS) }); if (!h) return;
  try {
    const { ctx, page, errors } = await h.open();
    await page.click('#navigation [data-view="authz"]'); await page.waitForTimeout(800);
    const hits = await slowApi(page);
    await page.click('#authz-refresh'); await page.waitForTimeout(250);
    let s = await state(page, '#authz-refresh');
    assert.deepEqual([s.busy, s.aria, s.text, s.bar], [true, 'true', 'Refreshing…', true]);
    const n = hits.length; await page.click('#authz-refresh', { force: true }); await page.waitForTimeout(100);
    assert.equal(hits.length, n, 'a second click while busy starts no new request');
    await page.waitForFunction(() => !document.querySelector('#authz-refresh').hasAttribute('data-e360-busy'), null, { timeout: 8000 });
    s = await state(page, '#authz-refresh');
    assert.deepEqual([s.busy, s.aria, s.text], [false, null, 'Refresh']);
    // Stop slowing the API first: other requests the page starts meanwhile keep the bar up, and on a slower PC
    // (Windows, tests in parallel) 1.2 s each can add up past the wait.
    await page.unroute('**/api/**');
    await page.waitForFunction(() => document.querySelector('.e360-busy-bar')?.hidden, null, { timeout: 15000 });
    // Export says "Exported ✓" only when a file was really built; with nothing to export the words stay as they are.
    await page.click('#authz-export'); await page.waitForTimeout(400);
    assert.equal((await state(page, '#authz-export')).text, 'Exported ✓');
    await page.click('#navigation [data-view="device"]'); await page.waitForTimeout(600);
    await page.click('#header-export'); await page.waitForTimeout(400);
    assert.match(await page.textContent('#toast'), /Nothing on this page to export/);
    assert.doesNotMatch((await state(page, '#header-export')).text, /Exported/);
    assert.deepEqual(errors, []);
    await ctx.close();
  } finally { await h.close(); }
});

test('browser: nav links and form submits show busy; buttons with their own busy state keep it', async t => {
  const h = await startHarness(t, { roles: Object.keys(ROLE_GROUPS) }); if (!h) return;
  try {
    const { ctx, page, errors } = await h.open();
    await slowApi(page);
    await page.click('#navigation [data-view="authz"]'); await page.waitForTimeout(250);
    const nav = await page.$eval('#navigation [data-view="authz"]', el => ({ busy: el.hasAttribute('data-e360-busy'), spin: Boolean(el.querySelector('.e360-spin')) }));
    assert.deepEqual(nav, { busy: true, spin: true });
    await page.waitForFunction(() => !document.querySelector('#navigation [data-view="authz"] .e360-spin'), null, { timeout: 8000 });
    // Access report: Search is a form submit; Run report manages its own aria-busy and "Running…" text.
    await page.click('#navigation [data-view="g-access-report"]'); await page.waitForTimeout(1600);
    await page.fill('#ar-q', 'admin'); await page.press('#ar-q', 'Enter'); await page.waitForTimeout(250);
    const s = await page.$eval('#ar-search-form button[type="submit"]', el => ({ busy: el.hasAttribute('data-e360-busy'), text: el.textContent.trim() }));
    assert.deepEqual(s, { busy: true, text: 'Searching…' });
    // Findings re-renders its whole panel (Refresh included) as the request starts; the new Refresh is the busy one.
    await page.click('#navigation [data-view="findings"]'); await page.waitForTimeout(2600);
    await page.click('[data-findings-refresh]'); await page.waitForTimeout(300);
    const f = await page.$eval('[data-findings-refresh]', el => ({ busy: el.hasAttribute('data-e360-busy'), text: el.textContent.trim() }));
    assert.deepEqual(f, { busy: true, text: 'Refreshing…' });
    // Device lookup re-renders its form before the request starts; the new Find device button carries the busy state.
    await page.click('#navigation [data-view="device"]'); await page.waitForTimeout(1600);
    await page.fill('#device-lookup-q', 'LAPTOP'); await page.click('#device-lookup-form button[type="submit"]'); await page.waitForTimeout(250);
    const d = await page.$eval('#device-lookup-form button[type="submit"]', el => ({ busy: el.hasAttribute('data-e360-busy'), text: el.textContent.trim() }));
    assert.deepEqual(d, { busy: true, text: 'Searching…' });
    assert.deepEqual(errors, []);
    await ctx.close();
  } finally { await h.close(); }
});
