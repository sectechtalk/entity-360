// 360 standard shell (2026-11-15): pages in the URL, the 360 app switcher, real links and buttons in the rail.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { viewFromHash, writeView } from '../public/router.js';
import { switcherHtml } from '../public/shell.js';
import { APPS_360 } from '../public/360-apps.js';
import { startHarness } from './e360-browser-harness.mjs';
import { openRail } from './open-rail.mjs';
import { freePort } from './free-port.mjs';

const html = readFileSync(new URL('../public/index.html', import.meta.url), 'utf8');
const isView = v => ['summary', 'signins', 'licenses'].includes(v);

test('viewFromHash reads #page, ignores a tab or query after it, and rejects unknown pages', () => {
  assert.equal(viewFromHash('#signins', isView), 'signins');
  assert.equal(viewFromHash('#/licenses', isView), 'licenses');
  assert.equal(viewFromHash('#signins/details?user=1', isView), 'signins');
  assert.equal(viewFromHash('#nope', isView), null);
  assert.equal(viewFromHash('', isView), null);
});

test('writeView replaces an empty hash, pushes a new page, and skips the current one', () => {
  const calls = []; const hist = { pushState: (_, __, u) => calls.push(['push', u]), replaceState: (_, __, u) => calls.push(['replace', u]) };
  writeView('summary', { pathname: '/', search: '', hash: '' }, hist);
  writeView('signins', { pathname: '/', search: '', hash: '#summary' }, hist);
  writeView('signins', { pathname: '/', search: '', hash: '#signins' }, hist);
  assert.deepEqual(calls, [['replace', '/#summary'], ['push', '/#signins']]);
});

test('app switcher lists every 360 app, marks this one, and never links an app with no URL', () => {
  const out = switcherHtml('e-360');
  for (const a of APPS_360) assert.ok(out.includes(a.name), a.name);
  assert.match(out, /<span class="app-switch-item" aria-current="page"><strong>Entity 360<\/strong>/);
  assert.doesNotMatch(out, /href=""/);
  assert.match(switcherHtml('x', [{ id: 'r-360', name: 'R', about: 'a', url: 'https://r.example/' }]), /<a class="app-switch-item" href="https:\/\/r\.example\/">/);
});

test('rail: page links are <a href="#view">, group headers are buttons, switcher sits under the brand', () => {
  const nav = html.slice(html.indexOf('<nav id="navigation"'), html.indexOf('</nav>'));
  assert.doesNotMatch(nav, /<button data-view=/);
  for (const m of nav.matchAll(/<a href="#([a-z0-9-]+)" data-view="([a-z0-9-]+)" class="nav-item(?: active)?">/g)) assert.equal(m[1], m[2]);
  assert.ok(html.indexOf('id="app-switcher"') > html.indexOf('class="brand"') && html.indexOf('id="app-switcher"') < html.indexOf('<nav id="navigation"'));
  const footer = html.slice(html.indexOf('<div class="sidebar-bottom">'));
  assert.ok(footer.indexOf('id="viewer-button"') > -1 && footer.indexOf('id="theme-toggle"') > -1, 'user and theme toggle live in the rail footer');
  assert.doesNotMatch(html.slice(html.indexOf('class="page-heading"'), html.indexOf('id="page-title"')), /eyebrow/);
});

test('browser: a linked page opens, the URL follows navigation, and Back returns to the previous page', async t => {
  const h = await startHarness(t, {}); if (!h) return;
  try {
    const ctx = await h.browser.newContext({ viewport: { width: 1280, height: 800 } }); await openRail(ctx); const page = await ctx.newPage(); const errors = [];
    page.on('pageerror', e => errors.push(e.message));
    await page.goto(`http://127.0.0.1:${h.port}/#licenses`);
    await page.waitForFunction(() => document.querySelector('#mode-badge')?.textContent.includes('LIVE'), null, { timeout: 15000 });
    assert.equal(await page.textContent('#page-title'), 'Licenses');
    await page.click('#navigation a[data-view="signins"]');
    assert.equal(new URL(page.url()).hash, '#signins');
    assert.equal(await page.textContent('#page-title'), 'Sign-ins');
    await page.goBack(); await page.waitForFunction(() => document.querySelector('#page-title').textContent === 'Licenses');
    assert.equal(new URL(page.url()).hash, '#licenses');
    await page.click('.app-switcher-toggle');
    assert.equal(await page.locator('.app-switch-list [aria-current="page"]').count(), 1);
    // Phone width: the rail is a drawer behind the menu button.
    await page.setViewportSize({ width: 400, height: 800 });
    assert.ok(await page.isVisible('#nav-toggle'));
    await page.click('#nav-toggle'); assert.equal(await page.getAttribute('#nav-toggle', 'aria-expanded'), 'true');
    await page.click('#navigation a[data-view="summary"]'); assert.equal(await page.getAttribute('#nav-toggle', 'aria-expanded'), 'false');
    assert.deepEqual(errors, []); await ctx.close();
  } finally { await h.close(); }
});

test('tabFromHash and writeTab keep the tab in #page/tab without adding history', async () => {
  const { tabFromHash, writeTab } = await import('../public/router.js');
  assert.equal(tabFromHash('#access/roles'), 'roles');
  assert.equal(tabFromHash('#access'), null);
  assert.equal(tabFromHash('#access/<x>'), null);
  const calls = []; const hist = { replaceState: (_, __, u) => calls.push(u), pushState: () => calls.push('push') };
  writeTab('access', 'roles', { pathname: '/', search: '', hash: '#access' }, hist);
  writeTab('access', 'roles', { pathname: '/', search: '', hash: '#access/roles' }, hist);
  assert.deepEqual(calls, ['/#access/roles']);
});

test('browser: Access tabs use arrow keys, a roving tabindex, and the URL', async t => {
  const h = await startHarness(t, { roles: ['E360.Reader', 'E360.Admin'] }); if (!h) return;
  try {
    const ctx = await h.browser.newContext({ viewport: { width: 1280, height: 800 } }); await openRail(ctx); const page = await ctx.newPage(); const errors = [];
    page.on('pageerror', e => errors.push(e.message));
    await page.goto(`http://127.0.0.1:${h.port}/#access/roles`);
    await page.waitForFunction(() => document.querySelector('#mode-badge')?.textContent.includes('LIVE'), null, { timeout: 15000 });
    await page.waitForSelector('#access-page:not([hidden]) .tab[data-tab="roles"][aria-selected="true"]', { timeout: 15000 });
    assert.equal(await page.getAttribute('#access-page .tab[data-tab="roles"]', 'tabindex'), '0');
    assert.equal(await page.locator('#access-page .tab[tabindex="0"]').count(), 1);
    await page.focus('#access-page .tab[data-tab="roles"]'); await page.keyboard.press('ArrowRight');
    const now = await page.$eval('#access-page .tab[aria-selected="true"]', el => el.dataset.tab);
    assert.notEqual(now, 'roles');
    assert.equal(await page.evaluate(() => document.activeElement.dataset.tab), now);
    assert.equal(new URL(page.url()).hash, `#access/${now}`);
    // Screen readers: every tab controls the shared tabpanel, which is labelled by the selected tab.
    assert.equal(await page.getAttribute('#access-tabpanel', 'role'), 'tabpanel');
    assert.equal(await page.locator('#access-page [role="tab"]:not([aria-controls="access-tabpanel"])').count(), 0);
    const selectedId = await page.$eval('#access-page .tab[aria-selected="true"]', el => el.id);
    assert.ok(selectedId); assert.equal(await page.getAttribute('#access-tabpanel', 'aria-labelledby'), selectedId);
    assert.deepEqual(errors, []); await ctx.close();
  } finally { await h.close(); }
});
