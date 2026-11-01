import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { readCollapsed, sectionKey, NAV_COLLAPSE_KEY } from '../public/nav-sections.js';

const css = readFileSync(new URL('../public/styles.css', import.meta.url), 'utf8');
const html = readFileSync(new URL('../public/index.html', import.meta.url), 'utf8');
const app = readFileSync(new URL('../public/app.js', import.meta.url), 'utf8');

test('sidebar nav scrolls inside a viewport-height sidebar with a thin themed scrollbar', () => {
  assert.match(css, /#navigation\{[^}]*overflow-y:auto/);
  assert.match(css, /#navigation\{[^}]*min-height:0/);
  assert.match(css, /#navigation\{[^}]*scrollbar-width:thin/);
  assert.match(css, /#navigation::-webkit-scrollbar-thumb\{/);
  assert.match(css, /\.sidebar\{[^}]*height:100dvh/);
});

test('every nav section header is a keyboard-focusable toggle with a chevron', () => {
  const labels = html.match(/<div class="nav-label"[^>]*>.*?<\/div>/g) || [];
  assert.ok(labels.length >= 8);
  for (const label of labels) {
    assert.match(label, /role="button"/); assert.match(label, /tabindex="0"/);
    assert.match(label, /aria-expanded="true"/); assert.match(label, /data-section="[a-z-]+"/);
    assert.match(label, /class="nav-chevron"/);
  }
  assert.match(css, /\.nav-label\[aria-expanded="false"\] \.nav-chevron\{/);
  assert.match(css, /\.nav-item\.nav-collapsed\{display:none\}/);
});

test('collapsed state helpers tolerate bad storage', () => {
  const store = v => ({ getItem: k => (k === NAV_COLLAPSE_KEY ? v : null) });
  assert.deepEqual(readCollapsed(store('["investigate",3]')), ['investigate']);
  assert.deepEqual(readCollapsed(store('not json')), []);
  assert.deepEqual(readCollapsed(null), []);
  assert.equal(sectionKey(' MY ACCOUNT '), 'my-account');
});

test('applyView guards every sub-view so one failure cannot block navigation', () => {
  const body = app.slice(app.indexOf('function applyView('), app.indexOf('\n}', app.indexOf('function applyView(')));
  assert.doesNotMatch(body, /^\s+\w+\.(setActive|setEmergency|setLogs)\(/m);
  assert.match(body, /guardView\('authzView\.setActive'/);
  assert.match(body, /navSections\.expandFor\(state\.view\)/);
});

// Browser click-through (Edge via Playwright). Skips only if no browser can launch on this machine.
test('admin can open Authorization log; sections collapse, persist and scroll', async t => {
  const PORT = 3672, TENANT = '11111111-1111-1111-1111-111111111111';
  Object.assign(process.env, { DEMO_MODE: 'false', ENTRA_TENANT_ID: TENANT, ENTRA_CLIENT_ID: '22222222-2222-2222-2222-222222222222', ENTRA_CERT_THUMBPRINT: 'A'.repeat(40), ENTRA_CERT_PRIVATE_KEY_PATH: 'C:\\outside\\x.pem' });
  let chromium; try { ({ chromium } = await import('@playwright/test')); } catch { t.skip('playwright not installed'); return; }
  let browser; try { browser = await chromium.launch({ channel: 'msedge' }); } catch { try { browser = await chromium.launch(); } catch { t.skip('no browser available'); return; } }
  const { createApp } = await import('../server/index.mjs');
  let authRequest;
  const account = { homeAccountId: `u.${TENANT}`, localAccountId: '33333333-3333-3333-3333-333333333333', tenantId: TENANT, username: 'aaron@example.test', name: 'Aaron' };
  const mock = { getAuthCodeUrl: async o => { authRequest = o; return `http://127.0.0.1:${PORT}/auth/callback?code=${'c'.repeat(20)}&state=${o.state}`; },
    acquireTokenByCode: async () => ({ account, idTokenClaims: { nonce: authRequest.nonce, roles: ['E360.Admin', 'E360.Reader'] }, accessToken: 'x' }),
    getTokenCache: () => ({ serialize: () => '{}', deserialize() {} }), acquireTokenSilent: async () => ({ accessToken: 'x', account }) };
  const server = createApp({ port: PORT, confidential: true, enforceRoles: true, demoMode: false, createConfidential: () => mock, certificate: () => ({ thumbprint: 'A'.repeat(40), privateKey: 'test' }),
    apiFetcher: async () => new Response(JSON.stringify({ value: [], id: account.localAccountId, displayName: 'Aaron', userPrincipalName: account.username, accountEnabled: true }), { status: 200, headers: { 'content-type': 'application/json' } }) }).listen(PORT, '127.0.0.1');
  await new Promise(r => server.once('listening', r));
  try {
    const page = await browser.newPage({ viewport: { width: 1100, height: 600 } });
    const errors = []; page.on('pageerror', e => errors.push(e.message));
    await page.goto(`http://127.0.0.1:${PORT}/`);
    await page.waitForFunction(() => !document.querySelector('#navigation [data-view=authz]').hidden, null, { timeout: 15000 });
    await page.click('#navigation [data-view="authz"]');
    await page.waitForFunction(() => !document.querySelector('#authz-panel').hidden);
    assert.equal(await page.textContent('#page-title'), 'Authorization log');
    assert.equal(await page.getAttribute('#navigation .active', 'data-view'), 'authz');

    const nav = await page.evaluate(() => { const n = document.querySelector('#navigation'); return { oy: getComputedStyle(n).overflowY, scrollable: n.scrollHeight > n.clientHeight }; });
    assert.equal(nav.oy, 'auto'); assert.ok(nav.scrollable, 'nav should scroll at 600px height');
    await page.locator('#navigation [data-view="p-consent"]').scrollIntoViewIfNeeded();
    await page.click('#navigation [data-view="p-consent"]');
    assert.equal(await page.getAttribute('#navigation .active', 'data-view'), 'p-consent');

    const label = '#navigation .nav-label[data-section="more-tools"]';
    await page.click(label);
    assert.equal(await page.getAttribute(label, 'aria-expanded'), 'false');
    assert.equal(await page.isVisible('#navigation [data-view="licenses"]'), false);
    await page.focus(label); await page.keyboard.press('Enter');
    assert.equal(await page.getAttribute(label, 'aria-expanded'), 'true');
    await page.keyboard.press(' ');
    assert.equal(await page.getAttribute(label, 'aria-expanded'), 'false');
    await page.reload();
    await page.waitForSelector(`${label}[aria-expanded="false"]`, { timeout: 15000 });
    assert.equal(await page.isVisible('#navigation [data-view="billing"]'), false);
    assert.deepEqual(errors, []);
  } finally { await browser.close(); server.close(); }
});