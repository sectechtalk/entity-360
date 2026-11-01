import test from 'node:test';
import assert from 'node:assert/strict';

test('browser: landing directly on authz as Admin shows matching count and clears loading', async t => {
  const PORT = 3674, TENANT = '11111111-1111-1111-1111-111111111111';
  Object.assign(process.env, { DEMO_MODE: 'false', ENTRA_TENANT_ID: TENANT, ENTRA_CLIENT_ID: '22222222-2222-2222-2222-222222222222', ENTRA_CERT_THUMBPRINT: 'A'.repeat(40), ENTRA_CERT_PRIVATE_KEY_PATH: 'C:\\outside\\x.pem' });
  let chromium; try { ({ chromium } = await import('@playwright/test')); } catch { t.skip('playwright not installed'); return; }
  let browser; try { browser = await chromium.launch({ channel: 'msedge' }); } catch { try { browser = await chromium.launch(); } catch { t.skip('no browser available'); return; } }
  const { createApp } = await import('../server/index.mjs');
  let authRequest; const roles = ['E360.Reader', 'E360.Admin'];
  const account = { homeAccountId: `u.${TENANT}`, localAccountId: '33333333-3333-3333-3333-333333333333', tenantId: TENANT, username: 'aaron@example.test', name: 'Aaron' };
  const mock = { getAuthCodeUrl: async o => { authRequest = o; return `http://127.0.0.1:${PORT}/auth/callback?code=${'c'.repeat(20)}&state=${o.state}`; },
    acquireTokenByCode: async () => ({ account, idTokenClaims: { nonce: authRequest.nonce, roles }, accessToken: 'x' }),
    getTokenCache: () => ({ serialize: () => '{}', deserialize() {} }), acquireTokenSilent: async () => ({ accessToken: 'x', account }) };
  const server = createApp({ port: PORT, confidential: true, enforceRoles: true, demoMode: false, createConfidential: () => mock, certificate: () => ({ thumbprint: 'A'.repeat(40), privateKey: 'test' }),
    apiFetcher: async () => new Response(JSON.stringify({ value: [], id: account.localAccountId, displayName: 'Aaron', userPrincipalName: account.username, accountEnabled: true }), { status: 200, headers: { 'content-type': 'application/json' } }) }).listen(PORT, '127.0.0.1');
  await new Promise(r => server.once('listening', r));
  const rows = Array.from({ length: 6 }, (_, i) => ({ time: `2026-10-30T04:5${i}:21.000Z`, user: 'aaron@example.test', path: '/api/billing', role: 'E360.Billing', outcome: i < 2 ? 'denied' : 'allowed' }));
  try {
    const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 } }); const page = await ctx.newPage(); const errors = []; page.on('pageerror', e => errors.push(e.message));
    await page.route('**/api/authz/log', route => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ enforced: true, rows }) }));
    let slow = false;
    await page.route('**/api/investigate*', async route => { if (slow) await new Promise(r => setTimeout(r, 4000)); route.continue().catch(() => {}); });
    await page.route('**/api/billing*', route => route.fulfill({ status: 403, contentType: 'application/json', body: JSON.stringify({ error: 'Your Entity 360 roles do not include this feature.', requiredRole: 'E360.Billing' }) }));
    await page.goto(`http://127.0.0.1:${PORT}/`);
    await page.waitForFunction(() => document.querySelector('#mode-badge')?.textContent.includes('LIVE'), null, { timeout: 15000 });
    // Land directly on the authz view on reload (same path the app uses to return to a view after sign-in).
    await page.evaluate(() => sessionStorage.setItem('e360resumeView', 'authz'));
    slow = true; await page.reload();
    await page.waitForSelector('#authz-panel:not([hidden]) td.authz-time', { timeout: 15000 });
    // The signed-in user's investigation is still loading (slowed to 4s): the global loader must not show on authz.
    assert.equal(await page.isHidden('#loading'), true, 'loader hidden on authz while investigate is in flight');
    assert.equal(await page.textContent('#authz-count'), '6 of 6');
    await page.waitForTimeout(4500);
    assert.equal(await page.locator('#authz-panel tbody tr').count(), 6);
    assert.equal(await page.textContent('#authz-count'), '6 of 6');
    assert.equal(await page.isHidden('#loading'), true, 'global loading indicator hidden on authz');
    await page.selectOption('#authz-filter', 'denied');
    assert.equal(await page.locator('#authz-panel tbody tr').count(), 2);
    assert.equal(await page.textContent('#authz-count'), '2 of 6');
    // Denial body text uses the normal text colour in dark and light themes (Admin lacks E360.Billing here).
    await page.click('#navigation [data-view="billing"]');
    await page.waitForSelector('#denied-panel:not([hidden]) .denied-card p');
    for (const theme of ['dark', 'light']) {
      await page.evaluate(th => { document.documentElement.dataset.theme = th; }, theme);
      const [body, ps] = await page.evaluate(() => [getComputedStyle(document.documentElement).color, [...document.querySelectorAll('#denied-panel .denied-card p')].map(p => getComputedStyle(p).color)]);
      for (const c of ps) assert.equal(c, body, `denial text colour in ${theme}`);
    }
    assert.deepEqual(errors, []); await ctx.close();
  } finally { await browser.close(); server.close(); }
});