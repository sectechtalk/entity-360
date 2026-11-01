import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { ROLE_GROUPS, PIM_GROUPS_URL, VIEW_ROLES, missingRole, deniedHtml } from '../public/access-denied.js';
import { fmtUtc } from '../public/authz-log.js';
import { ROUTE_ROLES } from '../server/authflow.mjs';

const css = readFileSync(new URL('../public/styles.css', import.meta.url), 'utf8');

test('role to group map is one client constant covering PIM-for-Groups roles', () => {
  assert.deepEqual(ROLE_GROUPS, { 'E360.Reader': 'sg-e360-reader', 'E360.Billing': 'sg-e360-billing', 'E360.Admin': 'sg-e360-admin' });
  assert.match(PIM_GROUPS_URL, /\/#view\/Microsoft_Azure_PIMCommon\/ActivationMenuBlade\/~\/aadgroup$/);
});

test('missingRole only applies when roles are enforced', () => {
  assert.equal(missingRole({ rolesEnforced: false, appRoles: [] }, 'billing'), null);
  assert.equal(missingRole({ rolesEnforced: true, appRoles: ['E360.Reader'] }, 'billing'), 'E360.Billing');
  assert.equal(missingRole({ rolesEnforced: true, appRoles: ['E360.Billing'] }, 'billing'), null);
  assert.equal(missingRole({ rolesEnforced: true, appRoles: [] }, 'portals'), null);
  assert.equal(missingRole(null, 'billing'), null);
});

test('view roles agree with the server route roles', () => {
  const server = Object.fromEntries(ROUTE_ROLES ?? []);
  if (!ROUTE_ROLES) return;
  assert.equal(VIEW_ROLES.billing, server['/api/billing']);
  assert.equal(VIEW_ROLES.signins, server['/api/signins']);
  assert.equal(VIEW_ROLES.health, server['/api/intune']);
  assert.equal(VIEW_ROLES.authz, server['/api/authz']);
});

test('denial for a PIM group role links activation and sign in again', () => {
  for (const [role, group] of Object.entries(ROLE_GROUPS)) {
    const html = deniedHtml(role);
    assert.match(html, /You don't have access to this page/);
    assert.ok(html.includes(role) && html.includes(group));
    assert.ok(html.includes(`href="${PIM_GROUPS_URL}"`));
    assert.match(html, /<button type="button" class="btn" data-go="my-pim">Activate in PIM \(groups\)<\/button>/);
    assert.match(html, /sign out and back in after activating/);
    assert.match(html, /data-denied-signin>Sign in again</);
  }
});

test('denial for a directly assigned role says ask your administrator', () => {
  const html = deniedHtml('E360.SignIns');
  assert.match(html, /Ask your administrator/);
  assert.ok(!html.includes(PIM_GROUPS_URL));
  assert.match(html, /Sign in again/);
});

test('denial markup uses only .btn and no em dashes', () => {
  for (const role of ['E360.Billing', 'E360.Admin', 'E360.Intune']) {
    const html = deniedHtml(role);
    assert.ok(!html.includes('\u2014'));
    for (const m of html.matchAll(/<(button|a)\b[^>]*>/g)) assert.match(m[0], /class="btn"/);
  }
  assert.ok(!deniedHtml('<x>').includes('<x>'));
});

test('authz time is compact UTC on one line, header actions hidden on authz', () => {
  assert.equal(fmtUtc('2026-10-30T04:59:21.123Z'), '2026-10-30 04:59:21Z');
  assert.equal(fmtUtc('nonsense'), 'nonsense');
  assert.equal(fmtUtc(undefined), '');
  assert.match(css, /td\.authz-time\{[^}]*white-space:nowrap/);
  assert.match(css, /td\.authz-time\{[^}]*min-width/);
  assert.match(css, /#main\.view-authz \.heading-actions[^{]*\{display:none\}/);
  assert.match(css, /\.nav-item\.nav-locked/);
});

test('browser: locked nav, friendly denial on lock and on 403, authz polish', async t => {
  const PORT = 3673, TENANT = '11111111-1111-1111-1111-111111111111';
  Object.assign(process.env, { DEMO_MODE: 'false', ENTRA_TENANT_ID: TENANT, ENTRA_CLIENT_ID: '22222222-2222-2222-2222-222222222222', ENTRA_CERT_THUMBPRINT: 'A'.repeat(40), ENTRA_CERT_PRIVATE_KEY_PATH: 'C:\\outside\\x.pem' });
  let chromium; try { ({ chromium } = await import('@playwright/test')); } catch { t.skip('playwright not installed'); return; }
  let browser; try { browser = await chromium.launch({ channel: 'msedge' }); } catch { try { browser = await chromium.launch(); } catch { t.skip('no browser available'); return; } }
  const { createApp } = await import('../server/index.mjs');
  let authRequest, roles = ['E360.Reader'];
  const account = { homeAccountId: `u.${TENANT}`, localAccountId: '33333333-3333-3333-3333-333333333333', tenantId: TENANT, username: 'aaron@example.test', name: 'Aaron' };
  const mock = { getAuthCodeUrl: async o => { authRequest = o; return `http://127.0.0.1:${PORT}/auth/callback?code=${'c'.repeat(20)}&state=${o.state}`; },
    acquireTokenByCode: async () => ({ account, idTokenClaims: { nonce: authRequest.nonce, roles }, accessToken: 'x' }),
    getTokenCache: () => ({ serialize: () => '{}', deserialize() {} }), acquireTokenSilent: async () => ({ accessToken: 'x', account }) };
  const server = createApp({ port: PORT, confidential: true, enforceRoles: true, demoMode: false, createConfidential: () => mock, certificate: () => ({ thumbprint: 'A'.repeat(40), privateKey: 'test' }),
    apiFetcher: async () => new Response(JSON.stringify({ value: [], id: account.localAccountId, displayName: 'Aaron', userPrincipalName: account.username, accountEnabled: true }), { status: 200, headers: { 'content-type': 'application/json' } }) }).listen(PORT, '127.0.0.1');
  await new Promise(r => server.once('listening', r));
  const open = async () => { const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 } }); const page = await ctx.newPage(); const errors = []; page.on('pageerror', e => errors.push(e.message)); await page.goto(`http://127.0.0.1:${PORT}/`); await page.waitForFunction(() => document.querySelector('#mode-badge')?.textContent.includes('LIVE'), null, { timeout: 15000 }); return { ctx, page, errors }; };
  try {
    // Reader only: Billing and Sign-ins are locked but clickable; Authorization log stays hidden.
    roles = ['E360.Reader'];
    { const { ctx, page, errors } = await open();
      assert.equal(await page.isHidden('#navigation [data-view="authz"]'), true);
      assert.match(await page.getAttribute('#navigation [data-view="billing"]', 'class'), /nav-locked/);
      assert.doesNotMatch(await page.getAttribute('#navigation [data-view="portals"]', 'class'), /nav-locked/);
      await page.click('#navigation [data-view="billing"]');
      await page.waitForSelector('#denied-panel:not([hidden]) .denied-card');
      const text = await page.textContent('#denied-panel');
      assert.match(text, /You don't have access to this page/); assert.match(text, /E360\.Billing/); assert.match(text, /sg-e360-billing/);
      assert.equal(await page.getAttribute('#denied-panel a.btn', 'href'), PIM_GROUPS_URL);
      assert.equal(await page.isHidden('#billing-panel'), true);
      assert.equal(await page.isHidden('.heading-actions'), true);
      await page.click('#navigation [data-view="signins"]');
      assert.match(await page.textContent('#denied-panel'), /Ask your administrator/);
      await page.click('#navigation [data-view="portals"]');
      assert.equal(await page.isHidden('#denied-panel'), true);
      assert.equal(await page.isVisible('#portals-panel'), true);
      assert.deepEqual(errors, []); await ctx.close(); }
    // No app role at all (sg-e360-reader inactive): My PIM still renders the table with Activate, without the My account toolbar,
    // and the Reader denial's Activate button opens My PIM in-app.
    roles = [];
    { const { ctx, page, errors } = await open();
      await page.route('**/api/me/pim', route => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ rows: [{ type: 'Group', name: 'sg-e360-reader', scope: 'g', scopeLabel: 'Group member', state: 'Eligible', start: '2026-10-01T00:00:00Z', end: null, action: 'activate', key: 'group|g|member', target: { groupId: '44444444-4444-4444-4444-444444444444', accessId: 'member' } }], problems: [], notes: [] }) }));
      await page.click('#navigation [data-view="my-summary"]');
      await page.waitForSelector('#denied-panel:not([hidden]) .denied-card');
      await page.click('#denied-panel [data-go="my-pim"]');
      await page.waitForSelector('#my-pim [data-pim-action="activate"]', { timeout: 10000 });
      assert.match(await page.textContent('#my-pim'), /sg-e360-reader/);
      assert.equal(await page.isHidden('#denied-panel'), true);
      assert.equal(await page.isHidden('#account-panel > .account-controls'), true);
      assert.equal(await page.isHidden('#account-run'), true);
      assert.deepEqual(errors, []); await ctx.close(); }
    // Admin: authz polish, then a server 403 with requiredRole renders the denial in-page.
    roles = ['E360.Reader', 'E360.Admin'];
    { const { ctx, page } = await open();
      let deny = false;
      await page.route('**/api/authz/log', route => deny ? route.fulfill({ status: 403, contentType: 'application/json', body: JSON.stringify({ error: 'Your Entity 360 roles do not include this feature.', requiredRole: 'E360.Admin' }) })
        : route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ enforced: true, rows: [{ time: '2026-10-30T04:59:21.123Z', user: 'aaron@example.test', path: '/api/billing', role: 'E360.Billing', outcome: 'denied' }] }) }));
      await page.click('#navigation [data-view="authz"]');
      await page.waitForSelector('#authz-panel td.authz-time');
      assert.equal(await page.textContent('#authz-panel td.authz-time'), '2026-10-30 04:59:21Z');
      assert.equal(await page.$eval('#authz-panel td.authz-time', el => getComputedStyle(el).whiteSpace), 'nowrap');
      assert.equal(await page.isHidden('#header-export'), true); assert.equal(await page.isHidden('#refresh-button'), true);
      assert.equal(await page.isVisible('#authz-export'), true);
      await page.click('#navigation [data-view="portals"]');
      assert.equal(await page.isVisible('#header-export'), true);
      deny = true;
      await page.click('#navigation [data-view="authz"]');
      await page.click('#authz-refresh').catch(() => {});
      await page.waitForSelector('#denied-panel:not([hidden]) .denied-card', { timeout: 10000 });
      const text = await page.textContent('#denied-panel');
      assert.match(text, /E360\.Admin/); assert.match(text, /sg-e360-admin/);
      await ctx.close(); }
  } finally { await browser.close(); server.close(); }
});