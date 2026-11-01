// Shared live-mode browser harness for tests: real server (mocked MSAL and Graph), msedge or bundled Chromium.
export async function startHarness(t, { port, roles = ['E360.Reader'] }) {
  const TENANT = '11111111-1111-1111-1111-111111111111';
  Object.assign(process.env, { DEMO_MODE: 'false', ENTRA_TENANT_ID: TENANT, ENTRA_CLIENT_ID: '22222222-2222-2222-2222-222222222222', ENTRA_CERT_THUMBPRINT: 'A'.repeat(40), ENTRA_CERT_PRIVATE_KEY_PATH: 'C:\\outside\\x.pem' });
  let chromium; try { ({ chromium } = await import('@playwright/test')); } catch { t.skip('playwright not installed'); return null; }
  let browser; try { browser = await chromium.launch({ channel: 'msedge' }); } catch { try { browser = await chromium.launch(); } catch { t.skip('no browser available'); return null; } }
  const { createApp } = await import('../server/index.mjs');
  const h = { roles, browser };
  let authRequest;
  const account = { homeAccountId: `u.${TENANT}`, localAccountId: '33333333-3333-3333-3333-333333333333', tenantId: TENANT, username: 'aaron@example.test', name: 'Aaron' };
  const mock = { getAuthCodeUrl: async o => { authRequest = o; return `http://127.0.0.1:${port}/auth/callback?code=${'c'.repeat(20)}&state=${o.state}`; },
    acquireTokenByCode: async () => ({ account, idTokenClaims: { nonce: authRequest.nonce, roles: h.roles }, accessToken: 'x' }),
    getTokenCache: () => ({ serialize: () => '{}', deserialize() {} }), acquireTokenSilent: async () => ({ accessToken: 'x', account }) };
  const server = createApp({ port, confidential: true, enforceRoles: true, demoMode: false, createConfidential: () => mock, certificate: () => ({ thumbprint: 'A'.repeat(40), privateKey: 'test' }),
    apiFetcher: async () => new Response(JSON.stringify({ value: [], id: account.localAccountId, displayName: 'Aaron', userPrincipalName: account.username, accountEnabled: true }), { status: 200, headers: { 'content-type': 'application/json' } }) }).listen(port, '127.0.0.1');
  await new Promise(r => server.once('listening', r));
  h.open = async ({ before } = {}) => {
    const ctx = await browser.newContext({ viewport: { width: 1280, height: 800 } }); const page = await ctx.newPage(); const errors = [];
    page.on('pageerror', e => errors.push(e.message));
    if (before) await before(page);
    await page.goto(`http://127.0.0.1:${port}/`);
    await page.waitForFunction(() => document.querySelector('#mode-badge')?.textContent.includes('LIVE'), null, { timeout: 15000 });
    return { ctx, page, errors };
  };
  h.close = async () => { await browser.close(); await new Promise(r => server.close(r)); };
  return h;
}
