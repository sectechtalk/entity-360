import { chromium } from '@playwright/test';
import assert from 'node:assert/strict';
const browser = await chromium.launch({ channel: 'msedge', headless: true });
try {
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } }); const errors = [];
  page.on('pageerror', e => errors.push(e.message)); await page.goto('http://localhost:3600');
  const order = await page.locator('#navigation [data-view]').evaluateAll(es => es.map(e => e.dataset.view));
  assert.equal(order[order.indexOf('coverage') + 1], 'licenses'); assert.equal(order[order.indexOf('licenses') + 1], 'billing');
  await page.locator('[data-view="licenses"]').click();
  await page.locator('#license-discover').click();
  await page.locator('#license-discovery').filter({ hasText: 'Fictional tenant discovery' }).waitFor();
  await page.locator('#license-run').click();
  await page.locator('#license-results').filter({ hasText: 'Cross-tenant coverage' }).waitFor();
  assert.match(await page.locator('#license-results').innerText(), /Global completeness: not established/);
  await page.locator('[data-view="billing"]').click(); await page.locator('#billing-run').click();
  await page.locator('#billing-status').filter({ hasText: 'Billing queries completed' }).waitFor();
  assert.match(await page.locator('#billing-results').innerText(), /42.5/);
  assert.match(await page.locator('#billing-results').innerText(), /Invoice summaries/);
  await page.screenshot({ path: '.runtime/billing-desktop.png', fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 }); assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
  await page.screenshot({ path: '.runtime/billing-mobile.png', fullPage: true });
  await page.locator('#billing-connect').click(); await page.locator('#demo-profile').selectOption('reader'); await page.locator('#demo-button').click();
  await page.locator('[data-view="billing"]').click(); await page.locator('#billing-run').click();
  await page.locator('#billing-status').filter({ hasText: 'Partial billing evidence' }).waitFor();
  assert.ok(!(await page.locator('#billing-results').innerText()).includes('DEMO-INV-001'));
  assert.equal(await page.locator('#source-links a').count(), 0);
  assert.deepEqual(errors, []); console.log('PASS: navigation placement, tenant discovery, all-context license coverage, billing scopes, restricted visibility, context clearing and mobile layout.');
} finally { await browser.close(); }
