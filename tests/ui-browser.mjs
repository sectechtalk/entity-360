// Browser smoke test for the UI v2 layout. Run against a server started with DEMO_MODE=true:
//   node tests/ui-browser.mjs http://localhost:4360
import { chromium } from '@playwright/test';
const base = process.argv[2] || 'http://localhost:4360';
const shots = process.argv[3] || '';
const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1400, height: 900 } });
const problems = [];
page.on('console', m => { if (m.type() === 'error') problems.push(`console: ${m.text()}`); });
page.on('pageerror', e => problems.push(`pageerror: ${e.message}`));
await page.goto(base);
await page.waitForSelector('#entity-search');
const views = ['summary', 'signins', 'access', 'devices', 'activity', 'health', 'my-summary', 'my-signins', 'my-access', 'my-device', 'licenses', 'billing', 'deployment', 'portals', 'defender'];
const styles = new Map(), report = {};
async function audit(view) {
  await page.mouse.move(1, 1);
  const r = await page.evaluate(() => [...document.querySelectorAll('.btn')].filter(b => b.offsetParent).map(b => { const s = getComputedStyle(b); return { id: b.id || b.textContent.trim().slice(0, 30), disabled: b.disabled === true, title: b.title, h: s.height, fs: s.fontSize, fw: s.fontWeight, pad: s.paddingLeft, bg: s.backgroundColor, color: s.color, cursor: s.cursor }; }));
  for (const b of r) {
    const key = `${b.h}|${b.fs}|${b.fw}|${b.pad}|${b.disabled ? 'off' : 'on'}|${b.bg}|${b.color}|${b.cursor}`;
    styles.set(key, (styles.get(key) || 0) + 1);
    if (b.disabled && (!b.title || b.cursor !== 'not-allowed')) problems.push(`${view}: disabled "${b.id}" lacks a title or not-allowed cursor`);
  }
  report[view] = { buttons: r.length, disabled: r.filter(b => b.disabled).map(b => `${b.id}: ${b.title}`) };
}
// Empty state first, before any user is picked.
await audit('summary (no user)');
report['empty reason'] = await page.textContent('#empty-reason');
await page.fill('#entity-search', 'Alex');
await page.waitForSelector('[data-search]');
await page.click('[data-search="0"]');
await page.waitForSelector('#summary-page:not([hidden])');
report.topbar = (await page.textContent('#current-entity')).replace(/\s+/g, ' ').trim();
for (const v of views) {
  await page.click(`#navigation [data-view="${v}"]`);
  await page.waitForTimeout(400);
  if (v === 'signins') { const row = await page.$('#signin-table-rows tr'); if (row) { await row.click(); await page.waitForSelector('#signin-drawer:not([hidden])'); report.drawer = (await page.textContent('#drawer-title')); } else problems.push('signins: no rows'); }
  if (v === 'access') for (const t of ['roles', 'groups', 'ca']) { await page.click(`.tab[data-tab="${t}"]`); report[`access-${t}`] = (await page.textContent('#access-tab-body h2')).replace(/\s+/g, ' '); }
  if (v === 'activity') { await page.click('#activity-load'); await page.waitForFunction(() => !document.querySelector('#activity-load').disabled); report['activity-status'] = await page.textContent('#activity-status'); }
  await audit(v);
  if (shots) await page.screenshot({ path: `${shots}/${v}.png`, fullPage: true });
}
// Summary links go to the filtered page.
await page.click('#navigation [data-view="summary"]');
const blocked = await page.$('[data-go="signins"][data-filter="Blocked"]:not([disabled])');
if (blocked) { await blocked.click(); report['summary->blocked filter'] = await page.inputValue('#signin-result-filter'); }
await browser.close();
const uniq = [...styles.keys()];
const on = uniq.filter(k => k.includes('|on|')), off = uniq.filter(k => k.includes('|off|'));
const hoverFree = s => s.split('|').slice(0, 4).join('|');
if (new Set(uniq.map(hoverFree)).size !== 1 || on.length > 1 || off.length > 1) problems.push(`button styles differ: ${uniq.join(' ; ')}`);
console.log(JSON.stringify({ report, enabledStyles: on, disabledStyles: off, problems }, null, 1));
process.exit(problems.length ? 1 : 0);
