import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, stat } from 'node:fs/promises';
const r = f => readFile(new URL('../public/' + f, import.meta.url), 'utf8');

test('summary lists the sources used instead of a count', async () => {
  const app = await r('app.js'), html = await r('index.html');
  assert.match(app, /The following sources were used - /);
  assert.doesNotMatch(app, /sources checked/);
  assert.match(app, /#coverage-sources'\)\.innerHTML = r\.sources\.map\(s => `<li>\$\{esc\(s\.name\)\}<\/li>`\)/);
  assert.match(html, /<ul id="coverage-sources"/);
});

test('connection panel: signed-in note in its own card above the tenant boundary; button gaps', async () => {
  const app = await r('app.js'), css = await r('styles.css');
  assert.match(app, /<div class="connection-box connection-signed"><p class="connection-note">/);
  assert.match(app, /firstElementChild\.insertAdjacentHTML\('afterend', `<div class="connection-box"><h3>Account and tenant boundary/);
  assert.match(app, /<div class="conn-actions">\$\{s\.configured \? '<button id="microsoft-login"/);
  assert.match(css, /\.conn-actions\{display:flex;flex-wrap:wrap;gap:12px 12px/);
  assert.match(css, /#switch-connection\{margin-top:14px!important\}/);
  assert.match(css, /\.connection-box label>input,\.connection-box label>select\{display:block;margin-top:8px\}/);
  assert.match(css, /#error-lookup-link\{margin-top:12px!important\}/);
});

test('four tables use self-hosted Inter at 9pt; CSP allows it', async () => {
  const css = await r('styles.css');
  assert.match(css, /@font-face\{font-family:Inter;[^}]*url\(\/fonts\/InterVariable\.woff2\)/);
  for (const id of ['signins-page', 'access-page', 'activity-page', 'my-device']) assert.match(css, new RegExp(`#${id} table td\\{?[^}]*?font-family:Inter,system-ui,sans-serif!important;font-size:9pt!important|#${id} table,`));
  assert.ok((await stat(new URL('../public/fonts/InterVariable.woff2', import.meta.url))).size > 100000);
  const idx = await readFile(new URL('../server/index.mjs', import.meta.url), 'utf8');
  assert.match(idx, /default-src 'self'/); assert.doesNotMatch(idx, /font-src/);
});

test('device explanations match the Graph endpoints in the server code', async () => {
  const html = await r('index.html'), acct = await r('account.js');
  const live = await readFile(new URL('../server/live.mjs', import.meta.url), 'utf8');
  const sacct = await readFile(new URL('../server/account.mjs', import.meta.url), 'utf8');
  assert.match(live, /\/v1\.0\/users\/\$\{id\}\/managedDevices/); assert.match(html, /id="devices-explain"[^>]*>[^<]*\/users\/\{id\}\/managedDevices/);
  assert.match(sacct, /\/v1\.0\/me\/registeredDevices/); assert.match(acct, /From Microsoft Graph \/me\/registeredDevices/);
  assert.match(sacct, /\/v1\.0\/me\/managedDevices/); assert.match(acct, /From Microsoft Graph \/me\/managedDevices/);
});
