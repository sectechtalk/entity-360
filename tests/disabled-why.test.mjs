// A disabled button says why to every user: the reason sits in a focusable "?" toggletip beside it (keyboard and touch)
// and in the button's aria-describedby (screen readers). Enabling the button removes the toggletip.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { readFileSync } from 'node:fs';

const pub = new URL('../public/', import.meta.url);

test('app.js installs the disabled-button explanations for the whole page', () => {
  const app = readFileSync(new URL('app.js', pub), 'utf8');
  assert.match(app, /import \{ installDisabledWhy \} from '\.\/disabled-why\.js';/);
  assert.match(app, /installDisabledWhy\(document\);/);
  assert.doesNotMatch(readFileSync(new URL('disabled-why.js', pub), 'utf8'), /innerHTML|insertAdjacentHTML/, 'no HTML strings (Trusted Types)');
});

test('browser: reason toggletip appears for disabled buttons, opens from the keyboard, and goes away when enabled', async t => {
  let chromium; try { ({ chromium } = await import('@playwright/test')); } catch { t.skip('playwright not installed'); return; }
  let browser; try { browser = await chromium.launch({ channel: 'msedge' }); } catch { try { browser = await chromium.launch(); } catch { t.skip('no browser available'); return; } }
  const page = `<!doctype html><link rel="stylesheet" href="/360-base.css"><link rel="stylesheet" href="/styles.css"><body>
    <div class="card-actions" id="a"><button type="button" class="btn" id="run" disabled title="Requires E360.SignIns role">Run query</button>
    <button type="button" class="btn" id="plain" disabled>Plain</button><button type="button" class="btn" id="ok">Fine</button></div>
    <script type="module">import { installDisabledWhy } from '/disabled-why.js'; installDisabledWhy(document); window.ready = true;</script></body>`;
  const server = createServer(async (req, res) => {
    if (req.url === '/') { res.setHeader('content-type', 'text/html'); return res.end(page); }
    try { const body = await readFile(new URL(req.url.slice(1), pub)); res.setHeader('content-type', req.url.endsWith('.js') ? 'text/javascript' : req.url.endsWith('.css') ? 'text/css' : 'application/octet-stream'); res.end(body); }
    catch { res.statusCode = 404; res.end(); }
  }).listen(0, '127.0.0.1');
  await new Promise(r => server.once('listening', r));
  t.after(async () => { await browser.close(); await new Promise(r => server.close(r)); });
  const p = await browser.newPage(); const errors = []; p.on('pageerror', e => errors.push(e.message));
  await p.goto(`http://127.0.0.1:${server.address().port}/`); await p.waitForFunction(() => window.ready);

  const tip = p.locator('#run + .why-tip');
  assert.equal(await tip.count(), 1, 'a reasoned disabled button gets a toggletip');
  assert.equal(await tip.getAttribute('aria-label'), 'Why is Run query unavailable?');
  const id = await tip.getAttribute('popovertarget');
  assert.equal(await p.locator('#run').getAttribute('aria-describedby'), id);
  assert.equal(await p.locator(`#${id}`).textContent(), 'Requires E360.SignIns role');
  assert.equal(await p.locator('#plain + .why-tip').count(), 0, 'no reason, no toggletip');
  assert.equal(await p.locator('#ok + .why-tip').count(), 0);

  // Keyboard: the disabled button is skipped, the toggletip takes focus, Enter shows the reason, Escape hides it.
  await p.keyboard.press('Tab');
  assert.equal(await p.evaluate(() => document.activeElement.className), 'tip why-tip');
  await p.keyboard.press('Enter');
  assert.equal(await p.locator(`#${id}`).evaluate(el => el.matches(':popover-open')), true);
  await p.keyboard.press('Escape');
  assert.equal(await p.locator(`#${id}`).evaluate(el => el.matches(':popover-open')), false);

  // A new reason updates the text; enabling removes the toggletip and the description; later renders get one too.
  await p.evaluate(() => { document.getElementById('run').title = 'Sign in first'; });
  await p.waitForFunction(i => document.getElementById(i)?.textContent === 'Sign in first', id);
  await p.evaluate(() => { const b = document.getElementById('run'); b.disabled = false; b.removeAttribute('title'); });
  await p.waitForFunction(() => !document.querySelector('.why-tip'));
  assert.equal(await p.locator('#run').getAttribute('aria-describedby'), null);
  assert.equal(await p.locator('.tip-text').count(), 0);
  await p.evaluate(() => { document.getElementById('a').insertAdjacentHTML('beforeend', '<button type="button" class="btn" id="late" disabled title="Pick a user first">Load</button>'); });
  await p.waitForSelector('#late + .why-tip');
  assert.deepEqual(errors, []);
});
