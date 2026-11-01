// Every button in the app: a real <button> (or a.btn link) wired to a click (or its form's submit) handler,
// with a pressed and a busy/disabled look, and no action fired on mousedown or pointerdown (native click semantics:
// press and release both on the button).
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { ROLE_GROUPS } from '../public/access-denied.js';
import { startHarness } from './e360-browser-harness.mjs';
const dir = new URL('../public/', import.meta.url);
const files = readdirSync(dir).filter(f => /\.(html|js)$/.test(f)).map(f => [f, readFileSync(new URL(f, dir), 'utf8')]);
const css = readFileSync(new URL('styles.css', dir), 'utf8');

test('no action is triggered by mousedown, pointerdown, touchstart or their inline forms', () => {
  const bad = [];
  for (const [f, src] of files) for (const m of src.matchAll(/(addEventListener\(\s*['"](mousedown|pointerdown|touchstart|mouseup|pointerup|touchend)['"])|\bon(mousedown|pointerdown|touchstart|mouseup|pointerup)\b/g)) {
    // The column resize handle is a drag (pointerdown, move, up), not a button action.
    if (f === 'col-resize.js') continue;
    bad.push(`${f}: ${m[0]}`);
  }
  assert.deepEqual(bad, []);
  const cr = readFileSync(new URL('col-resize.js', dir), 'utf8');
  assert.ok(!/<button/.test(cr) && /h\.addEventListener\('pointerdown'/.test(cr), 'pointerdown only on the resize handle');
});

test('.btn has a pressed state, a busy state and a disabled state; app installs click feedback', () => {
  assert.match(css, /\.btn:active:not\(:disabled\)[^{]*\{[^}]*filter:brightness/);
  assert.match(css, /\.btn\[aria-busy="true"\]::before/);
  assert.match(css, /\.btn:disabled,\.btn\[disabled\]\{/);
  const app = readFileSync(new URL('app.js', dir), 'utf8');
  assert.match(app, /installButtonFeedback\(document\)/);
  const fb = readFileSync(new URL('btn-feedback.js', dir), 'utf8');
  assert.match(fb, /addEventListener\('click'/); assert.doesNotMatch(fb, /mousedown|pointerdown/);
});

// Lists listeners (CDP) on each visible button and its ancestors up to document, ignoring the app-wide feedback listener.
async function listenersAt(cdp, expr) {
  const { result } = await cdp.send('Runtime.evaluate', { expression: expr });
  if (!result.objectId) return null;
  const { listeners } = await cdp.send('DOMDebugger.getEventListeners', { objectId: result.objectId });
  return listeners.filter(l => !/btn-clicked/.test(l.handler?.description || ''));
}
async function audit(page, cdp) {
  const n = await page.evaluate(() => { window.__audit = [...document.querySelectorAll('button, a.btn')].filter(el => el.checkVisibility ? el.checkVisibility() : el.offsetParent); return window.__audit.length; });
  const out = [];
  for (let i = 0; i < n; i++) {
    const info = await page.evaluate(i => { const el = window.__audit[i]; return { html: el.outerHTML.slice(0, 160), submit: el.tagName === 'BUTTON' && el.type === 'submit' && Boolean(el.form), href: el.tagName === 'A' ? el.getAttribute('href') : null, onclick: typeof el.onclick === 'function', formSubmit: typeof el.form?.onsubmit === 'function' }; }, i);
    let click = info.onclick || Boolean(info.href) || info.formSubmit; const press = [];
    for (let depth = 0; depth < 60; depth++) {
      const expr = `(() => { let n = window.__audit[${i}]; for (let d = 0; d < ${depth} && n; d++) n = n.parentNode; return n; })()`;
      const ls = await listenersAt(cdp, expr); if (!ls) break;
      for (const l of ls) {
        if (l.type === 'click') click = true;
        if (l.type === 'submit' && info.submit) click = true;
        if (['mousedown', 'pointerdown', 'touchstart'].includes(l.type)) press.push(`${l.type}@${depth}`);
      }
    }
    out.push({ ...info, click, press });
  }
  return out;
}

test('browser: every visible button on every page has click wiring and no press-triggered handler', async t => {
  const h = await startHarness(t, { port: 3693, roles: Object.keys(ROLE_GROUPS) }); if (!h) return;
  try {
    const { ctx, page, errors } = await h.open();
    const cdp = await ctx.newCDPSession(page); await cdp.send('DOM.enable'); await cdp.send('Runtime.enable');
    const views = await page.$$eval('#navigation [data-view]', els => els.filter(e => !e.hidden && e.offsetParent).map(e => e.dataset.view));
    assert.ok(views.length > 5, `nav views found: ${views.length}`);
    const bad = [], seen = new Set(); let total = 0;
    for (const v of views) {
      await page.click(`#navigation [data-view="${v}"]`); await page.waitForTimeout(400);
      for (const b of await audit(page, cdp)) {
        const k = b.html; if (seen.has(k)) continue; seen.add(k); total++;
        if (!b.click) bad.push(`${v}: no click handler: ${b.html}`);
        if (b.press.length) bad.push(`${v}: press handler ${b.press.join(',')}: ${b.html}`);
      }
    }
    assert.ok(total > 20, `audited ${total} buttons`);
    assert.deepEqual(bad, []);
    assert.deepEqual(errors, []);
    await ctx.close();
  } finally { await h.close(); }
});
