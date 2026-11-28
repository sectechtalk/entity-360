// App-wide button feedback, installed once for the whole app so every button gets it, including ones added later.
//
// 1. Pressed: the pressed look comes from CSS :active; actions fire only on the native 'click' event, which the browser
//    raises only when the press and the release are both on the button. On every click the control briefly gets
//    .btn-clicked so the click is visibly acknowledged even when the action itself is quiet.
// 2. Busy: any request (fetch) that a click starts is tied to the clicked control. While it runs, the control shows a
//    spinner, says what it is doing ("Searching…", "Running…", "Exporting…") and ignores further clicks. A control
//    the page replaces mid-request still has the top progress bar, which shows whenever any request is in flight.
//    A control can set its own wording with data-busy-label="Building PDF…", or opt out with data-busy="self" when
//    its code already manages a busy state itself.
// 3. Leaving: a click that navigates the page away (sign-in, links) keeps its control busy until the page changes.
// 4. Done: a purely local action (a file built in the browser, a copy to the clipboard) has no request to wait for,
//    so when it really happened its button briefly says "Exported ✓" or "Copied ✓".
// 5. Local work: a click that starts no request at all (a filter chip, a tab, "Use selected user", an export with
//    nothing to export) still shows its busy words and spinner for a moment, so no press ever looks ignored. A file
//    chosen through an "Import" label button says "Importing…" the same way. Controls whose result is the visible
//    change itself (section expanders, the theme switch) opt out with data-busy="none".

const CONTROLS = 'button, a.btn, a.nav-item, label.btn, [role="button"], [role="tab"]';
const CLAIM_MS = 1500;   // a request started this long after a click belongs to that click
const CHAIN_MS = 400;    // a follow-up request started this soon after the last one keeps the same control busy
const MIN_BUSY_MS = 450; // long enough to be seen even when the request is fast
const LOCAL_CHECK_MS = 250; // a local-only click that made a file or a copy by now says "Exported ✓" instead
const DONE_MS = 1400;

// [pattern on the button's own label, busy wording, done wording for local actions]
const VERBS = [
  [/pdf/i, 'Building PDF'],
  [/^(build|generate|create)\b/i, 'Building'],
  [/^look ?up\b/i, 'Looking up'],
  [/^(search|find)\b/i, 'Searching'],
  [/^(re-?)?run\b|^confirm run\b/i, 'Running'],
  [/^re-?check\b|^check\b.*\bagain$/i, 'Re-checking'],
  [/^check\b/i, 'Checking'],
  [/^export\b/i, 'Exporting', 'Exported'],
  [/^download\b/i, 'Downloading', 'Downloaded'],
  [/^copy\b/i, 'Copying', 'Copied'],
  [/^refresh\b/i, 'Refreshing'],
  [/^reload\b/i, 'Reloading'],
  [/^(load|show|more|next|previous|list)\b/i, 'Loading'],
  [/^sign in\b|^sign-in\b|^log ?in\b/i, 'Signing in'],
  [/^sign out\b|^log ?out\b/i, 'Signing out'],
  [/^(connect|microsoft connection)\b/i, 'Connecting'],
  [/^discover\b/i, 'Discovering'],
  [/^collect\b/i, 'Collecting'],
  [/^clear\b/i, 'Clearing'],
  [/^apply\b/i, 'Applying'],
  [/^save\b/i, 'Saving'],
  [/^record\b/i, 'Recording'],
  [/^(remove|delete)\b/i, 'Removing'],
  [/^deactivate\b/i, 'Deactivating'],
  [/^activate\b/i, 'Activating'],
  [/^request\b/i, 'Requesting'],
  [/^cancel\b/i, 'Cancelling'],
  [/^(use|switch|change)\b/i, 'Switching'],
  [/^investigate\b/i, 'Investigating'],
  [/^(open|view|see|evidence)\b/i, 'Opening'],
  [/^(import|upload)\b/i, 'Importing'],
  [/^test\b/i, 'Testing'],
  [/^send\b/i, 'Sending'],
  [/^(retry|try again)\b/i, 'Retrying'],
];

const labelOf = el => (el.getAttribute?.('aria-label') && !/[a-z]{2}/i.test(el.textContent || '') ? el.getAttribute('aria-label') : el.textContent || '').replace(/\s+/g, ' ').replace(/[↗→✓]/g, '').trim();
const verbFor = text => VERBS.find(([re]) => re.test(text));

// The words a control shows while its work runs, e.g. "Run report" -> "Running…".
export function busyLabel(el) {
  if (el?.dataset?.busyLabel) return el.dataset.busyLabel;
  const v = verbFor(labelOf(el || {}));
  return `${v ? v[1] : 'Working'}…`;
}
// The words a local-only action shows when it is done ("Exported ✓"), or '' when it has none.
export function doneLabel(el) {
  if (el?.dataset?.doneLabel) return el.dataset.doneLabel;
  const v = verbFor(labelOf(el || {}));
  return v?.[2] ? `${v[2]} ✓` : '';
}

const visibleText = el => {
  const out = []; const walk = n => { for (const c of n.childNodes) { if (c.nodeType === 3) { if (c.nodeValue.trim()) out.push(c); } else if (c.nodeType === 1 && !c.classList.contains('e360-spin') && c.getAttribute('aria-hidden') !== 'true') walk(c); } };
  walk(el); return out;
};
// Swaps the button's words for `label`; returns how to undo it, or null when the words should stay
// (icon-only buttons, buttons whose own code already says what it is doing, labels split over several nodes).
function swapLabel(el, label) {
  if (!el.classList.contains('btn') || !label) return null;
  const text = el.textContent.replace(/\s+/g, ' ').trim();
  if (!/[a-z]{2}/i.test(text) || /(…|\.\.\.)$/.test(text)) return null;
  const nodes = visibleText(el); if (nodes.length !== 1) return null;
  const node = nodes[0], old = node.nodeValue, width = el.style.minWidth;
  el.style.minWidth = `${Math.ceil(el.getBoundingClientRect().width)}px`;
  node.nodeValue = old.replace(old.trim(), label);
  return () => { if (node.isConnected && node.nodeValue.trim() === label) node.nodeValue = old; el.style.minWidth = width; };
}

export function installButtonFeedback(doc) {
  if (!doc || doc.__e360BtnFeedback) return; doc.__e360BtnFeedback = true;
  const win = doc.defaultView;
  const states = new Map(); // control -> { count, since, release, undo, ownAria, spin }
  let pressed = null, inflight = 0, barTimer = 0, bar = null, live = null;

  const ensureUi = () => {
    if (bar || !doc.body) return;
    bar = doc.createElement('div'); bar.className = 'e360-busy-bar'; bar.hidden = true; bar.setAttribute('aria-hidden', 'true');
    live = doc.createElement('div'); live.className = 'e360-busy-status'; live.setAttribute('role', 'status'); live.setAttribute('aria-live', 'polite');
    doc.body.append(bar, live);
  };
  const showBar = on => {
    ensureUi(); if (!bar) return;
    clearTimeout(barTimer);
    if (on) barTimer = setTimeout(() => { bar.hidden = false; }, 120);
    else { bar.hidden = true; if (live) live.textContent = ''; }
  };

  // Many pages re-render on click ("Searching…" state) before the request starts, which swaps the pressed button for an
  // identical new one. Find that new one by id, or by the same tag, class, words and data attributes in the same place.
  const dataKey = el => [...el.attributes].filter(a => a.name.startsWith('data-') && !a.name.startsWith('data-e360')).map(a => `${a.name}=${a.value}`).join('&');
  const signature = el => ({ id: el.id, tag: el.tagName, cls: el.className, text: labelOf(el), data: dataKey(el), anchor: el.parentElement?.closest('[id]')?.id || '' });
  const relocate = p => {
    if (p.el.isConnected) return p.el;
    const s = p.sig;
    if (s.id) { const n = doc.getElementById(s.id); return n && n.tagName === s.tag ? n : null; }
    const scope = (s.anchor && doc.getElementById(s.anchor)) || doc;
    const found = [...scope.querySelectorAll(s.tag)].filter(n => n.className.replace(/\s*btn-clicked/, '') === s.cls.replace(/\s*btn-clicked/, '') && labelOf(n) === s.text && dataKey(n) === s.data);
    return found.length === 1 ? found[0] : null;
  };
  const markBusy = (el, carry) => {
    const s = carry || { count: 0, since: Date.now(), release: 0, undo: null, ownAria: false, spin: null, visual: false, sig: signature(el) };
    s.el = el; s.undo = null; s.spin = null; s.visual = false; s.ownAria = false;
    states.set(el, s); watch();
    // Controls that run their own busy state (aria-busy already set, or data-busy="self") keep it; we only track them.
    if (el.dataset?.busy === 'self' || el.dataset?.busy === 'none' || el.hasAttribute('aria-busy')) return s;
    s.visual = true;
    const label = busyLabel(el);
    el.setAttribute('data-e360-busy', ''); el.setAttribute('aria-busy', 'true'); s.ownAria = true;
    s.undo = swapLabel(el, label);
    if (!el.classList.contains('btn')) { s.spin = doc.createElement('span'); s.spin.className = 'e360-spin'; s.spin.setAttribute('aria-hidden', 'true'); el.append(s.spin); }
    ensureUi(); if (live) live.textContent = label;
    return s;
  };
  // A page that re-renders while its request runs swaps the busy button for a new one: move the busy look across.
  let ticker = 0;
  const watch = () => { if (!ticker && win?.setInterval) ticker = win.setInterval(() => {
    if (!states.size) { win.clearInterval(ticker); ticker = 0; return; }
    for (const [el, s] of [...states]) {
      if (el.isConnected) continue;
      states.delete(el); s.el = null;
      const next = relocate({ el, sig: s.sig });
      if (next && !states.has(next)) markBusy(next, s);
    }
  }, 100); };
  const clearBusy = s => {
    clearTimeout(s.release);
    const el = s.el; if (!el || states.get(el) !== s) return;
    states.delete(el); s.el = null;
    if (!s.visual) return;
    el.removeAttribute('data-e360-busy');
    if (s.ownAria && el.getAttribute('aria-busy') === 'true') el.removeAttribute('aria-busy');
    s.undo?.(); s.spin?.remove();
  };

  // Which control a request that is starting now belongs to.
  const claim = () => {
    const now = Date.now();
    if (pressed && now - pressed.at <= CLAIM_MS) { const el = relocate(pressed); if (el) { pressed.el = el; pressed.used = true; return el; } }
    let last = null; for (const [el, st] of states) if (el.isConnected && !st.local) last = el; // a follow-up request of a busy control
    return last;
  };
  // begin returns the busy state the request belongs to (it follows the control across re-renders); end takes it back.
  const begin = el => {
    inflight++; showBar(true);
    if (!el) return null;
    const s = states.get(el) || markBusy(el); s.count++; s.local = false; clearTimeout(s.release); return s;
  };
  const end = s => {
    inflight = Math.max(0, inflight - 1); if (!inflight) showBar(false);
    if (!s) return;
    s.count = Math.max(0, s.count - 1);
    if (!s.count) { clearTimeout(s.release); s.release = setTimeout(() => clearBusy(s), Math.max(CHAIN_MS, MIN_BUSY_MS - (Date.now() - s.since))); }
  };

  if (typeof win?.fetch === 'function' && !win.fetch.__e360Busy) {
    const original = win.fetch.bind(win);
    const busyFetch = function (...args) {
      const owner = begin(claim());
      let p; try { p = original(...args); } catch (err) { end(owner); throw err; }
      return p.then(r => { end(owner); return r; }, err => { end(owner); throw err; });
    };
    busyFetch.__e360Busy = true; win.fetch = busyFetch;
  }

  // Local-only results: a file built in the browser (object URL) or text copied to the clipboard. The "done" words
  // show only when one of these really happened, so a click that ends in "Nothing to export yet" never says "Exported".
  let localDone = null;
  if (win?.URL?.createObjectURL && !win.URL.createObjectURL.__e360Busy) {
    const original = win.URL.createObjectURL.bind(win.URL);
    const wrapped = obj => { localDone = { kind: 'file', at: Date.now() }; return original(obj); };
    wrapped.__e360Busy = true; win.URL.createObjectURL = wrapped;
  }
  const clip = win?.navigator?.clipboard;
  if (clip?.writeText && !clip.writeText.__e360Busy) {
    const original = clip.writeText.bind(clip);
    const wrapped = text => original(text).then(r => { localDone = { kind: 'copy', at: Date.now() }; return r; });
    wrapped.__e360Busy = true; try { clip.writeText = wrapped; } catch { /* read-only clipboard object */ }
  }
  const flashDone = (el, since) => {
    if (!localDone || localDone.at < since || states.has(el) || !el.isConnected) return;
    const label = doneLabel(el) || (localDone.kind === 'copy' ? 'Copied ✓' : 'Exported ✓');
    const undo = swapLabel(el, label); if (undo) setTimeout(undo, DONE_MS);
  };

  doc.addEventListener('click', e => {
    const b = e.target?.closest?.(CONTROLS);
    if (!b) return;
    // A busy button ignores further presses (no double searches, double exports or double activations). Nav links and
    // tabs stay clickable: going back to a page that is still loading must always work.
    const held = states.get(b);
    if (held && held.local && !held.count) clearBusy(held); // only showing local work: a new press is a new action
    else if (b.hasAttribute('data-e360-busy') && !b.matches('a.nav-item, [role="tab"]')) { e.preventDefault(); e.stopImmediatePropagation(); return; }
    if (b.disabled || b.getAttribute('aria-disabled') === 'true') return;
    b.classList.add('btn-clicked'); setTimeout(() => b.classList.remove('btn-clicked'), 300);
    // A script's .click() on another button during a real press keeps the feedback on the button the person pressed.
    if (!e.isTrusted && pressed && Date.now() - pressed.at < 100) return;
    const p = pressed = { el: b, at: Date.now(), used: false, sig: signature(b) };
    // A link that downloads a file or opens a portal in a new tab finishes at once; say so on the button.
    if (b.matches('a.btn[download], a.btn[target="_blank"]')) {
      const undo = swapLabel(b, b.hasAttribute('download') ? 'Download started ✓' : 'Opened in new tab ↗'); if (undo) setTimeout(undo, DONE_MS); return;
    }
    // An Import label opens the file picker; it says "Importing…" once a file is chosen (see 'change' below).
    if (b.dataset.busy === 'none' || b.matches('.nav-label, summary, label.btn')) return;
    // After the page's own click handlers ran (so they read the button's real words): no request claimed it yet, so
    // show the busy look as local work. A request that starts later still claims it and keeps it busy until it ends.
    setTimeout(() => {
      if (p.used) return;
      const el = relocate(p); if (!el || states.has(el) || el.disabled) return;
      showLocal(el, p);
    }, 0);
  }, true);

  const showLocal = (el, p) => {
    const s = markBusy(el); s.local = true;
    const at = p ? p.at : Date.now();
    setTimeout(() => {
      // A file was built or text copied: say "Exported ✓" / "Copied ✓" now instead of the busy words.
      if (!s.count && states.get(s.el) === s && localDone && localDone.at >= at) { const node = s.el; clearBusy(s); flashDone(node, at); }
    }, LOCAL_CHECK_MS);
    s.release = setTimeout(() => { if (!s.count) clearBusy(s); }, MIN_BUSY_MS);
  };

  // A file chosen through an Import label button is read in the browser: say "Importing…" on that button, and tie any
  // upload that follows to it.
  doc.addEventListener('change', e => {
    const input = e.target; if (!input?.matches?.('input[type="file"]') || !input.files?.length) return;
    const b = input.closest('label.btn') || (input.id && doc.querySelector(`label.btn[for="${input.id}"]`)); if (!b || !b.isConnected) return;
    pressed = { el: b, at: Date.now(), used: false, sig: signature(b) };
    if (!states.has(b)) showLocal(b, pressed);
  }, true);

  // A click that leaves the page (sign-in redirect, full-page link) stays busy until the next page loads.
  win?.addEventListener?.('beforeunload', () => {
    if (pressed && pressed.el.isConnected && Date.now() - pressed.at <= CLAIM_MS && !states.has(pressed.el)) { markBusy(pressed.el); showBar(true); }
  });
  win?.addEventListener?.('pageshow', e => { if (e.persisted) { for (const st of [...states.values()]) clearBusy(st); showBar(false); } });
}
