// Why is this button greyed out? (Modern Web Guidance: disabled controls must still explain themselves.)
// A disabled button element cannot take focus, so its title="" tooltip never reaches keyboard or touch users. Next to every
// disabled .btn that carries a reason, this adds a "?" toggletip (focusable; opens on click, tap or Enter, like tip.js)
// with the same text, and points the button's aria-describedby at it so screen readers read the reason as well.
// Enabling the button, or clearing its reason, removes the toggletip. No HTML strings: safe under Trusted Types.
export const GENERIC_REASON = 'Not available right now';
let next = 0;

export function syncWhy(btn) {
  if (btn?.tagName !== 'BUTTON' || !btn.classList.contains('btn')) return;
  const doc = btn.ownerDocument;
  const sib = btn.nextElementSibling;
  let tip = sib?.classList.contains('why-tip') ? sib : null;
  const reason = btn.disabled ? (btn.getAttribute('title') || '').trim() : '';
  if (!reason || reason === GENERIC_REASON) {
    if (tip) { doc.getElementById(tip.getAttribute('popovertarget'))?.remove(); tip.remove(); }
    if (btn.dataset.whyId) { btn.removeAttribute('aria-describedby'); delete btn.dataset.whyId; }
    return;
  }
  if (!tip) {
    const id = `why-${++next}`;
    tip = doc.createElement('button');
    tip.type = 'button'; tip.className = 'tip why-tip'; tip.textContent = '?';
    tip.setAttribute('popovertarget', id);
    const text = doc.createElement('span');
    text.id = id; text.className = 'tip-text'; text.setAttribute('popover', ''); text.setAttribute('role', 'tooltip');
    btn.after(tip, text);
    btn.dataset.whyId = id;
    btn.setAttribute('aria-describedby', id);
  }
  const label = (btn.textContent || '').trim() || 'this button';
  const aria = `Why is ${label} unavailable?`;
  if (tip.getAttribute('aria-label') !== aria) tip.setAttribute('aria-label', aria);
  const text = doc.getElementById(tip.getAttribute('popovertarget'));
  if (text && text.textContent !== reason) text.textContent = reason;
}

export function syncWhyAll(root) { root.querySelectorAll?.('button.btn').forEach(syncWhy); }

// Watches the whole page: buttons rendered later, and buttons that become disabled, enabled or get a new reason.
export function installDisabledWhy(doc) {
  if (!doc?.body || doc.__e360Why) return;
  doc.__e360Why = true;
  syncWhyAll(doc);
  new doc.defaultView.MutationObserver(records => {
    for (const r of records) {
      if (r.type === 'attributes') { syncWhy(r.target); continue; }
      for (const n of r.addedNodes) if (n.nodeType === 1) { syncWhy(n); syncWhyAll(n); }
    }
  }).observe(doc.body, { subtree: true, childList: true, attributes: true, attributeFilter: ['disabled', 'title'] });
}
