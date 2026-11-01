// App-wide button feedback. The pressed look comes from CSS :active; actions fire only on the native 'click' event,
// which the browser raises only when the press and the release are both on the button. On every click the button
// briefly gets .btn-clicked so the click is visibly acknowledged even when the action itself is quiet.
export function installButtonFeedback(doc) {
  if (!doc || doc.__e360BtnFeedback) return; doc.__e360BtnFeedback = true;
  doc.addEventListener('click', e => {
    const b = e.target?.closest?.('button, a.btn');
    if (!b || b.disabled || b.getAttribute('aria-disabled') === 'true') return;
    b.classList.add('btn-clicked'); setTimeout(() => b.classList.remove('btn-clicked'), 250);
  }, true);
}
