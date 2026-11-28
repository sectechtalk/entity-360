// Toggletip: a "?" button that shows a short explanation on click, tap or Enter (Modern Web Guidance:
// interest-triggered-tooltips, "Toggletips"). Replaces title="" tooltips, which keyboard and touch users never see.
// Uses the declarative Popover API, so it needs no script and works under the strict CSP.
let next = 0;
const escText = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
export function tipHtml(label, text, esc = escText) {
  const id = `tip-${++next}`;
  return `<button type="button" class="tip" popovertarget="${id}" aria-label="More about ${esc(label)}">?</button><span id="${id}" class="tip-text" popover role="tooltip">${esc(text)}</span>`;
}
