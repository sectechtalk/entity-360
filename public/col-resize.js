// User-resizable columns for EVERY table with a header row, app-wide (all of them sit in scroll containers).
export const TABLE_SELECTOR = 'table:has(> thead th)';
// Drag the handle on a header's right edge; widths persist per table in localStorage; double-click a handle resets the table.
export const MIN_COL_WIDTH = 48;
export const storageKey = id => `e360-colw:${id}`;
export const clampWidth = w => Math.max(MIN_COL_WIDTH, Math.round(Number(w) || 0));
export function tableId(table) {
  if (table.dataset.tableId) return table.dataset.tableId;
  const body = table.querySelector('tbody[id]'); if (body) return body.id;
  const host = table.closest('[id]'); return `${host ? host.id : 'page'}:${[...table.querySelectorAll('thead th')].map(th => th.textContent.trim()).join('|')}`;
}
export function loadWidths(storage, id, count) {
  try { const v = JSON.parse(storage.getItem(storageKey(id)) || 'null'); return Array.isArray(v) && v.length === count && v.every(n => Number.isFinite(n)) ? v.map(clampWidth) : null; } catch { return null; }
}
export function saveWidths(storage, id, widths) { try { storage.setItem(storageKey(id), JSON.stringify(widths.map(clampWidth))); } catch { /* storage blocked */ } }
export function clearWidths(storage, id) { try { storage.removeItem(storageKey(id)); } catch { /* ignore */ } }
const headers = table => [...table.querySelectorAll('thead tr:last-child th')];
export function applyWidths(table, widths) {
  const ths = headers(table);
  if (!widths) { table.classList.remove('cols-sized'); table.style.removeProperty('width'); ths.forEach(th => { th.style.width = ''; }); return; }
  table.classList.add('cols-sized');
  ths.forEach((th, i) => { th.style.width = `${widths[i]}px`; });
  table.style.setProperty('width', `${widths.reduce((a, b) => a + b, 0)}px`, 'important');
}
export function enhanceTable(table, storage) {
  const ths = headers(table); if (!ths.length) return;
  const id = tableId(table);
  table.dataset.resizeReady = '1';
  applyWidths(table, loadWidths(storage, id, ths.length));
  ths.forEach((th, i) => {
    if (th.querySelector('.col-resizer')) return;
    const h = table.ownerDocument.createElement('span');
    h.className = 'col-resizer'; h.setAttribute('role', 'separator'); h.setAttribute('aria-orientation', 'vertical'); h.title = 'Drag to resize · double-click to reset';
    if (table.ownerDocument.defaultView?.getComputedStyle?.(th).position === 'static') th.style.position = 'relative';
    th.appendChild(h);
    h.addEventListener('click', e => e.stopPropagation());
    h.addEventListener('dblclick', e => { e.preventDefault(); e.stopPropagation(); clearWidths(storage, id); applyWidths(table, null); });
    h.addEventListener('pointerdown', e => {
      e.preventDefault(); e.stopPropagation();
      const start = headers(table).map(x => x.getBoundingClientRect().width), x0 = e.clientX;
      applyWidths(table, start.map(clampWidth));
      h.setPointerCapture?.(e.pointerId); table.classList.add('col-resizing');
      let widths = start.map(clampWidth);
      const move = ev => { widths = start.map(clampWidth); widths[i] = clampWidth(start[i] + ev.clientX - x0); applyWidths(table, widths); };
      const up = () => { h.removeEventListener('pointermove', move); h.removeEventListener('pointerup', up); h.removeEventListener('pointercancel', up); table.classList.remove('col-resizing'); saveWidths(storage, id, widths); };
      h.addEventListener('pointermove', move); h.addEventListener('pointerup', up); h.addEventListener('pointercancel', up);
    });
  });
}
export function installColumnResize(doc, storage) {
  const scan = () => doc.querySelectorAll(TABLE_SELECTOR).forEach(t => { if (!t.dataset.resizeReady || !t.querySelector('.col-resizer')) enhanceTable(t, storage); });
  scan();
  let queued = false;
  new doc.defaultView.MutationObserver(() => { if (queued) return; queued = true; doc.defaultView.requestAnimationFrame(() => { queued = false; scan(); }); }).observe(doc.body, { childList: true, subtree: true });
}
