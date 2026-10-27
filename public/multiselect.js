// Reusable multi-select checkbox filter. Native <details>/<summary>, no inline handlers (CSP safe).
// State per filter is the set of UNCHECKED values, so the default is everything checked and new values arrive checked.
// Rows match when every column passes (AND); a column passes when the row value is any checked value (OR).

export function filterOptions(known = [], values = []) {
  const out = [];
  for (const v of [...known, ...values]) { const s = v == null || v === '' ? 'n/a' : String(v); if (!out.includes(s)) out.push(s); }
  return out;
}
const norm = v => (v == null || v === '' ? 'n/a' : String(v));
// value may be a single value or an array (a row that belongs to several values passes if any is checked).
export function passes(value, excluded) {
  if (!excluded || !excluded.size) return true;
  const vals = Array.isArray(value) ? value.map(norm) : [norm(value)];
  return vals.some(v => !excluded.has(v));
}
// sort: { key, dir: 'asc'|'desc' } names one filter column; the table is ordered by that column's value (col.sortValue if given).
export function applyFilters(rows, columns, excludedByKey, sort = null) {
  return sortRows(rows.filter(row => columns.every(c => passes(c.get(row), excludedByKey[c.key]))), columns, sort);
}
const collator = new Intl.Collator(undefined, { numeric: true, sensitivity: 'base' });
const sortKey = v => (Array.isArray(v) ? v.map(norm).sort(collator.compare)[0] : v == null || v === '' ? 'n/a' : v);
export function compareValues(a, b) {
  const x = sortKey(a), y = sortKey(b);
  if (x === y) return 0;
  if (x === 'n/a') return 1; if (y === 'n/a') return -1; // missing values last in both directions
  if (typeof x === 'number' && typeof y === 'number') return x - y;
  return collator.compare(String(x), String(y));
}
export function sortRows(rows, columns, sort) {
  const col = sort && columns.find(c => c.key === sort.key);
  if (!col) return rows;
  const get = col.sortValue || col.get, sign = sort.dir === 'desc' ? -1 : 1;
  return rows.map((r, i) => [r, i]).sort(([a, i], [b, j]) => { const x = sortKey(get(a)), y = sortKey(get(b)); if (x === 'n/a' && y !== 'n/a') return 1; if (y === 'n/a' && x !== 'n/a') return -1; return sign * compareValues(x, y) || i - j; }).map(([r]) => r);
}
// Option labels shown A to Z; 'n/a' / 'Not stated' last.
export function sortOptions(opts) {
  return [...opts].sort((a, b) => (a.value === 'n/a') - (b.value === 'n/a') || collator.compare(a.label, b.label));
}
export const sortArrow = dir => (dir === 'desc' ? '▼' : '▲');
// Duration buckets for remaining time (ms). Permanent and n/a are handled by the caller's flags.
export const REMAINING_BUCKETS = ['Permanent', 'Expired', '<1h', '1-8h', '>8h', 'n/a'];
export function remainingBucket(ms, permanent) {
  if (permanent) return 'Permanent';
  if (!Number.isFinite(ms)) return 'n/a';
  if (ms <= 0) return 'Expired';
  const h = ms / 3600000;
  return h < 1 ? '<1h' : h <= 8 ? '1-8h' : '>8h';
}
// Granted is a point in time, so its bucket is the age of the grant.
export const GRANTED_BUCKETS = ['<1h', '1-8h', '8-24h', '1-7d', '7-30d', '>30d', 'n/a'];
export function grantedBucket(iso, now = Date.now()) {
  const t = Date.parse(iso || '');
  if (!Number.isFinite(t)) return 'n/a';
  const h = Math.max(0, now - t) / 3600000;
  return h < 1 ? '<1h' : h <= 8 ? '1-8h' : h <= 24 ? '8-24h' : h <= 168 ? '1-7d' : h <= 720 ? '7-30d' : '>30d';
}

const escape = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
// options: [{ value, label? }] or strings. open: keep open across re-render.
export function multiSelectHtml({ key, label, options, excluded, open = false, sort = null, header = label }) {
  const opts = sortOptions(options.map(o => (typeof o === 'string' ? { value: o, label: o } : { label: o.value, ...o })));
  const checked = opts.filter(o => !excluded?.has(o.value)).length;
  const dir = sort?.key === key ? sort.dir : null;
  const sortBtn = (d, text) => `<button type="button" class="btn" data-msel-sort="${d}" aria-pressed="${dir === d}">${text}</button>`;
  return `<details class="msel" data-msel="${escape(key)}" data-msel-header="${escape(header)}"${dir ? ` data-msel-sorted="${dir}"` : ''}${open ? ' open' : ''}><summary class="btn msel-trigger" aria-label="${escape(label)} filter">${escape(label)} (${checked} of ${opts.length})${dir ? ` ${sortArrow(dir)}` : ''}</summary><div class="msel-menu" role="group" aria-label="${escape(label)}"><div class="msel-actions msel-sort">${sortBtn('asc', 'Sort A→Z')}${sortBtn('desc', 'Sort Z→A')}</div><div class="msel-actions"><button type="button" class="btn" data-msel-all>Select all</button><button type="button" class="btn" data-msel-none>Clear</button></div>${opts.map(o => `<label class="msel-option"><input type="checkbox" value="${escape(o.value)}"${excluded?.has(o.value) ? '' : ' checked'}> ${escape(o.label)}</label>`).join('')}</div></details>`;
}
// Marks the sorted column header (aria-sort plus an arrow) in the table that belongs to these filters.
export function markSortedHeader(root) {
  const scope = root.closest('.panel, section, .page, .my-page') || root.ownerDocument;
  scope.querySelectorAll('th[aria-sort]').forEach(th => { th.removeAttribute('aria-sort'); th.querySelector('.sort-mark')?.remove(); });
  const d = root.querySelector('[data-msel-sorted]'); if (!d) return null;
  const want = d.dataset.mselHeader.toLowerCase();
  const th = [...scope.querySelectorAll('thead th')].find(h => h.textContent.trim().toLowerCase().startsWith(want));
  if (!th) return null;
  th.setAttribute('aria-sort', d.dataset.mselSorted === 'desc' ? 'descending' : 'ascending');
  th.insertAdjacentHTML('beforeend', `<span class="sort-mark"> ${sortArrow(d.dataset.mselSorted)}</span>`);
  return th;
}
// Wires every [data-msel] under root. store: { excluded: {key:Set}, open: key|null }. onChange re-renders.
export function wireMultiSelects(root, store, onChange) {
  root.querySelectorAll('[data-msel]').forEach(d => {
    const key = d.dataset.msel;
    const values = () => [...d.querySelectorAll('input[type=checkbox]')].map(i => i.value);
    const commit = set => { store.excluded[key] = set; store.open = key; onChange(key); };
    d.addEventListener('toggle', () => { if (d.open) { store.open = key; root.ownerDocument.querySelectorAll('[data-msel][open]').forEach(o => { if (o !== d) o.open = false; }); } else if (store.open === key) store.open = null; });
    d.querySelectorAll('input[type=checkbox]').forEach(i => i.addEventListener('change', () => {
      const set = new Set(store.excluded[key] || []);
      if (i.checked) set.delete(i.value); else set.add(i.value);
      commit(set);
    }));
    d.querySelectorAll('[data-msel-sort]').forEach(b => b.addEventListener('click', () => { store.sort = { key, dir: b.dataset.mselSort }; store.open = key; onChange(key); }));
    d.querySelector('[data-msel-all]').addEventListener('click', () => commit(new Set()));
    d.querySelector('[data-msel-none]').addEventListener('click', () => commit(new Set(values())));
  });
  markSortedHeader(root);
}
// Close an open filter on outside click or Escape. Install once.
export function installMultiSelectDismiss(doc, store) {
  doc.addEventListener('click', e => { if (!e.target.closest('[data-msel]')) doc.querySelectorAll('[data-msel][open]').forEach(d => { d.open = false; }); });
  doc.addEventListener('keydown', e => { if (e.key === 'Escape') doc.querySelectorAll('[data-msel][open]').forEach(d => { d.open = false; d.querySelector('summary')?.focus(); }); });
}

// Moves each [data-msel] filter from its bar into the matching header cell of table (label match), compacts the trigger
// to "n/m", and pins the menu with position:fixed so the scrolling table does not clip it. Unmatched filters stay in the bar.
export function filtersIntoHeaders(bar, table) {
  if (!bar || !table) return;
  const ths = [...table.querySelectorAll('thead tr:last-child th')];
  ths.forEach(th => th.querySelectorAll(':scope > [data-msel]').forEach(d => d.remove()));
  const label = th => (th.dataset.label ||= [...th.childNodes].filter(n => n.nodeType === 3 || !n.matches?.('[data-msel],.col-resizer,.sort-mark')).map(n => n.textContent).join('').trim());
  [...bar.querySelectorAll('[data-msel]')].forEach(d => {
    const want = (d.dataset.mselHeader || '').toLowerCase();
    const th = ths.find(h => label(h).toLowerCase().startsWith(want));
    if (!th) return;
    const s = d.querySelector('summary'), m = /\((\d+) of (\d+)\)/.exec(s.textContent);
    if (m) { s.textContent = m[1] === m[2] ? 'All' : m[1] + '/' + m[2]; s.title = d.dataset.mselHeader + ' filter: ' + m[1] + ' of ' + m[2] + ' values shown'; }
    d.classList.add('msel-th');
    const place = () => { if (!d.open) return; const r = s.getBoundingClientRect(), menu = d.querySelector('.msel-menu'), w = d.ownerDocument.defaultView; menu.style.top = (r.bottom + 4) + 'px'; menu.style.left = Math.max(4, Math.min(r.left, (w?.innerWidth || 1000) - 260)) + 'px'; };
    d.addEventListener('toggle', place);
    const resizer = th.querySelector(':scope > .col-resizer');
    th.insertBefore(d, resizer || null);
    place();
  });
  const left = bar.querySelectorAll('[data-msel]').length;
  bar.hidden = !left;
}
