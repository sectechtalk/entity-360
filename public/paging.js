// Shared paging for every multi-event table: 20/50/100 rows per page, a scroll container with a sticky header
// (.table-scroll in styles.css) and Previous/Next controls. pageSlice has no DOM so it is unit-tested.
export const PAGE_SIZES = [20, 50, 100];
export const DEFAULT_PAGE_SIZE = 20;
export function pageSlice(rows, page, size) {
  const n = PAGE_SIZES.includes(Number(size)) ? Number(size) : DEFAULT_PAGE_SIZE;
  const total = rows.length, pages = Math.max(1, Math.ceil(total / n));
  const p = Math.min(Math.max(0, Number(page) || 0), pages - 1);
  return { rows: rows.slice(p * n, (p + 1) * n), page: p, pages, size: n, total, from: total ? p * n + 1 : 0, to: Math.min((p + 1) * n, total), first: p === 0, last: p >= pages - 1 };
}
export const pageInfo = (s, noun = 'rows') => s.total ? `${s.from} to ${s.to} of ${s.total} ${noun}` : `0 ${noun}`;
// Rows-per-page dropdown; id must be unique on the page.
export const sizeSelect = (id, size = DEFAULT_PAGE_SIZE) => `<label class="page-size">Rows per page <select id="${id}">${PAGE_SIZES.map(n => `<option value="${n}"${n === Number(size) ? ' selected' : ''}>${n}</option>`).join('')}</select></label>`;
// Full pager markup for tables rendered from JS (Defender, sign-ins).
export const pagerHtml = (prefix, s, noun) => `<div class="pagination">${sizeSelect(`${prefix}-size`, s.size)}<span id="${prefix}-info">${pageInfo(s, noun)}</span><div><button type="button" class="btn" id="${prefix}-prev" aria-label="Previous page"${s.first ? ' disabled' : ''}>Previous</button><button type="button" class="btn" id="${prefix}-next" aria-label="Next page"${s.last ? ' disabled' : ''}>Next</button></div></div>`;
// Wires a pagerHtml block: st is { page, size }; rerender is called after every change.
export function wirePager(root, prefix, st, rerender) {
  const q = sel => root.querySelector(sel);
  const size = q(`#${prefix}-size`), prev = q(`#${prefix}-prev`), next = q(`#${prefix}-next`);
  if (size) size.onchange = () => { st.size = Number(size.value); st.page = 0; rerender(); };
  if (prev) prev.onclick = () => { st.page--; rerender(); };
  if (next) next.onclick = () => { st.page++; rerender(); };
}
