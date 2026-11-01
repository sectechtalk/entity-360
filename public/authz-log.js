// Authorization log page (Investigate). Shows the in-memory decision log from GET /api/authz/log: allow and deny
// decisions for feature routes since the app last started, newest first, at most 100 rows. Read-only; it shows only what the server recorded.
// Pure helpers (filter, sort, CSV) have no DOM so they are unit-tested.
export const AUTHZ_COLUMNS = [
  ['time', 'Time (UTC)'], ['user', 'User'], ['path', 'Route'], ['role', 'Required role'], ['outcome', 'Decision'],
  ['reason', 'Reason'], ['tenant', 'Tenant'], ['source', 'Source'],
];
// The page is shown only to E360.Admin when roles are enforced, and never when signed out. The server enforces the same rule.
// 2026-10-30T04:59:21.123Z -> 2026-10-30 04:59:21Z (CSV keeps the raw ISO value).
export const fmtUtc = value => { const d = new Date(value); return value && !Number.isNaN(d.getTime()) ? d.toISOString().replace('T', ' ').replace(/\.\d+Z$/, 'Z') : String(value ?? ''); };
export const AUTHZ_ROLE = 'E360.Admin';
export const authzVisible = s => !!s && s.mode !== 'signedout' && (!s.rolesEnforced || (s.appRoles || []).includes(AUTHZ_ROLE));
export const AUTHZ_FILTERS = [['all', 'All'], ['allowed', 'Allowed'], ['denied', 'Denied']];
export const AUTHZ_HELP = 'Every allow or deny decision Entity 360 made for a feature that needs an app role. The log lives in memory on the server: it starts empty each time the app starts (or scales up from zero) and keeps the last 100 decisions, newest first. Nothing is written to disk.';
export function filterDecisions(rows, filter) {
  const list = Array.isArray(rows) ? rows : [];
  return filter === 'allowed' || filter === 'denied' ? list.filter(r => r.outcome === filter) : list.slice();
}
// Default order is newest first. Any other column sorts as text; empty values go last.
export function sortDecisions(rows, sort = { key: 'time', dir: 'desc' }) {
  const { key, dir } = sort, m = dir === 'asc' ? 1 : -1;
  return rows.slice().sort((a, b) => {
    const x = a[key] ?? '', y = b[key] ?? '';
    if (x === y) return String(b.time ?? '').localeCompare(String(a.time ?? ''));
    if (x === '') return 1; if (y === '') return -1;
    return m * String(x).localeCompare(String(y), undefined, { numeric: true, sensitivity: 'base' });
  });
}
// Same formula guard as the other CSV exports: a leading = + @ - tab or newline is prefixed with a quote.
export function decisionsCsv(rows) {
  const cell = value => { let v = String(value ?? ''); if (/^[=+@\-\t\r\n]/.test(v)) v = `'${v}`; return `"${v.replaceAll('"', '""')}"`; };
  const out = [AUTHZ_COLUMNS.map(([, label]) => label), ...rows.map(r => AUTHZ_COLUMNS.map(([k]) => r[k]))];
  return '\ufeff' + out.map(row => row.map(cell).join(',')).join('\r\n');
}
const arrow = dir => (dir === 'asc' ? '\u25b2' : '\u25bc');
export function tableHtml(rows, sort, esc) {
  const head = AUTHZ_COLUMNS.map(([k, label]) => {
    const on = sort.key === k;
    return `<th data-authz-sort="${k}" tabindex="0" title="Sort by ${esc(label)}"${on ? ` aria-sort="${sort.dir === 'asc' ? 'ascending' : 'descending'}"` : ''}>${esc(label)}${on ? `<span class="sort-mark"> ${arrow(sort.dir)}</span>` : ''}</th>`;
  }).join('');
  const body = rows.map(r => `<tr>${AUTHZ_COLUMNS.map(([k]) => k === 'time' ? `<td class="authz-time" title="${esc(r.time ?? '')}">${esc(fmtUtc(r.time))}</td>` : k === 'outcome' ? `<td><span class="result ${r.outcome === 'denied' ? 'blocked' : 'success'}">${r.outcome === 'denied' ? 'Denied' : 'Allowed'}</span></td>` : `<td>${esc(r[k] ?? '')}</td>`).join('')}</tr>`).join('');
  return `<table class="event-table" data-table-id="authz-log"><thead><tr>${head}</tr></thead><tbody id="authz-rows">${body}</tbody></table>`;
}
export function createAuthzLogView({ api, esc, emptyBox }) {
  const $ = s => document.querySelector(s);
  const st = { rows: [], filter: 'all', sort: { key: 'time', dir: 'desc' }, loaded: false, enforced: null, active: false, generation: 0 };
  const shown = () => sortDecisions(filterDecisions(st.rows, st.filter), st.sort);
  function render() {
    const rows = shown();
    $('#authz-count').textContent = st.loaded ? `${rows.length} of ${st.rows.length}` : '';
    $('#authz-enforced').textContent = st.enforced === null ? '' : st.enforced ? 'App roles are enforced for your sign-in.' : 'App roles are not enforced for your sign-in type, so features are allowed without a role.';
    $('#authz-table').innerHTML = rows.length ? tableHtml(rows, st.sort, esc) : emptyBox(!st.loaded ? 'Loading the authorization log.' : st.rows.length ? `No ${st.filter} decisions in the log.` : 'No decisions yet. The log fills as people open features that need an Entity 360 role.');
    // The count always agrees with the rows actually drawn (read back from the table this render produced).
    if (st.loaded) $('#authz-count').textContent = `${document.querySelectorAll('#authz-rows > tr').length} of ${st.rows.length}`;
    $('#authz-export').disabled = !rows.length;
    document.querySelectorAll('th[data-authz-sort]').forEach(th => { const go = () => { const k = th.dataset.authzSort; st.sort = st.sort.key === k ? { key: k, dir: st.sort.dir === 'asc' ? 'desc' : 'asc' } : { key: k, dir: k === 'time' ? 'desc' : 'asc' }; render(); th.ownerDocument.querySelector(`th[data-authz-sort="${k}"]`)?.focus(); }; th.onclick = e => { if (!e.target.closest('.col-resizer')) go(); }; th.onkeydown = e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); go(); } }; });
  }
  async function load() {
    const id = ++st.generation; $('#authz-refresh').disabled = true; $('#authz-status').textContent = '';
    try { const r = await api('/api/authz/log'); if (id !== st.generation) return; st.rows = Array.isArray(r.rows) ? r.rows : []; st.enforced = Boolean(r.enforced); st.loaded = true; $('#authz-status').textContent = `Updated ${new Date().toLocaleTimeString()}.`; render(); }
    catch (e) { if (id === st.generation) { st.loaded = true; $('#authz-status').textContent = e.message; render(); } }
    finally { if (id === st.generation) $('#authz-refresh').disabled = false; }
  }
  $('#authz-help').textContent = AUTHZ_HELP;
  $('#authz-filter').onchange = ev => { st.filter = ev.target.value; render(); };
  $('#authz-refresh').onclick = load;
  $('#authz-export').onclick = () => {
    const rows = shown(); if (!rows.length) return;
    const url = URL.createObjectURL(new Blob([decisionsCsv(rows)], { type: 'text/csv;charset=utf-8;' })), a = document.createElement('a');
    a.href = url; a.download = `entity-360-authz-log-${new Date().toISOString().slice(0, 10)}.csv`; a.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
  };
  return { load, setActive(v) { const was = st.active; st.active = v; if (v && !was) load(); }, reset() { st.generation++; st.rows = []; st.loaded = false; st.enforced = null; render(); } };
}