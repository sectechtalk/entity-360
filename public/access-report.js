// GOVERNANCE > Access report. Pick a group, a directory role or a user; Run reads group members, directory roles,
// PIM eligibility and activations and last sign-in at that moment. The CSV is built here in the browser; nothing is
// stored on the server. Pure helpers (CSV, rows) have no DOM so they are unit-tested.
export const REPORT_COLUMNS = [['name', 'User'], ['upn', 'UPN'], ['objectType', 'Object type'], ['source', 'Source'], ['via', 'Group or role'], ['end', 'End date'], ['lastSignIn', 'Last sign-in (UTC)']];
export const KINDS = [['group', 'Group'], ['role', 'Directory role'], ['user', 'User']];
export const fmtUtc = v => { const d = new Date(v); return v && !Number.isNaN(d.getTime()) ? d.toISOString().replace('T', ' ').replace(/\.\d+Z$/, 'Z') : String(v ?? ''); };
const shown = (key, r) => key === 'end' ? (r.end ? fmtUtc(r.end) : '') : key === 'lastSignIn' ? (r.lastSignIn && r.lastSignIn !== 'Never' ? fmtUtc(r.lastSignIn) : r.lastSignIn || '') : String(r[key] ?? '');
// Same formula guard as the other CSV exports: a leading = + @ - tab or newline is prefixed with a quote.
export function reportCsv(rows) {
  const cell = value => { let v = String(value ?? ''); if (/^[=+@\-\t\r\n]/.test(v)) v = `'${v}`; return `"${v.replaceAll('"', '""')}"`; };
  return '﻿' + [REPORT_COLUMNS.map(([, l]) => l), ...rows.map(r => REPORT_COLUMNS.map(([k]) => shown(k, r)))].map(line => line.map(cell).join(',')).join('\r\n');
}
export const csvName = (scope, at = new Date()) => `entity-360-access-report-${scope?.kind || 'scope'}-${String(scope?.name || 'report').replace(/[^\w.-]+/g, '_').slice(0, 60)}-${at.toISOString().slice(0, 16).replace(/[-:T]/g, '')}.csv`;
export function rowsHtml(rows, esc) {
  return rows.map(r => `<tr>${REPORT_COLUMNS.map(([k]) => `<td>${esc(shown(k, r))}</td>`).join('')}</tr>`).join('');
}

export function createAccessReportView({ api, esc, emptyBox, toast }) {
  const $ = s => document.querySelector(s);
  const st = { kind: 'group', results: [], pick: null, data: null, running: false, started: 0, timer: null, msg: '' };
  let wired = false;
  function wire() {
    if (wired) return; wired = true;
    $('#ar-kind').innerHTML = KINDS.map(([v, l]) => `<option value="${v}">${esc(l)}</option>`).join('');
    $('#ar-kind').onchange = e => { st.kind = e.target.value; st.results = []; st.pick = null; draw(); };
    $('#ar-search-form').onsubmit = async e => {
      e.preventDefault();
      const q = $('#ar-q').value.trim(); if (!q) return;
      setStatus('Searching…');
      try { st.results = (await api(`/api/access-report/search?${new URLSearchParams({ kind: st.kind, q })}`)).results || []; setStatus(st.results.length ? '' : 'No matches. Type the start of the name.'); }
      catch (err) { st.results = []; setStatus(err.message); }
      draw();
    };
    $('#ar-results').onclick = e => { const b = e.target.closest('[data-ar-pick]'); if (!b) return; st.pick = st.results.find(x => x.id === b.dataset.arPick) || null; draw(); };
    $('#ar-run').onclick = run;
    $('#ar-export').onclick = () => {
      if (!st.data?.rows?.length) return toast('Run the report first; there is nothing to export yet.');
      const url = URL.createObjectURL(new Blob([reportCsv(st.data.rows)], { type: 'text/csv;charset=utf-8;' })), a = document.createElement('a');
      a.href = url; a.download = csvName(st.data.scope); a.click(); setTimeout(() => URL.revokeObjectURL(url), 1000); toast(`Exported ${st.data.rows.length} rows`);
    };
  }
  const setStatus = m => { st.msg = m; const s = $('#ar-status'); if (s) s.textContent = m; };
  async function run() {
    if (!st.pick || st.running) return;
    st.running = true; st.started = Date.now(); st.data = null; draw();
    const tick = () => setStatus(`Reading ${st.pick.name}: group members, directory roles, PIM and last sign-in… ${Math.round((Date.now() - st.started) / 1000)} s`);
    tick(); st.timer = setInterval(tick, 1000);
    try { st.data = await api('/api/access-report/run', { method: 'POST', body: JSON.stringify({ kind: st.kind, id: st.pick.id }) }); setStatus(`${st.data.rows.length} rows for ${st.data.scope.name}, read ${new Date(st.data.readAt).toLocaleTimeString()} in ${Math.round(st.data.ms / 100) / 10} s. Nothing was stored.`); }
    catch (err) { setStatus(err.message); }
    finally { clearInterval(st.timer); st.running = false; draw(); }
  }
  function draw() {
    const pick = st.pick;
    $('#ar-results').innerHTML = st.results.map(x => `<button type="button" class="btn" data-ar-pick="${esc(x.id)}" aria-pressed="${pick?.id === x.id}">${esc(x.name)}<small> ${esc(x.detail || '')}</small></button>`).join('');
    $('#ar-picked').textContent = pick ? `Selected: ${pick.name}` : 'Nothing selected yet.';
    const run = $('#ar-run'); run.disabled = !pick || st.running; run.setAttribute('aria-busy', String(st.running)); run.textContent = st.running ? 'Running…' : 'Run report';
    run.title = pick ? '' : 'Search and pick a group, role or user first';
    $('#ar-export').disabled = !st.data?.rows?.length;
    $('#ar-count').textContent = st.data ? String(st.data.rows.length) : '';
    const d = st.data;
    $('#ar-table').innerHTML = !d ? emptyBox(st.running ? 'Running…' : 'Pick a scope and choose Run report.') : d.rows.length
      ? `<div class="table-wrap table-scroll"><table class="event-table" data-table-id="access-report"><thead><tr>${REPORT_COLUMNS.map(([, l]) => `<th>${esc(l)}</th>`).join('')}</tr></thead><tbody>${rowsHtml(d.rows, esc)}</tbody></table></div>`
      : emptyBox('No members, roles or PIM assignments found for this scope.');
    $('#ar-notes').innerHTML = d ? [...(d.problems || []).map(p => `<p class="account-note">Not available: ${esc(p)}</p>`), ...(d.notes || []).map(n => `<p class="account-note">${esc(n)}</p>`)].join('') : '';
  }
  return { setActive(on) { $('#access-report-panel').hidden = !on; if (on) { wire(); draw(); } } };
}
