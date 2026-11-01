// Remediation results page (Investigate). Per-device results of the Entity 360 network connectivity Remediation,
// from GET /api/intune/remediation-results (E360.Intune). Read-only. Pure helpers have no DOM so they are unit-tested.
export const REM_COLUMNS = [
  ['device', 'Device'], ['user', 'User'], ['status', 'Status'], ['passTotal', 'Pass/total'], ['avgMs', 'Avg latency (ms)'],
  ['issues', 'Issues'], ['lastRun', 'Last run (UTC)'],
];
export const REM_FILTERS = [['all', 'All'], ['ok', 'OK'], ['problem', 'Problem']];
export const REM_HELP = 'Results of the Entity 360 network connectivity Remediation for each device, as last reported to Intune. Problem includes devices whose output is missing or unreadable.';
const STATUS = { ok: ['success', 'OK'], problem: ['blocked', 'Problem'], unknown: ['failed', 'No result'] };
export const fmtUtc = value => { const d = new Date(value); return value && !Number.isNaN(d.getTime()) ? d.toISOString().replace('T', ' ').replace(/\.\d+Z$/, 'Z') : String(value ?? ''); };
export const passTotal = r => (r.pass == null || r.total == null ? '' : `${r.pass}/${r.total}`);
export function filterDevices(rows, filter) {
  const list = Array.isArray(rows) ? rows : [];
  if (filter === 'ok') return list.filter(r => r.status === 'ok');
  if (filter === 'problem') return list.filter(r => r.status !== 'ok');
  return list.slice();
}
const sortValue = (r, key) => key === 'passTotal' ? (r.total ? r.pass / r.total : null) : key === 'avgMs' ? r.avgMs : key === 'status' ? ({ problem: 0, unknown: 1, ok: 2 })[r.status] : r[key];
// Default: problems first, then device name. Empty values go last in both directions.
export function sortDevices(rows, sort = { key: 'status', dir: 'asc' }) {
  const { key, dir } = sort, m = dir === 'asc' ? 1 : -1;
  return rows.slice().sort((a, b) => {
    const x = sortValue(a, key), y = sortValue(b, key);
    const ex = x === null || x === undefined || x === '', ey = y === null || y === undefined || y === '';
    if (ex && ey || x === y) return String(a.device ?? '').localeCompare(String(b.device ?? ''), undefined, { sensitivity: 'base' });
    if (ex) return 1; if (ey) return -1;
    return typeof x === 'number' && typeof y === 'number' ? m * (x - y) : m * String(x).localeCompare(String(y), undefined, { numeric: true, sensitivity: 'base' });
  });
}
const cellText = (r, k) => k === 'passTotal' ? passTotal(r) : k === 'status' ? STATUS[r.status]?.[1] ?? 'No result' : k === 'avgMs' ? (r.avgMs ?? '') : (r[k] ?? '');
const csvCell = value => { let v = String(value ?? ''); if (/^[=+@\-\t\r\n]/.test(v)) v = `'${v}`; return `"${v.replaceAll('"', '""')}"`; };
export function devicesCsv(rows) {
  const cell = csvCell;
  const out = [REM_COLUMNS.map(([, label]) => label), ...rows.map(r => REM_COLUMNS.map(([k]) => cellText(r, k)))];
  return '\ufeff' + out.map(row => row.map(cell).join(',')).join('\r\n');
}
const arrow = dir => (dir === 'asc' ? '\u25b2' : '\u25bc');
export function tableHtml(rows, sort, esc, opts = {}) {
  const head = REM_COLUMNS.map(([k, label]) => {
    const on = sort.key === k;
    return `<th data-rem-sort="${k}" tabindex="0" title="Sort by ${esc(label)}"${on ? ` aria-sort="${sort.dir === 'asc' ? 'ascending' : 'descending'}"` : ''}>${esc(label)}${on ? `<span class="sort-mark"> ${arrow(sort.dir)}</span>` : ''}</th>`;
  }).join('') + (opts.canRun ? '<th>Action</th>' : '');
  const td = (r, k) => {
    if (k === 'status') { const [cls, label] = STATUS[r.status] || STATUS.unknown; return `<td><span class="result ${cls}">${label}</span></td>`; }
    if (k === 'lastRun') return `<td title="${esc(r.lastRun ?? '')}">${esc(fmtUtc(r.lastRun))}</td>`;
    if (k === 'issues') return `<td${r.scriptError ? ` title="${esc(r.scriptError)}"` : ''}>${esc(r.issues || (r.status === 'ok' ? 'None' : ''))}${r.truncated ? ' <span class="muted">(output shortened)</span>' : ''}</td>`;
    return `<td>${esc(String(cellText(r, k)))}</td>`;
  };
  const action = r => !opts.canRun ? '' : `<td>${r.deviceId ? `<button type="button" class="btn" data-rem-run="${esc(r.deviceId)}">Run now</button>` : ''}</td>`;
  const body = rows.map(r => `<tr>${REM_COLUMNS.map(([k]) => td(r, k)).join('')}${action(r)}</tr>`).join('');
  return `<table class="event-table" data-table-id="remediation-results"><thead><tr>${head}</tr></thead><tbody id="rem-rows">${body}</tbody></table>`;
}
// Phase 4.8: admin-requested runs (POST /api/intune/remediation-run) and their audit trail (GET /api/intune/remediation-runs).
export const RUN_COLUMNS = [['time', 'Time (UTC)'], ['requester', 'Requester'], ['device', 'Device'], ['user', 'User'], ['reason', 'Reason'], ['result', 'Result']];
export const RUNS_HELP = 'Run now requests made from Entity 360 by an E360.Admin, newest first. Each request is also written to the app console log. Results reach this page after the device runs the script and reports to Intune.';
export const REASON_MAX = 500;
const RUN_RESULT = { accepted: ['success', 'Accepted'], denied: ['blocked', 'Denied'], failed: ['failed', 'Failed'] };
const runText = (r, k) => k === 'time' ? fmtUtc(r.time) : k === 'requester' ? (r.requester?.upn || r.requester?.objectId || '') : k === 'result' ? `${RUN_RESULT[r.result]?.[1] || r.result || ''}${r.error ? `: ${r.error}` : ''}` : (r[k] ?? '');
export function runsCsv(rows) {
  const out = [RUN_COLUMNS.map(([, label]) => label), ...rows.map(r => RUN_COLUMNS.map(([k]) => runText(r, k)))];
  return '\ufeff' + out.map(row => row.map(csvCell).join(',')).join('\r\n');
}
export function runsTableHtml(rows, esc) {
  const head = RUN_COLUMNS.map(([, label]) => `<th>${esc(label)}</th>`).join('');
  const td = (r, k) => k === 'result' ? `<td${r.error ? ` title="${esc(r.error)}"` : ''}><span class="result ${(RUN_RESULT[r.result] || RUN_RESULT.failed)[0]}">${esc(RUN_RESULT[r.result]?.[1] || r.result || '')}</span>${r.error ? ` ${esc(r.error)}` : ''}</td>` : `<td>${esc(String(runText(r, k)))}</td>`;
  return `<table class="event-table" data-table-id="remediation-runs"><thead><tr>${head}</tr></thead><tbody>${rows.map(r => `<tr>${RUN_COLUMNS.map(([k]) => td(r, k)).join('')}</tr>`).join('')}</tbody></table>`;
}
export function runFormHtml(row, esc) {
  return `<form id="rem-run-confirm" class="filter-row"><label>Reason for running on ${esc(row.device)} <input id="rem-run-reason" type="text" maxlength="${REASON_MAX}" required></label><button type="submit" class="btn">Confirm run</button><button type="button" id="rem-run-cancel" class="btn">Cancel</button><span id="rem-run-msg"></span></form>`;
}
export function createRemediationView({ api, esc, emptyBox, canRun = () => false }) {
  const $ = s => document.querySelector(s);
  const st = { runs: [], runFor: null, rows: [], filter: 'all', sort: { key: 'status', dir: 'asc' }, loaded: false, configured: null, note: '', error: '', active: false, generation: 0 };
  const shown = () => sortDevices(filterDevices(st.rows, st.filter), st.sort);
  function render() {
    const rows = shown();
    $('#rem-count').textContent = st.loaded && st.configured ? `${rows.length} of ${st.rows.length}` : '';
    const msg = !st.loaded ? 'Loading Remediation results.' : st.error ? st.error : st.configured === false ? `Not configured. ${st.note}` : st.rows.length ? `No ${st.filter === 'ok' ? 'OK' : 'problem'} devices.` : 'No devices have reported a result yet.';
    const admin = canRun();
    $('#rem-table').innerHTML = rows.length ? tableHtml(rows, st.sort, esc, { canRun: admin }) : emptyBox(msg);
    document.querySelectorAll('button[data-rem-run]').forEach(b => { b.onclick = () => openForm(b.dataset.remRun); });
    renderRuns();
    $('#rem-export').disabled = !rows.length;
    document.querySelectorAll('th[data-rem-sort]').forEach(th => { const go = () => { const k = th.dataset.remSort; st.sort = st.sort.key === k ? { key: k, dir: st.sort.dir === 'asc' ? 'desc' : 'asc' } : { key: k, dir: k === 'lastRun' ? 'desc' : 'asc' }; render(); document.querySelector(`th[data-rem-sort="${k}"]`)?.focus(); }; th.onclick = e => { if (!e.target.closest('.col-resizer')) go(); }; th.onkeydown = e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); go(); } }; });
  }
  function renderRuns() {
    const panel = $('#rem-runs-panel'); if (!panel) return;
    panel.hidden = !canRun();
    $('#rem-runs-count').textContent = st.runs.length ? String(st.runs.length) : '';
    $('#rem-runs-table').innerHTML = st.runs.length ? runsTableHtml(st.runs, esc) : emptyBox('No run requests since the app started.');
    $('#rem-runs-export').disabled = !st.runs.length;
  }
  function closeForm() { st.runFor = null; const box = $('#rem-run-form'); if (box) { box.hidden = true; box.innerHTML = ''; } }
  function openForm(deviceId) {
    const row = st.rows.find(r => r.deviceId === deviceId); const box = $('#rem-run-form'); if (!row || !box) return;
    st.runFor = deviceId; box.innerHTML = runFormHtml(row, esc); box.hidden = false; $('#rem-run-reason').focus();
    $('#rem-run-cancel').onclick = closeForm;
    $('#rem-run-confirm').onsubmit = async ev => {
      ev.preventDefault();
      const reason = $('#rem-run-reason').value.trim(), msg = $('#rem-run-msg');
      if (!reason) { msg.textContent = 'A reason is required.'; return; }
      const submit = ev.target.querySelector('button[type="submit"]'); submit.disabled = true; msg.textContent = 'Sending request.';
      try { await api('/api/intune/remediation-run', { method: 'POST', body: JSON.stringify({ managedDeviceId: deviceId, reason }) }); closeForm(); $('#rem-status').textContent = `Run requested for ${row.device}. Intune runs it at the device's next check-in.`; }
      catch (e) { msg.textContent = e.message; submit.disabled = false; }
      finally { loadRuns(); }
    };
  }
  async function loadRuns() {
    if (!canRun()) { st.runs = []; renderRuns(); return; }
    try { const r = await api('/api/intune/remediation-runs'); st.runs = Array.isArray(r.rows) ? r.rows : []; } catch { st.runs = []; }
    renderRuns();
  }
  async function load() {
    loadRuns();
    const id = ++st.generation; $('#rem-refresh').disabled = true; $('#rem-status').textContent = '';
    try {
      const r = await api('/api/intune/remediation-results'); if (id !== st.generation) return;
      st.rows = Array.isArray(r.rows) ? r.rows : []; st.configured = r.configured !== false; st.note = r.note || ''; st.error = ''; st.loaded = true;
      $('#rem-status').textContent = `Updated ${new Date().toLocaleTimeString()}.${r.truncated ? ' Only the first pages of results were read.' : ''}`; render();
    } catch (e) { if (id === st.generation) { st.loaded = true; st.rows = []; st.error = e.message; render(); } }
    finally { if (id === st.generation) $('#rem-refresh').disabled = false; }
  }
  $('#rem-help').textContent = REM_HELP;
  $('#rem-filter').onchange = ev => { st.filter = ev.target.value; render(); };
  $('#rem-refresh').onclick = load;
  if ($('#rem-runs-help')) $('#rem-runs-help').textContent = RUNS_HELP;
  if ($('#rem-runs-export')) $('#rem-runs-export').onclick = () => {
    if (!st.runs.length) return;
    const url = URL.createObjectURL(new Blob([runsCsv(st.runs)], { type: 'text/csv;charset=utf-8;' })), a = document.createElement('a');
    a.href = url; a.download = `entity-360-remediation-run-requests-${new Date().toISOString().slice(0, 10)}.csv`; a.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
  };
  $('#rem-export').onclick = () => {
    const rows = shown(); if (!rows.length) return;
    const url = URL.createObjectURL(new Blob([devicesCsv(rows)], { type: 'text/csv;charset=utf-8;' })), a = document.createElement('a');
    a.href = url; a.download = `entity-360-remediation-results-${new Date().toISOString().slice(0, 10)}.csv`; a.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
  };
  return { load, setActive(v) { const was = st.active; st.active = v; if (v && !was) load(); }, reset() { st.generation++; closeForm(); st.runs = []; st.rows = []; st.loaded = false; st.configured = null; st.error = ''; render(); } };
}
