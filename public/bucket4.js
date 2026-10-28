// Coverage bucket 4 pages: Emergency access and Logs (MORE TOOLS). Read-only, live connections only.
export const LOG_WINDOWS = [[1, 'Last 24 hours'], [7, 'Last 7 days'], [30, 'Last 30 days']];

export function emergencyHtml(st, { esc, fmtTime, resultBadge, external, emptyBox }) {
  const head = '<div class="panel-heading"><div><h2>Emergency access accounts</h2><p>Accounts excluded from Conditional Access or named for break-glass use, checked against what Microsoft recommends: excluded from every active policy, a permanent Global Administrator, rarely used, and watched by an alert rule.</p></div><div><button id="emergency-run" type="button" class="btn">Check accounts</button></div></div>';
  if (!st) return head + emptyBox('Choose Check accounts to read Conditional Access, roles and alert rules.');
  if (st.loading) return head + emptyBox('Checking accounts…');
  if (st.error) return head + emptyBox(st.error);
  const d = st.data, notes = (d.notes || []).map(n => `<p class="account-note">${esc(n)}</p>`).join('');
  if (!d.rows.length) return head + emptyBox('No account is excluded from Conditional Access or named for emergency access. Microsoft recommends two cloud-only emergency access accounts.') + notes;
  const alerts = a => a === null ? 'Not checked' : a.length ? a.map(r => `${esc(r.name)}${r.enabled ? '' : ' (disabled)'}`).join('<br>') : 'None';
  return head + `<div class="table-wrap"><table class="event-table" data-table-id="emergency"><thead><tr><th>Account</th><th>CA exclusions</th><th>Last sign-in</th><th>Roles</th><th>Alert rules</th><th>Findings</th><th></th></tr></thead><tbody>${d.rows.map(r => `<tr><td>${esc(r.name)}<small>${esc(r.upn)}${r.enabled ? '' : ' · disabled'}</small></td><td>${resultBadge(r.excludedFrom === r.policies ? 'Excluded from all' : `${r.excludedFrom} of ${r.policies}`)}${r.notExcluded.length ? `<small>Still applies: ${esc(r.notExcluded.join(', '))}</small>` : ''}</td><td>${r.lastSignIn === undefined ? 'Not returned' : r.lastSignIn ? esc(fmtTime(r.lastSignIn)) : 'Never'}</td><td>${esc(r.roles.join(', ') || 'None')}</td><td>${alerts(r.alerts)}</td><td>${r.findings.length ? r.findings.map(f => `<div>${esc(f)}</div>`).join('') : resultBadge('OK')}</td><td>${external(r.link, 'Open')}</td></tr>`).join('')}</tbody></table></div>` + notes;
}

export function logsHtml(ws, sel, run, { esc, external, emptyBox }) {
  const head = '<div class="panel-heading"><div><h2>Logs</h2><p>Saved KQL for the Entra sign-in and audit tables, run through Azure Resource Manager against a Log Analytics workspace you can read. Read-only; only the saved queries below can run.</p></div></div>';
  if (!ws) return head + `<div class="account-actions"><button id="logs-load" type="button" class="btn">List workspaces</button></div>`;
  if (ws.loading) return head + emptyBox('Listing workspaces…');
  if (ws.error) return head + emptyBox(ws.error) + `<div class="account-actions"><button id="logs-load" type="button" class="btn">List workspaces</button></div>`;
  const d = ws.data;
  if (!d.workspaces.length) return head + emptyBox('No Log Analytics workspace is visible to you. Create one (Pay-as-you-go includes 5 GB a month free) and point an Entra diagnostic setting at it.');
  const opt = (v, l, on) => `<option value="${esc(v)}"${on ? ' selected' : ''}>${esc(l)}</option>`;
  const form = `<div class="account-actions"><label>Workspace <select id="logs-ws">${d.workspaces.map(w => opt(w.id, `${w.name} (${w.subscription})`, w.id === sel.workspace)).join('')}</select></label><label>Query <select id="logs-q">${d.queries.map(q => opt(q.key, q.title, q.key === sel.query)).join('')}</select></label><label>Window <select id="logs-days">${LOG_WINDOWS.map(([v, l]) => opt(v, l, v === sel.days)).join('')}</select></label><button id="logs-run" type="button" class="btn">Run query</button></div>`;
  const w = d.workspaces.find(x => x.id === sel.workspace) || d.workspaces[0];
  const meta = `<p class="account-note">${esc(w.name)}: ${esc(w.sku || 'SKU not returned')}, retention ${esc(w.retention ?? '?')} days${w.dailyCapGb > 0 ? `, daily cap ${esc(w.dailyCapGb)} GB` : ''}. ${external(w.link, 'Open in Azure')}</p>`;
  const kql = (d.queries.find(q => q.key === sel.query) || d.queries[0]).kql;
  let out = '';
  if (run?.loading) out = emptyBox('Running…');
  else if (run?.error) out = emptyBox(run.error);
  else if (run?.data) out = run.data.missing ? emptyBox(run.data.missing) : run.data.rows.length ? `<div class="table-wrap"><table class="event-table" data-table-id="logs"><thead><tr>${run.data.columns.map(c => `<th>${esc(c)}</th>`).join('')}</tr></thead><tbody>${run.data.rows.map(r => `<tr>${r.map(v => `<td>${esc(typeof v === 'object' && v !== null ? JSON.stringify(v) : v)}</td>`).join('')}</tr>`).join('')}</tbody></table></div>` : emptyBox('No rows in this window.');
  const books = d.workbooks.length ? `<h3>Workbooks</h3><div class="account-actions">${d.workbooks.map(b => external(b.link, b.name)).join(' ')}</div>` : '<p class="account-note">No saved workbooks. Entra ships built-in workbooks under Monitoring &amp; health &gt; Workbooks.</p>';
  return head + form + meta + `<details><summary>KQL</summary><pre><code>${esc(kql)}</code></pre></details>` + out + books + (d.notes || []).map(n => `<p class="account-note">${esc(n)}</p>`).join('');
}

export function createBucket4Views({ api, esc, fmtTime, resultBadge, external, emptyBox }) {
  const h = { esc, fmtTime, resultBadge, external, emptyBox };
  let em = null, ws = null, run = null; const sel = { workspace: '', query: 'tables', days: 7 };
  const $ = s => document.querySelector(s);
  function renderEmergency() {
    $('#emergency-content').innerHTML = emergencyHtml(em, h);
    $('#emergency-run').onclick = () => { em = { loading: true }; renderEmergency(); api('/api/emergency-access').then(d => { em = { data: d }; }, e => { em = { error: e.message }; }).finally(renderEmergency); };
  }
  function renderLogs() {
    $('#logs-content').innerHTML = logsHtml(ws, sel, run, h);
    const load = $('#logs-load'); if (load) load.onclick = () => { ws = { loading: true }; renderLogs(); api('/api/logs/workspaces').then(d => { ws = { data: d }; sel.workspace = d.workspaces[0]?.id || ''; }, e => { ws = { error: e.message }; }).finally(renderLogs); };
    const go = $('#logs-run'); if (!go) return;
    $('#logs-ws').onchange = e => { sel.workspace = e.target.value; run = null; renderLogs(); };
    $('#logs-q').onchange = e => { sel.query = e.target.value; run = null; renderLogs(); };
    $('#logs-days').onchange = e => { sel.days = Number(e.target.value); };
    go.onclick = () => { run = { loading: true }; renderLogs(); api('/api/logs/query', { method: 'POST', body: JSON.stringify(sel) }).then(d => { run = { data: d }; }, e => { run = { error: e.message }; }).finally(renderLogs); };
  }
  return { setEmergency: on => { if (on) renderEmergency(); }, setLogs: on => { if (on) renderLogs(); } };
}
