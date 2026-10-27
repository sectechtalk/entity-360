export function createIntuneView({ api, session, esc, external, onSources, openConnection }) {
  const $ = s => document.querySelector(s);
  let report = null, snapshot = null, active = false, generation = 0;
  const LABEL = { fail: 'Needs attention', warn: 'Check', unknown: 'Not evaluated', info: 'Information', pass: 'Healthy' };
  const AREAS = ['Tenant & account', 'How compliance is calculated', 'Devices', 'This computer', 'Cross-check'];
  const unknown = v => v === null || v === undefined || v === '' ? 'Not returned' : String(v);
  const status = message => { $('#intune-status').textContent = message; };
  const badge = s => `<span class="health-badge health-${esc(s)}">${esc(LABEL[s] || s)}</span>`;
  const list = items => items.length ? `<ul>${items.map(i => `<li>${esc(i)}</li>`).join('')}</ul>` : '';
  function fixBlock(fix) {
    if (!fix) return '';
    const who = fix.change === 'tenant' ? 'Changes the tenant' : fix.change === 'device' ? 'Changes this computer' : 'Read or decide only';
    return `<div class="health-fix"><h4>Proposed fix <small>${esc(who)}. Entity 360 does not apply it.</small></h4><p>${esc(fix.summary)}</p><ol>${fix.steps.map(s => `<li>${esc(s)}</li>`).join('')}</ol>${fix.note ? `<p class="health-note">${esc(fix.note)}</p>` : ''}</div>`;
  }
  function portalBtn(p) {
    if (!p) return '';
    return `<p class="health-portal">${p.url ? `<a class="btn" href="${esc(p.url)}" target="_blank" rel="noopener noreferrer">${esc(p.label)}</a>` : `<button type="button" class="btn" disabled title="${esc(p.reason)}">No portal page</button> <small>${esc(p.reason)}</small>`}</p>`;
  }
  function checkRow(c) {
    return `<details class="health-check health-row-${esc(c.status)}"${c.status === 'fail' ? ' open' : ''}><summary>${badge(c.status)}<span class="health-title">${esc(c.title)}</span><span class="health-finding">${esc(c.finding)}</span></summary><div class="health-body">${portalBtn(c.portal)}${c.evidence.length ? `<h4>Evidence</h4>${list(c.evidence)}` : ''}${c.how ? `<h4>How this is determined</h4><p>${esc(c.how)}</p>` : ''}${fixBlock(c.fix)}${c.journal ? `<p class="health-note">Troubleshooting journal step ${esc(c.journal)} (Entity 360 reference, “Remote Control and Intune troubleshooting”).</p>` : ''}</div></details>`;
  }
  function deviceTable(devices) {
    if (!devices.length) return '<p>No managed devices were returned. This does not mean no device is enrolled: the viewer may lack the Intune permission to list them.</p>';
    return `<div class="table-wrap"><table class="account-table"><thead><tr><th>Device</th><th>Intune record</th><th>Entra object</th><th>Why it shows this</th></tr></thead><tbody>${devices.map(d => `<tr><th scope="row">${esc(d.name)}<small>${esc(d.os)}</small></th><td>Agent: ${esc(unknown(d.agent))}<small>Enrollment: ${esc(unknown(d.enrollment))} · Owner: ${esc(unknown(d.ownership))}</small><small>User: ${esc(unknown(d.user))}</small><small>Compliance: ${esc(unknown(d.compliance))}</small><small>Enrolled: ${esc(unknown(d.enrolled))} · Last sync: ${esc(unknown(d.lastSync))}</small></td><td>${d.entra ? `Trust: ${esc(unknown(d.entra.trust))}<small>isManaged: ${esc(unknown(d.entra.isManaged))} · isCompliant: ${esc(unknown(d.entra.isCompliant))}</small><small>MDM app: ${esc(unknown(d.entra.mdmApp))}</small>` : 'No matching Entra device returned'}</td><td>${d.why.length ? list(d.why) : 'No additional explanation.'}</td></tr>`).join('')}</tbody></table></div>`;
  }
  function render() {
    $('#intune-export').disabled = !report && !snapshot;
    const viewer = session();
    $('#intune-local-host').textContent = `Dashboard server: ${viewer?.serverHost || 'Unknown'}. Collect server host inspects that machine, not a remote browser.`;
    $('#intune-collect').disabled = !viewer?.localCollectionSupported;
    $('#intune-clear-local').disabled = !snapshot;
    $('#intune-snapshot-note').textContent = snapshot ? `Computer evidence loaded: ${snapshot.host}, collected ${snapshot.collectedAt}. ${snapshot.provenance}.` : 'No computer evidence loaded. Cloud checks run without it; the “This computer” and cross-checks need a snapshot.';
    if (!report) { $('#intune-results').innerHTML = '<section class="panel account-card"><div class="panel-heading"><h2>Intune health</h2></div><p>Choose Run Intune health to read the tenant side with your delegated permissions and, if loaded, compare it with this computer.</p></section>'; return; }
    const s = report.summary;
    const head = `<section class="panel account-card"><div class="panel-heading"><h2>Result</h2></div><p class="health-summary">${['fail', 'warn', 'unknown', 'info', 'pass'].map(k => `<span class="health-count health-${k}">${esc(s[k])} ${esc(LABEL[k])}</span>`).join('')}</p><p class="account-note">${esc(report.notes.join(' '))} Updated ${esc(report.updatedAt)}.${report.unavailable?.length ? ' Some sources were not available to this account.' : ''}</p></section>`;
    const groups = AREAS.map(a => ({ a, rows: report.checks.filter(c => c.area === a) })).filter(g => g.rows.length).map(g => `<section class="panel account-card"><div class="panel-heading"><h2>${esc(g.a)}</h2></div>${g.rows.map(checkRow).join('')}</section>`).join('');
    const devices = `<section class="panel account-card"><div class="panel-heading"><h2>Devices in Intune and how each state was reached</h2></div>${deviceTable(report.devices)}</section>`;
    const calc = `<section class="panel account-card"><div class="panel-heading"><h2>How Intune and Windows calculate these values</h2></div>${report.calculation.map(c => `<h3>${esc(c.title)} <small>${esc(c.field)}</small></h3><p>${esc(c.how)}</p><p class="health-note">On the computer: ${esc(c.client)} ${external(c.url, 'Microsoft Learn')}</p>`).join('')}</section>`;
    $('#intune-results').innerHTML = head + groups + devices + calc;
    if (active) onSources(report.sources || []);
  }
  async function run() {
    const current = ++generation;
    $('#intune-run').disabled = true; status('Reading Intune, Entra and Conditional Access with your delegated permissions…');
    try {
      const r = await api('/api/intune/health', { method: 'POST', body: JSON.stringify({ snapshot }) });
      if (current !== generation) return;
      report = r; render();
      status(r.unavailable?.length ? 'Done. Some sources were not available to this account and are shown as not evaluated.' : 'Intune health checked.');
    } catch (e) { if (current === generation) status(e.message); }
    finally { if (current === generation) $('#intune-run').disabled = false; }
  }
  $('#intune-run').onclick = run;
  $('#intune-connect').onclick = openConnection;
  $('#intune-collect').onclick = async () => {
    const current = generation; $('#intune-collect').disabled = true; status('Reading Windows configuration on the dashboard server host…');
    try { const r = await api('/api/device/collect', { method: 'POST', body: '{}' }); if (current !== generation) return; snapshot = r; render(); status(`Local evidence collected on ${r.host}. Verify that is the machine you are investigating, then run the check.`); }
    catch (e) { status(e.message); }
    finally { $('#intune-collect').disabled = !session()?.localCollectionSupported; }
  };
  $('#intune-import').onchange = async event => {
    const current = generation, file = event.target.files[0]; if (!file) return;
    try { if (file.size > 256 * 1024) throw new Error('Snapshot must be 256 KB or smaller.'); const raw = JSON.parse(await file.text()); const r = await api('/api/device/import', { method: 'POST', body: JSON.stringify(raw) }); if (current !== generation) return; snapshot = r; render(); status(`Imported evidence from ${r.host}; verify the collection time, then run the check.`); }
    catch (e) { status(e.message); }
    finally { event.target.value = ''; }
  };
  $('#intune-clear-local').onclick = () => { snapshot = null; render(); status('Computer evidence cleared.'); };
  $('#intune-export').onclick = () => {
    const blob = new Blob([JSON.stringify({ health: report || null, snapshot: snapshot || null }, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = url; a.download = 'Entity360-intune-health.json'; a.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
  };
  return { run, reset() { generation++; report = null; snapshot = null; $('#intune-run').disabled = false; status(''); render(); }, setActive(value) { active = value; if (active) render(); } };
}
