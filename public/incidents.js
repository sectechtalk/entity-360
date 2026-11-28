// Incidents (INVESTIGATE > Incidents, route #incidents): Defender XDR incidents and alerts plus Identity Protection risk,
// ranked on one page. Read-only: classifying, assigning and closing stay in the Defender and Entra portals. Each user or
// device an item names opens in Entity 360 (Summary or Device lookup) so the investigation starts from the alert.
export const INCIDENTS_TITLE = ['Incidents', 'What Defender XDR and Identity Protection raised in the last 30 days, ranked. Open a user or device to investigate it here.'];
const SEV_LABEL = { high: 'High', medium: 'Medium', low: 'Low', informational: 'Informational', unknown: 'Unknown' };
const SEV_CLASS = { high: 'critical', medium: 'high', low: 'medium', informational: 'low', unknown: 'low' };
const SOURCE_LABEL = { ok: 'Read', denied: 'Not granted', unavailable: 'Not available', failed: 'Failed' };
export const FILTERS = [['open', 'Open'], ['all', 'All, including resolved'], ['identity', 'Identity Protection only'], ['defender', 'Defender XDR only']];

const when = t => (t ? `${String(t).slice(0, 16).replace('T', ' ')} UTC` : '');
export function filterItems(items, filter) {
  if (filter === 'all') return items;
  if (filter === 'identity') return items.filter(i => i.active && i.source === 'Identity Protection');
  if (filter === 'defender') return items.filter(i => i.active && i.source !== 'Identity Protection');
  return items.filter(i => i.active);
}

export function sourcesHtml(sources, esc) {
  const rows = sources.map(s => `<tr data-source="${esc(s.id)}" class="source-${esc(s.status)}"><td>${esc(s.label)}</td><td>${esc(SOURCE_LABEL[s.status] || s.status)}${s.status === 'ok' ? ` (${esc(s.count)}${s.truncated ? '+' : ''})` : ''}</td><td><code>${esc(s.scope)}</code></td><td>${s.status === 'ok' ? '' : `${esc(s.reason)}${s.needs ? `<br><span class="muted">Needs: ${esc(s.needs)}</span>` : ''}`}</td></tr>`).join('');
  const bad = sources.filter(s => s.status !== 'ok').length;
  return `<details class="finding-items incident-sources"><summary>Sources: ${esc(sources.length - bad)} of ${esc(sources.length)} read${bad ? ` · ${esc(bad)} need attention` : ''}</summary><div class="table-wrap"><table class="event-table" data-table-id="incident-sources"><thead><tr><th>Source</th><th>Result</th><th>Delegated permission</th><th>Why not</th></tr></thead><tbody>${rows}</tbody></table></div></details>`;
}

function entitiesHtml(i, idx, esc) {
  const users = i.users.map((u, n) => `<li><span>${esc(u.name)}${u.upn && u.upn !== u.name ? ` <span class="muted">${esc(u.upn)}</span>` : ''}</span>${u.id ? `<button type="button" class="btn" data-incident-user="${idx}:${n}">Open person</button>` : '<span class="muted">Not an Entra account</span>'}</li>`).join('');
  const devices = i.devices.map((d, n) => `<li><span>${esc(d.name)}${d.os ? ` <span class="muted">${esc(d.os)}</span>` : ''}</span><button type="button" class="btn" data-incident-device="${idx}:${n}">Open device</button></li>`).join('');
  const ips = i.ips.length ? `<li><span>IP addresses: ${i.ips.map(ip => `<code>${esc(ip)}</code>`).join(' ')}</span></li>` : '';
  return users || devices || ips ? `<ul class="incident-entities">${users}${devices}${ips}</ul>` : '<p class="account-note">Microsoft named no user or device on this item.</p>';
}

function alertsHtml(i, esc, external) {
  if (!i.alerts?.length) return '';
  const rows = i.alerts.map(a => `<tr><td>${a.link ? external(a.link, a.title, 'finding-link') : esc(a.title)}</td><td>${esc(SEV_LABEL[a.severity])}</td><td>${esc(a.status)}</td><td>${esc(a.product || '')}</td><td>${esc(a.mitre.join(', '))}</td><td>${esc(when(a.created))}</td></tr>`).join('');
  const rec = i.alerts.find(a => a.recommended)?.recommended;
  return `<details class="finding-items"><summary>Alerts (${esc(i.alerts.length)})</summary><div class="table-wrap"><table class="event-table" data-table-id="incident-alerts"><thead><tr><th>Alert</th><th>Severity</th><th>Status</th><th>Product</th><th>ATT&amp;CK</th><th>Created</th></tr></thead><tbody>${rows}</tbody></table></div>${rec ? `<p class="finding-note"><b>Microsoft recommends:</b> ${esc(rec)}</p>` : ''}</details>`;
}

function detectionsHtml(i, esc) {
  if (!i.detections?.length) return '';
  const rows = i.detections.map(d => `<tr><td>${esc(d.type)}</td><td>${esc(SEV_LABEL[d.level])}</td><td>${esc(d.state)}</td><td>${esc(d.activity)}${d.timing ? ` · ${esc(d.timing)}` : ''}</td><td>${esc(d.ip || '')}</td><td>${esc(d.location || '')}</td><td>${esc(when(d.when))}</td></tr>`).join('');
  return `<details class="finding-items"><summary>Risk detections (${esc(i.detections.length)})</summary><div class="table-wrap"><table class="event-table" data-table-id="incident-detections"><thead><tr><th>Detection</th><th>Level</th><th>State</th><th>Activity</th><th>IP</th><th>Location</th><th>Detected</th></tr></thead><tbody>${rows}</tbody></table></div></details>`;
}

export function itemHtml(i, idx, { esc, external }) {
  const meta = [i.source, i.status, i.assignedTo ? `Assigned to ${i.assignedTo}` : 'Unassigned', i.classification, i.determination, `Updated ${when(i.updated)}`].filter(Boolean);
  if (i.kind !== 'incident') meta.splice(2, 1);
  const mitre = i.mitre.length ? `<p class="incident-mitre">ATT&amp;CK: ${i.mitre.map(t => `<code>${esc(t)}</code>`).join(' ')}</p>` : '';
  const related = i.related?.length ? `<p class="finding-note incident-related"><b>Same user or device in ${esc(i.related.length)} other item${i.related.length === 1 ? '' : 's'}:</b> ${i.related.map(r => esc(r.title)).join('; ')}</p>` : '';
  return `<article class="finding finding-${i.active ? 'open' : 'pass'} sev-${esc(SEV_CLASS[i.severity])} incident" data-incident="${esc(i.id)}">
<header class="finding-head"><span class="finding-sev">${esc(SEV_LABEL[i.severity])}</span><span class="finding-area">${esc(meta.join(' · '))}</span><h3>${esc(i.title)}</h3></header>
${i.detail ? `<p class="finding-why">${esc(i.detail)}</p>` : ''}${mitre}${related}
${entitiesHtml(i, idx, esc)}
<div class="finding-actions">${i.link ? external(i.link, i.kind === 'incident' ? 'Open in Defender' : i.source === 'Identity Protection' ? 'Open in Entra' : 'Open alert in Defender') : ''}</div>
${alertsHtml(i, esc, external)}${detectionsHtml(i, esc)}</article>`;
}

export function incidentsHtml(st, filter, h) {
  const { esc, emptyBox } = h;
  const picker = `<label class="posture-picker">Show <select data-incident-filter>${FILTERS.map(([v, l]) => `<option value="${v}"${v === filter ? ' selected' : ''}>${esc(l)}</option>`).join('')}</select></label>`;
  const head = `<div class="panel-heading"><div><h2>Incident queue</h2><p>Read from Microsoft Graph with your sign-in: Defender XDR incidents and alerts, and Identity Protection risky users and detections. Read-only: classify, assign and close in the Defender or Entra portal.</p></div><div class="posture-controls">${picker}<button type="button" class="btn" data-incidents-refresh>Refresh</button></div></div>`;
  if (!st || st.loading) return head + emptyBox('Reading Defender XDR and Identity Protection…');
  if (st.error) return head + emptyBox(st.error);
  const d = st.data, shown = filterItems(d.items, filter);
  const chips = ['high', 'medium', 'low', 'informational'].filter(s => d.tally[s]).map(s => `<span class="findings-chip sev-${SEV_CLASS[s]}">${esc(d.tally[s])} ${esc(SEV_LABEL[s])}</span>`).join('') || '<span class="findings-chip sev-pass">Nothing open</span>';
  const summary = `<div class="findings-summary">${chips}<span class="muted">${esc(d.items.filter(i => i.active).length)} open · ${esc(d.total)} in the last ${esc(d.days)} days · read ${esc(when(d.generated))}</span></div>`;
  const allDown = d.sources.every(s => s.status !== 'ok');
  const setup = allDown ? `<div class="posture-off"><p class="finding-reason">None of the four sources could be read.</p><p class="account-note">Run Grant-E360IncidentScopes.ps1 once (it adds four read-only delegated permissions), make sure your account has the Security Reader role, then sign out and sign in again.</p></div>` : '';
  const more = d.more ? `<p class="account-note">${esc(d.more)} more not shown; the Defender portal lists them all.</p>` : '';
  const list = shown.length ? `<div class="findings-list">${shown.map(i => itemHtml(i, d.items.indexOf(i), h)).join('')}</div>` : (allDown ? '' : emptyBox(filter === 'open' ? 'Nothing open. Choose "All, including resolved" to see closed items.' : 'Nothing matches this filter.'));
  return head + summary + sourcesHtml(d.sources, esc) + setup + list + more;
}

export function createIncidentsView({ api, esc, external, emptyBox, onPerson, onDevice }) {
  const h = { esc, external, emptyBox };
  let st = null, filter = 'open', active = false;
  const el = () => document.querySelector('#incidents-content');
  const render = () => { if (active) el().innerHTML = incidentsHtml(st, filter, h); };
  async function load() {
    st = { loading: true }; render();
    try { st = { data: await api('/api/incidents') }; } catch (e) { st = { error: e.message }; }
    render();
  }
  const pick = (attr, list) => { const [i, n] = String(attr).split(':').map(Number); return st?.data?.items?.[i]?.[list]?.[n]; };
  document.addEventListener('click', e => {
    if (!active) return;
    if (e.target.closest('[data-incidents-refresh]')) load();
    const u = e.target.closest('[data-incident-user]');
    if (u) { const p = pick(u.dataset.incidentUser, 'users'); if (p?.id) onPerson({ id: p.id, type: 'user', name: p.name, subtitle: p.upn || '' }); }
    const d = e.target.closest('[data-incident-device]');
    if (d) { const x = pick(d.dataset.incidentDevice, 'devices'); if (x) onDevice(x); }
  });
  document.addEventListener('change', e => { if (active && e.target.matches('[data-incident-filter]')) { filter = e.target.value; render(); } });
  return {
    setActive(on) {
      active = on;
      document.querySelector('#incidents-panel').hidden = !on;
      if (!on) return;
      if (st && !st.error) render(); else load();
    },
  };
}
