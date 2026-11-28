import { bindReportButton, REPORT_LABEL, REPORT_TIP } from './entity-pdf.js';
// Device lookup page (Investigate). Find a device by name, serial number or ID, then see its details and the people tied
// to it: Intune primary user, Entra registered owners and users, and (Graph beta) everyone who logged on to it.
// Data: GET /api/entities (search, devices only shown here) and GET /api/device/details (E360.Reader). Policy states come
// from GET /api/intune/device-states (E360.Intune). Pure helpers have no DOM so they are unit-tested.

const fmtUtc = t => { const d = new Date(t); return t && !Number.isNaN(d.getTime()) ? `${d.toLocaleString('en-GB', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', timeZone: 'UTC' })} UTC` : ''; };
const yesNo = v => (v === true ? 'Yes' : v === false ? 'No' : 'Not returned');
const gb = bytes => `${(bytes / 1024 ** 3).toFixed(0)} GB`;
const COMPLIANCE = { compliant: 'Compliant', noncompliant: 'Not compliant', ingraceperiod: 'In grace period', conflict: 'Conflict', error: 'Error', unknown: 'Unknown', configmanager: 'Configuration Manager' };
export const complianceText = v => (v ? COMPLIANCE[String(v).toLowerCase()] || String(v) : 'Not returned');

// Label/value pairs for the device card, in reading order. Missing values say so instead of disappearing.
export function deviceFacts(d) {
  const nr = v => (v === null || v === undefined || v === '' ? 'Not returned' : String(v));
  return [
    ['Operating system', [d.operatingSystem, d.osVersion].filter(Boolean).join(' ') || 'Not returned'],
    ['Manufacturer', nr(d.manufacturer)],
    ['Model', nr(d.model)],
    ['Serial number', d.intuneId ? nr(d.serialNumber) : 'Needs an Intune record'],
    ['Ownership', nr(d.ownership)],
    ['Join type', nr(d.joinType)],
    ['Compliance', complianceText(d.compliance)],
    ['Encrypted', d.intuneId ? yesNo(d.encrypted) : 'Needs an Intune record'],
    ['Enrolled in Intune', d.intuneId ? fmtUtc(d.enrolled) || 'Not returned' : 'Not enrolled'],
    ['Registered in Entra', d.entraId ? fmtUtc(d.registered) || 'Not returned' : 'Not in Entra'],
    ['Last Intune sync', d.intuneId ? fmtUtc(d.lastSync) || 'Not returned' : 'Not enrolled'],
    ['Last Entra sign-in', d.entraId ? fmtUtc(d.lastSignIn) || 'Not returned' : 'Not in Entra'],
    ['Device enabled', d.entraId ? yesNo(d.enabled) : 'Not in Entra'],
    ['Enrollment type', nr(d.enrollmentType)],
    ['Management agent', nr(d.managementAgent)],
    ...(d.storage ? [['Storage', d.storage.free != null ? `${gb(d.storage.free)} free of ${gb(d.storage.total)}` : gb(d.storage.total)]] : []),
  ];
}
export function peopleHtml(people, esc) {
  if (!people?.length) return '<div class="inline-empty">No person is linked to this device in Intune or Entra.</div>';
  return `<div class="table-wrap"><table class="event-table" data-table-id="device-people"><thead><tr><th>Person</th><th>User principal name</th><th>How they are linked</th><th>Last logon <span class="muted">UTC</span></th><th>Account</th><th></th></tr></thead><tbody>${people.map((p, i) => `<tr><td>${esc(p.name || p.id)}</td><td>${esc(p.upn || '')}</td><td>${esc(p.relations.join(', '))}</td><td>${esc(fmtUtc(p.lastLogOn))}</td><td>${p.enabled === false ? 'Disabled' : p.enabled === true ? 'Enabled' : ''}</td><td><button type="button" class="btn" data-device-person="${i}">Open person</button></td></tr>`).join('')}</tbody></table></div>`;
}
export const deviceQuery = entity => new URLSearchParams(Object.fromEntries([['entraId', entity?.entraId], ['intuneId', entity?.intuneId]].filter(([, v]) => v)));

export function createDeviceLookupView({ root, api, esc, external, resultBadge, onPerson, onReport = null, intuneReason = () => '', canSearch = () => true }) {
  const st = { active: false, query: '', results: null, searching: false, searchError: '', entity: null, report: null, loading: false, error: '', states: null };
  let version = 0, searchVersion = 0;
  const box = t => `<div class="inline-empty">${esc(t)}</div>`;
  function statesHtml() {
    const s = st.states;
    if (!s) return '';
    if (s.loading) return '<p class="muted">Loading policy states from Intune</p>';
    if (s.error) return `<p class="error-text">${esc(s.error)}</p>`;
    if (!s.rows.length) return box('Intune returned no compliance or configuration policy states for this device.');
    return `<div class="table-wrap"><table class="event-table" data-table-id="device-lookup-states"><thead><tr><th>Policy</th><th>Type</th><th>State</th></tr></thead><tbody>${s.rows.map(x => `<tr><td>${esc(x.name)}</td><td>${esc(x.kind)}</td><td>${resultBadge(x.state)}</td></tr>`).join('')}</tbody></table></div>`;
  }
  function detailHtml() {
    if (st.loading) return '<p class="muted" role="status">Loading the device from Entra and Intune</p>';
    if (st.error) return `<p class="error-text">${esc(st.error)}</p>`;
    const r = st.report;
    if (!r) return box('Search for a device by name, serial number, Entra device ID or Intune device ID. You can also open a device from a person’s Devices page.');
    const d = r.device;
    const reason = !d.intuneId ? 'This device has no Intune record' : intuneReason();
    const banner = [...(r.partial ? r.partialReasons.map(p => `${p.source}: ${p.reason}`) : []), ...r.unavailable.map(u => `${u.source}: ${u.reason}`)];
    return `${banner.length ? `<div class="banner">${banner.map(b => esc(b)).join('<br>')}</div>` : ''}
      <section class="panel device-card device-detail"><h3>${esc(d.name)}</h3>
        <dl>${deviceFacts(d).map(([k, v]) => `<dt>${esc(k)}</dt><dd>${k === 'Compliance' && d.compliance ? resultBadge(complianceText(d.compliance)) : esc(v)}</dd>`).join('')}</dl>
        <div class="card-actions"><button type="button" class="btn" id="device-lookup-states" ${reason ? `disabled title="${esc(reason)}"` : ''}>${st.states && !st.states.loading && !st.states.error ? 'Hide policy states' : 'Load policy states'}</button>${d.entraLink ? external(d.entraLink, 'Open in Entra', 'btn') : ''}${d.intuneLink ? external(d.intuneLink, 'Open in Intune', 'btn') : ''}${onReport ? `<button type="button" class="btn" id="device-lookup-pdf" data-busy="self" title="${esc(REPORT_TIP)}">${REPORT_LABEL}</button>` : ''}</div>
        <div class="device-states">${statesHtml()}</div>
        <p class="panel-footnote">IDs: Entra object ${esc(d.entraId || 'none')} · Entra device ${esc(d.deviceId || 'none')} · Intune ${esc(d.intuneId || 'none')}</p>
      </section>
      <section class="panel"><div class="panel-heading"><div><h2>People on this device <span class="count">${r.people.length}</span></h2><p>The Intune primary user, Entra registered owners and users, and people Intune saw log on. Open a person to investigate them.</p></div></div>${peopleHtml(r.people, esc)}</section>
      ${r.notes.length ? `<section class="panel"><ul class="page-note">${r.notes.map(n => `<li>${esc(n)}</li>`).join('')}</ul></section>` : ''}`;
  }
  function resultsHtml() {
    if (st.searching) return '<p class="muted" role="status">Searching Entra and Intune devices</p>';
    if (st.searchError) return `<p class="error-text">${esc(st.searchError)}</p>`;
    if (!st.results) return '';
    if (!st.results.length) return box('No device matched. Device names match from the start in Entra and anywhere in Intune; serial numbers must match exactly.');
    return `<div class="device-results" role="list">${st.results.map((e, i) => `<button type="button" role="listitem" class="search-option" aria-current="${st.entity && st.entity.id === e.id ? 'true' : 'false'}" data-device-result="${i}"><span><strong>${esc(e.name)}</strong><small>${esc(e.subtitle)}</small></span></button>`).join('')}</div>`;
  }
  function render() {
    if (!root) return;
    root.innerHTML = `<section class="panel"><form id="device-lookup-form" class="ondemand"><label for="device-lookup-q">Device name, serial number or ID</label> <input id="device-lookup-q" type="search" autocomplete="off" value="${esc(st.query)}" placeholder="e.g. LAPTOP-042 or CND1234XYZ"> <button type="submit" class="btn">Find device</button></form>${resultsHtml()}</section><div id="device-lookup-detail">${detailHtml()}</div>`;
    root.querySelector('#device-lookup-form').onsubmit = ev => { ev.preventDefault(); search(root.querySelector('#device-lookup-q').value); };
    root.querySelectorAll('[data-device-result]').forEach(b => { b.onclick = () => open(st.results[Number(b.dataset.deviceResult)]); });
    root.querySelectorAll('[data-device-person]').forEach(b => { b.onclick = () => { const p = st.report.people[Number(b.dataset.devicePerson)]; onPerson({ id: p.id, type: 'user', name: p.name || p.upn || p.id, subtitle: p.upn || '' }); }; });
    const sb = root.querySelector('#device-lookup-states'); if (sb) sb.onclick = loadStates;
    if (onReport && st.report?.device) { const d = st.report.device; bindReportButton(root.querySelector('#device-lookup-pdf'), { url: () => onReport.url(d), headers: onReport.headers, toast: onReport.toast }); }
  }
  async function search(q) {
    st.query = String(q || '').trim();
    if (!canSearch()) { st.searchError = 'Sign in first.'; render(); return; }
    if (st.query.length < 2) { st.searchError = 'Type at least two characters.'; st.results = null; render(); return; }
    const v = ++searchVersion; st.searching = true; st.searchError = ''; render();
    try {
      const data = await api(`/api/entities?q=${encodeURIComponent(st.query)}`);
      if (v !== searchVersion) return;
      st.results = (data.entities || []).filter(e => e.type === 'device');
      if (st.results.length === 1) { st.searching = false; open(st.results[0]); return; }
    } catch (e) { if (v === searchVersion) st.searchError = e.message; }
    finally { if (v === searchVersion) { st.searching = false; render(); } }
  }
  async function open(entity) {
    if (!entity) return;
    const v = ++version;
    st.entity = entity; st.report = null; st.error = ''; st.states = null; st.loading = true; render();
    try { const r = await api(`/api/device/details?${deviceQuery(entity)}`); if (v === version) st.report = r; }
    catch (e) { if (v === version) st.error = e.message; }
    finally { if (v === version) { st.loading = false; render(); } }
  }
  async function loadStates() {
    const id = st.report?.device?.intuneId;
    if (!id) return;
    if (st.states && !st.states.loading && !st.states.error) { st.states = null; render(); return; }
    st.states = { loading: true }; render();
    try { const r = await api(`/api/intune/device-states?${new URLSearchParams({ id })}`); st.states = { rows: r.states || [] }; }
    catch (e) { st.states = { error: e.message }; }
    render();
  }
  return {
    setActive(on) { st.active = on; if (on) render(); },
    open, search,
    reset() { version++; searchVersion++; Object.assign(st, { query: '', results: null, searching: false, searchError: '', entity: null, report: null, loading: false, error: '', states: null }); if (st.active) render(); },
    get state() { return st; },
  };
}
