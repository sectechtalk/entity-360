import { pageSlice, pagerHtml, wirePager, DEFAULT_PAGE_SIZE } from './paging.js';
import { multiSelectHtml, wireMultiSelects, filterOptions, applyFilters } from './multiselect.js';
import { GROUP_KINDS, ROLE_KINDS, ACCESS_MEMBERSHIPS, accessRows, accessLink, accessType, roleTiming, isRoleRow } from './group-types.js';
import { partialMessage } from './access-text.js';
import { entraDeviceLink, intuneDeviceLink, intuneMatch, PIM_ACTIVATION_LINKS } from './device-links.js';
export function createAccountView({ api, session, esc, external, onSources, openConnection }) {
  const $ = s => document.querySelector(s);
  let report, snapshot, active = false, generation = 0;
  const unknown = v => v === null || v === undefined || v === '' ? 'Not returned' : String(v);
  const rows = list => list.map(([key, value]) => `<tr><th scope="row">${esc(key)}</th><td>${esc(unknown(value))}</td></tr>`).join('');
  const table = body => `<div class="table-wrap"><table class="account-table">${body}</table></div>`;
  const box = (title, body) => `<section class="panel account-card"><div class="panel-heading"><h2>${esc(title)}</h2></div>${body}</section>`;
  function status(message) { $('#account-status').textContent = message; }
  function render() {
    $('#account-export').disabled = !report && !snapshot;
    const viewer = session();
    $('#account-local-host').textContent = `Dashboard server: ${viewer?.serverHost || 'Unknown'}. Collect server host inspects that machine, not a remote browser.`;
    $('#account-collect').disabled = !viewer?.localCollectionSupported;
    $('#account-identity').innerHTML = report ? box('Microsoft identity signed into this dashboard', table(rows([['Account', report.identity.upn], ['Display name', report.identity.name], ['Object ID', report.identity.id], ['Tenant', report.identity.tenant], ['User type', report.identity.userType], ['Evidence', report.mode === 'demo' ? 'Fictional demo data' : 'Microsoft Graph /me, delegated session']])) + `<p class="account-note">${report.notes.map(esc).join(' ')}</p>`) : box('Microsoft identity', '<p>Nothing collected yet. Choose Check my account above to read your own account with your signed-in permissions.</p>');
    const out = { access: '', device: '', signins: '' };
    if (report) {
      const s = report.sections;
      if (s.licenses) out.access += box('Licenses & enabled services', s.licenses.length ? s.licenses.map(l => `<details class="license-sku"><summary><strong>${esc(l.sku)}</strong> <span class="muted">${l.plans.length} services</span></summary>${table('<thead><tr><th>Service</th><th>Provisioning status</th></tr></thead><tbody>' + l.plans.map(p => `<tr><td>${esc(p.name)}${p.appliesTo === 'Company' ? ' (tenant service)' : ''}</td><td>${esc(p.status)}</td></tr>`).join('') + '</tbody>')}</details>`).join('') : '<p>No license details returned by this successful query.</p>');
      if (s.groups || s.roles) out.access += box('Group memberships and Role assignments', '<div id="my-groups"></div>');
      if (s.authentication) out.access += box('Registered authentication methods', table(s.authentication.map(m => `<tr><td>${esc(m.type)}</td><td>${esc(m.name || 'Name not returned')}</td><td>${esc(m.model)}<small>${esc(m.aaguid)}</small>${m.aaguid ? external('https://github.com/passkeydeveloper/passkey-authenticator-aaguids', 'AAGUID reference lookup') : ''}</td></tr>`).join('')) + '<p>AAGUID reference is community naming information. This view does not automatically verify attestation or compare the live repository.</p>');
      if (s.devices) out.device += box('Entra devices registered to this account', '<p class="account-note device-explain">From Microsoft Graph /me/registeredDevices: devices where you are the registered user. Not included: devices you only own, devices joined by Autopilot or a device enrollment manager (DEM) account, and hybrid joined devices with no registered user. Up to 10 result pages are read.</p>' + deviceTable(s.devices, false, s.intune));
      if (s.intune) out.device += box('Intune-managed devices associated with this account', '<p class="account-note device-explain">From Microsoft Graph /me/managedDevices: devices where you are the Intune primary user. Not included: shared or userless devices, and devices whose primary user is someone else. Up to 10 result pages are read.</p>' + deviceTable(s.intune, true));
      if (s.conditionalAccess) out.access += box('Conditional Access policies that apply to me', `<p>Evaluated by Microsoft (What If) for SharePoint, Exchange and Azure management. Device platform, location and device state are not supplied, so results can be incomplete. Event enforcement still requires sign-in evidence.</p>${table(s.conditionalAccess.map(p => `<tr><td>${external('https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/PolicyBlade/policyId/' + encodeURIComponent(p.id), p.name)}</td><td>${esc(p.state)}</td><td>${esc(p.targeting)}${p.groupsComplete ? '' : ' · Group evidence incomplete'}</td></tr>`).join(''))}`);
      if (s.signins) out.signins += box('Authentication & event-time policy evidence', `<p>${esc(report.range.from)} → ${esc(report.range.to)} UTC. Missing authentication details are not proof that a method was unused.</p>${table(s.signins.map(e => `<tr><td>${esc(e.time)}</td><td>${esc(e.app)}<small>Code ${esc(unknown(e.code))}</small></td><td>${e.methods.map(m => `${esc(m.method)}: ${m.succeeded === true ? 'Succeeded' : m.succeeded === false ? 'Not completed' : 'Not returned'} · ${esc(m.detail)}`).join('<br>') || 'Authentication steps not returned'}<small>${esc(e.reason)}</small></td><td>${e.policiesReturned ? e.policies.map(p => `${esc(p.name)}: ${esc(p.result)}`).join('<br>') || 'No evaluations returned' : 'Policy results not returned'}</td></tr>`).join(''))}`);
    }
    // Each My account page shows one slice of the same report; nothing is repeated across them.
    const why = report ? 'This section was not returned. The source may be unavailable or your account lacks the permission to read it.' : 'Nothing collected yet. Choose Check my account above.';
    const elevate = box('Elevate (PIM)', `<p>Activate an eligible role or group membership in Privileged Identity Management. Opens in a new tab.</p><div class="card-actions">${PIM_ACTIVATION_LINKS.map(([label, url]) => external(url, label)).join(' ')}</div>`);
    $('#my-access').innerHTML = elevate + (out.access || box('My access', `<p>${esc(why)}</p>`));
    renderGroups();
    $('#account-cloud').innerHTML = out.device || box('My devices in Entra and Intune', `<p>${esc(why)}</p>`);
    $('#my-signins').innerHTML = out.signins || box('My sign-ins', `<p>${esc(report?.sections?.signins ? 'No sign-ins in the selected timeframe.' : why)}</p>`);
    const s2 = report?.sections || {};
    const card = (title, value, note, go, label) => `<section class="panel summary-card"><h3>${esc(title)}</h3><div class="summary-value">${esc(value)}</div><p>${esc(note)}</p><button class="btn" data-go="${go}">${esc(label)}</button></section>`;
    $('#my-summary-cards').innerHTML = report ? [
      card('My sign-ins', s2.signins ? s2.signins.length : 'n/a', s2.signins ? `In the last ${$('#account-hours').selectedOptions[0]?.textContent.toLowerCase() || 'timeframe'}` : 'Not returned', 'my-signins', 'Open My sign-ins'),
      card('Conditional Access policies', s2.conditionalAccess ? s2.conditionalAccess.length : 'n/a', s2.conditionalAccess ? 'Apply to me (Microsoft What If)' : 'Not returned', 'my-access', 'Open My access'),
      card('My devices', (s2.devices || []).length + (s2.intune || []).length, `${(s2.intune || []).filter(d => String(d.compliance).toLowerCase() === 'compliant').length} compliant in Intune`, 'my-device', 'Open My device'),
    ].join('') : '';
    renderSnapshot();
    if (active) onSources(report?.sources || []);
  }
  // Group memberships: a paged, filterable table (same multi-select and pager conventions as the entity pages).
  const groupState = { page: 0, size: DEFAULT_PAGE_SIZE, fx: { excluded: {}, open: null, sort: null } };
  const GROUP_COLS = [
    { key: 'mg.kind', label: 'Type', get: r => r.kind, known: [...ROLE_KINDS, ...GROUP_KINDS] },
    { key: 'mg.assign', label: 'Assignment', get: r => r.membershipType, known: ['Assigned', 'Dynamic'] },
    { key: 'mg.membership', label: 'Membership', get: r => r.membership, known: ACCESS_MEMBERSHIPS },
    { key: 'mg.source', label: 'Source', get: r => r.source, known: ['Direct', 'Cloud (Entra ID)', 'Synced from on-premises AD'] },
  ];
  function renderGroups() {
    const root = document.querySelector('#my-groups'); if (!root) return;
    const all = accessRows(report?.sections?.groups || [], report?.sections?.roles || []);
    const bar = `<div class="msel-bar">${GROUP_COLS.map(c => multiSelectHtml({ key: c.key, label: c.label, options: filterOptions(c.known, all.map(c.get)), excluded: groupState.fx.excluded[c.key], open: groupState.fx.open === c.key, sort: groupState.fx.sort })).join('')}</div>`;
    const shown = applyFilters(all, GROUP_COLS, groupState.fx.excluded, groupState.fx.sort), slice = pageSlice(shown, groupState.page, groupState.size);
    groupState.page = slice.page;
    const cell = r => { const t = roleTiming(r); return `<tr><td>${external(accessLink(r), r.name || r.id || 'Open')}${isRoleRow(r) && r.scope ? `<small>Scope: ${esc(r.scope)}</small>` : ''}</td><td>${esc(accessType(r))}</td><td>${esc(r.membership)}</td><td>${esc(t.granted)}</td><td>${esc(t.remaining)}</td><td>${esc(r.source)}</td></tr>`; };
    root.innerHTML = all.length ? `${bar}<div class="table-wrap table-scroll"><table class="account-table"><thead><tr><th>Name</th><th>Type</th><th>Membership</th><th>Granted</th><th>Remaining</th><th>Source</th></tr></thead><tbody>${slice.rows.map(cell).join('') || '<tr><td colspan="6">No rows match the filters.</td></tr>'}</tbody></table></div>${pagerHtml('my-groups', slice, 'rows')}` : '<p>No group memberships or role assignments returned.</p>';
    wireMultiSelects(root, groupState.fx, () => { groupState.page = 0; renderGroups(); });
    wirePager(root, 'my-groups', groupState, renderGroups);
  }
  // Entra devices: Open (their own Entra device page) plus Open in Intune when the device is managed and its Intune record is readable.
  function deviceLinks(d, managed, intune) {
    if (managed) { const i = intuneDeviceLink(d.id); return i ? external(i, 'Open in Intune') : 'Intune ID not returned'; }
    const entra = entraDeviceLink(d), m = intuneMatch(d, intune), i = m && intuneDeviceLink(m.id);
    return `${entra ? external(entra, 'Open') : 'Object ID not returned'}${i ? ` · ${external(i, 'Open in Intune')}` : d.managed ? ' · Managed (Intune record not readable)' : ''}`;
  }
  function deviceTable(devices, managed, intune = []) {
    if (!devices.length) return '<p>No devices returned by this successful query. This does not establish the browser device is unregistered.</p>';
    return table('<thead><tr><th>Device</th><th>Identity / OS</th><th>State</th></tr></thead><tbody>' + devices.map(d => `<tr><td>${esc(d.name)}<small>${deviceLinks(d, managed, intune)}</small></td><td>${esc(d.deviceId || 'Device ID not returned')}<small>${esc(d.os)} ${esc(d.version)}</small></td><td>${managed ? `${esc(d.compliance)} · ${esc(d.agent)}<small>Last sync: ${esc(d.lastSync)}</small>` : `${esc(d.trust || 'Trust type not returned')}<small>Managed: ${esc(unknown(d.managed))} · Compliant: ${esc(unknown(d.compliant))}</small>`}</td></tr>`).join('') + '</tbody>');
  }
  function renderSnapshot() {
    $('#account-clear-local').disabled = !snapshot;
    if (!snapshot) { $('#account-local').innerHTML = box('Local Windows evidence', '<p>No snapshot loaded. Download the collector and run it on the PC you want to investigate, then import its JSON. On a local installation, Collect server host is a shortcut.</p>'); return; }
    const age = Date.now() - Date.parse(snapshot.collectedAt);
    let text = 'Cloud-device correlation not established.';
    if (report?.mode === 'live') {
      const ids = snapshot.deviceIds.filter(d => d.tenantId.toLowerCase() === report.identity.tenant.toLowerCase());
      const all = [...(report.sections.devices || []), ...(report.sections.intune || [])];
      const matches = all.filter(d => ids.some(x => x.deviceId.toLowerCase() === String(d.deviceId).toLowerCase()));
      text = matches.length ? `Tenant + device ID match: ${matches.map(d => d.name).join(', ')}. Snapshot identity is still user-supplied evidence.` : 'No tenant + device ID match in returned cloud records. Missing permissions or incomplete records can prevent correlation.';
    }
    const fact = key => snapshot.facts.find(f => f.key === key && f.status !== 'unavailable')?.value;
    const findings = [];
    if (fact('Windows account source') === 'MicrosoftAccount') findings.push('Windows reports a personal Microsoft-account-backed profile. This is separate from the tenant account signed into Entity 360.');
    if (fact('AzureAdJoined') === 'NO' && fact('WorkplaceJoined') === 'YES') findings.push('This Windows profile has workplace registrations, while the PC is not Entra joined. Registration, join, and Intune management are different states.');
    if (fact('NgcSet') === 'NO') findings.push('No Windows Hello key was reported in the collector’s user context. This does not inventory every password manager’s passkeys.');
    if (fact('NgcSet') === 'YES') findings.push('A Windows Hello key was reported for this Windows user. It does not prove a passkey or Hello for Business credential exists for the selected tenant account.');
    if (fact('Endpoint sensor service') === 'Stopped') findings.push('The Defender for Endpoint sensor service was stopped at collection time. A Microsoft 365 license or active antivirus alone does not establish endpoint onboarding.');
    if (fact('Microsoft MDM enrollment records') === 0) findings.push('No Microsoft MDM enrollment records were found by this local check. Use matching Intune cloud records to establish management status.');
    $('#account-local').innerHTML = box(`Local snapshot: ${snapshot.host}`, table(rows([['Windows account', snapshot.windowsAccount], ['SID', snapshot.sid], ['Collected', snapshot.collectedAt], ['Provenance', snapshot.provenance], ['Cloud comparison', text], ['Freshness', age > 3600000 ? 'Older than one hour; collect again before troubleshooting current state.' : 'Recent snapshot; configuration can change afterward.']])) + '<p>Windows account, cached Microsoft identities, and the browser’s tenant account are separate evidence. A cached email or matching name does not prove identity equivalence.</p>') + box('What these findings mean for troubleshooting', `<ul class="account-findings">${findings.map(f => `<li>${esc(f)}</li>`).join('') || '<li>No automatic conclusion from the returned facts. Inspect the source evidence.</li>'}</ul>`) + [...new Set(snapshot.facts.map(f => f.area))].map(area => box(area, table('<thead><tr><th>Check</th><th>Value</th><th>Source / availability</th></tr></thead><tbody>' + snapshot.facts.filter(f => f.area === area).map(f => `<tr><th scope="row">${esc(f.key)}</th><td class="account-value">${String(f.value).length > 600 ? `<details><summary>View collected text</summary><pre>${esc(f.value)}</pre></details>` : esc(unknown(f.value))}</td><td>${esc(f.source)}<small>${esc(f.status)}</small></td></tr>`).join('') + '</tbody>'))).join('');
  }
  async function run() {
    const current = ++generation;
    $('#account-run').disabled = true; status('Reading the signed-in account’s authorized evidence…');
    try { const r = await api('/api/account/report?hours=' + encodeURIComponent($('#account-hours').value)); if (current !== generation) return; report = r; render(); status(r.partial ? partialMessage(r) : (r.unavailable || []).length ? `Account evidence collected. Not available: ${r.unavailable.map(u => `${u.source} (${u.reason})`).join('; ')}.` : 'Account evidence collected.'); }
    catch(e) { if (current === generation) status(e.message); }
    finally { if (current === generation) $('#account-run').disabled = false; }
  }
  $('#account-run').onclick = run;
  $('#account-connect').onclick = openConnection;
  $('#account-collect').onclick = async () => {
    const current = generation; $('#account-collect').disabled = true; status('Reading Windows configuration on the dashboard server host…');
    try { const r = await api('/api/device/collect', { method: 'POST', body: '{}' }); if (current !== generation) return; snapshot = r; render(); status(`Local evidence collected on ${r.host}. Verify that is the machine you are investigating.`); }
    catch(e) { status(e.message); }
    finally { $('#account-collect').disabled = !session()?.localCollectionSupported; }
  };
  $('#account-import').onchange = async event => {
    const current = generation, file = event.target.files[0]; if (!file) return;
    try { if (file.size > 256 * 1024) throw new Error('Snapshot must be 256 KB or smaller.'); const raw = JSON.parse(await file.text()); const r = await api('/api/device/import', { method: 'POST', body: JSON.stringify(raw) }); if (current !== generation) return; snapshot = r; render(); status(`Imported evidence from ${r.host}; verify collection time and Windows account.`); }
    catch(e) { status(e.message); }
    finally { event.target.value = ''; }
  };
  $('#account-clear-local').onclick = () => { snapshot = null; renderSnapshot(); status('Local snapshot cleared.'); };
  $('#account-export').onclick = () => {
    const blob = new Blob([JSON.stringify({ cloud: report || null, local: snapshot || null }, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = url; a.download = 'Entity360-account-device.json'; a.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
  };
  return { run, reset() { generation++; report = null; snapshot = null; $('#account-run').disabled = false; status(''); render(); }, setActive(value) { active = value; if (active) render(); } };
}
