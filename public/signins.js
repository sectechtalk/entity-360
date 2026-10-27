import { signInColumns, signInCells } from './signin-columns.js';
import { applyFilters, filterOptions, multiSelectHtml, wireMultiSelects, filtersIntoHeaders } from './multiselect.js';
import { partialMessage } from './access-text.js';
export function createSignInLookup({ api, session, entity, esc, external, resultBadge, showEvidence, onSources }) {
  const $ = selector => document.querySelector(selector);
  let report = null, requestId = 0, page = 0, active = false, selected = null, controller;
  const fx = { excluded: {}, open: null, sort: { key: 'si.date', dir: 'desc' } };
  let pageSize = 20; // rows per page: 20, 50 or 100 (#signin-page-size)
  const time = value => new Date(value).toLocaleString('en-GB', { timeZone: 'UTC', hour12: false });
  const feedback = (message, error = false) => { $('#signin-feedback').textContent = message; $('#signin-feedback').classList.toggle('error-text', error); };
  const chosenPolicies = event => event.policies.filter(p => report.options.allPolicies || p.status !== 'notApplied');
  function populate() {
    const s = session();
    if (!s) return;
    if (!$('#signin-users').value.trim()) $('#signin-users').value = entity()?.type === 'user' ? entity().subtitle : s.signInDefaults.join(', ');
    $('#signin-use-selected').disabled = entity()?.type !== 'user';
    $('#signin-use-defaults').textContent = s.mode === 'demo' ? 'Use demo users' : 'Use lab users';
    $('#signin-mode-note').textContent = s.mode === 'demo' ? 'Demo mode · fictional records' : 'Uses your signed-in Microsoft account · read only';
  }
  function reset() {
    requestId++; controller?.abort(); report = null; page = 0; selected = null;
    $('#signin-users').value = ''; $('#signin-results').hidden = true; $('#signin-rows').innerHTML = ''; $('#signin-user-status').innerHTML = ''; $('#signin-summary').innerHTML = ''; $('#signin-group-details').innerHTML = ''; $('#signin-group-details').hidden = true; $('#signin-run').disabled = false; $('#signin-run').textContent = 'Look up sign-ins'; feedback('');
    if (active) populate();
  }
  async function run() {
    if (!$('#signin-lookup-form').reportValidity()) return;
    const hours = Number($('#signin-lookback').value) * ($('#signin-lookback-unit').value === 'days' ? 24 : 1);
    if (!Number.isFinite(hours) || hours < 0.25 || hours > 2160) { feedback('Choose a lookback from 15 minutes to 90 days.', true); return; }
    const options = { users: $('#signin-users').value, hours, detail: $('#signin-detail').checked, allPolicies: $('#signin-all-policies').checked, beta: $('#signin-beta').checked, nonInteractive: $('#signin-noninteractive').checked };
    const current = ++requestId;
    controller?.abort(); controller = new AbortController();
    report = null; selected = null; page = 0; $('#signin-results').hidden = true; $('#signin-rows').innerHTML = ''; $('#signin-group-details').hidden = true; $('#signin-group-details').innerHTML = ''; if (active) onSources([]);
    $('#signin-run').disabled = true; $('#signin-run').textContent = 'Looking up…'; feedback('Reading sign-ins for the requested timeframe…');
    try {
      const result = await api('/api/signins/lookup', { method: 'POST', body: JSON.stringify(options), signal: controller.signal });
      if (current !== requestId) return;
      report = result; $('#signin-results').hidden = false;
      feedback(result.partial ? partialMessage(result) : 'Lookup complete.');
      if (active) onSources(result.sources);
      render();
    } catch (error) { if (current === requestId) feedback(error.message, true); }
    finally { if (current === requestId) { $('#signin-run').disabled = false; $('#signin-run').textContent = 'Look up sign-ins'; } }
  }
  function render() {
    $('#signin-summary').innerHTML = `<strong>${report.totalEvents} observed sign-ins · ${report.groups.length} ${report.options.detail ? 'rows' : 'groups'}</strong><span>Last ${report.options.hours} hours · ${esc(time(report.range.from))} – ${esc(time(report.range.to))} UTC</span><span>${report.mode === 'demo' ? 'Fictional demo data' : 'Live, viewer-authorized results'}${report.options.beta ? ' · Beta requested; API version shown per event' : ' · Graph v1.0'}${report.options.nonInteractive ? ' · Includes background authentication' : ' · Interactive sign-ins'}</span>`;
    $('#signin-user-status').innerHTML = report.users.map(user => `<div class="signin-user-status ${user.status !== 'complete' ? 'incomplete' : ''}"><strong>${esc(user.user)}</strong><span>${user.status === 'complete' ? `${user.count} observed events` : user.status === 'partial' ? `${user.count} events · incomplete` : 'Records unavailable'}</span>${user.notes.map(n => `<p>${esc(n)}</p>`).join('')}</div>`).join('');
    const cols = signInColumns(), all = applyFilters(report.groups, cols, fx.excluded, fx.sort);
    const box = $('#signin-filters');
    box.innerHTML = cols.filter(c => c.filter !== false).map(c => multiSelectHtml({ key: c.key, label: c.label, options: filterOptions([], report.groups.map(c.get)), excluded: fx.excluded[c.key], open: fx.open === c.key, sort: fx.sort })).join('');
    wireMultiSelects(box, fx, () => { page = 0; render(); document.querySelector('#signins-page [data-msel][open] summary')?.focus(); });
    filtersIntoHeaders(box, document.querySelector('table[data-table-id="signins"]'));
    const rows = all.slice(page * pageSize, (page + 1) * pageSize);
    $('#signin-rows').innerHTML = rows.map(g => {
      const c = signInCells(g.event), idx = report.groups.indexOf(g);
      return `<tr data-signin-group="${idx}" tabindex="0" title="Open details" class="${selected === idx ? 'selected' : ''}"><td>${esc(time(g.last))}${g.count > 1 ? ` <span class="repeat-count">×${g.count}</span>` : ''}</td><td><code>${esc(c.requestId)}</code></td><td>${esc(c.app)}</td><td>${resultBadge(c.status)}</td><td>${esc(c.code)}</td><td>${esc(c.ip)}</td><td>${esc(c.location)}</td><td>${esc(c.ca)}</td><td>${esc(c.agent)}</td><td>${esc(c.authReq)}</td></tr>`;
    }).join('') || '<tr><td colspan="10" class="inline-empty">No observed sign-ins returned or none match the filters. Check each user’s query status above; unavailable records are not an empty successful result.</td></tr>';
    document.querySelectorAll('#signin-rows tr[data-signin-group]').forEach(tr => { const open = () => { selected = Number(tr.dataset.signinGroup); render(); renderDetails(); $('#signin-group-details').scrollIntoView?.({ block: 'nearest' }); }; tr.onclick = open; tr.onkeydown = ev => { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); open(); } }; });
    $('#signin-page-info').textContent = all.length ? `${page * pageSize + 1}–${Math.min((page + 1) * pageSize, all.length)} of ${all.length} ${report.options.detail ? 'events' : 'groups'}` : '0 result rows';
    $('#signin-prev').disabled = page === 0; $('#signin-next').disabled = (page + 1) * pageSize >= all.length;
  }
  function renderDetails() {
    const group = report.groups[selected]; if (!group) return;
    const e = group.event;
    $('#signin-group-details').hidden = false;
    $('#signin-group-details').innerHTML = `<h3>${esc(e.app)} · ${group.count} ${group.count === 1 ? 'event' : 'matching events'}</h3><dl class="evidence-grid"><dt>User</dt><dd>${esc(e.user)}</dd><dt>Resource</dt><dd>${esc(e.resource)}</dd><dt>Kind</dt><dd>${esc(e.kind)}</dd><dt>Result</dt><dd>${resultBadge(e.status || e.result)}${e.code !== null ? (e.code === 0 ? ' Code 0' : ` <button type="button" class="btn" data-error-code="${esc(e.code)}" aria-label="Look up error code ${esc(e.code)}">Code ${esc(e.code)} ↗</button>`) : ''}${e.reason ? `<br>${esc(e.reason)}` : ''}</dd><dt>Time span</dt><dd>${esc(time(group.first))} – ${esc(time(group.last))}</dd><dt>Correlation ID</dt><dd>${esc(e.correlationId || 'Not returned')}</dd><dt>Device</dt><dd>${esc([e.device.name, e.device.os, e.device.browser].filter(Boolean).join(' / ') || 'Not returned')}</dd><dt>Device ID</dt><dd>${esc(e.device.id || 'Not returned')}</dd><dt>Compliance</dt><dd>${e.device.compliant === null ? 'Not returned' : e.device.compliant ? 'Compliant' : 'Noncompliant'}</dd><dt>Managed</dt><dd>${e.device.managed === null ? 'Not returned' : e.device.managed ? 'Yes' : 'No'}</dd><dt>IP address</dt><dd>${esc(e.ip || 'Not returned')}</dd><dt>API version</dt><dd>${esc(e.version)}</dd></dl><div class="signin-detail-columns"><section><h3>Authentication methods</h3>${e.methods.length ? e.methods.map(a => `<p><strong>${esc(a.method)}</strong> · ${a.succeeded === null ? 'Result not returned' : a.succeeded ? 'Succeeded' : 'Not completed'}<br>${esc(a.detail)}${a.result ? `<br>${esc(a.result)}` : ''}</p>`).join('') : `<p>Not returned for this event.${e.version === 'v1.0' && !report.options.beta ? ' Request beta details or inspect Authentication Details in the source portal.' : ''}</p>`}</section><section><h3>Session rules</h3>${e.sessions.length ? e.sessions.map(s => `<p><strong>${esc(s.requirement)}</strong><br>${esc(s.detail)}</p>`).join('') : '<p>Not returned for this event. This does not mean no session rule applied.</p>'}</section><section><h3>Conditional Access policies</h3>${chosenPolicies(e).map(p => `<p>${external(p.link, p.name)}<br>${esc(p.status)}${p.detail ? ` · ${esc(p.detail)}` : ''}</p>`).join('') || `<p>${e.policiesReturned ? 'No policy results matching the display option.' : 'Policy evaluation details were not supplied by the source.'}</p>`}</section></div><h3>Individual records</h3><div class="signin-records">${group.events.map((event, i) => `<button type="button" class="btn" data-signin-record="${i}">${esc(time(event.time))} · View raw evidence</button>`).join('')}</div>${external(e.link, 'Open sign-in logs', 'btn')}`;
    document.querySelectorAll('[data-signin-record]').forEach(button => button.onclick = () => {
      const record = group.events[Number(button.dataset.signinRecord)];
      showEvidence({ title: `${record.app} sign-in`, time: record.time, id: record.id || 'Not returned', actor: record.user, target: record.resource, direction: 'Actor', ip: record.ip, correlationId: record.correlationId, link: record.link, linkLabel: 'Open sign-in logs', query: `User: ${record.user}\nTime (UTC): ${record.time}\nRecord ID: ${record.id || 'Not returned'}\nAPI version: ${record.version}`, evidence: record.evidence });
    });
  }
  $('#signin-lookup-form').onsubmit = event => { event.preventDefault(); run(); };
  $('#signin-lookback-unit').onchange = () => { $('#signin-lookback').max = $('#signin-lookback-unit').value === 'days' ? '90' : '2160'; };
  document.querySelectorAll('[data-signin-hours]').forEach(button => button.onclick = () => { $('#signin-lookback').value = button.dataset.signinHours; $('#signin-lookback-unit').value = 'hours'; $('#signin-lookback').max = '2160'; });
  $('#signin-use-selected').onclick = () => { if (entity()?.type === 'user') $('#signin-users').value = entity().subtitle; };
  $('#signin-use-defaults').onclick = () => { $('#signin-users').value = (session().labSignInUsers || session().signInDefaults).join(', '); };
  $('#signin-noninteractive').onchange = () => { if ($('#signin-noninteractive').checked) $('#signin-beta').checked = true; };
  $('#signin-beta').onchange = () => { if (!$('#signin-beta').checked) $('#signin-noninteractive').checked = false; };
  $('#signin-page-size').onchange = () => { pageSize = Number($('#signin-page-size').value) || 20; page = 0; render(); };
  $('#signin-prev').onclick = () => { page--; render(); };
  $('#signin-next').onclick = () => { page++; render(); };
  return { reset, run, setActive(value) { active = value; if (active) { populate(); onSources(report?.sources || []); } }, get sources() { return report?.sources || []; } };
}
