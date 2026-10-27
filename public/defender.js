// Defender tab: process events for the selected user, from GET /api/defender. Loads once per user and timeframe
// (not with the entity report). Default 1 day keeps most results under Defender's 1,000-row cap.
import { pageSlice, pagerHtml, wirePager, DEFAULT_PAGE_SIZE } from './paging.js';
import { partialMessage } from './access-text.js';
export const DEFENDER_DAYS = [1, 3, 7, 14, 30];
export function createDefenderEvents({ api, esc, external, entity, session, showEvidence }) {
  const root = document.querySelector('#defender-events');
  const st = { page: 0, size: DEFAULT_PAGE_SIZE };
  let days = 1, report = null, loadedKey = null, loading = false, error = '', generation = 0;
  const key = () => `${entity()?.id}|${days}`;
  async function load() {
    const e = entity();
    if (!e || e.type !== 'user') return render();
    const id = ++generation; loading = true; error = ''; loadedKey = key(); render();
    try { const r = await api(`/api/defender?${new URLSearchParams({ id: e.id, days: String(days) })}`); if (id !== generation) return; report = r; st.page = 0; }
    catch (err) { if (id !== generation) return; report = null; error = err.message; loadedKey = null; }
    finally { if (id === generation) { loading = false; render(); } }
  }
  function render() {
    const e = entity();
    const select = `<label>Timeframe <select id="defender-days">${DEFENDER_DAYS.map(d => `<option value="${d}"${d === days ? ' selected' : ''}>Last ${d === 1 ? '24 hours' : `${d} days`}</option>`).join('')}</select></label>`;
    const head = `<div class="panel-heading"><div><h2>Defender process events <span class="count">${report ? report.events.length : ''}</span></h2><p>Process creations on onboarded devices where the selected user is the account or initiating account (Defender advanced hunting). Defender returns at most 1,000 events per query, so a short timeframe is the default.</p></div><div class="account-actions">${select}<button type="button" class="btn" id="defender-reload">Reload</button></div></div>`;
    if (!e || e.type !== 'user') { root.innerHTML = `<section class="panel">${head}<div class="inline-empty">${e ? 'Defender process events are matched by user principal name, so they are available for users only.' : 'Pick a user first.'}</div></section>`; return wire(); }
    if (session()?.mode === 'personal') { root.innerHTML = `<section class="panel">${head}<div class="inline-empty">Defender hunting needs an organizational connection.</div></section>`; return wire(); }
    const banner = report && report.partial ? `<div class="notice">${esc(partialMessage(report))}</div>` : report?.unavailable?.length ? `<div class="notice">${esc(`Not available: ${report.unavailable.map(u => `${u.source} (${u.reason})`).join('; ')}.`)}</div>` : '';
    const rows = report?.events || [];
    const slice = pageSlice(rows, st.page, st.size); st.page = slice.page;
    const body = loading ? '<div class="inline-empty">Loading Defender events…</div>' : error ? `<div class="notice error">${esc(error)}</div>` : !report ? '' : rows.length ? `<div class="table-wrap table-scroll"><table class="event-table defender-table" data-table-id="defender"><thead><tr><th class="col-action"><span class="sr-only">Evidence</span></th><th>Time <span class="muted">UTC</span></th><th>Process</th><th>Device</th><th class="col-cmd">Command line</th></tr></thead><tbody>${slice.rows.map((r, i) => `<tr><td class="col-action"><button type="button" class="btn" data-defender-evidence="${i}">Evidence</button></td><td>${esc(r.time)}</td><td>${esc(r.title)}<small>${esc(r.account || '')}</small></td><td>${esc(r.device || '')}</td><td class="col-cmd"><code>${esc(r.command || '')}</code></td></tr>`).join('')}</tbody></table></div>${pagerHtml('defender', slice, 'events')}` : `<div class="inline-empty">No process events for this user in the ${days === 1 ? 'last 24 hours' : `last ${days} days`}. An empty result does not prove no activity.</div>`;
    root.innerHTML = `<section class="panel">${head}${banner}${body}<p class="panel-footnote">${external('https://security.microsoft.com/v2/advanced-hunting', 'Open advanced hunting')}</p></section>`;
    wire();
    wirePager(root, 'defender', st, render);
    root.querySelectorAll('[data-defender-evidence]').forEach(b => b.onclick = () => { const r = slice.rows[Number(b.dataset.defenderEvidence)]; showEvidence({ title: r.title, time: r.time, id: r.id, actor: r.account, target: r.device, direction: 'Actor', command: r.command, link: r.link, linkLabel: 'Open advanced hunting', query: report.query, evaluatedPolicies: [], evidence: r.evidence }); });
  }
  function wire() {
    const sel = root.querySelector('#defender-days'), reload = root.querySelector('#defender-reload');
    if (sel) sel.onchange = () => { days = Number(sel.value); load(); };
    if (reload) { reload.disabled = loading || !entity() || entity().type !== 'user'; reload.onclick = () => load(); }
  }
  return { setActive(active) { if (!active) return; if (loadedKey !== key() && !loading) load(); else render(); } };
}
