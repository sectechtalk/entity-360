// Security hardening (TENANT > Security hardening, route #findings): ranked findings from data Entity 360 already reads, each with a playbook.
// Read-only, live connections only. Each fix opens the exact Entra page where the setting is changed.
export const FINDINGS_TITLE = ['Security hardening', 'What to fix first, ranked: Entra ID findings from Microsoft Graph, then AD posture for the on-premises forest. Each finding has a playbook.'];
const SEV_LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' };

function itemsHtml(f, { esc, external }) {
  if (!f.items.length) return '';
  const rows = f.items.map(i => `<tr><td>${i.link ? external(i.link, i.text, 'finding-link') : esc(i.text)}</td><td>${esc(i.detail)}</td></tr>`).join('');
  const more = f.more ? `<p class="account-note">${esc(f.more)} more not shown.${f.playbook.view ? ` ${esc(f.playbook.view.label)} lists them all.` : ' The PDF report lists the first 50 too; rerun after fixing these.'}</p>` : '';
  return `<details class="finding-items"><summary>Affected (${esc(f.count)})</summary><div class="table-wrap"><table class="event-table" data-table-id="findings-${esc(f.id)}"><thead><tr><th>Name</th><th>Detail</th></tr></thead><tbody>${rows}</tbody></table></div>${more}</details>`;
}

function cardHtml(f, h) {
  const { esc, external } = h;
  const pb = f.playbook;
  const status = f.status === 'open' ? `<span class="finding-count">${esc(f.count)}<small> affected</small></span>` : f.status === 'pass' ? '<span class="finding-pass">Passing</span>' : '<span class="finding-na">Could not check</span>';
  const reason = f.status === 'unavailable' ? `<p class="finding-reason">${esc(f.reason)}</p>` : '';
  const steps = `<details class="finding-playbook"${f.rank === 1 && !h.closed ? ' open' : ''}><summary>Playbook</summary><ol>${pb.steps.map(s => `<li>${esc(s)}</li>`).join('')}</ol></details>`;
  const actions = `<div class="finding-actions">${pb.fix ? external(pb.fix.url, pb.fix.label) : ''}${pb.view ? `<button type="button" class="btn" data-go="${esc(pb.view.key)}">See it in Entity 360</button>` : ''}${external(pb.guidance, 'Microsoft guidance')}</div>`;
  return `<article class="finding finding-${esc(f.status)} sev-${esc(f.severity)}" data-finding="${esc(f.id)}">
<header class="finding-head">${f.rank ? `<span class="finding-rank">#${esc(f.rank)}</span>` : ''}<span class="finding-sev">${esc(SEV_LABEL[f.severity])}</span>${f.area ? `<span class="finding-area">${esc(f.area)}${h.showDomain && f.domain ? ` · ${esc(f.domain)}` : ''}</span>` : ''}<h3>${esc(f.title)}</h3>${status}</header>
<p class="finding-why">${esc(f.why)}</p>${f.note && f.status !== 'unavailable' ? `<p class="finding-note">${esc(f.note)}</p>` : ''}${reason}
${f.status === 'pass' ? '' : actions + steps}${f.status === 'open' ? itemsHtml(f, h) : ''}</article>`;
}

// Open findings first; then "Could not check" and "Passing" each under their own heading, indented one step from it.
export function groupedCards(cards, h) {
  const list = (fs, cls = '') => `<div class="findings-list${cls}">${fs.map(f => cardHtml(f, h)).join('')}</div>`;
  const open = cards.filter(f => f.status === 'open'), na = cards.filter(f => f.status === 'unavailable'), pass = cards.filter(f => f.status === 'pass');
  const group = (label, fs) => fs.length ? `<div class="findings-group"><h3 class="findings-group-title">${h.esc(label)} (${h.esc(fs.length)})</h3>${list(fs, ' findings-sub')}</div>` : '';
  return (open.length ? list(open) : '') + group('Could not check', na) + group('Passing', pass);
}

export function findingsHtml(st, h) {
  const { esc, emptyBox } = h;
  const head = `<div class="panel-heading"><div><h2>Entra ID findings</h2><p>Read from Microsoft Graph with your sign-in. Ranked by severity, then by how many are affected. Read-only: every fix opens the Entra page where you make the change.</p></div><button type="button" class="btn" data-findings-refresh>Refresh</button></div>`;
  if (!st || st.loading) return head + emptyBox('Checking the tenant…');
  if (st.error) return head + emptyBox(st.error);
  const all = st.data.findings;
  const open = all.filter(f => f.status === 'open');
  const tally = ['critical', 'high', 'medium', 'low'].map(s => [s, open.filter(f => f.severity === s).length]).filter(([, n]) => n);
  const summary = `<div class="findings-summary">${open.length ? tally.map(([s, n]) => `<span class="findings-chip sev-${s}">${n} ${esc(SEV_LABEL[s])}</span>`).join('') : '<span class="findings-chip sev-pass">Nothing open</span>'}<span class="muted">${esc(all.filter(f => f.status === 'pass').length)} passing · ${esc(all.filter(f => f.status === 'unavailable').length)} could not be checked · read ${esc(String(st.data.generated).slice(0, 16).replace('T', ' '))} UTC</span></div>`;
  return head + summary + groupedCards(all, h);
}

// ------------------------------------------------------------------ AD posture (on-premises forest)
const ALL = '';
// Score trend as a small inline SVG: one point per reading, 0 to 100.
export function sparkline(points, { w = 160, h = 36 } = {}) {
  if (!points || points.length < 2) return '';
  const step = w / (points.length - 1), y = s => (h - 3 - (s / 100) * (h - 6)).toFixed(1);
  const d = points.map((p, i) => `${i ? 'L' : 'M'}${(i * step).toFixed(1)} ${y(p.score)}`).join(' ');
  const last = points[points.length - 1];
  return `<svg class="posture-spark" viewBox="0 0 ${w} ${h}" width="${w}" height="${h}" role="img" aria-label="Score trend: ${points.map(p => p.score).join(', ')}"><path d="${d}" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/><circle cx="${((points.length - 1) * step).toFixed(1)}" cy="${y(last.score)}" r="3" fill="currentColor"/></svg>`;
}
const scoreClass = s => (s == null ? 'na' : s >= 80 ? 'good' : s >= 50 ? 'fair' : 'poor');
function scoreHtml(d, history, esc) {
  const pts = history?.[d.name] || [];
  const first = pts.length > 1 ? pts[0] : null;
  const delta = first && d.score != null ? d.score - first.score : null;
  return `<div class="posture-score score-${scoreClass(d.score)}" data-posture-score="${esc(d.name)}"><span class="posture-score-num">${d.score == null ? '–' : esc(d.score)}<small>/100</small></span><span class="posture-score-text"><b>${esc(d.name)}</b><span class="muted">${d.reachable ? `${esc(d.tally.critical)} critical · ${esc(d.tally.high)} high · ${esc(d.tally.medium)} medium${d.functionalLevel ? ` · ${esc(d.functionalLevel)} level` : ''}` : 'Not reachable from this host'}</span>${delta != null ? `<span class="muted">${delta >= 0 ? '+' : ''}${esc(delta)} since ${esc(first.date)}</span>` : ''}</span>${sparkline(pts)}</div>`;
}
function inventoryHtml(d, esc) {
  const dcs = d.dcs.length ? `<details class="finding-items posture-inv"><summary>Domain controllers (${esc(d.dcs.length)})</summary><div class="table-wrap"><table class="event-table" data-table-id="posture-dcs"><thead><tr><th>DC</th><th>Operating system</th><th>LDAP signing (live test)</th></tr></thead><tbody>${d.dcs.map(x => `<tr><td>${esc(x.name)}</td><td>${esc(x.os)}</td><td title="${esc(x.detail)}">${esc(x.ldapSigning)}</td></tr>`).join('')}</tbody></table></div></details>` : '';
  const trusts = `<details class="finding-items posture-inv"><summary>Trusts (${esc(d.trusts.length)})</summary>${d.trusts.length ? `<div class="table-wrap"><table class="event-table" data-table-id="posture-trusts"><thead><tr><th>Partner</th><th>Type</th><th>Direction</th><th>Transitive</th><th>SID filtering</th><th>Authentication</th><th>Created</th></tr></thead><tbody>${d.trusts.map(t => `<tr><td>${esc(t.partner)}</td><td>${esc(t.kind)}</td><td>${esc(t.direction)}</td><td>${esc(t.transitive)}</td><td>${esc(t.sidFiltering)}</td><td>${esc(t.authentication)}</td><td>${esc(t.created)}</td></tr>`).join('')}</tbody></table></div>` : '<p class="account-note">This domain has no trusts.</p>'}</details>`;
  const gpos = `<details class="finding-items posture-inv"><summary>Group Policy read from SYSVOL (${esc(d.gpos?.length || 0)})</summary>${d.gpoStatus === 'unavailable' ? `<p class="finding-reason">${esc(d.gpoMessage)}</p>` : `<div class="table-wrap"><table class="event-table" data-table-id="posture-gpos"><thead><tr><th>GPO</th><th>Linked to</th><th>Enforced</th><th>Sets</th></tr></thead><tbody>${(d.gpos || []).map(g => `<tr><td>${esc(g.name)}</td><td>${esc(g.linkedTo)}</td><td>${g.enforced ? 'Yes' : 'No'}</td><td>${esc(g.sets.join(', ') || 'none of the checked settings')}</td></tr>`).join('')}</tbody></table></div>`}</details>`;
  return `<div class="posture-inventory">${dcs}${trusts}${gpos}</div>`;
}

export function postureHtml(ps, picked, h) {
  const { esc, emptyBox } = h;
  const head = (controls = '') => `<div class="panel-heading posture-heading"><div><h2>AD posture</h2><p>On-premises Active Directory and AD CS hardening, read live from a domain controller with the read-only AD reader. Nothing is installed on the DCs.</p></div><div class="posture-controls">${controls}<button type="button" class="btn" data-posture-refresh>Read AD again</button></div></div>`;
  if (!ps || ps.loading) return head() + emptyBox('Reading the forest from a domain controller… this can take a minute.');
  if (ps.error) return head() + emptyBox(ps.error);
  const p = ps.data;
  if (p.status !== 'live') return head() + `<div class="posture-off"><p class="finding-reason">${esc(p.message)}</p><p class="account-note">Set up: run Set-E360AdReader.ps1 on the Entity 360 host (the same step as the AD groups tab).</p></div>`;
  const domains = p.domains, sel = domains.some(d => d.name === picked) ? picked : ALL;
  const shown = sel ? domains.filter(d => d.name === sel) : domains;
  const picker = `<label class="posture-picker">Domain <select data-posture-domain><option value=""${sel ? '' : ' selected'}>All domains (${esc(domains.length)})</option>${domains.map(d => `<option value="${esc(d.name)}"${d.name === sel ? ' selected' : ''}>${esc(d.name)}${d.score != null ? ` · ${esc(d.score)}` : ''}</option>`).join('')}</select></label>`;
  const pdf = `<button type="button" class="btn" data-busy="self" data-posture-pdf="${esc(sel)}">PDF report</button>`;
  const scores = `<div class="posture-scores">${shown.map(d => scoreHtml(d, p.history, esc)).join('')}</div>`;
  const findings = shown.flatMap(d => d.findings);
  const open = findings.filter(f => f.status === 'open').sort((a, b) => ({ critical: 4, high: 3, medium: 2, low: 1 })[b.severity] - ({ critical: 4, high: 3, medium: 2, low: 1 })[a.severity] || (b.count || 0) - (a.count || 0));
  const rest = findings.filter(f => f.status !== 'open');
  const cards = sel ? findings : [...open, ...rest.filter(f => f.status === 'unavailable'), ...rest.filter(f => f.status === 'pass')];
  const hh = { ...h, showDomain: !sel, closed: !sel };
  const unreachable = shown.filter(d => !d.reachable).map(d => `<p class="finding-reason">${esc(d.name)}: ${esc(d.message)}</p>`).join('');
  const meta = `<div class="findings-summary"><span class="muted">Read from ${esc(p.server)} · ${esc(String(p.generated).slice(0, 16).replace('T', ' '))} UTC${p.cached ? ' (saved read, under 10 minutes old)' : ''} · AD CS: ${esc(p.pki.cas.length)} CA(s), ${esc(p.pki.templates)} templates (${esc(p.pki.published)} published)</span></div>`;
  const gaps = `<details class="finding-items posture-gaps"><summary>Not readable over this connection (${esc(p.gaps.length)})</summary><ul>${p.gaps.map(g => `<li><b>${esc(g.what)}.</b> ${esc(g.why)} <span class="muted">${esc(g.path)}</span></li>`).join('')}</ul></details>`;
  return head(picker + pdf) + meta + scores + unreachable + (sel ? inventoryHtml(shown[0], esc) : '') + groupedCards(cards, hh) + `<div class="posture-foot">${gaps}</div>`;
}

export function createFindingsView({ api, esc, external, emptyBox, download }) {
  const h = { esc, external, emptyBox };
  let st = null, ps = null, picked = ALL, active = false;
  const el = () => document.querySelector('#findings-content');
  const render = () => { if (active) el().innerHTML = `<div class="e360-section">${findingsHtml(st, h)}</div>` + `<div class="posture-section e360-section" id="ad-posture">${postureHtml(ps, picked, h)}</div>`; };
  async function load() {
    st = { loading: true }; render();
    try { st = { data: await api('/api/findings') }; } catch (e) { st = { error: e.message }; }
    render();
  }
  async function loadPosture(refresh = false) {
    ps = { loading: true }; render();
    try { ps = { data: await api(`/api/findings/ad-posture${refresh ? '?refresh=1' : ''}`) }; } catch (e) { ps = { error: e.message }; }
    render();
  }
  document.addEventListener('click', e => {
    if (!active) return;
    if (e.target.closest('[data-findings-refresh]')) load();
    if (e.target.closest('[data-posture-refresh]')) loadPosture(true);
    const b = e.target.closest('[data-posture-pdf]');
    if (b && download) download(`/api/findings/ad-posture/report.pdf${b.dataset.posturePdf ? `?domain=${encodeURIComponent(b.dataset.posturePdf)}` : ''}`, b);
  });
  document.addEventListener('change', e => { if (active && e.target.matches('[data-posture-domain]')) { picked = e.target.value; render(); } });
  return {
    setActive(on) {
      active = on;
      document.querySelector('#findings-panel').hidden = !on;
      if (!on) return;
      if (st && !st.error) render(); else load();
      if (!ps || ps.error) loadPosture();
    },
  };
}
