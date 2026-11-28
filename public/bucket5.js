// Coverage bucket 5: tenant-wide pages, one generic table view per nav item. Read-only, live connections only.
export const B5_VIEWS = {
  't-settings': ['Tenant settings', 'User, guest and device settings plus security defaults, read from Entra policies.'],
  't-domains': ['Domains and branding', 'Verified domains, organization details and company branding.'],
  't-roles': ['Roles and admin units', 'Roles in use, custom roles, PIM eligibility counts and administrative units with scoped admins.'],
  'h-sync': ['On-prem AD sync health', 'Is on-premises Active Directory syncing to Entra? Cloud Sync or Entra Connect: last run, password hash sync, quarantine and sync errors.'],
  'h-groups': ['On-prem AD groups', 'Groups synced from on-premises Active Directory with their SAM name, SID, members and the apps they grant.'],
  'a-methods': ['Authentication methods', 'Which methods are enabled and for whom, plus the registration campaign and system-preferred MFA.'],
  'a-registration': ['Registration', 'MFA and self-service password reset registration across users. Needs the Reports Reader role or higher.'],
  'a-strength': ['MFA strength', 'Every MFA method ranked strongest to weakest: whether it is on here, who has it, which Conditional Access policies accept it, and how to set up what is missing.'],
  'a-ca': ['Conditional Access inventory', 'All policies with their state, plus named locations, authentication contexts and authentication strengths.'],
  'x-guests': ['Guests', 'Guest accounts with invitation state and last sign-in, stale guests first, grouped by home domain.'],
  'x-cross': ['Cross-tenant access', 'External collaboration settings plus default and per-organization cross-tenant access.'],
  'g-entitlements': ['Entitlement management', 'Catalogs, access packages, connected organizations and the external user lifecycle.'],
  'g-pim': ['PIM settings and audit', 'Activation rules for Entra roles in use and recent PIM activity from the audit log.'],
  'g-pim-azure': ['PIM for Azure resources', 'Eligible and active Azure role assignments across your subscriptions. Needs Azure connected.'],
  'p-enterprise': ['Enterprise applications', 'Every integrated app with assignment requirement, visibility, SSO mode and owners, open apps first.'],
  'p-registrations': ['App registration credentials', 'Secret and certificate expiry for every app registration, soonest first, plus requested API permissions.'],
  'p-consent': ['Consent settings', 'User consent policy, the admin consent workflow and permission grant policies.'],
};
// Status words to badge colours, shared by the verdict banner and status cells.
export const TONE = { OK: 'pass', Healthy: 'pass', Warning: 'warn', 'Needs attention': 'warn', Failed: 'fail', Failing: 'fail', Unknown: 'unknown', 'Partly checked': 'unknown' };
export const badge = (text, esc, tone) => `<span class="health-badge health-${tone || TONE[text] || 'info'}">${esc(text)}</span>`;
export function cell(c, { esc, external }) {
  if (c && typeof c === 'object') return c.badge ? badge(c.text, esc, c.tone) : c.link ? external(c.link, c.text) : esc(c.text);
  return esc(c);
}
export function pageHtml(view, st, h) {
  const { esc, external, emptyBox } = h;
  const [title, intro] = B5_VIEWS[view] || ['', ''];
  const head = `<div class="panel-heading"><div><h2>${esc(title)}</h2><p>${esc(intro)} Read-only.</p></div><button type="button" class="btn" data-b5-refresh>Refresh</button></div>`;
  if (!st || st.loading) return head + emptyBox('Loading…');
  if (st.error) return head + emptyBox(st.error);
  const d = st.data;
  // A guides table: one collapsed setup panel per item (why, numbered steps, a command to copy, how to check).
  const guide = g => `<details class="b5-guide"><summary><strong>${esc(g.title)}</strong>${g.status ? ` <span class="health-badge health-info">${esc(g.status)}</span>` : ''}</summary>`
    + `${g.why ? `<p>${esc(g.why)}</p>` : ''}${(g.steps || []).length ? `<ol>${g.steps.map(s => `<li>${esc(s)}</li>`).join('')}</ol>` : ''}`
    + `${g.code ? `<p class="account-note">${esc(g.codeNote || 'PowerShell (changes the tenant; read it before you run it):')}</p><pre class="b5-code"><code>${esc(g.code)}</code></pre>` : ''}`
    + `${g.check ? `<p class="account-note">Check it worked: ${esc(g.checkNote || '')}</p><pre class="b5-code"><code>${esc(g.check)}</code></pre>` : ''}`
    + `${g.learn ? `<div class="account-actions">${external(g.learn, 'Microsoft Learn')}</div>` : ''}</details>`;
  const one = t => t.guides ? `${t.note ? `<p class="account-note">${esc(t.note)}</p>` : ''}${t.guides.map(guide).join('')}` : `${t.note ? `<p class="account-note">${esc(t.note)}</p>` : ''}${t.rows.length
    ? `<div class="table-wrap"><table class="event-table" data-table-id="${esc(view)}"><thead><tr>${t.columns.map(c => `<th>${esc(c)}</th>`).join('')}</tr></thead><tbody>${t.rows.map(r => `<tr>${r.map(c => `<td>${cell(c, h)}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`
    : emptyBox('Nothing to show.')}${t.link ? `<div class="account-actions">${external(t.link, 'Open in Entra')}</div>` : ''}`;
  // A collapsed table is reference detail that no longer drives the verdict (for example Connect Sync after a move to Cloud Sync).
  const tables = d.tables.map(t => t.collapsed ? `<details class="b5-collapsed"><summary><h3>${esc(t.title)}</h3></summary>${one(t)}</details>` : `<div class="e360-section b5-table"><h3>${esc(t.title)}</h3>${one(t)}</div>`).join('');
  const v = d.verdict;
  const banner = v ? `<div class="verdict-banner verdict-${TONE[v.status] || 'info'}" role="status"><span class="verdict-status">${esc(v.status)}</span><div><strong>${esc(v.headline)}</strong>${v.detail ? `<p>${esc(v.detail)}</p>` : ''}</div></div>` : '';
  return head + banner + tables + (d.notes || []).map(n => `<p class="account-note">${esc(n)}</p>`).join('');
}
export function createBucket5View({ api, esc, external, emptyBox }) {
  const h = { esc, external, emptyBox }, cache = {};
  let current = null;
  const el = () => document.querySelector('#b5-content');
  const render = () => { if (current) el().innerHTML = pageHtml(current, cache[current], h); };
  async function load(view) {
    cache[view] = { loading: true }; render();
    try { cache[view] = { data: await api(`/api/tenant-page/${encodeURIComponent(view)}`) }; } catch (e) { cache[view] = { error: e.message }; }
    render();
  }
  document.addEventListener('click', e => { if (e.target.closest('[data-b5-refresh]') && current) load(current); });
  return {
    setActive(view) {
      const on = Boolean(B5_VIEWS[view]);
      document.querySelector('#b5-panel').hidden = !on;
      current = on ? view : null;
      if (on) cache[view] ? render() : load(view);
    },
  };
}
