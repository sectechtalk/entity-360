// Coverage bucket 5: tenant-wide pages, one generic table view per nav item. Read-only, live connections only.
export const B5_VIEWS = {
  't-settings': ['Tenant settings', 'User, guest and device settings plus security defaults, read from Entra policies.'],
  't-domains': ['Domains and branding', 'Verified domains, organization details and company branding.'],
  't-roles': ['Roles and admin units', 'Roles in use, custom roles, PIM eligibility counts and administrative units with scoped admins.'],
  't-hybrid': ['Hybrid sync', 'Directory synchronization status from the organization object.'],
  'a-methods': ['Authentication methods', 'Which methods are enabled and for whom, plus the registration campaign and system-preferred MFA.'],
  'a-registration': ['Registration', 'MFA and self-service password reset registration across users. Needs the Reports Reader role or higher.'],
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
export function cell(c, { esc, external }) {
  if (c && typeof c === 'object') return c.link ? external(c.link, c.text) : esc(c.text);
  return esc(c);
}
export function pageHtml(view, st, h) {
  const { esc, external, emptyBox } = h;
  const [title, intro] = B5_VIEWS[view] || ['', ''];
  const head = `<div class="panel-heading"><div><h2>${esc(title)}</h2><p>${esc(intro)} Read-only.</p></div><button type="button" class="btn" data-b5-refresh>Refresh</button></div>`;
  if (!st || st.loading) return head + emptyBox('Loading…');
  if (st.error) return head + emptyBox(st.error);
  const d = st.data;
  const tables = d.tables.map(t => `<h3>${esc(t.title)}</h3>${t.note ? `<p class="account-note">${esc(t.note)}</p>` : ''}${t.rows.length
    ? `<div class="table-wrap"><table class="event-table" data-table-id="${esc(view)}"><thead><tr>${t.columns.map(c => `<th>${esc(c)}</th>`).join('')}</tr></thead><tbody>${t.rows.map(r => `<tr>${r.map(c => `<td>${cell(c, h)}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`
    : emptyBox('Nothing to show.')}${t.link ? `<div class="account-actions">${external(t.link, 'Open in Entra')}</div>` : ''}`).join('');
  return head + tables + (d.notes || []).map(n => `<p class="account-note">${esc(n)}</p>`).join('');
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
