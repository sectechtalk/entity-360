// Unified PIM table (MY ACCOUNT > My PIM with Activate/Deactivate; INVESTIGATE > PIM read-only).
// The table is drawn once and then updated in place: polling and refreshes only rewrite the rows when the data changed,
// and keep the scroll position. Sorting and per-column filters only touch the rows. Busy state is per row, never global.
import { ROLE_GROUPS } from './access-denied.js';
import { PIM_ACTIVATION_LINKS } from './device-links.js';
const activation = label => PIM_ACTIVATION_LINKS.find(([l]) => l === label)[1];
// Activating a group that grants an Entity 360 app role only takes effect in a new token, so say so.
export function groupNote(row) {
  if (row?.type !== 'Group') return '';
  const role = Object.entries(ROLE_GROUPS).find(([, g]) => g.toLowerCase() === String(row.name || '').toLowerCase())?.[0];
  return role ? ` This group grants ${role} in Entity 360: sign out and sign in again for it to take effect.` : ' If this group grants an Entity 360 role, sign out and sign in again for it to take effect.';
}
export const PIM_COLUMNS = ['Type', 'Name', 'Scope', 'State', 'Eligibility', 'Start', 'End', 'Action'];
export const PIM_TYPES = ['Entra role', 'Group', 'Azure role'];
export const STATE_FILTERS = ['Active', 'Eligible', 'Assigned', 'Pending'];
export const ACTION_FILTERS = ['Activate', 'Deactivate', 'None'];
export const POLL_MS = 5000, POLL_MAX = 36;
export const fmtWhen = v => { const d = new Date(v); return v && !Number.isNaN(d.getTime()) ? d.toLocaleString(undefined, { month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit' }) : ''; };
export const fmtDay = v => { const d = new Date(v); return v && !Number.isNaN(d.getTime()) ? d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' }) : ''; };
export function durationOptions(maxMinutes = 480) {
  const max = Math.max(5, Math.floor(Number(maxMinutes) || 480));
  const list = [30, 60, 120, 240, 480, 720, 1440, 2880, 10080].filter(n => n < max);
  return [...list, max];
}
export const durationLabel = n => n % 60 ? (n < 60 ? `${n} minutes` : `${Math.floor(n / 60)} h ${n % 60} min`) : `${n / 60} hour${n === 60 ? '' : 's'}`;
// Has the row's state changed the way the request asked for? (rows are merged: one row per key)
export function settled(rows, key, action) {
  const active = (rows || []).some(r => r.key === key && r.state === 'Active (activated)');
  return action === 'activate' ? active : !active;
}
const ACTIVATED = 'Active (activated)';
// One row per group/role/scope: an activation absorbs its eligibility (shown in the Eligibility column).
// Standing assignments (time-bound or permanent, for example a group owner) stay their own rows. Safe on merged input.
export function mergeRows(rows, self = true) {
  const list = rows || [], elig = new Map(), act = new Map();
  for (const r of list) { if (r.state === 'Eligible' && !elig.has(r.key)) elig.set(r.key, r); if (r.state === ACTIVATED && !act.has(r.key)) act.set(r.key, r); }
  const out = [];
  for (const r of list) {
    if (r.state === 'Eligible') {
      if (act.has(r.key) || elig.get(r.key) !== r) continue;
      out.push({ ...r, eligible: true, eligibleStart: r.eligibleStart ?? r.start ?? null, eligibleEnd: r.eligibleEnd !== undefined ? r.eligibleEnd : r.end ?? null, start: r.eligible ? r.start ?? null : null, end: r.eligible ? r.end ?? null : null, action: self ? 'activate' : null });
    } else if (r.state === ACTIVATED) {
      if (act.get(r.key) !== r) continue;
      const e = elig.get(r.key);
      out.push({ ...r, eligible: Boolean(e) || Boolean(r.eligible), eligibleStart: e ? e.start ?? null : r.eligibleStart ?? null, eligibleEnd: e ? (e.eligibleEnd !== undefined ? e.eligibleEnd : e.end ?? null) : r.eligibleEnd ?? null, action: self ? 'deactivate' : null });
    } else out.push({ ...r, eligible: false, action: null });
  }
  return out;
}
const accessWord = r => r.type === 'Group' ? (r.target?.accessId === 'owner' || /owner/i.test(r.scopeLabel || '') ? 'owner' : 'member') : 'role';
export function stateLabel(r, pending) {
  if (pending) return pending.action === 'activate' ? 'Activation pending' : 'Deactivation pending';
  if (r.state === ACTIVATED) return r.end ? `Active until ${fmtWhen(r.end)}` : 'Active';
  if (r.state === 'Eligible') return 'Eligible';
  if (r.state === 'Active (time-bound)') return `Assigned until ${fmtWhen(r.end)}`;
  if (r.state === 'Active (permanent)') return 'Assigned (permanent)';
  return r.state || '';
}
export const stateCategory = (r, pending) => pending ? 'Pending' : r.state === ACTIVATED ? 'Active' : r.state === 'Eligible' ? 'Eligible' : 'Assigned';
export function eligibilityLabel(r) {
  if (r.eligible) return r.eligibleEnd ? `Eligible until ${fmtDay(r.eligibleEnd)}` : 'Eligible, no end';
  return r.state === ACTIVATED ? '' : `Standing ${accessWord(r)} assignment, no activation needed`;
}
const actionLabel = r => r.action === 'activate' ? 'Activate' : r.action === 'deactivate' ? 'Deactivate' : 'None';
// Column definitions: label, filter kind, display text and sort value.
export function pimColumns(self) {
  const cols = [
    { key: 'type', label: 'Type', filter: 'select', options: PIM_TYPES, text: r => r.type || '' },
    { key: 'name', label: 'Name', filter: 'text', text: r => r.name || '' },
    { key: 'scope', label: 'Scope', filter: 'text', text: r => r.scopeLabel || r.scope || '' },
    { key: 'state', label: 'State', filter: 'select', options: STATE_FILTERS, text: (r, p) => stateLabel(r, p), cat: (r, p) => stateCategory(r, p) },
    { key: 'eligibility', label: 'Eligibility', filter: 'text', text: r => eligibilityLabel(r), sort: r => r.eligible ? (r.eligibleEnd ? Date.parse(r.eligibleEnd) : 9e15) : -1 },
    { key: 'start', label: 'Start', filter: 'text', text: r => fmtWhen(r.start), sort: r => r.start ? Date.parse(r.start) : -1 },
    { key: 'end', label: 'End', filter: 'text', text: r => r.end ? fmtWhen(r.end) : r.state === 'Active (permanent)' ? 'No end' : '', sort: r => r.end ? Date.parse(r.end) : r.state === 'Active (permanent)' ? 9e15 : -1 },
  ];
  if (self) cols.push({ key: 'action', label: 'Action', filter: 'select', options: ACTION_FILTERS, text: r => actionLabel(r), cat: r => actionLabel(r) });
  return cols;
}
// Each column's menu lists the column's values as checkboxes: the fixed categories for Type, State and Action,
// the distinct shown values for the rest. '(blank)' stands for an empty cell.
export const BLANK = '(blank)';
export const valueOf = (c, r, p) => String((c.cat ? c.cat(r, p) : c.text(r, p)) || '') || BLANK;
export function menuOptions(rows, c, pending = new Map()) {
  if (c.options) return [...c.options];
  const seen = new Map();
  for (const r of rows || []) { const v = valueOf(c, r, pending.get(r.key)); if (!seen.has(v)) seen.set(v, c.sort ? c.sort(r) : v); }
  return [...seen].sort(([a, x], [b, y]) => (a === BLANK) - (b === BLANK) || (typeof x === 'number' && typeof y === 'number' ? x - y : String(x).localeCompare(String(y), undefined, { numeric: true, sensitivity: 'base' }))).map(([v]) => v);
}
// Filter then sort. filters: { key: text } and excluded: { key: Set of unchecked values }.
// A text filter that names a category of a select column (for example State "Active") matches that category exactly;
// any other text matches a substring of the cell. Unchecked values are hidden.
export function shownRows(rows, { self, filters = {}, excluded = {}, sort = null, pending = new Map() }) {
  const cols = pimColumns(self);
  let out = rows.filter(r => cols.every(c => {
    const p = pending.get(r.key), ex = excluded[c.key];
    if (ex?.size && ex.has(valueOf(c, r, p))) return false;
    const f = String(filters[c.key] || '').trim().toLowerCase(); if (!f) return true;
    if (c.options?.some(o => o.toLowerCase() === f)) return (c.cat ? c.cat(r, p) : c.text(r, p)).toLowerCase() === f;
    return c.text(r, p).toLowerCase().includes(f);
  }));
  const c = sort && cols.find(x => x.key === sort.key);
  if (c) {
    const m = sort.dir === 'desc' ? -1 : 1, val = r => c.sort ? c.sort(r) : c.text(r, pending.get(r.key));
    out = out.map((r, i) => [r, i]).sort(([a, i], [b, j]) => { const x = val(a), y = val(b); const d = typeof x === 'number' && typeof y === 'number' ? x - y : String(x).localeCompare(String(y), undefined, { numeric: true, sensitivity: 'base' }); return m * d || i - j; }).map(([r]) => r);
  }
  return out;
}
const stateClass = (r, p) => p ? 'pim-pending' : r.state === 'Eligible' ? 'pim-eligible' : r.state === ACTIVATED ? 'success' : 'pim-active';
// ---- Portal links. Built only from ids the rows already hold, checked against the known portal hosts. ----
const ENTRA = 'https://entra.microsoft.com/', AZPORTAL = 'https://portal.azure.com/';
const GUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
// Only https links on entra.microsoft.com or portal.azure.com, with no quote, angle bracket or space in them.
export const safeLink = url => typeof url === 'string' && (url.startsWith(ENTRA) || url.startsWith(AZPORTAL)) && !/["'<>\s\\]/.test(url) ? url : null;
const AZ_SCOPE_RE = /^\/subscriptions\/[0-9a-f-]{36}(\/resourceGroups\/[\w.()-]{1,90}(\/providers\/[\w.]{1,100}(\/[\w.()-]{1,260}){2,8})?)?$/i;
// Each link opens the page where the assignment is added or removed: Entra role -> the role's Assignments in Roles and
// administrators; group -> the group's Members (or Owners); Azure role -> Access control (IAM) of the subscription,
// resource group or resource it applies to. Anything else (management groups, unknown shapes) -> no link.
export function nameLink(r) {
  const t = r?.target || {};
  if (r?.type === 'Entra role' && GUID_RE.test(t.roleDefinitionId || '')) { const id = encodeURIComponent(t.roleDefinitionId); return safeLink(`${ENTRA}#view/Microsoft_AAD_IAM/RoleMenuBlade/~/RoleMembers/objectId/${id}/roleName/${encodeURIComponent(r.name || '')}/roleTemplateId/${id}/adminUnitObjectId//customRole~/false/resourceScope/%2F`); }
  if (r?.type === 'Group' && GUID_RE.test(t.groupId || '')) return safeLink(`${ENTRA}#view/Microsoft_AAD_IAM/GroupDetailsMenuBlade/~/${t.accessId === 'owner' ? 'Owners' : 'Members'}/groupId/${encodeURIComponent(t.groupId)}`);
  const scope = String(t.scope || r?.scope || '');
  if (r?.type === 'Azure role' && AZ_SCOPE_RE.test(scope)) return safeLink(`${AZPORTAL}#@/resource${scope.split('/').map(encodeURIComponent).join('/')}/users`);
  return null;
}
export const linkOr = (url, text, esc) => url ? `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(text)}</a>` : esc(text);
// Where the table's data comes from. Only the sources for the row types shown.
export const PIM_SOURCES = {
  'Entra role': [['PIM: My roles (Entra roles)', activation('Entra roles')], ['Entra: Roles and administrators', `${ENTRA}#view/Microsoft_AAD_IAM/RolesManagementMenuBlade/~/AllRoles`]],
  Group: [['PIM: My roles (Groups)', activation('Groups')], ['Entra: All groups', `${ENTRA}#view/Microsoft_AAD_IAM/GroupsManagementMenuBlade/~/AllGroups`]],
  'Azure role': [['PIM: My roles (Azure resources)', activation('Azure resource roles')], ['Azure: Subscriptions', `${AZPORTAL}#browse/Microsoft.Resources%2Fsubscriptions`], ['Azure: Resource groups', `${AZPORTAL}#browse/resourcegroups`]],
};
export function sourcesHtml(rows, self, esc) {
  const types = PIM_TYPES.filter(t => (rows || []).some(r => r.type === t));
  if (!types.length) return '';
  const links = types.flatMap(t => PIM_SOURCES[t]).filter(([label]) => self || !label.startsWith('PIM: My roles'));
  return `Sources: ${links.map(([label, url]) => `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(label)}</a>`).join(' \u00b7 ')}`;
}
export const rowId = r => String(r.id || r.key || '');
export function pimRowsHtml(rows, { esc, self, pending = new Map() }) {
  const cols = pimColumns(self);
  return rows.map(r => {
    const p = pending.get(r.key), cells = cols.map(c => {
      if (c.key === 'name') return `<td>${linkOr(nameLink(r), r.name, esc)}${r.memberType && String(r.memberType).toLowerCase() !== 'direct' ? `<small>${esc(String(r.memberType).toLowerCase() === 'group' ? 'Through a group' : r.memberType)}</small>` : ''}</td>`;
      if (c.key === 'scope') return `<td title="${esc(r.scope || '')}">${esc(c.text(r))}</td>`;
      if (c.key === 'state') return `<td><span class="result ${stateClass(r, p)}">${esc(c.text(r, p))}</span></td>`;
      if (c.key === 'action') {
        if (!r.action) return '<td></td>';
        const busy = Boolean(p), label = busy ? (p.action === 'activate' ? 'Activating\u2026' : 'Deactivating\u2026') : r.action === 'activate' ? 'Activate' : 'Deactivate';
        return `<td><button type="button" class="btn" data-pim-action="${r.action}" data-pim-row="${esc(rowId(r))}"${busy ? ' disabled aria-busy="true"' : ''}>${esc(label)}</button></td>`;
      }
      return `<td>${esc(c.text(r, p))}</td>`;
    }).join('');
    return `<tr data-pim-key="${esc(r.key || '')}"${p ? ' class="pim-row-pending"' : ''}>${cells}</tr>`;
  }).join('');
}
const arrow = dir => dir === 'asc' ? '\u25b2' : '\u25bc';
export const menuLabel = (text, ex) => String(text || '').trim() || ex?.size ? 'Filtered' : 'All';
export function menuOptsHtml(values, ex, esc) {
  return values.length ? values.map(v => `<label class="msel-option"><input type="checkbox" data-pim-check value="${esc(v)}"${ex?.has(v) ? '' : ' checked'}> ${esc(v)}</label>`).join('') : '<p class="muted">No values yet.</p>';
}
// Sort stays on the header cell (click the column name). Under it, one menu per column: a text filter and the column's values as checkboxes.
export function pimHeadHtml({ esc, self, sort = null, filters = {}, excluded = {}, rows = [], pending = new Map() }) {
  const cols = pimColumns(self);
  const head = cols.map(c => { const on = sort?.key === c.key; return `<th data-pim-sort="${c.key}" tabindex="0" title="Sort by ${esc(c.label)}"${on ? ` aria-sort="${sort.dir === 'asc' ? 'ascending' : 'descending'}"` : ''}>${esc(c.label)}<span class="sort-mark">${on ? ` ${arrow(sort.dir)}` : ''}</span></th>`; }).join('');
  const filt = cols.map(c => `<th><details class="msel msel-th pim-menu" data-msel="pim-${c.key}" data-pim-menu="${c.key}"><summary class="btn msel-trigger" aria-label="Filter ${esc(c.label)}">${menuLabel(filters[c.key], excluded[c.key])}</summary><div class="msel-menu" role="group" aria-label="Filter ${esc(c.label)}">`
    + `<input class="pim-filter" data-pim-filter="${c.key}" type="search" aria-label="Filter ${esc(c.label)} by text" placeholder="Type to filter" autocomplete="off" value="${esc(filters[c.key] || '')}">`
    + `<div class="msel-actions"><button type="button" class="btn" data-pim-all>Select all</button><button type="button" class="btn" data-pim-none>Clear</button></div>`
    + `<div class="pim-menu-opts" data-pim-opts="${c.key}">${menuOptsHtml(menuOptions(rows, c, pending), excluded[c.key], esc)}</div></div></details></th>`).join('');
  return `<tr>${head}</tr><tr class="pim-filter-row">${filt}</tr>`;
}
// Whole table (used by tests and first draw).
export function pimTableHtml(rows, { esc, self, pending = new Map(), sort = null, filters = {}, excluded = {} }) {
  return `<div class="table-wrap table-scroll" data-pim-scroll><table class="event-table" data-table-id="pim"><thead>${pimHeadHtml({ esc, self, sort, filters, excluded, rows, pending })}</thead><tbody class="pim-rows">${pimRowsHtml(rows, { esc, self, pending })}</tbody></table></div>`;
}
// Microsoft refuses a deactivation until the assignment has been active for 5 minutes (ActiveDurationTooShort).
export const MIN_ACTIVE_MS = 5 * 60000;
export function deactivateWait(row, now = Date.now()) { const t = Date.parse(row?.start || ''); return Number.isFinite(t) ? Math.max(0, t + MIN_ACTIVE_MS - now) : 0; }
export function friendlyError(message) {
  return /ActiveDurationTooShort/i.test(String(message)) ? 'Microsoft allows a deactivation only after the assignment has been active for 5 minutes. Try again in a few minutes.' : String(message || 'The request failed.');
}
export function activateFormHtml(row, policy, { esc }) {
  const opts = durationOptions(policy.maxMinutes), def = opts.includes(60) ? 60 : opts[0];
  const rules = [policy.approval ? 'needs approval' : '', policy.mfa ? 'needs MFA' : '', policy.ticket ? 'needs a ticket' : ''].filter(Boolean).join(', ');
  return `<form class="rem-run-form pim-form" data-pim-form><h3>Activate ${esc(row.name)}</h3><p class="muted">${esc(row.type)} \u00b7 ${esc(row.scopeLabel || row.scope || '')}. Maximum ${esc(durationLabel(policy.maxMinutes))}${rules ? `; ${esc(rules)}` : ''}.${policy.reason ? ` ${esc(policy.reason)}` : ''}</p>
<label>Reason<input name="reason" required maxlength="500" autocomplete="off"></label>
<label>Duration<select name="minutes">${opts.map(n => `<option value="${n}"${n === def ? ' selected' : ''}>${esc(durationLabel(n))}</option>`).join('')}</select></label>
${policy.ticket ? '<label>Ticket number<input name="ticketNumber" required maxlength="100" autocomplete="off"></label><label>Ticket system<input name="ticketSystem" maxlength="100" autocomplete="off"></label>' : ''}
<p class="page-note" data-pim-form-status aria-live="polite"></p>
<div class="card-actions"><button type="submit" class="btn" data-pim-confirm>Activate</button><button type="button" class="btn" data-pim-cancel>Cancel</button></div></form>`;
}
// Busy look on one button: disabled, aria-busy (spinner from CSS) and a label saying what is happening.
export function setBusy(btn, busy, label) {
  if (!btn) return;
  if (busy) { if (btn.dataset.idleLabel === undefined) btn.dataset.idleLabel = btn.textContent; btn.disabled = true; btn.setAttribute('aria-busy', 'true'); if (label) btn.textContent = label; }
  else { btn.disabled = false; btn.removeAttribute('aria-busy'); if (btn.dataset.idleLabel !== undefined) { btn.textContent = btn.dataset.idleLabel; delete btn.dataset.idleLabel; } }
}
export function createPimView({ api, esc, emptyBox, root, self, entity = () => null }) {
  const $ = s => document.querySelector(s);
  const st = { rows: [], loaded: false, loading: false, userLoad: false, active: false, gen: 0, forId: null, data: null, form: null, msg: '', err: false, sort: null, filters: {}, excluded: {}, pending: new Map(), timer: null, lastBody: null, lastTable: null, lastNotes: null, lastSources: null, lastOpts: {} };
  // root may be a selector or a function returning the host element (app.js passes a function).
  const el = () => typeof root === 'function' ? root() : $(root);
  const q = s => el()?.querySelector(s);
  const title = () => self ? 'My PIM roles and groups' : `PIM for ${entity()?.name || 'the selected user'}`;
  function shell(host) {
    if (host.querySelector('[data-pim-shell]')) return;
    const sub = self ? 'Everything you are eligible for or active in: Entra roles, PIM groups and Azure roles. Activate or deactivate here; Microsoft applies the PIM policy.' : 'Read-only. Eligible and active Entra roles, PIM groups and Azure roles for the selected user.';
    host.innerHTML = `<section class="panel" data-pim-shell><div class="panel-heading"><div><h2><span data-pim-title>${esc(title())}</span> <span class="count" data-pim-count></span></h2><p>${esc(sub)}</p></div><div class="card-actions"><button type="button" class="btn" data-pim-refresh>Refresh</button></div></div>
<p class="page-note" data-pim-status aria-live="polite"></p><div data-pim-form-host></div><p class="pim-sources" data-pim-sources></p><div data-pim-table-host></div><div data-pim-notes></div></section>`;
    st.lastBody = st.lastTable = st.lastNotes = st.lastSources = null;
    host.querySelector('[data-pim-refresh]').addEventListener('click', () => load({ user: true }));
    const th = host.querySelector('[data-pim-table-host]');
    th.addEventListener('click', e => {
      const b = e.target.closest('button[data-pim-action]');
      if (b) { if (!b.disabled) start(b, st.rows.find(r => rowId(r) === b.dataset.pimRow), b.dataset.pimAction); return; }
      const h = e.target.closest('th[data-pim-sort]'); if (h && !e.target.closest('.col-resizer')) sortBy(h.dataset.pimSort);
    });
    th.addEventListener('keydown', e => { const h = e.target.closest?.('th[data-pim-sort]'); if (h && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); sortBy(h.dataset.pimSort); } });
    const onFilter = e => {
      const f = e.target.closest?.('[data-pim-filter]');
      if (f) { st.filters[f.dataset.pimFilter] = f.value; label(f.dataset.pimFilter); drawRows(); return; }
      const box = e.target.closest?.('input[data-pim-check]'); if (!box || e.type !== 'change') return;
      const key = box.closest('[data-pim-menu]').dataset.pimMenu, set = new Set(st.excluded[key] || []);
      if (box.checked) set.delete(box.value); else set.add(box.value);
      st.excluded[key] = set; label(key); drawRows();
    };
    th.addEventListener('input', onFilter); th.addEventListener('change', onFilter);
    th.addEventListener('click', e => {
      const b = e.target.closest('[data-pim-all],[data-pim-none]'); if (!b) return;
      const menu = b.closest('[data-pim-menu]'), key = menu.dataset.pimMenu;
      st.excluded[key] = b.hasAttribute('data-pim-none') ? new Set([...menu.querySelectorAll('input[data-pim-check]')].map(i => i.value)) : new Set();
      st.lastOpts[key] = null; label(key); drawRows();
    });
    // toggle does not bubble, so listen in the capture phase. One menu open at a time, pinned under its button so the scrolling table does not clip it.
    th.addEventListener('toggle', e => {
      const d = e.target; if (!d.matches?.('[data-pim-menu]') || !d.open) return;
      th.querySelectorAll('[data-pim-menu][open]').forEach(o => { if (o !== d) o.open = false; });
      const r = d.querySelector('summary').getBoundingClientRect(), menu = d.querySelector('.msel-menu');
      menu.style.top = `${r.bottom + 4}px`; menu.style.left = `${Math.max(4, Math.min(r.left, (globalThis.innerWidth || 1000) - 260))}px`;
      d.querySelector('[data-pim-filter]')?.focus();
    }, true);
  }
  function label(key) { const s = q(`[data-pim-menu="${key}"] > summary`); if (s) s.textContent = menuLabel(st.filters[key], st.excluded[key]); }
  // Keeps each menu's checkbox list in step with the rows without touching the text box (focus and typing are kept).
  function syncMenus() {
    for (const c of pimColumns(self)) {
      const box = q(`[data-pim-opts="${c.key}"]`); if (!box) continue;
      const html = menuOptsHtml(menuOptions(st.rows, c, st.pending), st.excluded[c.key], esc);
      if (st.lastOpts[c.key] !== html) { box.innerHTML = html; st.lastOpts[c.key] = html; }
    }
  }
  function sortBy(key) {
    st.sort = st.sort?.key === key ? { key, dir: st.sort.dir === 'asc' ? 'desc' : 'asc' } : { key, dir: 'asc' };
    el()?.querySelectorAll('th[data-pim-sort]').forEach(h => { const on = h.dataset.pimSort === key; if (on) h.setAttribute('aria-sort', st.sort.dir === 'asc' ? 'ascending' : 'descending'); else h.removeAttribute('aria-sort'); const m = h.querySelector('.sort-mark'); if (m) m.textContent = on ? ` ${arrow(st.sort.dir)}` : ''; });
    drawRows();
  }
  // Rewrites the rows only when their markup changed, keeping the table's and the page's scroll position.
  function drawRows() {
    const body = q('tbody.pim-rows'); if (!body) return;
    syncMenus();
    const html = pimRowsHtml(shownRows(st.rows, { self, filters: st.filters, excluded: st.excluded, sort: st.sort, pending: st.pending }), { esc, self, pending: st.pending });
    if (html === st.lastBody) return;
    const wrap = q('[data-pim-scroll]'), top = wrap?.scrollTop, left = wrap?.scrollLeft, page = [globalThis.scrollX, globalThis.scrollY], main = document.scrollingElement, mainTop = main?.scrollTop;
    body.innerHTML = html; st.lastBody = html;
    if (wrap) { wrap.scrollTop = top; wrap.scrollLeft = left; }
    if (main && mainTop !== undefined) main.scrollTop = mainTop;
    if (typeof globalThis.scrollTo === 'function' && page[1] !== undefined && (globalThis.scrollY !== page[1] || globalThis.scrollX !== page[0])) globalThis.scrollTo(page[0], page[1]);
  }
  function setHtml(node, html, key) { if (node && st[key] !== html) { node.innerHTML = html; st[key] = html; } }
  function render() {
    const host = el(); if (!host) return;
    shell(host);
    const t = q('[data-pim-title]'); if (t && t.textContent !== title()) t.textContent = title();
    const c = q('[data-pim-count]'); if (c) c.textContent = st.loaded ? String(st.rows.length) : '';
    const s = q('[data-pim-status]'); if (s) { if (s.textContent !== st.msg) s.textContent = st.msg; s.classList.toggle('pim-status-error', st.err && Boolean(st.msg)); }
    setBusy(q('[data-pim-refresh]'), st.userLoad, 'Refreshing\u2026');
    const tableHost = q('[data-pim-table-host]');
    if (st.loaded && st.rows.length) {
      if (!tableHost.querySelector('tbody.pim-rows')) { tableHost.innerHTML = pimTableHtml([], { esc, self, sort: st.sort, filters: st.filters, excluded: st.excluded }); st.lastTable = 'table'; st.lastBody = ''; st.lastOpts = {}; }
      drawRows();
    } else setHtml(tableHost, !st.loaded ? emptyBox(st.loading ? 'Reading PIM eligibility and assignments.' : 'Not loaded yet.') : emptyBox('No eligible or active PIM assignments returned.'), 'lastTable');
    const d = st.data, problems = d?.problems || [], notes = d?.notes || [];
    setHtml(q('[data-pim-sources]'), st.loaded ? sourcesHtml(st.rows, self, esc) : '', 'lastSources');
    setHtml(q('[data-pim-notes]'), `${problems.length ? `<p class="account-note">Not available: ${problems.map(p => `${esc(p.source)} (${esc(p.reason)})`).join('; ')}.</p>` : ''}${notes.map(n => `<p class="account-note">${esc(n)}</p>`).join('')}`, 'lastNotes');
  }
  // Errors are styled and scrolled into view so a refused request is never silent.
  const status = (m, err = false) => {
    st.msg = m; st.err = err; const s = q('[data-pim-status]'); if (!s) return;
    s.textContent = m; s.classList.toggle('pim-status-error', err && Boolean(m));
    if (err && m) s.scrollIntoView?.({ block: 'nearest' });
  };
  async function load({ quiet = false, user = false } = {}) {
    const g = ++st.gen;
    if (!self) { const e = entity(); if (!e || e.type !== 'user') { st.loaded = true; st.rows = []; st.data = { notes: [e ? 'PIM applies to users. Pick a user.' : 'Pick a user first.'] }; render(); return null; } st.forId = e.id; }
    st.loading = true; if (user) st.userLoad = true; if (!quiet) render();
    try {
      const d = await api(self ? '/api/me/pim' : `/api/investigate/pim?${new URLSearchParams({ id: st.forId })}`);
      if (g !== st.gen) return d;
      st.data = d; st.rows = mergeRows(d.rows || [], self); st.loaded = true;
      if (!st.pending.size && !quiet) { st.msg = `Updated ${new Date().toLocaleTimeString()}.`; st.err = false; }
      return d;
    } catch (e) { if (g === st.gen) { st.loaded = true; if (!quiet) { st.msg = e.message; st.err = true; } } return null; }
    finally { if (g === st.gen) { st.loading = false; st.userLoad = false; render(); } else if (user) { st.userLoad = false; setBusy(q('[data-pim-refresh]'), false); } }
  }
  function closeForm() { st.form = null; const h = q('[data-pim-form-host]'); if (h) h.innerHTML = ''; }
  async function start(btn, row, action) {
    if (!row) return;
    if (action === 'deactivate') {
      const wait = deactivateWait(row);
      if (wait > 0) return status(`Microsoft allows a deactivation only after 5 minutes of active time. You can deactivate ${row.name} at ${new Date(Date.now() + wait).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' })}.`, true);
      if (!confirm(`Deactivate ${row.name}?`)) return;
      return send(row, { action });
    }
    setBusy(btn, true, 'Opening\u2026'); status(`Reading the activation policy for ${row.name}.`);
    let policy;
    try { policy = await api('/api/me/pim/policy', { method: 'POST', body: JSON.stringify({ type: row.type, target: row.target }) }); }
    catch (e) { policy = { maxMinutes: 480, justification: true, reason: e.message }; }
    setBusy(q(`button[data-pim-row="${globalThis.CSS?.escape ? globalThis.CSS.escape(rowId(row)) : rowId(row)}"]`) || btn, false);
    st.form = { row, policy };
    const h = q('[data-pim-form-host]'); h.innerHTML = activateFormHtml(row, policy, { esc }); status('');
    const f = h.querySelector('[data-pim-form]');
    f.addEventListener('submit', e => { e.preventDefault(); submit(f); });
    f.querySelector('[data-pim-cancel]').addEventListener('click', () => { closeForm(); status(''); });
    f.scrollIntoView?.({ block: 'nearest' });
    f.querySelector('input[name="reason"]')?.focus();
  }
  async function submit(f) {
    const { row } = st.form, v = n => f.elements[n]?.value?.trim() || '';
    const confirmBtn = f.querySelector('[data-pim-confirm]');
    setBusy(confirmBtn, true, 'Activating\u2026'); f.querySelector('[data-pim-cancel]').disabled = true;
    const fs = f.querySelector('[data-pim-form-status]'); if (fs) fs.textContent = `Sending the activation of ${row.name} to Microsoft.`;
    const ok = await send(row, { action: 'activate', reason: v('reason'), minutes: Number(v('minutes')), ticket: v('ticketNumber') ? { number: v('ticketNumber'), system: v('ticketSystem') } : null });
    if (ok) { if (st.form?.row === row) closeForm(); }
    else if (f.isConnected) { setBusy(confirmBtn, false); f.querySelector('[data-pim-cancel]').disabled = false; if (fs) fs.textContent = st.msg; }
  }
  async function send(row, extra) {
    const verb = extra.action === 'activate' ? 'activation' : 'deactivation';
    st.pending.set(row.key, { action: extra.action, n: 0, row }); status(`Submitting the ${verb} of ${row.name}.`); drawRows();
    let r;
    try { r = await api('/api/me/pim/request', { method: 'POST', body: JSON.stringify({ type: row.type, target: row.target, ...extra }) }); }
    catch (e) { st.pending.delete(row.key); status(friendlyError(e.message), true); drawRows(); return false; }
    if (/pending/i.test(r.status || '')) { st.pending.delete(row.key); status(`Request sent: ${r.status}. It becomes active after an approver approves it. Choose Refresh later.`); drawRows(); return true; }
    st.pending.get(row.key).status = r.status;
    status(`Request accepted (${r.status || 'Submitted'}). Waiting for Microsoft to ${extra.action === 'activate' ? 'activate' : 'remove'} ${row.name}.`);
    schedule(500);
    return true;
  }
  // One quiet poller for every pending row. Each row stops as soon as its state changes; other rows stay usable.
  function schedule(ms = POLL_MS) { clearTimeout(st.timer); st.timer = st.pending.size ? setTimeout(tick, ms) : null; }
  async function tick() {
    st.timer = null;
    const d = await load({ quiet: true });
    const done = [];
    for (const [key, p] of st.pending) {
      if (d && settled(st.rows, key, p.action)) { st.pending.delete(key); done.push(`${p.row.name} is ${p.action === 'activate' ? 'active' : 'deactivated'}.${p.action === 'activate' ? groupNote(p.row) : ''}`); continue; }
      if (++p.n >= POLL_MAX) { st.pending.delete(key); done.push(`${p.row.name}: Microsoft has not shown the change after ${Math.round(POLL_MAX * POLL_MS / 60000)} minutes. Choose Refresh to check again.`); continue; }
    }
    if (done.length) status(done.join(' '));
    else if (st.pending.size) { const [, p] = [...st.pending][0]; status(`Request accepted (${p.status || 'Submitted'}). Waiting for Microsoft to ${p.action === 'activate' ? 'activate' : 'remove'} ${p.row.name} (check ${p.n} of ${POLL_MAX}).`); }
    drawRows();
    schedule();
  }
  return {
    setActive(value) {
      st.active = value; if (!value) return;
      const e = entity();
      if (!st.loaded || (!self && (e?.id || null) !== st.forId)) load(); else render();
    },
    refresh() { return load({ user: true }); },
    reset() { st.gen++; clearTimeout(st.timer); Object.assign(st, { rows: [], loaded: false, loading: false, userLoad: false, data: null, form: null, msg: '', err: false, forId: null, pending: new Map(), timer: null, lastBody: null, lastTable: null, lastNotes: null, lastSources: null, lastOpts: {} }); const h = el(); if (h) h.innerHTML = ''; },
  };
}
