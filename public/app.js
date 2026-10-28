import { createBillingView } from './billing.js';
import { createPortalsView, createDefenderView } from './portals.js';
import { createDeploymentView } from './deployment.js';
import { partialMessage, bannerFor, APP_LEGEND } from './access-text.js';
import { pageSlice, pageInfo, pagerHtml, wirePager, DEFAULT_PAGE_SIZE } from './paging.js';
import { createDefenderEvents } from './defender.js';
import { createBucket4Views } from './bucket4.js';
import { createBucket5View, B5_VIEWS } from './bucket5.js';
import { createLicenseView } from './licenses.js';
import { createAccountView } from './account.js';
import { createIntuneView } from './intune.js';
import './error-lookup.js';
import { createSignInLookup } from './signins.js';
import { joinTypeLabel } from './device-links.js';
import { accountCardText } from './account-state.js';
import { B3_TABS, b3Panel, b3Url, whatIfForm, whatIfResult, diagnosticsPanel } from './tab-tables.js';
import { installColumnResize } from './col-resize.js';
import { ACTIVITY_HEADERS, activityColumns, activityService, activityCategory, activityStatus, activityActor } from './activity-columns.js';
import { filterOptions, applyFilters, multiSelectHtml, wireMultiSelects, filtersIntoHeaders, installMultiSelectDismiss, remainingBucket, grantedBucket, REMAINING_BUCKETS, GRANTED_BUCKETS } from './multiselect.js';
const $ = selector => document.querySelector(selector);
const $$ = selector => [...document.querySelectorAll(selector)];
const icons = {
  overview: '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>',
  activity: '<path d="M4 18V9m5 9V4m5 14v-7m5 7V6"/>',
  shield: '<path d="m12 3 8 3v6c0 5-8 9-8 9s-8-4-8-9V6z"/>',
  network: '<circle cx="6" cy="12" r="3"/><circle cx="18" cy="5" r="3"/><circle cx="18" cy="19" r="3"/><path d="m9 10 6-4M9 14l6 4"/>',
  database: '<ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v7c0 4 16 4 16 0V5M4 12v7c0 4 16 4 16 0v-7"/>',
  search: '<circle cx="10" cy="10" r="6.5"/><path d="m15 15 5 5"/>',
  calendar: '<rect x="3" y="5" width="18" height="16" rx="2"/><path d="M7 3v4m10-4v4M3 11h18m-13 4h1m6 0h1"/>',
  refresh: '<path d="M20 10a8 8 0 0 0-14-5L3 8m0-5v5h5m-4 6a8 8 0 0 0 14 5l3-3m0 5v-5h-5"/>',
  settings: '<path d="m9 3-1 3-3 1 1 4-2 2 2 4 3-1 3 3 3-3 3 1 2-4-2-2 1-4-3-1-1-3z"/><circle cx="12" cy="11" r="3"/>',
  terminal: '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="m7 9 3 3-3 3m6 0h4"/>',
  user: '<circle cx="12" cy="7" r="4"/><path d="M4 21v-2c0-7 16-7 16 0v2"/>',
  document: '<path d="M6 3h8l4 4v14H6zM14 3v5h4M9 12h6m-6 4h6"/>',
  cloud: '<path d="M6 18a5 5 0 0 1-1-10 7 7 0 0 1 13-1 5.5 5.5 0 0 1 0 11z"/>',
  key: '<circle cx="8" cy="9" r="5"/><path d="m12 13 8 8m-3-3 3-3m-6 0 3-3"/>',
  warning: '<path d="m12 3 10 18H2zM12 9v5m0 3h.01"/>',
  check: '<circle cx="12" cy="12" r="9"/><path d="m8 12 3 3 5-6"/>',
  copy: '<rect x="8" y="8" width="12" height="13" rx="2"/><path d="M16 8V3H3v13h5"/>',
  download: '<path d="M12 3v12m-5-5 5 5 5-5M4 16v5h16v-5"/>',
  device: '<rect x="5" y="3" width="14" height="13" rx="1"/><path d="m5 16-3 5h20l-3-5"/>',
  info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v6m0-10h.01"/>',
};
const icon = name => `<svg class="icon" viewBox="0 0 24 24" aria-hidden="true">${icons[name] || icons.document}</svg>`;
$$('[data-icon]').forEach(el => el.replaceWith(Object.assign(document.createElement('span'), { innerHTML: icon(el.dataset.icon) })));
const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const safeUrl = value => { try { const url = new URL(value); return url.protocol === 'https:' ? esc(url.href) : '#'; } catch { return '#'; } };
const external = (url, label, cls = 'btn') => `<a href="${safeUrl(url)}" target="_blank" rel="noopener noreferrer" class="${cls || 'btn'}">${esc(label)}</a>`;
const initials = name => String(name || '').split(/[\s-]+/).map(s => s[0]).slice(0, 2).join('').toUpperCase();
const typeLabel = type => ({ user: 'User', application: 'Application', managedIdentity: 'Managed identity' }[type] || type);
const categoryIcon = category => ({ 'Sign-ins': 'user', CLI: 'terminal', API: 'cloud', Changes: 'document', Governance: 'key', 'Data access': 'document' }[category] || 'activity');
const state = { resultFilter: null, policyKind: null, autoRan: new Set(), session: null, report: null, entity: null, view: 'summary', tab: 'ca', signinFilter: 'all', deviceStates: {}, category: 'All', source: 'all', direction: 'all', selected: null, page: 0, policyMode: 'current', days: 7, range: null, searchResults: [], searchIndex: -1, loading: false, fx: { excluded: {}, open: null } };
let searchTimer, searchVersion = 0, requestVersion = 0, pollTimer, toastTimer;
let pageSize = DEFAULT_PAGE_SIZE;
const signinPaging = { page: 0, size: DEFAULT_PAGE_SIZE };
const presetRange = days => ({ from: new Date(Date.now() - days * 86400000).toISOString(), to: new Date().toISOString() });
state.range = presetRange(7);
async function api(url, options = {}) {
  const response = await fetch(url, { ...options, headers: { 'Content-Type': 'application/json', ...(state.session ? { 'X-CSRF-Token': state.session.csrf } : {}), ...options.headers } });
  const data = await response.json();
  if (response.status === 401 && data.signin) signedOut(data.signin);
  if (!response.ok) throw new Error(data.error || 'Request failed.');
  return data;
}
// Signed out (new session, restart, or expired token): go to Microsoft sign-in. Never fall back to demo data.
function signedOut(signin) {
  if (state.session?.confidentialSignIn === false) { notice('Signed out. Sign in with Microsoft to load real data.', true); return; }
  resumeSignIn(signin);
}
// A lost server session (restart, scale-to-zero, idle) resumes with the last account and no account picker,
// then returns to the same view. Guarded so a failing sign-in cannot loop.
function resumeSignIn(signin) {
  let recent = false;
  try {
    recent = Date.now() - Number(sessionStorage.getItem('e360resumeAt') || 0) < 120000;
    sessionStorage.setItem('e360resumeAt', String(Date.now()));
    if (state.view) sessionStorage.setItem('e360resumeView', state.view);
  } catch { /* storage unavailable */ }
  if (state.session?.mode && state.session.mode !== 'signedout') toast('Session ended (server restarted or idle). Signing you back in.');
  location.assign(recent ? (signin || '/auth/login') : '/auth/login?resume=1');
}
function toast(message) { $('#toast').textContent = message; $('#toast').hidden = false; clearTimeout(toastTimer); toastTimer = setTimeout(() => { $('#toast').hidden = true; }, 3500); }
function notice(message, error = false) { $('#notice').textContent = message || ''; $('#notice').classList.toggle('error', error); $('#notice').hidden = !message; }
async function copy(value) { try { await navigator.clipboard.writeText(String(value)); toast('Copied to clipboard'); } catch { toast('Clipboard unavailable. Select and copy the text from details.'); } }
const signInLookup = createSignInLookup({ api, session: () => state.session, entity: () => state.entity, esc, external, resultBadge, showEvidence, onSources: sourceLinks });
const accountView = createAccountView({ api, session: () => state.session, esc, external, onSources: sourceLinks, openConnection });
const intuneView = createIntuneView({ api, session: () => state.session, esc, external, onSources: sourceLinks, openConnection });
const licenseView = createLicenseView({ api, session: () => state.session, esc, external, onSources: sourceLinks, openConnection, onConnectionsChanged: async () => { state.session = await api('/api/session'); sessionUI(); } });
const billingView = createBillingView({ api, esc, external, onSources: sourceLinks, openConnection });
const portalsView = createPortalsView({ esc, external });
const defenderView = createDefenderView({ esc, external });
const bucket5 = createBucket5View({ api, esc, external: (u, l) => external(u, l), emptyBox: t => emptyBox(t) });
const bucket4 = createBucket4Views({ api, esc, fmtTime: t => fmtTime(t), resultBadge: v => resultBadge(v), external, emptyBox: t => emptyBox(t) });
const defenderEvents = createDefenderEvents({ api, esc, external, entity: () => state.report?.entity || null, session: () => state.session, showEvidence });
const deploymentView = createDeploymentView({ esc });
function sessionUI() {
  const s = state.session;
  $('#viewer-name').textContent = s.viewer.name;
  $('#viewer-initials').textContent = initials(s.viewer.name);
  $('#mode-badge').textContent = s.mode === 'demo' ? 'DEMO DATA' : s.mode === 'signedout' ? 'SIGNED OUT' : s.mode === 'personal' ? 'PERSONAL · READ ONLY' : 'LIVE · READ ONLY';
  $('#mode-badge').classList.toggle('live', s.mode === 'live');
}
// ---- UI v2: shared helpers ----
const ENTITY_VIEWS = ['summary', 'signins', 'access', 'devices', 'activity'];
const MY_VIEWS = ['my-summary', 'my-signins', 'my-access', 'my-device'];
const roleReason = role => { const s = state.session; return s?.rolesEnforced && !(s.appRoles || []).includes(role) ? `Requires ${role} role` : ''; };
// Disable a button with a visible reason; enabling clears a reason we set.
function setOff(el, reason) {
  if (!el) return;
  if (reason) { el.title = reason; el.dataset.autoTitle = '1'; el.dataset.gated = '1'; el.disabled = true; }
  else { el.disabled = false; if (el.dataset.autoTitle) { el.removeAttribute('title'); delete el.dataset.autoTitle; } }
}
// Buttons that need an app role stay greyed out even after a module re-enables them.
const ROLE_GATES = { 'signin-run': 'E360.SignIns', 'intune-run': 'E360.Intune', 'billing-run': 'E360.Billing', 'license-run': 'E360.Reader', 'account-run': 'E360.Reader', 'activity-load': 'E360.Reader' };
function gateReason(el) {
  const s = state.session;
  if (!s) return '';
  if (s.mode === 'signedout') return 'Sign in first';
  if (el.id === 'activity-load') {
    if (s.mode === 'personal') return 'Needs an organizational connection';
    if (s.mode === 'live' && !s.azureConnected) return 'Azure not connected';
    if (!state.report?.entity) return 'Pick a user first';
  }
  if (el.dataset.role) return roleReason(el.dataset.role);
  return ROLE_GATES[el.id] ? roleReason(ROLE_GATES[el.id]) : '';
}
function applyGates(root = document) {
  root.querySelectorAll('.btn').forEach(el => {
    const reason = (ROLE_GATES[el.id] || el.dataset.role) ? gateReason(el) : '';
    if (reason) { el.dataset.gated = '1'; setOff(el, reason); }
    else if (el.dataset.gated) { delete el.dataset.gated; setOff(el, ''); }
    else if (el.disabled && !el.title) { el.title = el.dataset.why || 'Not available right now'; el.dataset.autoTitle = '1'; }
  });
}
// Every disabled .btn gets a title saying why; a re-enabled button loses the reason we added.
new MutationObserver(records => {
  for (const r of records) {
    const el = r.target;
    if (!el.classList?.contains('btn')) continue;
    if (el.disabled) {
      if (!el.title) { el.title = el.dataset.why || 'Not available right now'; el.dataset.autoTitle = '1'; }
    } else {
      const reason = (ROLE_GATES[el.id] || el.dataset.role) ? gateReason(el) : '';
      if (reason) { el.title = reason; el.dataset.autoTitle = '1'; el.dataset.gated = '1'; el.disabled = true; }
      else if (el.dataset.autoTitle) { el.removeAttribute('title'); delete el.dataset.autoTitle; }
    }
  }
}).observe(document.body, { subtree: true, attributes: true, attributeFilter: ['disabled'] });
const linkBtn = (url, label, reason = '') => reason || !url ? `<button type="button" class="btn" disabled title="${esc(reason || 'No link returned by the source')}">${esc(label)}</button>` : external(url, label, 'btn');
const fmtDuration = ms => { if (!Number.isFinite(ms)) return ''; const m = Math.round(Math.abs(ms) / 60000), d = Math.floor(m / 1440), h = Math.floor((m % 1440) / 60), mm = m % 60; return d ? `${d}d ${h}h` : h ? `${h}h ${mm}m` : `${mm}m`; };
const fmtTime = t => t ? `${new Date(t).toLocaleString('en-GB', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', timeZone: 'UTC' })} UTC` : '';
const emptyBox = text => `<div class="inline-empty">${esc(text)}</div>`;
const sourceOk = id => { const s = state.report?.sources.find(x => x.id === id); return s && !/unavailable|denied|error|not connected|failed/i.test(String(s.status)); };
const signIns = () => (state.report?.events || []).filter(e => e.category === 'Sign-ins');
// Defender process events live on the Defender tab only, so the Activity table does not repeat them.
const otherEvents = () => (state.report?.events || []).filter(e => e.category !== 'Sign-ins' && e.source !== 'defender');
const caResult = p => p.result || (p.status === 'Incomplete' ? 'Incomplete' : 'Applies');
export function isSelf(entityId, viewerId) { return !!entityId && !!viewerId && String(entityId).toLowerCase() === String(viewerId).toLowerCase(); }
function isSignedInUser() { return isSelf(state.report?.entity?.id, state.session?.viewer?.id); }
// Access > Admin roles: one line listing PIM for Groups eligibilities (group, member/owner, end date).
function pimGroupsLine(pg) {
  if (!pg) return '';
  const text = !pg.readable ? `Not readable (${pg.reason || 'scope not consented'})`
    : !pg.rows.length ? 'None'
    : pg.rows.map(x => `${x.group} (${x.access.toLowerCase()}, ${x.end ? `until ${new Date(x.end).toLocaleDateString()}` : 'permanent'})`).join('; ');
  return `<p class="pim-groups-line"><strong>PIM group memberships:</strong> ${esc(text)}</p>`;
}
function roleRow(p) {
  const t = p.timing || null;
  const type = /eligible/i.test(`${p.status} ${p.assignment}`) ? 'Eligible' : t && !t.permanent ? 'Active' : 'Permanent';
  const m = String(p.detail || '').match(/scope: (\S+)/i);
  const scope = p.scopeName ? p.scopeName : m ? m[1].replace(/[.;,]+$/, '') : String(p.detail || '').startsWith('/') ? String(p.detail).split(/\s/)[0] : p.source === 'azure' ? 'Not returned' : '/ (directory)';
  const g = String(p.assignment || '').match(/(?:through|inherited through) (.+)$/i);
  const pg = String(p.assignment || '').match(/^Eligible via PIM group (.+)$/);
  const via = pg ? `Eligible via PIM group ${pg[1]}` : g ? `Group: ${g[1].replace(/ group$/i, '')}` : 'Direct';
  const granted = t?.granted && Number.isFinite(Date.parse(t.granted)) ? fmtTime(t.granted) : ''; // startDateTime; blank when not returned
  const remaining = t && Number.isFinite(t.remaining) ? (t.remaining > 0 ? fmtDuration(t.remaining) : 'Expired') : type === 'Permanent' ? 'No end date' : 'Not returned';
  const ms = t && Number.isFinite(t.remaining) ? t.remaining : null;
  const definition = p.builtIn === true ? 'Built-in' : p.builtIn === false ? 'Custom' : p.source === 'azure' ? 'Azure RBAC' : 'Not returned';
  return { p, plane: p.source === 'azure' ? 'Azure' : 'Entra', type, definition, scope, via, granted, remaining, ms, remainingBucket: remainingBucket(ms, ms == null && type === 'Permanent'), grantedBucket: grantedBucket(t?.granted) };
}
const roles = () => (state.report?.policies || []).filter(p => p.kind === 'Role').map(roleRow);
const devicePolicies = () => (state.report?.policies || []).filter(p => p.kind === 'Device');
function sourceLinks() { /* Source links now live under Health checks > Source coverage. */ }

async function loadHosting() {
  try {
    const { groups } = await api('/api/hosting');
    $('#hosting-panel').hidden = !groups.length;
    $('#hosting-list').innerHTML = groups.map(g => `<article class="coverage-card"><header><h3>${esc(g.group)}</h3></header><p>${esc(g.name)}</p>${g.status ? `<p><small>${esc(g.status)}</small></p>` : ''}<div class="card-actions">${g.links.map(l => linkBtn(l.url, l.label, l.reason)).join('')}${g.links.filter(l => l.reason).map(l => `<small>${esc(l.reason)}</small>`).join('')}</div></article>`).join('');
  } catch { $('#hosting-panel').hidden = true; }
}
function clearReport() {
  requestVersion++;
  searchVersion++; clearTimeout(searchTimer); hideSearch(); state.searchResults = []; state.searchIndex = -1; $('#search-results').innerHTML = ''; $('#entity-search').value = '';
  state.report = null; state.entity = null; state.selected = null; state.source = 'all'; state.loading = false; state.autoRan = new Set(); state.deviceStates = {};
  for (const selector of ['#summary-cards', '#signin-table-rows', '#access-tab-body', '#device-cards', '#event-rows', '#coverage-list', '#evidence-content', '#entity-header']) $(selector).innerHTML = '';
  $('#signin-drawer').hidden = true; $('#loading').hidden = true; $('#refresh-button').disabled = false; notice('');
  renderTopbar();
  signInLookup.reset(); accountView.reset(); intuneView.reset(); licenseView.reset(); billingView.reset(); applyView();
}
async function loadEntity(entity, { refresh = false } = {}) {
  const version = ++requestVersion;
  state.entity = entity; state.report = null;
  if (refresh && state.days) state.range = presetRange(state.days);
  state.loading = true; renderTopbar();
  $('#loading').hidden = false; $('#refresh-button').disabled = true;
  notice(''); applyView();
  try {
    const report = await api(`/api/investigate?${new URLSearchParams({ id: entity.id, type: entity.type, ...state.range })}`);
    if (version !== requestVersion) return;
    state.report = report; state.entity = report.entity; state.page = 0; state.selected = null; state.deviceStates = {};
    if (!report.sources.some(s => s.id === state.source)) state.source = 'all';
    render();
    // The Partial results banner is tab-scoped and set in applyView().
  } catch (error) {
    if (version !== requestVersion) return;
    state.report = null; state.selected = null; notice(error.message, true);
  } finally {
    if (version === requestVersion) { state.loading = false; $('#loading').hidden = true; $('#refresh-button').disabled = false; renderTopbar(); applyView(); }
  }
}
function renderTopbar() {
  const e = state.report?.entity || state.entity;
  $('#current-initials').textContent = e ? initials(e.name) || '?' : '?';
  $('#current-name').textContent = e ? e.name || 'Loading' : 'No user selected';
  $('#current-detail').textContent = e ? [e.subtitle || e.email || e.upn, typeLabel(e.type)].filter(Boolean).join(' · ') : 'Use Change user (press /) to pick one';
}
function render() {
  const r = state.report;
  if (!r) return;
  renderTopbar();
  renderSummary(); renderSignins(); renderAccess(); renderDevices(); renderActivity(); renderCoverage();
  $('#coverage-footer').textContent = `The following sources were used - ${r.partial ? 'Partial collection' : 'Available evidence only'}`;
  $('#coverage-sources').innerHTML = r.sources.map(s => `<li>${esc(s.name)}</li>`).join('');
  $('#updated-at').textContent = `Retrieved ${new Date(r.updatedAt).toLocaleTimeString('en-GB', { timeZone: 'UTC' })} UTC`;
}
// ---- Summary: counts only, each linking to the page that holds the rows ----
function renderSummary() {
  const r = state.report, e = r.entity;
  $('#entity-header').innerHTML = `<section class="panel entity-strip"><span>Object ID <code>${esc(e.id)}</code></span><button type="button" class="btn" id="copy-entity">Copy ID</button>${linkBtn(r.mode === 'demo' ? 'https://entra.microsoft.com/' : e.link, 'Open in Entra')}</section>`;
  $('#copy-entity').onclick = () => copy(e.id);
  const si = signIns(), n = res => si.filter(x => x.result === res).length;
  const siOk = sourceOk('signins') || si.length;
  const rs = roles(), active = rs.filter(x => x.type !== 'Eligible'), soon = active.filter(x => x.ms > 0).sort((a, b) => a.ms - b.ms)[0];
  const dev = devicePolicies(), comp = dev.filter(d => /^compliant$/i.test(d.status)).length;
  const ca = (r.policies || []).filter(p => p.kind === 'Conditional Access'), caApply = ca.filter(p => caResult(p) === 'Applies').length, caInc = ca.filter(p => caResult(p) === 'Incomplete').length;
  const go = (label, view, extra = '', reason = '') => `<button type="button" class="btn" data-go="${view}" ${extra}${reason ? ` disabled title="${esc(reason)}"` : ''}>${esc(label)}</button>`;
  const card = (title, value, note, actions) => `<section class="panel summary-card"><h3>${esc(title)}</h3><div class="summary-value">${esc(value)}</div><p>${esc(note)}</p><div class="card-actions">${actions}</div></section>`;
  $('#summary-cards').innerHTML = [
    card(`Sign-ins (${$('#range-label').textContent})`, siOk ? si.length : 'n/a', siOk ? `${n('Success')} succeeded, ${n('Blocked')} blocked, ${n('Failed')} failed` : 'Sign-in source unavailable or permission missing',
      [['Success', 'succeeded'], ['Blocked', 'blocked'], ['Failed', 'failed']].map(([res, word]) => go(`${n(res)} ${word}`, 'signins', `data-filter="${res}"`, n(res) ? '' : `No ${word} sign-ins in this range`)).join('')),
    card('Active admin roles', active.length, active.length ? soon ? `Soonest ends in ${soon.remaining} (${soon.p.name})` : 'None are time-limited' : `${rs.length - active.length} eligible, none active`, go('Open Admin roles', 'access', 'data-tab="roles"', rs.length ? '' : 'No role assignments returned for this user')),
    card('Devices', dev.length, dev.length ? `${comp} compliant, ${dev.length - comp} not compliant` : sourceOk('intune') ? 'No Intune device for this user' : 'Intune source unavailable or permission missing', go('Open Devices', 'devices', '', dev.length ? '' : 'No Intune device for this user')),
    accountCard(r.account, card),
    card('Conditional Access', caApply, ca.length ? `Policies applying${caInc ? `, ${caInc} incomplete` : ''}` : 'No policies returned (source unavailable or none apply)', go('Open Conditional Access', 'access', 'data-tab="ca"', ca.length ? '' : 'No Conditional Access results returned')),
  ].join('');
}
document.addEventListener('click', event => {
  const b = event.target.closest('[data-go]');
  if (!b || b.disabled) return;
  if (b.dataset.filter) state.signinFilter = b.dataset.filter;
  if (b.dataset.tab) state.tab = b.dataset.tab;
  state.view = b.dataset.go;
  if (state.report) { renderSignins(); renderAccess(); }
  applyView();
});
// ---- Sign-ins: table plus a side drawer with the reason and applied policies ----
function renderSignins() {
  const all = signIns(), f = state.signinFilter || 'all';
  $('#signin-result-filter').value = f;
  if (state.signinPagedFor !== state.report) { state.signinPagedFor = state.report; signinPaging.page = 0; }
  const rows = f === 'all' ? all : all.filter(e => e.result === f);
  $('#signin-count').textContent = rows.length;
  const slice = pageSlice(rows, signinPaging.page, signinPaging.size); signinPaging.page = slice.page;
  $('#signin-table-pager').innerHTML = rows.length ? pagerHtml('signin-table', slice, 'sign-ins') : '';
  wirePager($('#signin-table-pager'), 'signin-table', signinPaging, renderSignins);
  $('#signin-table-rows').innerHTML = slice.rows.map((e, i) => `<tr data-signin="${i}" tabindex="0" class="${e.id === state.selected?.id ? 'selected' : ''}"><td>${esc(fmtTime(e.time))}</td><td>${esc(e.target || e.title)}</td><td>${resultBadge(e.result)}</td><td>${esc(e.ip || 'Not returned')}</td></tr>`).join('');
  const empty = !rows.length;
  $('#signin-table-empty').hidden = !empty;
  $('#signin-table-empty').textContent = !sourceOk('signins') && !all.length ? 'Sign-in source unavailable or permission missing (needs AuditLog.Read.All and an Entra ID P1 tenant).' : all.length ? `No ${f.toLowerCase()} sign-ins in this range. Set Result to All.` : 'No sign-ins for this user in the selected date range.';
  $$('#signin-table-rows tr').forEach(tr => { const open = () => { state.selected = slice.rows[Number(tr.dataset.signin)]; renderSignins(); }; tr.onclick = open; tr.onkeydown = ev => { if (ev.key === 'Enter') open(); }; });
  renderDrawer();
}
function renderDrawer() {
  const e = state.selected, d = $('#signin-drawer');
  if (!e || e.category !== 'Sign-ins') { d.hidden = true; d.innerHTML = ''; $('#signin-split').classList.remove('open'); return; }
  const ps = e.evaluatedPolicies || [];
  const head = e.result === 'Blocked' ? 'Why was it blocked?' : e.result === 'Failed' ? 'Why did it fail?' : 'Sign-in details';
  d.innerHTML = `<div class="panel-heading"><div><h2 id="drawer-title">${esc(head)}</h2><p>${esc(fmtTime(e.time))} · ${esc(e.target || e.title)}</p></div><button type="button" class="btn" id="drawer-close">Close</button></div>
    <h3>Result</h3><p>${resultBadge(e.result)}</p><h3>Failure reason</h3><p>${esc(e.result === 'Success' ? 'None. The sign-in succeeded.' : e.explanation || 'Not returned by the source')}</p>
    <h3>Conditional Access applied</h3>${ps.length ? `<div class="table-wrap"><table class="event-table" data-table-id="access-ca"><thead><tr><th>Policy</th><th>Result</th></tr></thead><tbody>${ps.map(p => `<tr><td>${esc(p.name)}${p.detail ? `<small>${esc(p.detail)}</small>` : ''}</td><td>${resultBadge(p.status || 'Not returned')}</td></tr>`).join('')}</tbody></table></div>` : emptyBox('No Conditional Access results were returned for this sign-in, so none applied or the source did not include them.')}
    <div class="card-actions"><button type="button" class="btn" id="drawer-evidence">View evidence (raw)</button>${linkBtn(e.link, 'Open in Entra', e.link ? '' : 'No Entra link for this record')}</div>`;
  d.hidden = false; $('#signin-split').classList.add('open');
  $('#drawer-close').onclick = () => { state.selected = null; renderSignins(); };
  $('#drawer-evidence').onclick = () => showEvidence(e);
}
$('#signin-result-filter').onchange = ev => { state.signinFilter = ev.target.value; renderSignins(); };
// ---- Access: CA, admin roles, groups (and app records when present) ----
// Column filters (multi-select). Known values first, then anything present in the data.
const APP_KINDS = ['Application assignment', 'API permission', 'Delegated permission', 'Credential'];
const appExpires = p => p.kind === 'Credential' ? (p.expires ? `${fmtTime(p.expires)}${Date.parse(p.expires) < Date.now() ? ' (expired)' : ''}` : 'Not returned') : 'No expiry';
const appVia = p => p.consent ? `${p.consent} consent` : /^Through /.test(p.assignment || '') ? 'Group' : p.kind === 'Application assignment' ? 'Direct' : p.assignment || 'Not returned';
const KNOWN = {
  'ca.result': ['Applies', 'Incomplete', 'Does not apply'],
  'roles.type': ['Permanent', 'Active', 'Eligible'], 'roles.granted': GRANTED_BUCKETS, 'roles.remaining': REMAINING_BUCKETS, 'roles.source': ['Direct'],
  'groups.kind': ['Group', 'User', 'Application', 'Device', 'Virtual machine', 'API'], 'groups.relation': ['Member of', 'Transitive membership', 'Owner', 'Owns this application', 'Permission grant', 'Managed device', 'Observed target', 'Observed dependency'],
  'apps.kind': ['Application assignment', 'API permission', 'Delegated permission', 'Credential'], 'apps.status': ['Assigned', 'Granted', 'Consented', 'Configured', 'Expired'], 'apps.via': ['Direct'],
  'act.direction': ['Actor', 'Target'],
};
function filterBar(rows, cols) {
  return `<div class="msel-bar">${cols.map(c => multiSelectHtml({ key: c.key, label: c.label, options: c.options || filterOptions(KNOWN[c.key], rows.map(c.get).flat()), excluded: state.fx.excluded[c.key], open: state.fx.open === c.key, sort: state.fx.sort, header: c.header || c.label })).join('')}</div>`;
}
function filtered(rows, cols) { return applyFilters(rows, cols, state.fx.excluded, state.fx.sort); }
const countOf = (shown, all) => shown === all ? `${all}` : `${shown} of ${all}`;
function renderAccess() {
  const r = state.report; if (!r) return;
  const other = r.policies.filter(p => APP_KINDS.includes(p.kind));
  const isApp = (r.entity?.type || 'user') !== 'user';
  $('#access-tab-apps').hidden = !other.length;
  $('#access-tab-sso').hidden = !isApp;
  if (!state.tab || (state.tab === 'apps' && !other.length) || (state.tab === 'sso' && !isApp)) state.tab = 'ca';
  $$('#access-page .tab').forEach(t => { const on = t.dataset.tab === state.tab; t.classList.toggle('active', on); t.setAttribute('aria-selected', on); });
  const body = $('#access-tab-body');
  if (B3_TABS[state.tab]) { renderB3(body); return; }
  if (state.tab === 'ca') {
    const all = r.policies.filter(p => p.kind === 'Conditional Access');
    const cols = [{ key: 'ca.result', label: 'Result', get: caResult }];
    const ca = filtered(all, cols);
    const note = r.sources.find(s => s.id === 'policies')?.note || '';
    body.innerHTML = `<div class="panel-heading"><div><h2>Conditional Access <span class="count">${countOf(ca.length, all.length)}</span></h2><p>${esc(note || 'Which policies apply to this identity today.')}</p></div></div>` + (state.session?.mode === 'live' ? `<details class="whatif-box"${state.whatIf?.id === r.entity.id ? ' open' : ''}><summary>What If inputs</summary><p class="account-note">Supply the sign-in conditions e360 cannot know, then run Microsoft What If again. Read-only.</p>${whatIfForm(state.whatIf?.id === r.entity.id ? state.whatIf.input : {}, esc)}${whatIfResult(state.whatIf?.id === r.entity.id ? state.whatIf.st : null, b3Help())}</details>` : '') + (all.length ? filterBar(all, cols) : '') + (ca.length ? `<div class="table-wrap"><table class="event-table" data-table-id="access-ca"><thead><tr><th>Policy</th><th>Result</th><th>Controls</th><th>Reason</th><th></th></tr></thead><tbody>${ca.map(p => `<tr><td>${esc(p.name)}<small>State: ${esc(p.state || p.status)}</small></td><td>${resultBadge(caResult(p))}</td><td>${esc(p.controls || 'None returned')}</td><td>${esc([p.assignment, p.detail].filter(Boolean).join('. '))}</td><td>${linkBtn(p.link, 'Open policy')}</td></tr>`).join('')}</tbody></table></div>` : emptyBox(all.length ? 'No policies match these filters. Use Select all to show every result.' : sourceOk('policies') ? 'No Conditional Access policy applies to this identity for the evaluated apps.' : 'Conditional Access source unavailable or permission missing (needs Policy.Read.All).'));
  } else if (state.tab === 'roles' && isSignedInUser()) {
    // No duplication: the signed-in user's roles live on My access.
    body.innerHTML = `<p class="self-roles-note">Your own admin roles are listed on My access, under Group memberships and Role assignments. <button type="button" class="btn" data-go="my-access">Open My access</button></p>`;
  } else if (state.tab === 'roles') {
    const all = roles();
    const cols = [{ key: 'roles.role', label: 'Role', get: x => x.p.name }, { key: 'roles.type', label: 'Type', get: x => x.type }, { key: 'roles.granted', label: 'Granted', get: x => x.grantedBucket, sortValue: x => x.p.timing?.granted ?? null }, { key: 'roles.remaining', label: 'Remaining', get: x => x.remainingBucket, sortValue: x => x.ms }, { key: 'roles.source', label: 'Source', get: x => x.via }];
    const rs = filtered(all, cols);
    body.innerHTML = `<div class="panel-heading"><div><h2>Admin roles <span class="count">${countOf(rs.length, all.length)}</span></h2><p>Entra directory roles and Azure RBAC together. Remaining time comes from PIM. Granted filters by age of the grant; Remaining by time left.</p></div></div>` + pimGroupsLine(r.pimGroups) + (all.length ? filterBar(all, cols) : '') + (rs.length ? `<div class="table-wrap"><table class="event-table" data-table-id="access-roles"><thead><tr><th>Role</th><th>Scope</th><th>Type</th><th>Granted</th><th>Remaining</th><th>Source</th><th title="Actions the role definition allows (rolePermissions.allowedResourceActions)">Permissions</th><th title="PIM activation rules for eligible Entra roles">Activation</th><th></th></tr></thead><tbody>${rs.map(x => `<tr><td>${esc(x.p.name)}<small>${esc(x.plane)}</small></td><td><code>${esc(x.scope)}</code></td><td>${resultBadge(x.type)}<small>${esc(x.definition)}</small></td><td>${esc(x.granted)}</td><td>${esc(x.remaining)}</td><td>${esc(x.via)}</td><td${x.p.permissions?.length ? ` title="${esc(x.p.permissions.join('\n'))}"` : ''}>${esc(x.p.permissionText || (x.plane === 'Azure' ? 'See Azure portal' : 'Not returned'))}</td><td>${esc(x.p.activation || (x.type === 'Eligible' ? 'Not returned' : ''))}</td><td>${linkBtn(x.p.link, 'Open')}</td></tr>`).join('')}</tbody></table></div>` : emptyBox(all.length ? 'No roles match these filters. Use Select all to show every role.' : sourceOk('roles') || sourceOk('azure') ? 'No admin roles are assigned to this identity, directly or through groups.' : 'Role sources unavailable or permission missing (Entra roles need RoleManagement.Read.Directory; Azure roles need Connect Azure).'));
  } else if (state.tab === 'packages') {
    // Read-only entitlement management view: packages held, resources each grants, and pending requests.
    const ap = r.accessPackages || { packages: [], requests: [] };
    const all = ap.packages;
    const cols = [{ key: 'pkg.state', label: 'State', get: p => p.state }, { key: 'pkg.catalog', label: 'Catalog', get: p => p.catalog }];
    const ps = filtered(all, cols);
    const res = p => p.resources.length ? p.resources.map(x => `${esc(x.name)} <small>${esc([x.role, x.type].filter(Boolean).join(', '))}</small>`).join('<br>') : 'Not returned';
    const reqs = ap.requests.length ? `<h3>Pending requests <span class="count">${ap.requests.length}</span></h3><div class="table-wrap"><table class="event-table" data-table-id="access-pkg-requests"><thead><tr><th>Package</th><th>Request</th><th>State</th><th>Created</th></tr></thead><tbody>${ap.requests.map(q => `<tr><td>${esc(q.name)}</td><td>${esc(q.type)}</td><td>${resultBadge(q.state)}</td><td>${esc(fmtTime(q.created))}</td></tr>`).join('')}</tbody></table></div>` : '';
    body.innerHTML = `<div class="panel-heading"><div><h2>Access packages <span class="count">${countOf(ps.length, all.length)}</span></h2><p>Entitlement management assignments for this identity, the policy that granted each one, and the resources it gives. Read-only.</p></div></div>` + (all.length ? filterBar(all, cols) : '') + (ps.length ? `<div class="table-wrap"><table class="event-table" data-table-id="access-packages"><thead><tr><th>Package</th><th>Policy</th><th>Assigned</th><th>Expires</th><th>State</th><th>Resources</th><th></th></tr></thead><tbody>${ps.map(p => `<tr><td>${esc(p.name)}<small>Catalog: ${esc(p.catalog)}</small></td><td>${esc(p.policy)}</td><td>${esc(fmtTime(p.assigned) || 'Not returned')}</td><td>${esc(fmtTime(p.expires) || 'No expiry')}</td><td>${resultBadge(p.state)}<small>${esc(p.status)}</small></td><td>${res(p)}</td><td>${linkBtn('https://entra.microsoft.com/#view/Microsoft_AAD_ERM/DashboardBlade/~/elmEntitlement', 'Open')}</td></tr>`).join('')}</tbody></table></div>` : emptyBox(all.length ? 'No packages match these filters. Use Select all to show every package.' : sourceOk('governance') ? 'This identity holds no access packages.' : 'Entitlement management unavailable or permission missing (needs EntitlementManagement.Read.All and an Entra ID P2 or Governance license).')) + reqs;
  } else if (state.tab === 'groups') {
    const all = r.relationships.filter(x => !['intune', 'azure'].includes(x.source));
    const cols = [{ key: 'groups.kind', label: 'Kind', get: x => x.kind }, { key: 'groups.relation', label: 'Relation', get: x => x.relation }];
    const gs = filtered(all, cols);
    body.innerHTML = `<div class="panel-heading"><div><h2>Groups and related identities <span class="count">${countOf(gs.length, all.length)}</span></h2><p>Memberships, owners and related applications from Entra.</p></div></div>` + (all.length ? filterBar(all, cols) : '') + (gs.length ? `<div class="table-wrap"><table class="event-table" data-table-id="access-groups"><thead><tr><th>Name</th><th>Kind</th><th>Relation</th><th></th></tr></thead><tbody>${gs.map((x, i) => `<tr><td>${esc(x.name)}</td><td>${esc(x.kind)}</td><td>${esc(x.relation)}</td><td>${x.entityId ? `<button type="button" class="btn" data-related="${i}">Investigate</button>` : linkBtn(x.link, 'Open', x.link ? '' : 'No portal link returned')}</td></tr>`).join('')}</tbody></table></div>` : emptyBox(all.length ? 'Nothing matches these filters. Use Select all to show every row.' : sourceOk('directory') ? 'This identity is not a member of any group.' : 'Directory source unavailable or permission missing (needs GroupMember.Read.All).'));
    $$('[data-related]').forEach(b => b.onclick = () => { const x = gs[Number(b.dataset.related)]; loadEntity({ id: x.entityId, type: x.entityType, name: x.name }); });
  } else {
    const cols = [{ key: 'apps.kind', label: 'Kind', get: p => p.kind }, { key: 'apps.status', label: 'Status', get: p => p.status }, { key: 'apps.role', label: 'Role', get: p => p.role || 'Not returned' }, { key: 'apps.via', label: 'Assignment', get: appVia }];
    const shown = filtered(other, cols);
    const kinds = [...new Set(other.flatMap(p => [p.kind, p.status]))].filter(k => APP_LEGEND[k]);
    const legend = `<details class="apps-legend"><summary>What Kind and Status mean</summary><dl>${kinds.map(k => `<dt>${esc(k)}</dt><dd>${esc(APP_LEGEND[k])}</dd>`).join('')}</dl></details>`;
    const date = p => p.date ? fmtTime(p.date) : p.kind === 'Delegated permission' ? 'Not recorded by Microsoft' : 'Not returned';
    body.innerHTML = `<div class="panel-heading"><div><h2>App permissions <span class="count">${countOf(shown.length, other.length)}</span></h2><p>App assignments, permissions and credentials for this identity. Open goes to the specific assignment or the app's permissions page.</p></div></div>${legend}${filterBar(other, cols)}<div class="table-wrap"><table class="event-table" data-table-id="access-apps"><thead><tr><th>App</th><th>Kind</th><th>Status</th><th>Role</th><th>Assignment</th><th>Date</th><th>Expires</th><th></th></tr></thead><tbody>${shown.map(p => `<tr><td>${esc(p.name)}<small>${esc(p.detail || '')}</small></td><td>${esc(p.kind)}</td><td>${resultBadge(p.status)}</td><td>${esc(p.role || 'Not returned')}</td><td>${esc(p.assignment || '')}</td><td>${esc(date(p))}</td><td>${esc(appExpires(p))}</td><td>${linkBtn(p.link, p.linkLabel || 'Open')}</td></tr>`).join('')}</tbody></table></div>`;
  }
  wireWhatIf(body);
  wireMultiSelects(body, state.fx, () => renderAccess());
  body.querySelectorAll('.msel-bar').forEach(bar => filtersIntoHeaders(bar, body.querySelector('table')));
  body.querySelector('[data-msel][open] summary')?.focus();
}
$$('#access-page .tab').forEach(t => t.onclick = () => { state.tab = t.dataset.tab; renderAccess(); });
// ---- Bucket 3: tables loaded when their tab is opened, cached per entity ----
const b3Help = () => ({ esc, fmtTime, resultBadge, linkBtn, emptyBox, external });
function renderB3(body) {
  const key = state.tab, e = state.report.entity, cache = state.b3 && state.b3.id === e.id ? state.b3 : (state.b3 = { id: e.id });
  if (!cache[key]) {
    cache[key] = { loading: true };
    api(b3Url(key, e)).then(d => { cache[key] = { data: d }; }, err => { cache[key] = { error: err.message }; }).finally(() => { if (state.tab === key && state.report?.entity?.id === e.id) renderAccess(); });
  }
  body.innerHTML = b3Panel(key, cache[key], b3Help());
}
function wireWhatIf(body) {
  const run = body.querySelector('#whatif-run'); if (!run) return;
  run.onclick = () => {
    const input = {}; body.querySelectorAll('[data-whatif]').forEach(x => { if (x.value) input[x.dataset.whatif] = x.value.trim(); });
    const e = state.report.entity; state.whatIf = { id: e.id, input, st: { loading: true } }; renderAccess();
    api('/api/ca/whatif', { method: 'POST', body: JSON.stringify({ id: e.id, type: e.type || 'user', input }) }).then(d => { state.whatIf.st = { data: d }; }, err => { state.whatIf.st = { error: err.message }; }).finally(() => { if (state.tab === 'ca') renderAccess(); });
  };
}
let diagState = null;
function renderDiagnostics() {
  const root = $('#diag-panel'); if (!root) return;
  root.hidden = state.session?.mode !== 'live';
  root.innerHTML = `<div class="panel">${diagnosticsPanel(diagState, b3Help())}</div>`;
  root.querySelector('#diag-run').onclick = () => { diagState = { loading: true }; renderDiagnostics(); api('/api/tab-table?table=diagnostics').then(d => { diagState = { data: d }; }, err => { diagState = { error: err.message }; }).finally(renderDiagnostics); };
}
// ---- Devices: one card each; policy states load inline ----
function renderDevices() {
  const dev = devicePolicies();
  if (!dev.length) { $('#device-cards').innerHTML = emptyBox(sourceOk('intune') ? 'No Intune device for this user.' : 'Intune source unavailable or permission missing (needs DeviceManagementManagedDevices.Read.All).'); return; }
  const intuneRole = roleReason('E360.Intune');
  $('#device-cards').innerHTML = dev.map((p, i) => {
    const st = state.deviceStates?.[i];
    const sync = p.evidence?.lastSyncDateTime ? fmtTime(p.evidence.lastSyncDateTime) : (/^Last synchronized:\s*/i.test(p.detail || '') ? String(p.detail).replace(/^Last synchronized:\s*/i, '') : 'Not returned');
    const reason = !p.deviceId ? 'No Intune device record for this device' : intuneRole;
    const states = !st ? '' : st.loading ? '<p class="muted">Loading policy states from Intune</p>' : st.error ? `<p class="error-text">${esc(st.error)}</p>` : st.rows.length ? `${filterBar(st.rows, devCols(i))}<div class="table-wrap"><table class="event-table" data-table-id="device-states"><thead><tr><th>Policy</th><th>Type</th><th>State</th></tr></thead><tbody>${filtered(st.rows, devCols(i)).map(x => `<tr><td>${esc(x.name)}</td><td>${esc(x.kind)}</td><td>${resultBadge(x.state)}</td></tr>`).join('')}</tbody></table></div>` : emptyBox('Intune returned no compliance or configuration policy states for this device.');
    return `<section class="panel device-card"><h3>${esc(p.assignment || p.name)}</h3><dl><dt>Compliance</dt><dd>${resultBadge(p.status)}</dd><dt>Last sync</dt><dd>${esc(sync)}</dd><dt>Join type</dt><dd>${esc(joinTypeLabel(p.trustType))}</dd><dt>Policy</dt><dd>${esc(p.name)}</dd></dl><div class="card-actions"><button type="button" class="btn" data-states="${i}" ${reason ? `disabled title="${esc(reason)}"` : ''}>${st && !st.loading && !st.error ? 'Hide policy states' : 'Load policy states'}</button>${linkBtn(p.link, 'Open in Intune')}</div><div class="device-states">${states}</div></section>`;
  }).join('');
  $$('[data-states]').forEach(b => b.onclick = () => loadDeviceStates(Number(b.dataset.states)));
  $$('#device-cards .device-states').forEach(el => { const bar = el.querySelector('.msel-bar'); if (!bar) return; wireMultiSelects(bar, state.fx, () => renderDevices()); filtersIntoHeaders(bar, el.querySelector('table')); });
}
// Per-device policy-state filters (Type, State); keys are per card so devices filter independently.
function devCols(i) { return [{ key: `dev${i}.kind`, label: 'Type', get: x => x.kind }, { key: `dev${i}.state`, label: 'State', get: x => x.state }]; }
async function loadDeviceStates(i) {
  const p = devicePolicies()[i];
  state.deviceStates ||= {};
  if (state.deviceStates[i] && !state.deviceStates[i].loading && !state.deviceStates[i].error) { delete state.deviceStates[i]; renderDevices(); return; }
  state.deviceStates[i] = { loading: true }; renderDevices();
  try { const r = await api(`/api/intune/device-states?${new URLSearchParams({ id: p.deviceId })}`); state.deviceStates[i] = { rows: r.states || [] }; }
  catch (err) { state.deviceStates[i] = { error: err.message }; }
  renderDevices();
}
// ---- Azure activity: everything except sign-ins ----
function filteredEvents() {
  return filtered(otherEvents(), activityCols());
}
// Perspective: a row passes if any of its perspectives (Actor, Target) is checked.
function activityCols() {
  const src = state.report?.sources || [], ev = otherEvents();
  return [
    { key: 'act.direction', label: 'Perspective', get: e => ['Actor', 'Target'].filter(d => String(e.direction || '').includes(d)).concat(String(e.direction || '').match(/Actor|Target/) ? [] : ['n/a']), options: [{ value: 'Actor', label: 'Actions by entity' }, { value: 'Target', label: 'Changes to entity' }, ...(ev.some(e => !/Actor|Target/.test(e.direction || '')) ? [{ value: 'n/a', label: 'Not stated' }] : [])] },
    ...activityColumns(src, ev, filterOptions),
  ];
}
function renderActivityFilters() {
  const box = $('#activity-filters');
  box.innerHTML = filterBar(otherEvents(), activityCols()).replace('<div class="msel-bar">', '').replace(/<\/div>$/, '');
  wireMultiSelects(box, state.fx, () => { state.page = 0; renderActivity(); $('#activity-page [data-msel][open] summary')?.focus(); });
  filtersIntoHeaders(box, $('#event-rows').closest('table'));
  box.hidden = false; // Perspective has no column and stays in the bar
}
// Investigate > Summary: account state card (accountEnabled, userType, sync, last session revocation).
function accountCard(a, card) {
  const t = accountCardText(a, fmtTime);
  return card('Account', t.value, t.note, '');
}
function resultBadge(result) { return `<span class="result ${esc(String(result).toLowerCase().replace(/[^a-z]/g, ''))}">${esc(result)}</span>`; }
function renderActivity() {
  const s = state.session;
  const banner = s?.mode === 'live' && !s.azureConnected;
  $('#azure-banner').hidden = !banner;
  applyGates($('#activity-page'));
  renderActivityFilters();
  const events = filteredEvents();
  state.page = Math.max(0, Math.min(state.page, Math.ceil(events.length / pageSize) - 1));
  $('#page-info').title = pageInfo(pageSlice(events, state.page, pageSize), 'events');
  const page = events.slice(state.page * pageSize, (state.page + 1) * pageSize);
  $('#event-count').textContent = events.length;
  $('#filter-summary').textContent = `${events.length} events`;
  const srcs = state.report?.sources || [];
  $('#event-rows').innerHTML = page.map((e, i) => `<tr data-event="${i}" tabindex="0" title="Open details"><td>${esc(fmtTime(e.time))}</td><td>${esc(activityService(e, srcs))}</td><td>${esc(activityCategory(e))}</td><td>${esc(e.title)}</td><td>${resultBadge(activityStatus(e))}</td><td>${esc(activityActor(e))}</td></tr>`).join('');
  $$('#event-rows tr[data-event]').forEach(tr => { const open = () => showEvidence(page[Number(tr.dataset.event)]); tr.onclick = open; tr.onkeydown = ev => { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); open(); } }; });
  const loaded = otherEvents().some(e => e.onDemand);
  $('#timeline-empty').hidden = Boolean(events.length);
  $('#timeline-empty').textContent = !state.report ? 'Pick a user first.' : otherEvents().length ? 'No events match these filters. Use Select all in the filters.' : loaded ? 'The Azure activity log returned no events for this identity in that lookback.' : 'Nothing loaded yet. The activity log runs only when you click Load activity log.';
  $('#page-info').textContent = events.length ? `${state.page * pageSize + 1} to ${Math.min((state.page + 1) * pageSize, events.length)} of ${events.length}` : '0 events';
  setOff($('#previous-page'), state.page === 0 ? 'Already on the first page' : '');
  setOff($('#next-page'), (state.page + 1) * pageSize >= events.length ? 'Already on the last page' : '');
  syncHeaderExport();
}
const renderTimeline = renderActivity;
$('#azure-connect').onclick = () => state.session?.azureConnectMode === 'redirect' ? startLogin('azure') : openConnection();
// ---- Health checks: source coverage ----
function renderCoverage() {
  const r = state.report;
  if (!r) { $('#coverage-list').innerHTML = emptyBox('Pick a user first. Coverage describes the sources read for the selected user.'); return; }
  $('#coverage-list').innerHTML = r.sources.map(s => `<article class="coverage-card"><header><h3>${esc(s.name)}</h3>${resultBadge(s.status)}</header><dl><dt>Scope</dt><dd>${esc(s.scope)}</dd><dt>Window</dt><dd>${esc(s.coverage)}</dd><dt>Activity</dt><dd>${esc(s.count)} observed events</dd><dt>Freshness</dt><dd>${esc(s.freshness)}</dd></dl><p>${esc(s.note)}</p>${linkBtn(s.url, 'Open source portal')}</article>`).join('') + `<article class="coverage-card"><h3>Interpretation and limits</h3>${(r.notes || []).map(n => `<p>${esc(n)}</p>`).join('')}<p>Returned rows are not a guarantee of complete retention, collection, or historical configuration.</p></article>`;
}
// ---- Page switching ----
const TITLES = { ...B5_VIEWS, emergency: ['Emergency access', 'Break-glass accounts: Conditional Access exclusions, last sign-in, roles and alert rules.'], logs: ['Logs', 'Saved KQL and workbooks for Log Analytics workspaces you can read.'], summary: ['Summary', 'Counts for the selected user. Each count opens the page that holds the rows.'], signins: ['Sign-ins', 'Select a sign-in to see why it succeeded, failed or was blocked.'], access: ['Access', 'Conditional Access, admin roles and groups for the selected user.'], devices: ['Devices', 'Intune devices for the selected user.'], activity: ['Azure activity', 'Azure control-plane activity, loaded only on demand.'], health: ['Health checks', 'Intune health run and which sources returned data.'], 'my-summary': ['My account', 'Your own account, read with your signed-in permissions.'], 'my-signins': ['My sign-ins', 'Your recent sign-ins and the policies Microsoft evaluated.'], 'my-access': ['My access', 'Licenses, groups, authentication methods and Conditional Access for you.'], 'my-device': ['My device', 'Your devices in Entra and Intune, and this computer.'], licenses: ['Licenses', 'Signed-in account first, authorized tenant inventory next.'], billing: ['Billing', 'Authorized billing evidence across connected contexts and scopes.'], deployment: ['Deployment/Onboarding', 'Every step used to bring each machine into Azure Arc, Intune and Defender.'], portals: ['Azure Portals', 'Every Azure and Microsoft 365 admin portal in one place. Links only; each portal checks your access.'], defender: ['Defender', 'Microsoft Defender workloads. Links only; each portal checks your access.'] };
function applyView() {
  const v = TITLES[state.view] ? state.view : 'summary'; state.view = v;
  const entityPage = ENTITY_VIEWS.includes(v), my = MY_VIEWS.includes(v);
  const pages = { summary: '#summary-page', signins: '#signins-page', access: '#access-page', devices: '#devices-page', activity: '#activity-page', health: '#health-page', deployment: '#deployment-panel', portals: '#portals-panel', defender: '#defender-panel', emergency: '#emergency-panel', logs: '#logs-panel', billing: '#billing-panel', licenses: '#license-panel' };
  const showEntity = entityPage && state.report && !state.loading;
  for (const [key, sel] of Object.entries(pages)) $(sel).hidden = ENTITY_VIEWS.includes(key) ? !(showEntity && key === v) : key !== v;
  $('#intune-panel').hidden = v !== 'health';
  if (v === 'health') renderDiagnostics();
  $('#account-panel').hidden = !my;
  MY_VIEWS.forEach(id => { $(`#${id}`).hidden = id !== v; });
  const s = state.session;
  $('#empty-state').hidden = !entityPage || Boolean(state.report) || state.loading;
  $('#empty-reason').textContent = s?.mode === 'signedout' ? 'You are signed out. Sign in with Microsoft, then pick a user.' : !$('#notice').hidden && $('#notice').classList.contains('error') ? 'The last load failed (see the message above). Pick the user again or choose Refresh.' : 'No user is selected. Use Change user at the top (press /) to pick a person, application or managed identity.';
  setOff($('#range-button'), entityPage || v === 'health' ? '' : 'The date range applies to the Investigate pages');
  setOff($('#focus-search'), s?.mode === 'signedout' ? 'Sign in first' : '');
  signInLookup.setActive(v === 'signins');
  accountView.setActive(my);
  intuneView.setActive(v === 'health');
  licenseView.setActive(v === 'licenses');
  billingView.setActive(v === 'billing');
  portalsView.setActive(v === 'portals');
  defenderView.setActive(v === 'defender');
  defenderEvents.setActive(v === 'defender');
  bucket4.setEmergency(v === 'emergency');
  bucket4.setLogs(v === 'logs');
  bucket5.setActive(v);
  // Partial results: only the tab whose data is affected, listing only that tab's sources (Defender shows its own).
  const banner = state.report && !state.loading && (entityPage || v === 'health') ? bannerFor(state.report, v) : '';
  $('#partial-banner').textContent = banner; $('#partial-banner').hidden = !banner;
  deploymentView.setActive(v === 'deployment');
  $('#main').className = `view-${v}`;
  $('#page-title').textContent = TITLES[v][0];
  $('#page-subtitle').textContent = TITLES[v][1];
  $('#breadcrumb').textContent = (my ? 'MY ACCOUNT' : entityPage || v === 'health' ? 'INVESTIGATE' : 'MORE TOOLS');
  $$('#navigation [data-view]').forEach(b => { b.classList.toggle('active', b.dataset.view === v); if (b.dataset.view === v) b.setAttribute('aria-current', 'page'); else b.removeAttribute('aria-current'); });
  if (v === 'activity') renderActivity();
  applyGates();
  syncHeaderExport();
  autoRunView();
}
// The header Export button exports whatever the current page shows.
const exportTargets = { activity: '#activity-export-proxy', 'my-summary': '#account-export', 'my-signins': '#account-export', 'my-access': '#account-export', 'my-device': '#account-export', health: '#intune-export', licenses: '#license-export', billing: '#billing-export', signins: '#signin-export-proxy' };
function exportReason() {
  const v = state.view;
  if (v === 'activity') return filteredEvents().length ? '' : 'No activity events to export';
  if (v === 'signins') return signIns().length ? '' : 'No sign-ins to export';
  const t = exportTargets[v] && $(exportTargets[v]);
  if (!t) return 'Nothing on this page to export';
  return t.disabled ? 'Run this page first; there is nothing to export yet' : '';
}
function syncHeaderExport() { const reason = exportReason(), el = $('#header-export'); if (el.disabled !== Boolean(reason) || (reason && el.title !== reason)) setOff(el, reason); }
$('#header-export').onclick = () => {
  const v = state.view;
  if (v === 'activity') return exportCsv(filteredEvents(), 'activity');
  if (v === 'signins') return exportCsv(signIns(), 'signins');
  const t = exportTargets[v] && $(exportTargets[v]); if (t && !t.disabled) t.click();
};
new MutationObserver(records => { if (records.some(r => r.target.id !== 'header-export')) syncHeaderExport(); }).observe(document.querySelector('#main'), { subtree: true, attributes: true, attributeFilter: ['disabled'] });
function exportCsv(events, kind) {
  // Guard against spreadsheet formula execution when exporting untrusted source fields.
  const cell = value => { let v = String(value ?? ''); if (/^[=+@\-\t\r\n]/.test(v)) v = `'${v}`; return `"${v.replaceAll('"', '""')}"`; };
  const rows = [['Time UTC', 'Activity', 'Category', 'Result', 'Source', 'Actor', 'Target', 'Direction', 'IP', 'Record ID'], ...events.map(e => [e.time, e.title, e.category, e.result, e.source, e.actor, e.target, e.direction, e.ip, e.id])];
  const blob = new Blob(['\ufeff' + rows.map(row => row.map(cell).join(',')).join('\r\n')], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob), anchor = document.createElement('a'); anchor.href = url; anchor.download = `entity-360-${kind}-${state.report.entity.id}-${state.range.from.slice(0, 10)}.csv`; anchor.click(); setTimeout(() => URL.revokeObjectURL(url), 1000); toast(`Exported ${rows.length - 1} rows`);
}
// Live sign-in: My account and Health checks run their default query the first time they are opened.
function autoRunView(forced) {
  const key = forced || (MY_VIEWS.includes(state.view) ? 'account' : state.view === 'health' ? 'intune' : state.view);
  const views = { account: accountView, intune: intuneView, licenses: licenseView, billing: billingView };
  if (state.session?.mode !== 'live' || !views[key] || state.autoRan.has(key)) return;
  const gate = { account: 'account-run', intune: 'intune-run', licenses: 'license-run', billing: 'billing-run' }[key];
  if ($(`#${gate}`)?.disabled) return;
  state.autoRan.add(key);
  Promise.resolve(views[key].run()).catch(() => {});
  const onHost = ['localhost', '127.0.0.1', '::1', '[::1]'].includes(location.hostname);
  if (onHost && state.session.localCollectionSupported && ['account', 'intune'].includes(key)) $(`#${key}-collect`)?.click();
}
async function loadSignedInUser() {
  const email = state.session?.viewer?.email;
  if (state.session?.mode !== 'live' || !email) return;
  // Default to the signed-in user by object id; search only if the id is missing.
  const id = state.session.viewer.id;
  if (id) return loadEntity({ id, type: 'user', name: state.session.viewer.name, subtitle: email });
  const data = await api(`/api/entities?q=${encodeURIComponent(email)}`);
  const users = data.entities.filter(e => e.type === 'user');
  const me = users.find(e => e.id === state.session.viewer.id) || users.find(e => String(e.subtitle).toLowerCase() === email.toLowerCase()) || users[0];
  if (me) await loadEntity(me);
}
function showEvidence(e) {
  $('#evidence-title').textContent = e.title;
  const fields = [['Time (UTC)', e.time], ['Record ID', e.id], ['Actor', e.actor], ['Target', e.target], ['Perspective', e.direction], ['IP address', e.ip], ['Correlation ID', e.correlationId]];
  $('#evidence-content').innerHTML = `<dl class="evidence-grid">${fields.filter(([, v]) => v).map(([label, value]) => `<dt>${label}</dt><dd>${esc(value)}</dd>`).join('')}</dl>${e.command ? `<h3>Observed command line</h3><pre>${esc(e.command)}</pre>` : ''}${e.query ? `<h3>Source query / record locator</h3><pre>${esc(e.query)}</pre><button id="copy-query" class="btn">${icon('copy')}Copy query / locator</button>` : ''}${external(e.link, e.linkLabel || 'Open source', 'btn')}<button id="copy-record" class="btn">Copy record ID</button><details><summary>Raw source evidence</summary><pre>${esc(JSON.stringify(e.evidence || {}, null, 2))}</pre></details>`;
  $('#copy-record').onclick = () => copy(e.id);
  if ($('#copy-query')) $('#copy-query').onclick = () => copy(e.query);
  $('#evidence-dialog').showModal();
}
// The Azure activity log runs only on this click. Lookback defaults to 1 day, max 90.
async function loadActivityLog() {
  const r = state.report;
  if (!r?.entity) { $('#activity-status').textContent = 'Open an entity first.'; return; }
  const choice = $('#activity-days').value;
  const days = Number(choice === 'custom' ? $('#activity-days-custom').value : choice);
  if (!Number.isInteger(days) || days < 1 || days > 90) { $('#activity-status').textContent = 'Enter a whole number of days from 1 to 90.'; return; }
  const plural = days === 1 ? 'day' : 'days';
  $('#activity-load').disabled = true; $('#activity-status').textContent = `Loading ${days} ${plural} of Azure activity...`;
  try {
    const a = await api(`/api/activity?${new URLSearchParams({ id: r.entity.id, type: r.entity.type || 'user', days: String(days) })}`);
    if (state.report !== r) return;
    r.events = r.events.filter(ev => !ev.onDemand).concat(a.events);
    if (a.source) { const i = r.sources.findIndex(x => x.id === a.source.id); if (i >= 0) r.sources[i] = { ...r.sources[i], ...a.source }; else r.sources.push(a.source); }
    $('#activity-status').textContent = `${a.events.length} Azure activity event${a.events.length === 1 ? '' : 's'} loaded for the last ${days} ${plural}${a.partial ? ` (partial: ${a.notes.length} note${a.notes.length === 1 ? '' : 's'})` : ''}. Runs only when clicked.`;
    renderTimeline();
  } catch (err) { $('#activity-status').textContent = err.message; } finally { $('#activity-load').disabled = false; }
}
function showPolicyEvidence(p) { $('#evidence-title').textContent = p.name; $('#evidence-content').innerHTML = `<p>${esc(p.assignment)}</p><pre>${esc(JSON.stringify(p.evidence, null, 2))}</pre>${external(p.link, p.linkLabel || 'Open configuration', 'btn')}`; $('#evidence-dialog').showModal(); }

function hideSearch() { searchVersion++; $('#search-results').hidden = true; $('#entity-search').setAttribute('aria-expanded', 'false'); $('#entity-search').removeAttribute('aria-activedescendant'); }
async function search(query) {
  const version = ++searchVersion;
  const container = $('#search-results');
  container.hidden = false; $('#entity-search').setAttribute('aria-expanded', 'true');
  if (state.session.mode === 'live' && query.trim().length < 2) { container.innerHTML = '<div class="search-message">Type at least two characters.</div>'; state.searchResults = []; return; }
  container.innerHTML = '<div class="search-message">Searching authorized identities…</div>';
  try {
    const data = await api(`/api/entities?q=${encodeURIComponent(query)}`);
    if (version !== searchVersion) return;
    state.searchResults = data.entities; state.searchIndex = -1;
    container.innerHTML = data.entities.map((e, i) => `<button id="search-option-${i}" class="search-option" role="option" aria-selected="false" data-search="${i}"><span class="relationship-icon">${icon(e.type === 'user' ? 'user' : 'cloud')}</span><span><strong>${esc(e.name)}</strong><small>${esc(e.subtitle)} · ${esc(typeLabel(e.type))}</small></span></button>`).join('') || '<div class="search-message">No matching entities in your authorized results.</div>';
    if (data.partial) container.insertAdjacentHTML('beforeend', '<div class="search-message">Partial results. Refine your search.</div>');
    $$('[data-search]').forEach(button => button.onclick = () => selectSearch(Number(button.dataset.search)));
  } catch (error) { if (version === searchVersion) container.innerHTML = `<div class="search-message">${esc(error.message)}</div>`; }
}
function selectSearch(index) { const entity = state.searchResults[index]; if (!entity) return; hideSearch(); $('#entity-search').value = ''; state.fx.excluded = {}; state.fx.open = null; state.fx.sort = null; loadEntity(entity); }
$('#entity-search').addEventListener('input', event => { clearTimeout(searchTimer); searchTimer = setTimeout(() => search(event.target.value), 250); });
$('#entity-search').addEventListener('focus', event => search(event.target.value));
$('#entity-search').addEventListener('keydown', event => {
  if (event.key === 'Escape') { hideSearch(); return; }
  if (['ArrowDown', 'ArrowUp'].includes(event.key)) {
    event.preventDefault();
    if (!state.searchResults.length) return;
    state.searchIndex = (state.searchIndex + (event.key === 'ArrowDown' ? 1 : -1) + state.searchResults.length) % state.searchResults.length;
    $$('[data-search]').forEach((b, i) => { b.classList.toggle('selected', i === state.searchIndex); b.setAttribute('aria-selected', i === state.searchIndex); });
    $('#entity-search').setAttribute('aria-activedescendant', `search-option-${state.searchIndex}`);
  }
  if (event.key === 'Enter' && !$('#search-results').hidden) { event.preventDefault(); selectSearch(Math.max(0, state.searchIndex)); }
});
document.addEventListener('click', event => { if (!event.target.closest('.search-wrap')) hideSearch(); });
document.addEventListener('keydown', event => { if (event.key === '/' && !['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement.tagName) && !$('dialog[open]')) { event.preventDefault(); $('#entity-search').focus(); } });
$('#focus-search').onclick = () => $('#entity-search').focus();
$('#navigation').onclick = event => { const button = event.target.closest('[data-view]'); if (button) { state.view = button.dataset.view; applyView(); } };
installMultiSelectDismiss(document, state.fx);
{ let ls = null; try { ls = localStorage; } catch { /* blocked */ } installColumnResize(document, ls || { getItem: () => null, setItem() {}, removeItem() {} }); }
$('#activity-page-size').onchange = () => { pageSize = Number($('#activity-page-size').value) || DEFAULT_PAGE_SIZE; state.page = 0; renderTimeline(); };
$('#previous-page').onclick = () => { state.page--; renderTimeline(); };
$('#next-page').onclick = () => { state.page++; renderTimeline(); };
$('#refresh-button').onclick = () => state.view === 'deployment' ? deploymentView.refresh() : state.view === 'health' && state.session?.mode === 'live' && !state.entity ? intuneView.run() : state.view === 'billing' ? billingView.run() : state.view === 'licenses' ? licenseView.run() : MY_VIEWS.includes(state.view) ? accountView.run() : state.entity ? loadEntity(state.entity, { refresh: true }) : $('#entity-search').focus();
$('#range-button').onclick = () => { $('#from-date').value = state.range.from.slice(0, 16); $('#to-date').value = state.range.to.slice(0, 16); $('#range-error').textContent = ''; $('#range-dialog').showModal(); };
function setRange(range, days = null) { state.range = range; state.days = days; $('#range-label').textContent = days ? days === 1 ? 'Last 24 hours' : `Last ${days} days` : `${range.from.slice(5, 10)} – ${range.to.slice(5, 10)}`; $('#range-button').title = `${range.from} – ${range.to}`; $('#range-dialog').close(); if (state.entity) loadEntity(state.entity); }
$$('[data-days]').forEach(b => b.onclick = () => setRange(presetRange(Number(b.dataset.days)), Number(b.dataset.days)));
$('#range-form').onsubmit = event => { event.preventDefault(); const from = new Date(`${$('#from-date').value}Z`), to = new Date(`${$('#to-date').value}Z`); if (!Number.isFinite(+from) || !Number.isFinite(+to) || from >= to || +to - +from > 90 * 86400000) { $('#range-error').textContent = 'Choose a valid range of 90 days or less, with the end after the start.'; return; } setRange({ from: from.toISOString(), to: to.toISOString() }); };
$$('.close-dialog').forEach(b => b.onclick = () => b.closest('dialog').close());

function connectionUI() {
  const s = state.session;
  $('#connection-title').textContent = ['live', 'personal'].includes(s.mode) ? 'Microsoft connected' : 'Connect Microsoft';
  $('#connection-content').innerHTML = `<div class="connection-box connection-signed"><p class="connection-note">${['live', 'personal'].includes(s.mode) ? `Signed in as ${esc(s.viewer.email)}. Each source checks your delegated permissions. Access tokens stay in server memory.` : 'Demo mode is ready to explore. Connect your tenant for live, read-only evidence under your Microsoft identity.'}</p></div><div class="connection-box"><h3>${s.configured ? 'Microsoft account' : 'One-time tenant setup'}</h3><p>${s.configured ? (s.confidentialSignIn ? 'Sign in with your Microsoft work account. Azure connects automatically when consent allows; otherwise Connect Azure asks Microsoft for consent once.' : 'Sign in using a Microsoft verification code. Your organization’s consent and sign-in policies apply.') : 'Create an Entra public-client app registration, grant the required read permissions, and set the tenant and client IDs in the local .env file. No client secret is needed.'}</p><div class="conn-actions">${s.configured ? '<button id="microsoft-login" class="btn">Sign in with Microsoft ↗</button>' : '<a class="btn" href="/setup.html" target="_blank" rel="noopener">Open setup guide ↗</a>'}${['live', 'personal'].includes(s.mode) ? `${s.mode === 'live' ? `<button id="azure-login" class="btn">${s.azureConnected ? 'Renew Azure access' : 'Connect Azure'}</button>` : ''}<button id="logout-button" class="btn">Sign out all connections</button>` : ''}</div></div><div id="login-status" role="status"></div><div class="connection-box"><h3>Explore demo permissions</h3><p>Switch fictional viewers to see inaccessible sources disappear. This affects demo data only.</p><label for="demo-profile">Demo viewer</label><select id="demo-profile"><option value="analyst" ${s.profile === 'analyst' ? 'selected' : ''}>Morgan Lee · Security analyst</option><option value="reader" ${s.profile === 'reader' ? 'selected' : ''}>Casey Rivera · Directory reader</option></select><button id="demo-button" class="btn">${s.mode === 'demo' ? 'Apply demo viewer' : 'Switch to demo'}</button></div><p class="connection-note">${s.betaEnabled ? 'Optional Graph beta sign-ins are enabled.' : 'Stable Graph APIs are used. Workload and noninteractive sign-ins require opting into the beta connector.'}</p>`;
  $('#connection-content').firstElementChild.insertAdjacentHTML('afterend', `<div class="connection-box"><h3>Account and tenant boundary</h3><label>Organization tenant ID<input id="connection-tenant" type="text" value="${esc(s.activeTenant && s.mode === 'live' ? s.activeTenant : s.defaultTenant || '')}" placeholder="Tenant GUID"></label><p>${s.multiTenantEnabled ? 'Multiple organizations enabled; each needs independent sign-in and consent.' : 'Default tenant only. Enable ALLOW_MULTI_TENANT with a compatible app registration for other organizations.'}</p>${s.connections.length ? '<label>Connected account / tenant<select id="connection-switch">'+s.connections.map(c => '<option value="'+esc(c.key)+'" '+(c.key === s.activeConnection ? 'selected' : '')+'>'+esc(c.email)+' · '+esc(c.type === 'personal' ? 'Personal Microsoft account' : c.tenant)+'</option>').join('')+'</select></label><button id="switch-connection" class="btn">Use selected connection</button>' : ''}</div>`);
  if ($('#microsoft-login')) $('#microsoft-login').onclick = () => s.confidentialSignIn ? location.assign('/auth/login') : startLogin('graph', { tenantId: $('#connection-tenant').value });
  if ($('#switch-connection')) $('#switch-connection').onclick = async () => { try { state.session = await api('/api/connections/switch', { method: 'POST', body: JSON.stringify({ key: $('#connection-switch').value }) }); clearReport(); sessionUI(); connectionUI(); $('#connection-dialog').close(); state.view = 'licenses'; applyView(); } catch(e) { toast(e.message); } };
  if ($('#azure-login')) $('#azure-login').onclick = () => startLogin('azure');
  if (s.mode === 'live' && s.logsConfigured) {
    $('#azure-login').insertAdjacentHTML('afterend', `<button id="logs-login" class="btn">${s.logsConnected ? 'Renew log access' : 'Connect workspace logs'}</button>`);
    $('#logs-login').onclick = () => startLogin('logs');
  }
  if ($('#logout-button')) $('#logout-button').onclick = async () => { try { clearTimeout(pollTimer); await api('/api/logout', { method: 'POST', body: '{}' }); state.session = await api('/api/session'); clearReport(); sessionUI(); connectionUI(); toast('Microsoft session removed from this app'); } catch (e) { toast(e.message); } };
  if (!s.demoMode) $('#demo-button')?.closest('.connection-box')?.remove();
  if ($('#demo-button')) $('#demo-button').onclick = async () => {
    try {
      clearTimeout(pollTimer);
      state.session = await api('/api/demo', { method: 'POST', body: JSON.stringify({ profile: $('#demo-profile').value }) });
      clearReport(); sessionUI(); $('#connection-dialog').close();
      const data = await api('/api/entities?q=Alex'); if (data.entities[0]) await loadEntity(data.entities[0]);
    } catch (error) { toast(error.message); }
  };
}
async function startLogin(resource, options = {}) {
  const box = $('#login-status') || { set innerHTML(v) {}, set textContent(v) { toast(v); } };
  box.innerHTML = '<p class="connection-note">Requesting Microsoft sign-in…</p>';
  try {
    const r = await api('/api/auth/start', { method: 'POST', body: JSON.stringify({ resource, ...options }) });
    if (r.status === 'redirect' && /^\/auth\/connect\?resource=(azure|logs)$/.test(r.url)) { box.innerHTML = '<p class="connection-note">Opening Microsoft consent for this resource…</p>'; location.assign(r.url); return; }
    if (r.status === 'complete' && r.session) { state.session = r.session; sessionUI(); connectionUI(); applyView(); toast(resource === 'logs' ? 'Workspace logs connected.' : 'Azure connected.'); return; }
    pollLogin();
  } catch (error) { box.textContent = error.message; }
}
async function pollLogin() {
  clearTimeout(pollTimer);
  try {
    const result = await api('/api/auth/status');
    if (result.status === 'complete') {
      state.session = result.session; clearReport(); sessionUI(); connectionUI(); state.view = 'my-summary'; applyView(); toast('Microsoft connected. Check your account or licenses.'); return;
    }
    if (result.status === 'error') { $('#login-status').innerHTML = `<p class="error-text">${esc(result.error)}</p>`; return; }
    if (result.status === 'idle') return;
    if (result.code) {
      $('#login-status').innerHTML = `<div class="connection-box"><h3>Complete sign-in with Microsoft</h3><p>Enter this code at Microsoft’s verification page:</p><code class="device-code">${esc(result.code)}</code>${external(result.verificationUri, 'Open Microsoft sign-in', 'btn')}<button id="copy-code" class="btn">Copy code</button><button id="cancel-login" class="btn">Cancel</button><p>Waiting for sign-in. Expires ${esc(new Date(result.expiresAt).toLocaleTimeString())}.</p></div>`;
      $('#copy-code').onclick = () => copy(result.code);
      $('#cancel-login').onclick = async () => { clearTimeout(pollTimer); await api('/api/auth/cancel', { method: 'POST', body: '{}' }); $('#login-status').innerHTML = ''; };
    }
    pollTimer = setTimeout(pollLogin, 2500);
  } catch (error) { $('#login-status').innerHTML = `<p class="error-text">${esc(error.message)}</p>`; }
}
function openConnection() { connectionUI(); $('#connection-dialog').showModal(); api('/api/auth/status').then(result => { if (result.status === 'pending') pollLogin(); }).catch(() => {}); }
$('#connection-button').onclick = openConnection;
$('#viewer-button').onclick = openConnection;

// Optional browser WebMCP interface shares the UI's server-authorized investigation path.
function registerBrowserTools() {
  const context = document.modelContext;
  if (!context?.registerTool) return;
  const lifecycle = new AbortController();
  window.addEventListener('pagehide', () => lifecycle.abort(), { once: true });
  Promise.resolve(context.registerTool({ name: 'investigate_entity', title: 'Investigate an entity', description: 'Search an identity and update the visible investigation. Ambiguous results require a more specific identifier.', inputSchema: { type: 'object', properties: { query: { type: 'string', minLength: 2, maxLength: 150 } }, required: ['query'], additionalProperties: false }, annotations: { readOnlyHint: false, untrustedContentHint: true }, async execute(input) {
    if (!input || typeof input.query !== 'string' || input.query.length < 2 || input.query.length > 150) throw new Error('Provide a query of 2–150 characters.');
    const result = await api(`/api/entities?q=${encodeURIComponent(input.query)}`);
    if (result.entities.length !== 1) return { status: 'refine_search', entities: result.entities.map(e => ({ id: e.id, name: e.name, type: e.type })) };
    await loadEntity(result.entities[0]);
    if (!state.report) throw new Error('Investigation could not be loaded.');
    return { status: 'loaded', entity: state.report.entity.name, mode: state.report.mode, summary: state.report.summary, partial: state.report.partial };
  } }, { signal: lifecycle.signal })).catch(() => {});
}
try {
  state.session = await api('/api/session');
  if (state.session.mode === 'signedout' && state.session.confidentialSignIn) resumeSignIn('/auth/login');
  else {
    sessionUI(); clearReport();
    try {
      const back = sessionStorage.getItem('e360resumeView');
      sessionStorage.removeItem('e360resumeView');
      if (back && state.session.mode === 'live' && TITLES[back]) { state.view = back; applyView(); }
    } catch { /* storage unavailable */ }
    // Nothing auto-loads a demo entity. Live opens the signed-in user; demo (DEMO_MODE=true) waits for a search.
    if (state.session.mode === 'signedout') { notice('Signed out. Sign in with Microsoft to load real data.', true); openConnection(); }
    // Live: load every page once, in parallel, at page load. Nothing refetches on its own afterwards; use Refresh.
    else if (state.session.mode !== 'demo') await Promise.all([loadSignedInUser(), loadHosting(), ...(state.session.mode === 'live' ? ['account', 'intune', 'licenses', 'billing'].map(k => Promise.resolve().then(() => autoRunView(k))) : [])]);
  }
  registerBrowserTools();
} catch (error) { clearReport(); notice(`Could not connect to the local server. ${error.message}`, true); }
$('#activity-days').onchange = () => { $('#activity-days-custom').hidden = $('#activity-days').value !== 'custom'; };
$('#activity-load').onclick = loadActivityLog;
