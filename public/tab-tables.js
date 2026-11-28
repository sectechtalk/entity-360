// Coverage bucket 3 tables. Pure renderers: data in, HTML out. Helpers come from the caller.
export const B3_TABS = {
  au: { table: 'adminUnits', title: 'Administrative units', intro: 'Administrative units this identity belongs to, how membership is set, and the roles scoped to each unit.', scope: 'AdministrativeUnit.Read.All', headers: ['Unit', 'Membership', 'Management', 'Roles scoped to it', ''] },
  adgroups: { table: 'adGroups', title: 'Active Directory groups', intro: 'On-premises Active Directory security groups this user is in, directly or through another group, across the whole AD forest. Read live from a domain controller when Entity 360 is connected to AD, otherwise only the groups that sync to Entra. Membership is changed in AD, not in Entra.', scope: 'GroupMember.Read.All and User.Read.All', headers: ['Group', 'SAM account', 'Membership', 'Through', 'Type', 'In Entra', 'SID', ''], usersOnly: true },
  pimreq: { table: 'pimRequests', title: 'PIM requests', intro: 'Directory role requests for this principal: activations, assignments and their status. Microsoft Graph does not return the approver on this API.', scope: 'RoleManagement.Read.Directory', headers: ['Role', 'Action', 'Status', 'Approver', 'Justification', 'Created'] },
  audit: { table: 'entraAudit', title: 'Entra audit', intro: 'Entra directory audit events with this identity as actor or target, last 7 days. RoleManagement is the PIM category.', scope: 'AuditLog.Read.All', headers: ['Time', 'Activity', 'Category', 'Initiator', 'Target', 'Result', 'Role'] },
  prov: { table: 'provisioning', title: 'Provisioning', intro: 'Entra provisioning events for this identity, last 7 days. Needs Entra ID P1 or P2.', scope: 'AuditLog.Read.All', headers: ['Time', 'App', 'Action', 'Status', 'Error', 'Target'] },
  sso: { table: 'appSso', title: 'App roles and SSO', intro: 'App roles this application defines, its single sign-on mode and reply URLs.', scope: 'Application.Read.All', headers: ['App role', 'Value', 'Allowed members', 'State'], appsOnly: true },
};
const ACTIONS = { selfActivate: 'Self activate', selfDeactivate: 'Self deactivate', selfExtend: 'Self extend', selfRenew: 'Self renew', adminAssign: 'Admin assign', adminRemove: 'Admin remove', adminUpdate: 'Admin update', adminExtend: 'Admin extend', adminRenew: 'Admin renew' };
export const actionLabel = a => ACTIONS[a] || a || 'Not returned';

export function b3Rows(key, data, { esc, fmtTime, resultBadge, linkBtn }) {
  const rows = data?.rows || [];
  const td = v => `<td>${esc(v)}</td>`;
  if (key === 'au') return rows.map(r => `<tr>${td(r.name)}${td(r.membership)}${td(r.restricted)}${td(r.roles)}<td>${linkBtn(r.link, 'Open')}</td></tr>`);
  if (key === 'adgroups') return rows.map(r => `<tr>${td(r.name)}<td><code>${esc(r.sam || 'Not returned')}</code></td><td>${resultBadge(r.membership)}</td>${td(r.via || (r.membership === 'Direct' ? 'Member of this group in AD' : ''))}${td(r.type)}${td(r.note || r.inEntra || 'Synced')}<td><code>${esc(r.sid)}</code></td><td>${r.link ? linkBtn(r.link, 'Open') : ''}</td></tr>`);
  if (key === 'pimreq') return rows.map(r => `<tr><td>${esc(r.role)}<small>Scope: ${esc(r.scope)}</small></td>${td(actionLabel(r.action))}<td>${resultBadge(r.status || 'Not returned')}</td>${td(r.approver)}${td(r.justification || 'None given')}${td(fmtTime(r.created) || 'Not returned')}</tr>`);
  if (key === 'audit') return rows.map(r => `<tr>${td(fmtTime(r.time))}<td>${esc(r.activity)}${r.pim ? '<small>PIM</small>' : ''}</td>${td(r.category)}${td(r.initiator)}${td(r.target)}<td>${resultBadge(r.result)}</td>${td(r.role)}</tr>`);
  if (key === 'prov') return rows.map(r => `<tr>${td(fmtTime(r.time))}${td(r.app)}${td(r.action)}<td>${resultBadge(r.status)}</td>${td(r.error || 'None')}${td(r.target)}</tr>`);
  if (key === 'sso') return rows.map(r => `<tr>${td(r.role)}<td><code>${esc(r.value)}</code></td>${td(r.members)}${td(r.enabled)}</tr>`);
  return [];
}

// Where the AD groups list came from: live from a domain controller, or Graph only and why.
export const AD_SETUP_HINT = 'To list every AD group, run Set-E360AdReader.ps1 on the Entity 360 host.';
export function adSource(ad, esc) {
  if (ad.status === 'live') {
    const off = (ad.domains || []).filter(x => !x.reachable).map(x => x.name);
    return `<p class="account-note">Read live from domain controller <code>${esc(ad.server || 'Not returned')}</code>${ad.forest ? ` in forest <code>${esc(ad.forest)}</code>` : ''}: every security group in the forest, synced to Entra or not.${off.length ? ` Not reachable from this host: ${esc(off.join(', '))}.` : ''}</p>`;
  }
  if (ad.status === 'skipped') return '';
  if (ad.status === 'cloud') return `<div class="verdict-banner verdict-warn" role="status"><span class="verdict-status">Warning</span><div><strong>On-premises AD is out of reach from the cloud</strong><p>${esc(ad.message)}</p></div></div>`;
  const why = ad.message || 'Live AD lookups are not set up.';
  const hint = ad.status === 'off' && /Windows/.test(why) ? '' : ` ${AD_SETUP_HINT}`;
  return `<p class="account-note">Only groups synced to Entra are shown. ${esc(why)}${esc(hint)}</p>`;
}

// One bucket 3 tab: heading, loading or error state, table, notes.
export function b3Panel(key, st, h) {
  const t = B3_TABS[key], { esc, emptyBox } = h;
  const head = `<div class="panel-heading"><div><h2>${esc(t.title)}${st?.data ? ` <span class="count">${st.data.rows.length}</span>` : ''}</h2><p>${esc(t.intro)}</p></div></div>`;
  if (!st || st.loading) return head + '<p class="muted">Loading</p>';
  if (st.error) return head + emptyBox(`${st.error} This table needs ${t.scope}.`);
  const d = st.data, rows = b3Rows(key, d, h);
  const adUser = key === 'adgroups' && d.user?.synced ? `<dl class="kv"><dt>AD account</dt><dd><code>${esc(d.user.sam || 'Not returned')}</code></dd><dt>Location in AD</dt><dd><code>${esc(d.user.dn || 'Not returned')}</code></dd><dt>Groups</dt><dd>${esc(`${rows.length} from on-premises AD (${d.rows.filter(r => r.membership === 'Direct').length} direct, ${d.rows.filter(r => r.membership === 'Nested').length} nested)${d.cloudGroups ? `, plus ${d.cloudGroups} cloud ${d.cloudGroups === 1 ? 'group' : 'groups'} on the Groups tab` : ''}`)}</dd></dl>` : '';
  const adSrc = key === 'adgroups' && d.user?.synced && d.ad ? adSource(d.ad, esc) : '';
  const sso = key === 'sso' && d.sso ? `<dl class="kv"><dt>SSO mode</dt><dd>${esc(d.sso.mode)}</dd><dt>Reply URLs</dt><dd>${d.sso.replyUrls.length ? d.sso.replyUrls.map(u => `<code>${esc(u)}</code>`).join('<br>') : 'None'}</dd>${d.sso.loginUrl ? `<dt>Sign-on URL</dt><dd><code>${esc(d.sso.loginUrl)}</code></dd>` : ''}</dl>` : '';
  const notes = (d.notes || []).length ? `<p class="account-note">${esc(d.notes.join(' · '))}</p>` : '';
  const empty = { adgroups: d.user && !d.user.synced ? 'This user is cloud-only, so they are in no on-premises AD groups.' : d.user ? (d.source === 'ad' ? 'This user is in no Active Directory security group.' : 'This user is in no Active Directory group that syncs to Entra.') : 'Active Directory groups apply to users only.', au: 'This identity is not in any administrative unit.', pimreq: 'No PIM requests were returned for this principal.', audit: 'No Entra audit events in the last 7 days.', prov: 'No provisioning events in the last 7 days.', sso: 'This application defines no app roles.' }[key];
  return head + adUser + adSrc + sso + (rows.length ? `<div class="table-wrap"><table class="event-table" data-table-id="access-${key}"><thead><tr>${t.headers.map(x => `<th>${esc(x)}</th>`).join('')}</tr></thead><tbody>${rows.join('')}</tbody></table></div>` : emptyBox(empty)) + notes;
}

export const b3Url = (key, entity) => `/api/tab-table?table=${B3_TABS[key].table}&id=${encodeURIComponent(entity.id)}&type=${encodeURIComponent(entity.type || 'user')}&appId=${encodeURIComponent(entity.appId || '')}`;

// CA What If inputs, shown above the Conditional Access table.
export const WHATIF_FIELDS = [
  ['devicePlatform', 'Device platform', ['', 'windows', 'macOS', 'iOS', 'android', 'linux']],
  ['clientAppType', 'Client app', ['', 'browser', 'mobileAppsAndDesktopClients', 'exchangeActiveSync', 'other']],
  ['signInRiskLevel', 'Sign-in risk', ['', 'none', 'low', 'medium', 'high']],
  ['userRiskLevel', 'User risk', ['', 'none', 'low', 'medium', 'high']],
];
export function whatIfForm(values = {}, esc) {
  const sel = ([k, label, opts]) => `<label>${esc(label)} <select data-whatif="${k}">${opts.map(o => `<option value="${esc(o)}"${values[k] === o ? ' selected' : ''}>${esc(o || 'Not supplied')}</option>`).join('')}</select></label>`;
  return `<div class="account-actions whatif">${WHATIF_FIELDS.map(sel).join('')}<label>Country <input data-whatif="country" maxlength="2" size="3" placeholder="US" value="${esc(values.country || '')}"></label><label>IP address <input data-whatif="ipAddress" maxlength="45" size="16" value="${esc(values.ipAddress || '')}"></label><button type="button" class="btn" id="whatif-run">Run What If</button></div>`;
}
export function whatIfResult(st, { esc, resultBadge, emptyBox }) {
  if (!st) return '';
  if (st.loading) return '<p class="muted">Running What If</p>';
  if (st.error) return emptyBox(st.error);
  const d = st.data, given = Object.entries(d.conditions).map(([k, v]) => `${k}=${v}`).join(', ') || 'none';
  return `<h3>What If result <span class="count">${d.rows.length}</span></h3><p class="account-note">Inputs: ${esc(given)}. Apps: ${esc(d.apps.join(', '))}.</p>` + (d.rows.length ? `<div class="table-wrap"><table class="event-table" data-table-id="access-whatif"><thead><tr><th>Policy</th><th>Result</th><th>Controls</th><th>Still unknown</th></tr></thead><tbody>${d.rows.map(p => `<tr><td>${esc(p.name)}<small>State: ${esc(p.state)}</small></td><td>${resultBadge(p.result)}</td><td>${esc(p.controls || 'None returned')}</td><td>${esc(p.missing.join(', ') || 'None')}</td></tr>`).join('')}</tbody></table></div>` : emptyBox('No policy applies with these inputs.'));
}

// Entra diagnostic settings (Health checks).
export function diagnosticsPanel(st, { esc, emptyBox }) {
  const head = `<div class="panel-heading"><div><h2>Entra diagnostic settings</h2><p>Where Entra sign-in and audit logs are exported (microsoft.aadiam). Read with your Azure connection; needs Reader at the tenant root for aadiam.</p></div></div><div class="account-actions"><button type="button" class="btn" id="diag-run">Check diagnostic settings</button></div>`;
  if (!st) return head;
  if (st.loading) return head + '<p class="muted">Loading</p>';
  if (st.error) return head + emptyBox(st.error);
  const rows = st.data.rows;
  return head + (rows.length ? `<div class="table-wrap"><table class="event-table" data-table-id="health-diag"><thead><tr><th>Setting</th><th>Destinations</th><th>Log categories</th></tr></thead><tbody>${rows.map(r => `<tr><td>${esc(r.name)}</td><td>${esc(r.destinations)}</td><td>${esc(r.categories)}</td></tr>`).join('')}</tbody></table></div>` : emptyBox('No Entra diagnostic settings: sign-in and audit logs are kept only for the Entra retention period.'));
}

// PIM for Groups elevation: eligible group rows from My access with an Activate link each.
import { PIM_ACTIVATION_LINKS } from './device-links.js';
export const PIM_GROUP_ACTIVATE = PIM_ACTIVATION_LINKS.find(([l]) => l === 'Groups')[1];
export function groupEligibilityTable(groups, { esc, external, fmtTime }) {
  const rows = (groups || []).filter(g => g.pim && g.membership === 'Eligible' && g.kind === 'Group');
  if (!rows.length) return '<p class="account-note">No PIM for Groups eligibility returned for you.</p>';
  return `<div class="table-wrap"><table class="account-table"><thead><tr><th>Group</th><th>Access</th><th>Eligible since</th><th>Ends</th><th></th></tr></thead><tbody>${rows.map(g => `<tr><td>${esc(g.name)}</td><td>${esc(g.source)}</td><td>${esc(fmtTime(g.granted) || '')}</td><td>${esc(g.end ? fmtTime(g.end) : 'Permanent')}</td><td>${external(PIM_GROUP_ACTIVATE, 'Activate')}</td></tr>`).join('')}</tbody></table></div>`;
}
