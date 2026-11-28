// Findings overview: one ranked page of what Entity 360 already reads, each finding with a linked fix (playbook).
// Delegated Graph and ARM reads only, with the scopes the other pages already use (no new permission, no
// Directory.Read.All). Nothing here writes to Microsoft. A read that fails becomes an "Could not check" row with
// Microsoft's reason, and the rest of the page still loads.
import { describeError } from './model.mjs';
import { breakGlass } from './bucket4.mjs';
import { readSync, syncHealth, errorText, LINKS as ONPREM, GUIDANCE as ONPREM_GUIDE } from './pages/onprem.mjs';

const E = 'https://entra.microsoft.com/#view/';
const LEARN = 'https://learn.microsoft.com/entra/';
const DAY = 864e5;
export const SEVERITY = { critical: 4, high: 3, medium: 2, low: 1 };
export const ITEM_LIMIT = 50;
export const STALE_GUEST_DAYS = 90;
export const PENDING_INVITE_DAYS = 30;
export const EXPIRING_DAYS = 30;

// Links used in the playbooks. Entra admin center blades open where the setting is changed.
export const LINKS = {
  appCredentials: appId => `${E}Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/${appId}`,
  appRegistrations: `${E}Microsoft_AAD_RegisteredApps/ApplicationsListBlade`,
  enterpriseProperties: (id, appId) => `${E}Microsoft_AAD_IAM/ManagedAppMenuBlade/~/Properties/objectId/${id}/appId/${appId}`,
  enterpriseApps: `${E}Microsoft_AAD_IAM/StartboardApplicationsMenuBlade/~/AppAppsPreview`,
  user: id => `${E}Microsoft_AAD_UsersAndTenants/UserProfileMenuBlade/~/overview/userId/${id}`,
  allUsers: `${E}Microsoft_AAD_UsersAndTenants/UserManagementMenuBlade/~/AllUsers`,
  accessReviews: `${E}Microsoft_AAD_ERM/DashboardBlade/~/Controls`,
  registrationDetails: `${E}Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/UserRegistrationDetails`,
  caPolicies: `${E}Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies`,
  roles: `${E}Microsoft_AAD_IAM/RolesManagementMenuBlade/~/AllRoles`,
  azureAlerts: 'https://portal.azure.com/#view/Microsoft_Azure_Monitoring/AzureMonitoringBrowseBlade/~/alertsV2',
};
export const GUIDANCE = {
  credentials: `${LEARN}identity-platform/how-to-add-credentials`,
  openApps: `${LEARN}identity/enterprise-apps/assign-user-or-group-access-portal`,
  staleGuests: `${LEARN}identity/users/clean-up-stale-guest-accounts`,
  adminMfa: `${LEARN}identity/conditional-access/policy-old-require-mfa-admin`,
  userMfa: `${LEARN}identity/conditional-access/policy-all-users-mfa-strength`,
  breakGlass: `${LEARN}identity/role-based-access-control/security-emergency-access`,
};

const day = t => (t ? String(t).slice(0, 10) : '');
const lastSignIn = u => [u.signInActivity?.lastSignInDateTime, u.signInActivity?.lastNonInteractiveSignInDateTime].filter(Boolean).sort().pop() || null;

// Each check returns { count, items, note? }. An item is { text, detail, link? }.
export function credentialFindings(apps, now) {
  const soon = now + EXPIRING_DAYS * DAY, items = [];
  let expired = 0, expiring = 0;
  for (const a of apps) {
    for (const [type, c] of [...(a.passwordCredentials || []).map(c => ['Secret', c]), ...(a.keyCredentials || []).map(c => ['Certificate', c])]) {
      const end = Date.parse(c.endDateTime);
      if (!Number.isFinite(end) || end >= soon) continue;
      if (end < now) expired++; else expiring++;
      items.push({ end, text: a.displayName || a.appId, detail: `${type}${c.displayName ? ` "${c.displayName}"` : ''} ${end < now ? 'expired' : 'expires'} ${day(c.endDateTime)}`, link: LINKS.appCredentials(a.appId) });
    }
  }
  items.sort((x, y) => x.end - y.end);
  return { count: items.length, items: items.map(({ end, ...i }) => i), note: `${expired} expired, ${expiring} expiring in the next ${EXPIRING_DAYS} days.` };
}

export function openAppFindings(sps, tenantId) {
  const open = sps.filter(s => s.accountEnabled !== false && s.appRoleAssignmentRequired === false);
  const own = s => tenantId && s.appOwnerOrganizationId === tenantId;
  open.sort((a, b) => own(b) - own(a) || String(a.displayName).localeCompare(String(b.displayName)));
  return { count: open.length, items: open.map(s => ({ text: s.displayName || s.appId, detail: own(s) ? 'Registered in this tenant' : 'External publisher', link: LINKS.enterpriseProperties(s.id, s.appId) })),
    note: `${open.filter(own).length} registered in this tenant, ${open.filter(s => !own(s)).length} from external publishers.` };
}

export function staleGuestFindings(guests, now) {
  const items = [];
  for (const u of guests) {
    if (u.accountEnabled === false) continue;
    const last = lastSignIn(u), pendingSince = Date.parse(u.externalUserStateChangeDateTime || u.createdDateTime);
    let detail = null;
    if (u.externalUserState === 'PendingAcceptance' && Number.isFinite(pendingSince) && now - pendingSince > PENDING_INVITE_DAYS * DAY) detail = `Invitation not accepted since ${day(u.externalUserStateChangeDateTime || u.createdDateTime)}`;
    else if (last && now - Date.parse(last) > STALE_GUEST_DAYS * DAY) detail = `Last sign-in ${day(last)}`;
    else if (!last && u.externalUserState !== 'PendingAcceptance' && Number.isFinite(Date.parse(u.createdDateTime)) && now - Date.parse(u.createdDateTime) > STALE_GUEST_DAYS * DAY) detail = `Never signed in (created ${day(u.createdDateTime)})`;
    if (detail) items.push({ sort: last || '', text: u.displayName || u.mail || u.userPrincipalName, detail, link: LINKS.user(u.id) });
  }
  items.sort((a, b) => String(a.sort).localeCompare(String(b.sort)));
  return { count: items.length, items: items.map(({ sort, ...i }) => i), note: `Enabled guests with no sign-in for ${STALE_GUEST_DAYS} days, or an invitation pending for more than ${PENDING_INVITE_DAYS} days.` };
}

export function mfaFindings(rows) {
  const missing = rows.filter(r => r.isMfaRegistered === false && String(r.userType || 'member').toLowerCase() !== 'guest');
  const item = r => ({ text: r.userDisplayName || r.userPrincipalName, detail: `${r.userPrincipalName}${(r.methodsRegistered || []).length ? ` · methods: ${r.methodsRegistered.join(', ')}` : ' · no methods registered'}`, link: r.id ? LINKS.user(r.id) : null });
  const admins = missing.filter(r => r.isAdmin === true), users = missing.filter(r => r.isAdmin !== true);
  return { admins: { count: admins.length, items: admins.map(item) }, users: { count: users.length, items: users.map(item), note: 'Members only; guests register MFA in their home tenant.' } };
}

export function breakGlassFindings(result) {
  const rows = result.rows || [], items = [];
  if (!rows.length) items.push({ text: 'No emergency access account found', detail: 'No account is excluded from Conditional Access or named for break-glass use. Microsoft recommends two cloud-only accounts.', link: LINKS.allUsers });
  else if (rows.length === 1) items.push({ text: 'Only one emergency access account', detail: 'Microsoft recommends at least two, so one lost credential does not lock the tenant.', link: LINKS.allUsers });
  for (const r of rows) for (const f of r.findings || []) items.push({ text: r.upn || r.name, detail: f, link: r.link });
  return { count: items.length, items, note: (result.notes || []).join(' ') || null };
}

// Directory sync from on-premises AD. A tenant that never synced passes (nothing to watch).
export function syncFindings(data, now) {
  const verdict = syncHealth({ ...data, now });
  if (verdict.status === 'Not set up') return { count: 0, items: [], note: 'This tenant does not sync from on-premises AD.' };
  const items = verdict.checks.filter(c => c.status === 'Failed' || c.status === 'Warning').map(c => ({ text: `${c.check}: ${c.status}`, detail: c.detail, link: c.fix || null }));
  for (const o of data.errors || []) items.push({ text: o.displayName || o.userPrincipalName, detail: `${o.kind} sync error: ${errorText(o.onPremisesProvisioningErrors)}`, link: o.kind === 'User' ? LINKS.user(o.id) : ONPREM.group(o.id) });
  return { count: items.length, items, note: `Sync health: ${verdict.status}. Last sync cycle ${data.org?.onPremisesLastSyncDateTime ? day(data.org.onPremisesLastSyncDateTime) + ' ' + String(data.org.onPremisesLastSyncDateTime).slice(11, 16) + ' UTC' : 'never'}.` };
}

// The catalogue: what each finding means, its severity, and the playbook (steps, the fix link, Microsoft's guidance).
export const CATALOGUE = [
  { id: 'admins-no-mfa', title: 'Admins without MFA', severity: 'critical', source: 'registration', pick: d => d.admins,
    why: 'An admin who has not registered MFA can be taken over with a single stolen password.',
    view: ['a-registration', 'AUTHENTICATION > Registration'], fix: ['Open Conditional Access', LINKS.caPolicies], guidance: GUIDANCE.adminMfa,
    steps: ['Contact each admin listed and have them register a method at https://aka.ms/mysecurityinfo (passkey or Microsoft Authenticator).',
      'In Conditional Access, choose New policy from template and pick "Require multifactor authentication for admins" (or the phishing-resistant version).',
      'Exclude your emergency access accounts, start in Report-only, check the results, then turn it On.',
      'Refresh this page: the admin drops off the list once registration is recorded (the report can lag by a day).'] },
  { id: 'break-glass', title: 'Break-glass gaps', severity: 'high', source: 'breakGlass', pick: d => d,
    why: 'Emergency access accounts are how you get back in when Conditional Access, MFA or federation fails. A gap here can mean a locked-out tenant.',
    view: ['emergency', 'MORE TOOLS > Emergency access'], fix: ['Open Conditional Access', LINKS.caPolicies], guidance: GUIDANCE.breakGlass,
    steps: ['Keep two cloud-only accounts on the .onmicrosoft.com domain with a permanent active Global Administrator role (not PIM eligible).',
      'Exclude both from every Conditional Access policy that blocks or restricts sign-in (put them in one group and exclude the group).',
      'Give them a phishing-resistant method (passkey or certificate) that differs from your normal admin accounts.',
      'Send sign-in logs to Log Analytics and create an Azure Monitor alert that fires on any sign-in by these accounts.',
      'Test sign-in at least every 90 days and after admin staff changes.'] },
  { id: 'users-no-mfa', title: 'Users without MFA', severity: 'high', source: 'registration', pick: d => d.users,
    why: 'Password-only accounts are the most common way in for phishing and password spray.',
    view: ['a-registration', 'AUTHENTICATION > Registration'], fix: ['Open registration details', LINKS.registrationDetails], guidance: GUIDANCE.userMfa,
    steps: ['Turn on the registration campaign (Authentication methods > Registration campaign) so users are prompted to set up Microsoft Authenticator.',
      'Create a Conditional Access policy from the "Require multifactor authentication for all users" template, excluding emergency access accounts.',
      'Run it in Report-only first and review the impact, then switch it On.',
      'Follow up with anyone still listed after two weeks.'] },
  { id: 'hybrid-sync', title: 'On-premises AD sync problems', severity: 'high', source: 'sync', pick: d => d,
    why: 'When sync from on-premises AD stops (Entra Connect or Cloud Sync), people disabled or removed from groups in AD keep their cloud access, and password changes stop reaching Entra.',
    view: ['h-sync', 'ON-PREM AD > Sync health'], fix: ['Open Entra Connect', ONPREM.connect], guidance: ONPREM_GUIDE.scheduler,
    steps: ['If a Cloud Sync check failed: on the Cloud Sync agent server run Get-Service AADConnectProvisioningAgent (should be Running; Restart-Service AADConnectProvisioningAgent if not), then open Entra Connect > Cloud sync, check the configuration status and provisioning logs, fix the cause and select Restart sync to clear a quarantine.',
      'If Entra Connect Sync is still the active engine: on the Entra Connect server, open PowerShell as administrator and run Get-ADSyncScheduler: SyncCycleEnabled should be True and StagingModeEnabled False.',
      'Run Get-ADSyncRunProfileResult -NumberRequested 6 and look for a Result other than success.',
      'For password hash sync, check the Application event log for event 654 in the last 3 hours (611, 652 or 655 mean it is failing).',
      'For a sync error on one object, fix the clashing value (usually UPN or proxy address) in on-premises AD; it clears on the next cycle.',
      'Start a cycle with Start-ADSyncSyncCycle -PolicyType Delta and refresh this page after a few minutes.'] },
  { id: 'app-credentials', title: 'Expired or expiring app credentials', severity: 'medium', source: 'apps', pick: d => d,
    why: 'An expired secret or certificate breaks the app that uses it; old ones left in place are clutter an attacker can hide behind.',
    view: ['p-registrations', 'APPS > App registrations'], fix: ['Open App registrations', LINKS.appRegistrations], guidance: GUIDANCE.credentials,
    steps: ['Open the app (each row links to its Certificates & secrets page) and find who owns it.',
      'If the app is still used: add a new certificate (preferred) or secret, update the app, confirm it works.',
      'Delete the expired or replaced credential.',
      'If nobody uses the app any more, delete the app registration instead.'] },
  { id: 'stale-guests', title: 'Stale guests', severity: 'medium', source: 'guests', pick: d => d,
    why: 'Guests who stopped signing in still hold whatever access they were given.',
    view: ['x-guests', 'EXTERNAL > Guests'], fix: ['Open access reviews', LINKS.accessReviews], guidance: GUIDANCE.staleGuests,
    steps: ['Check with the sponsor or team that invited each guest whether collaboration is still active.',
      'Disable (Block sign-in) guests that are no longer needed, then delete them after 30 days.',
      'Resend or delete invitations that were never accepted.',
      'To keep it clean, create a recurring access review scoped to inactive guests that blocks and then removes them (needs Entra ID Governance).'] },
  { id: 'open-apps', title: 'Apps open to everyone', severity: 'medium', source: 'sps', pick: d => d,
    why: 'With Assignment required set to No, every user (and invited guest) can sign in and get a token for the app.',
    view: ['p-enterprise', 'APPS > Enterprise apps'], fix: ['Open Enterprise apps', LINKS.enterpriseApps], guidance: GUIDANCE.openApps,
    steps: ['Decide which apps should be limited to specific people. Start with apps registered in this tenant.',
      'On the app\'s Users and groups page, assign the groups that need it.',
      'On its Properties page, set Assignment required? to Yes and save.',
      'Test with a user who is not a Global Administrator (admins bypass the assignment check).'] },
];

// Read every source in parallel; a failure becomes the reason on that source's findings.
async function read(fn) { try { return { data: await fn() }; } catch (e) { return { error: describeError(e) }; } }

export async function findingsOverview(api, { azure = false, now = Date.now() } = {}) {
  const [apps, sps, org, guests, registration, bg, sync] = await Promise.all([
    read(() => api.pages('/v1.0/applications?$top=999&$select=id,appId,displayName,passwordCredentials,keyCredentials').then(r => r.rows)),
    read(() => api.pages("/v1.0/servicePrincipals?$filter=tags/any(t:t eq 'WindowsAzureActiveDirectoryIntegratedApp')&$count=true&$top=999&$select=id,appId,displayName,accountEnabled,appRoleAssignmentRequired,appOwnerOrganizationId").then(r => r.rows)),
    read(() => api.request('/v1.0/organization?$select=id').then(r => r.value?.[0]?.id || null)),
    read(() => api.pages("/v1.0/users?$filter=userType eq 'Guest'&$count=true&$top=999&$select=id,displayName,mail,userPrincipalName,externalUserState,externalUserStateChangeDateTime,createdDateTime,accountEnabled,signInActivity").then(r => r.rows)),
    read(() => api.pages('/v1.0/reports/authenticationMethods/userRegistrationDetails?$top=999').then(r => r.rows)),
    read(() => breakGlass(api, { azure, now })),
    read(() => readSync(api, [])),
  ]);
  const computed = {
    apps: apps.error ? apps : { data: credentialFindings(apps.data, now) },
    sps: sps.error ? sps : { data: openAppFindings(sps.data, org.data) },
    guests: guests.error ? guests : { data: staleGuestFindings(guests.data, now) },
    registration: registration.error ? registration : { data: mfaFindings(registration.data) },
    breakGlass: bg.error ? bg : { data: breakGlassFindings(bg.data) },
    sync: sync.error ? sync : { data: syncFindings(sync.data, now) },
  };
  const findings = CATALOGUE.map(c => {
    const src = computed[c.source];
    const base = { id: c.id, title: c.title, severity: c.severity, why: c.why, playbook: { steps: c.steps, fix: { label: c.fix[0], url: c.fix[1] }, guidance: c.guidance, view: { key: c.view[0], label: c.view[1] } } };
    if (src.error) return { ...base, status: 'unavailable', count: null, reason: src.error, items: [] };
    const r = c.pick(src.data);
    return { ...base, status: r.count ? 'open' : 'pass', count: r.count, note: r.note || null, items: r.items.slice(0, ITEM_LIMIT), more: Math.max(0, Math.max(r.count || 0, r.items.length) - Math.min(r.items.length, ITEM_LIMIT)) };
  });
  return { generated: new Date(now).toISOString(), findings: rank(findings) };
}

// Open findings first (most severe, then most affected), then the ones that could not be checked, then passing ones.
export function rank(findings) {
  const group = f => (f.status === 'open' ? 0 : f.status === 'unavailable' ? 1 : 2);
  return [...findings].sort((a, b) => group(a) - group(b) || SEVERITY[b.severity] - SEVERITY[a.severity] || (b.count || 0) - (a.count || 0))
    .map((f, i) => ({ ...f, rank: f.status === 'open' ? i + 1 : null }));
}
