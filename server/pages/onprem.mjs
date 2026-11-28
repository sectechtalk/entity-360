// ON-PREM AD section: Sync health (is on-premises AD syncing?) and Groups (groups synced from on-premises AD).
// Two sync engines can feed the tenant: Entra Connect Sync (a server running the ADSync service) and Entra Cloud Sync
// (a provisioning agent; Microsoft runs the engine). Cloud Sync configurations are service principals made from
// application template CLOUD_SYNC_TEMPLATE (found with Application.Read.All); their job status needs Synchronization.Read.All.
// Delegated Graph reads only. Users, groups and the organization object use scopes the app already has
// (User.Read.All, GroupMember.Read.All, Organization.Read.All). Connect's feature flags, version, server and pending
// export counts come from /directory/onPremisesSynchronization, which needs OnPremDirectorySynchronization.Read.All;
// without it that part becomes a note and the health checks still run from the organization object.
// Groups that are not in sync scope never reach Entra, so Graph cannot list them.
// Own copies of bucket5's helpers: findings.mjs imports this file, and importing bucket5 here would make a cycle.
import { describeError } from '../model.mjs';
async function part(notes, label, fn) { try { return await fn(); } catch (e) { notes.push(`${label}: ${describeError(e)}`); return null; } }
const yesNo = v => v === true ? 'Yes' : v === false ? 'No' : 'Not returned';
const day = t => t ? String(t).slice(0, 10) : '';

const E = 'https://entra.microsoft.com/#view/';
const LEARN = 'https://learn.microsoft.com/entra/identity/hybrid/connect/';
const HOUR = 36e5;
// Connect Sync runs a delta cycle every 30 minutes. One missed cycle is a warning; six missed cycles is a failure.
export const SYNC_WARN_HOURS = 1;
export const SYNC_FAIL_HOURS = 3;
export const GROUP_LIMIT = 100;
export const SYNC_SCOPE = 'OnPremDirectorySynchronization.Read.All';
export const CLOUD_SYNC_SCOPE = 'Synchronization.Read.All';
// "AD2AAD" application template from Microsoft's Cloud Sync Graph guide (how-to-inbound-synch-ms-graph).
export const CLOUD_SYNC_TEMPLATE = '1a4721b3-e57f-4451-ae87-ef078703ec94';
export const LINKS = {
  // Verified 2026-11-14 in a real browser: the old DirectoriesADConnectBlade now redirects to Connect Health.
  connect: `${E}Microsoft_AAD_Connect_Provisioning/AADConnectMenuBlade/~/ConnectSync`,
  cloudSync: `${E}Microsoft_AAD_Connect_Provisioning/AADConnectMenuBlade/~/CloudSync`,
  allGroups: `${E}Microsoft_AAD_IAM/GroupsManagementMenuBlade/~/AllGroups`,
  group: id => `${E}Microsoft_AAD_IAM/GroupDetailsMenuBlade/~/Overview/groupId/${id}`,
  members: id => `${E}Microsoft_AAD_IAM/GroupDetailsMenuBlade/~/Members/groupId/${id}`,
  user: id => `${E}Microsoft_AAD_UsersAndTenants/UserProfileMenuBlade/~/overview/userId/${id}`,
};
export const GUIDANCE = {
  scheduler: `${LEARN}how-to-connect-sync-feature-scheduler`,
  passwordSync: `${LEARN}tshoot-connect-password-hash-synchronization`,
  syncErrors: `${LEARN}tshoot-connect-sync-errors`,
  filtering: `${LEARN}how-to-connect-sync-configure-filtering`,
  cloudSync: 'https://learn.microsoft.com/entra/identity/hybrid/cloud-sync/how-to-troubleshoot',
};

const PROVISIONING = 'onPremisesProvisioningErrors';
const USER_SELECT = `id,displayName,userPrincipalName,accountEnabled,onPremisesSamAccountName,onPremisesDomainName,onPremisesDistinguishedName,onPremisesLastSyncDateTime,${PROVISIONING}`;
const GROUP_SELECT = `id,displayName,description,securityEnabled,mailEnabled,groupTypes,onPremisesSamAccountName,onPremisesDomainName,onPremisesNetBiosName,onPremisesSecurityIdentifier,onPremisesLastSyncDateTime,${PROVISIONING}`;
export const ORG_URL = '/v1.0/organization?$select=id,onPremisesSyncEnabled,onPremisesLastSyncDateTime,onPremisesLastPasswordSyncDateTime';
export const SYNC_URL = '/v1.0/directory/onPremisesSynchronization';
export const SYNCED_USERS_URL = `/v1.0/users?$filter=onPremisesSyncEnabled eq true&$count=true&$top=999&$select=${USER_SELECT}`;
export const CLOUD_SYNC_SPS_URL = `/v1.0/servicePrincipals?$filter=applicationTemplateId eq '${CLOUD_SYNC_TEMPLATE}'&$select=id,appId,displayName`;
export const cloudJobsUrl = spId => `/v1.0/servicePrincipals/${spId}/synchronization/jobs`;
export const SYNCED_GROUPS_URL = `/v1.0/groups?$filter=onPremisesSyncEnabled eq true&$count=true&$top=999&$select=${GROUP_SELECT}`;

export function ago(t, now = Date.now()) {
  const ms = now - Date.parse(t);
  if (!Number.isFinite(ms)) return '';
  if (ms < HOUR) return `${Math.max(0, Math.round(ms / 6e4))} minutes ago`;
  if (ms < 48 * HOUR) return `${Math.round(ms / HOUR)} hours ago`;
  return `${Math.round(ms / (24 * HOUR))} days ago`;
}
const when = (t, now) => (t ? `${String(t).replace('T', ' ').slice(0, 16)} UTC (${ago(t, now)})` : 'Never');
const ageStatus = (t, now) => {
  const h = (now - Date.parse(t)) / HOUR;
  return h > SYNC_FAIL_HOURS ? 'Failed' : h > SYNC_WARN_HOURS ? 'Warning' : 'OK';
};
// One line per error: which attribute clashed, with what value, since when.
export const errorText = errs => (errs || []).map(e => `${e.category || 'Error'}: ${e.propertyCausingError || 'property'}${e.value ? ` = ${e.value}` : ''}${e.occurredDateTime ? ` (since ${day(e.occurredDateTime)})` : ''}`).join('; ');

// Cloud Sync jobs. templateId says what the job carries.
export const JOB_KINDS = { AD2AADProvisioning: 'Users and groups', AD2AADPasswordHash: 'Password hash sync', AD2AADDeviceSync: 'Devices' };
export const jobKind = j => JOB_KINDS[j?.templateId] || j?.templateId || 'Job';
// "PT20M" -> 20, "PT2H" -> 120. Null when absent or not a simple duration.
export function intervalMinutes(iso) {
  const m = /^P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:[\d.]+S)?)?$/.exec(String(iso || ''));
  if (!m || (!m[1] && !m[2] && !m[3])) return null;
  return (+m[1] || 0) * 1440 + (+m[2] || 0) * 60 + (+m[3] || 0);
}
const objectCount = s => (s?.synchronizedEntryCountByType || []).reduce((n, e) => n + (Number(e.value) || 0), 0);
// Live tenant 2026-11-15: lastSuccessfulExecution can be null while lastExecution succeeded, and timeBegan can be
// 0001-01-01. So the last good run is the latest real time among the succeeded runs and the last steady state.
const realTime = t => (t && Date.parse(t) > Date.parse('2000-01-01') ? t : null);
export const lastRun = s => [s?.lastExecution?.state === 'Succeeded' && s.lastExecution.timeEnded, s?.lastSuccessfulExecution?.timeEnded, s?.steadyStateLastAchievedTime]
  .map(realTime).filter(Boolean).sort((x, y) => Date.parse(y) - Date.parse(x))[0] || null;
export const jobActive = j => j?.schedule?.state === 'Active';
// One job, one check. Quarantine and failures come first; a paused job is a warning; otherwise the age of the last good run.
export function jobCheck(config, job, now = Date.now()) {
  // Short name: the check column is narrow. The configuration (AD domain) leads the detail instead.
  const s = job.status || {}, name = `Cloud Sync: ${jobKind(job)}`, where = config.displayName ? `${config.displayName}. ` : '';
  const base = { check: name, fix: GUIDANCE.cloudSync, link: LINKS.cloudSync };
  const r = jobCheckRaw(s, job, now);
  return { ...base, ...r, detail: where + r.detail };
}
function jobCheckRaw(s, job, now) {
  if (s.quarantine) {
    const q = s.quarantine, msg = q.error?.message || q.error?.code || '';
    return { status: 'Failed', detail: `In quarantine${q.since ? ` since ${when(q.since, now)}` : ''}: ${q.reason || 'reason not returned'}${msg ? `. ${msg}` : ''}. Fix the cause, then Restart sync on the configuration in Entra.` };
  }
  if (!jobActive(job)) return { status: 'Warning', detail: `Not running (schedule ${String(job.schedule?.state || 'not returned').toLowerCase()}, status ${s.code || 'not returned'}). Nothing syncs through this job until the configuration is enabled.` };
  const lastExec = s.lastExecution;
  if (lastExec?.state === 'Failed' || s.countSuccessiveCompleteFailures > 0) {
    const msg = lastExec?.error?.message || lastExec?.error?.code || 'no error message returned';
    return { status: 'Failed', detail: `The last run failed (${s.countSuccessiveCompleteFailures || 1} in a row): ${msg}. Check the provisioning logs and the agent on the sync server.` };
  }
  const last = lastRun(s), every = intervalMinutes(job.schedule?.interval);
  const cadence = every ? `Runs every ${every} minutes` : 'Runs on a schedule';
  if (!last) return { status: 'Warning', detail: `${cadence}, but no run has finished successfully yet.` };
  return { status: ageStatus(last, now), detail: `Last good run ${when(last, now)}. ${cadence}: warning after ${SYNC_WARN_HOURS} hour, failure after ${SYNC_FAIL_HOURS} hours.${objectCount(s) ? ` ${objectCount(s)} objects in scope.` : ''}` };
}

// The sync verdict. Pure, so TENANT > Findings and the Sync health page agree.
// org: organization object. sync: onPremisesSynchronization row or null (scope missing). errors: synced objects with
// provisioning errors, or null when they could not be read. cloud: { configs, jobs: [{ config, job }], denied } or null
// when Cloud Sync could not be looked up. Each check is { check, status, detail, fix? }.
export function syncHealth({ org = {}, sync = null, errors = null, cloud = null, now = Date.now() } = {}) {
  const checks = [];
  if (org.onPremisesSyncEnabled !== true) {
    checks.push({ check: 'Directory sync turned on', status: 'Not set up', detail: org.onPremisesSyncEnabled === false ? 'Directory sync was turned on once and is now off. Nothing syncs from on-premises AD.' : 'This tenant has never synced from on-premises AD.', fix: GUIDANCE.scheduler });
    return { status: 'Not set up', checks };
  }
  checks.push({ check: 'Directory sync turned on', status: 'OK', detail: 'The tenant accepts objects from on-premises AD.' });
  const cloudJobs = cloud?.jobs || [];
  const cloudOn = cloudJobs.some(x => jobActive(x.job));
  const engine = cloudOn ? 'Cloud Sync runs every few minutes' : 'Connect syncs every 30 minutes';
  const last = org.onPremisesLastSyncDateTime;
  checks.push(last
    ? { check: 'Last sync cycle', status: ageStatus(last, now), detail: `${when(last, now)}. ${engine}: warning after ${SYNC_WARN_HOURS} hour, failure after ${SYNC_FAIL_HOURS} hours.`, fix: cloudOn ? GUIDANCE.cloudSync : GUIDANCE.scheduler }
    : { check: 'Last sync cycle', status: 'Failed', detail: 'Sync is on but Microsoft has no record of a completed cycle.', fix: GUIDANCE.scheduler });
  for (const { config, job } of cloudJobs) checks.push(jobCheck(config, job, now));
  if (cloud?.denied) checks.push({ check: 'Cloud Sync jobs', status: 'Unknown', detail: `${cloud.configs.length} Cloud Sync ${cloud.configs.length === 1 ? 'configuration exists' : 'configurations exist'} (${cloud.configs.map(c => c.displayName).join(', ')}), but their job status needs the delegated permission ${CLOUD_SYNC_SCOPE} (read-only).`, fix: GUIDANCE.cloudSync });
  const phsOn = sync?.features?.passwordSyncEnabled;
  const lastPw = org.onPremisesLastPasswordSyncDateTime;
  const cloudPhs = cloudJobs.some(x => x.job.templateId === 'AD2AADPasswordHash' && jobActive(x.job));
  if (cloudPhs) { /* the Cloud Sync password hash job above is the check */ }
  else if (phsOn === false) checks.push({ check: 'Password hash sync', status: 'Off', detail: 'Password hash sync is turned off, so on-premises passwords do not work for cloud sign-in unless pass-through authentication or federation is used.' });
  else if (lastPw) checks.push({ check: 'Password hash sync', status: ageStatus(lastPw, now), detail: `Last password sync ${when(lastPw, now)}. The Connect server sends a heartbeat every 30 minutes even with no password changes.`, fix: GUIDANCE.passwordSync });
  // Graph v1.0 does not return onPremisesLastPasswordSyncDateTime (checked against a live tenant 2026-11-14), so a missing
  // time is not evidence of a problem. The heartbeat can only be confirmed on the Connect server.
  else checks.push({ check: 'Password hash sync', status: 'Check on server', detail: `${phsOn ? 'Turned on' : 'Microsoft did not say whether it is on'}. Microsoft Graph does not report when passwords last synced. To confirm it is working, look on the Connect server for event 654 (heartbeat, every 30 minutes) in the Application log; events 611, 652 or 655 mean it is failing.`, fix: GUIDANCE.passwordSync });
  if (errors) {
    const n = errors.length;
    checks.push({ check: 'Objects with sync errors', status: n ? 'Failed' : 'OK', detail: n ? `${n} synced ${n === 1 ? 'object has' : 'objects have'} a sync error (usually a duplicate UPN or proxy address). They are listed below.` : 'No synced user or group has a sync error.', fix: GUIDANCE.syncErrors });
  } else checks.push({ check: 'Objects with sync errors', status: 'Unknown', detail: 'Sync errors could not be read. See the notes below.' });
  // Once Cloud Sync is running, Connect's export counts are frozen at its last export (Connect is in staging or retired).
  const pending = cloudOn ? null : sync?.configuration?.currentExportData;
  if (pending) {
    const p = (pending.pendingObjectsAddition || 0) + (pending.pendingObjectsUpdate || 0) + (pending.pendingObjectsDeletion || 0);
    checks.push({ check: 'Changes waiting to export', status: p ? 'Warning' : 'OK', detail: `${pending.pendingObjectsAddition || 0} adds, ${pending.pendingObjectsUpdate || 0} updates, ${pending.pendingObjectsDeletion || 0} deletes waiting${pending.totalConnectorSpaceObjects != null ? `, ${pending.totalConnectorSpaceObjects} objects in the connector space` : ''}.` });
  }
  const del = sync?.configuration?.accidentalDeletionPrevention;
  if (del) checks.push({ check: 'Accidental delete protection', status: del.synchronizationPreventionType === 'disabled' ? 'Warning' : 'OK', detail: del.synchronizationPreventionType === 'disabled' ? 'Turned off: one bad OU filter change could delete every synced object in Entra.' : `On: a cycle that would delete more than ${del.alertThreshold ?? 'the threshold'} objects is stopped.`, fix: GUIDANCE.filtering });
  const order = ['Failed', 'Warning', 'Unknown'];
  const status = order.find(s => checks.some(c => c.status === s)) || 'OK';
  return { status: status === 'OK' ? 'Healthy' : status === 'Failed' ? 'Failing' : status === 'Warning' ? 'Needs attention' : 'Partly checked', checks };
}

// Read everything the verdict needs. Shared with TENANT > Findings.
export async function readSync(api, notes, { beta = false } = {}) {
  const org = (await api.request(ORG_URL)).value?.[0] || {};
  if (org.onPremisesSyncEnabled !== true) return { org, sync: null, users: [], groups: [], errors: [] };
  let sync = await part(notes, `Connect settings (needs ${SYNC_SCOPE})`, () => api.request(SYNC_URL).then(r => r.value?.[0] || r));
  // Graph beta also returns the Connect server name, version and export counts. Only read when beta is allowed.
  if (sync && beta) {
    const b = await part(notes, 'Connect server details (Graph beta)', () => api.request(SYNC_URL.replace('/v1.0/', '/beta/')).then(r => r.value?.[0] || r));
    if (b) sync = { ...sync, ...b, features: { ...b.features, ...sync.features }, configuration: { ...sync.configuration, ...b.configuration } };
  }
  const cloud = await readCloudSync(api, notes);
  const users = await part(notes, 'Synced users', () => api.pages(SYNCED_USERS_URL).then(r => r.rows));
  const groups = await part(notes, 'Synced groups', () => api.pages(SYNCED_GROUPS_URL).then(r => r.rows));
  const errors = users && groups ? [...users.map(u => ({ ...u, kind: 'User' })), ...groups.map(g => ({ ...g, kind: 'Group' }))].filter(o => (o[PROVISIONING] || []).length) : null;
  return { org, sync, cloud, users: users || [], groups: groups || [], errors };
}

// Cloud Sync configurations and their jobs. A 403 on the jobs is asked once and recorded as denied.
export async function readCloudSync(api, notes) {
  const configs = await part(notes, 'Cloud Sync configurations', () => api.pages(CLOUD_SYNC_SPS_URL).then(r => r.rows));
  if (!configs) return null;
  const jobs = [];
  let denied = false;
  for (const config of configs) {
    const rows = await api.pages(cloudJobsUrl(config.id)).then(r => r.rows, e => {
      if (e?.status === 403) denied = true; else notes.push(`Cloud Sync jobs for ${config.displayName}: ${describeError(e)}`);
      return [];
    });
    for (const job of rows) jobs.push({ config, job });
    if (denied) break;
  }
  return { configs, jobs, denied };
}

// Detail sits second: the shared table CSS pins the third and last columns narrow.
const STATUS_ORDER = { Failed: 0, Warning: 1, Unknown: 2, 'Not set up': 3, 'Check on server': 4, Off: 5, OK: 6 };

const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;
// One-line answer for the banner at the top of Sync health.
export function verdictSummary(verdict, org = {}, now = Date.now()) {
  const bad = verdict.checks.filter(c => ['Failed', 'Warning', 'Unknown'].includes(c.status));
  const last = org.onPremisesLastSyncDateTime ? ` Last sync ${ago(org.onPremisesLastSyncDateTime, now)}.` : '';
  if (verdict.status === 'Not set up') return { status: verdict.status, headline: 'This tenant does not sync from on-premises AD.', detail: '' };
  if (verdict.status === 'Healthy') return { status: verdict.status, headline: `On-premises AD is syncing to Entra. All ${verdict.checks.length} checks passed.`, detail: `Nothing to do.${last}` };
  const head = verdict.status === 'Failing' ? 'Sync is broken or stalled.' : verdict.status === 'Needs attention' ? 'Sync is running, with problems to look at.' : 'Some checks could not run.';
  return { status: verdict.status, headline: `${head} ${plural(bad.length, 'check needs', 'checks need')} attention: ${bad.map(c => c.check).join(', ')}.`, detail: `See How to fix on each row below.${last}` };
}

async function syncPage(api, { notes, beta, meta = {}, now = Date.now() }) {
  const data = await readSync(api, notes, { beta });
  const verdict = syncHealth({ ...data, now });
  const { org, sync, cloud, users, groups, errors } = data;
  const cfg = sync?.configuration || {}, f = sync?.features || {}, exp = cfg.currentExportData || {};
  const cloudOn = (cloud?.jobs || []).some(x => jobActive(x.job));
  const checks = [...verdict.checks].sort((a, b) => STATUS_ORDER[a.status] - STATUS_ORDER[b.status]);
  meta.verdict = verdictSummary(verdict, org, now);
  const tables = [
    { title: `Sync health: ${verdict.status}`, note: `Checked ${String(new Date(now).toISOString()).replace('T', ' ').slice(0, 16)} UTC from what Microsoft Entra records about ${cloudOn ? 'Cloud Sync and Entra Connect' : 'Entra Connect'}. Refresh to check again.`,
      columns: ['Check', 'Detail', 'Status', 'How to fix'], link: cloudOn ? LINKS.cloudSync : LINKS.connect,
      rows: checks.map(c => [c.check, c.detail, { text: c.status, badge: true }, c.fix ? { text: 'Microsoft guidance', link: c.fix } : '']) },
  ];
  if (org.onPremisesSyncEnabled !== true) return tables;
  if (cloud?.jobs?.length) tables.push({ title: 'Cloud Sync', note: 'Microsoft runs the sync engine; the provisioning agent on your server reads AD. Change scope and settings under Entra Connect > Cloud sync.', link: LINKS.cloudSync,
    columns: ['Configuration', 'Job', 'State', 'Runs every', 'Last run', 'Last result', 'Objects in scope', 'Quarantine'],
    rows: cloud.jobs.map(({ config, job }) => {
      const st = job.status || {}, le = st.lastExecution, every = intervalMinutes(job.schedule?.interval), n = objectCount(st);
      const counts = (st.synchronizedEntryCountByType || []).map(e => `${e.value} ${String(e.key).split(' to ')[0]}s`).join(', ');
      return [config.displayName || config.id, jobKind(job), st.code || job.schedule?.state || 'Not returned', every ? `${every} minutes` : 'Not returned',
        le?.timeEnded ? when(le.timeEnded, now) : 'Never', le ? `${le.state || 'Not returned'}${le.error?.message ? `: ${le.error.message}` : ''}${le.countExported ? ` (${le.countExported} exported)` : ''}` : 'Not returned',
        n ? `${n} (${counts})` : job.templateId === 'AD2AADPasswordHash' ? 'Not applicable' : 'Not returned', st.quarantine ? `Yes: ${st.quarantine.reason || 'reason not returned'}` : 'No'];
    }) });
  tables.push({ title: cloudOn ? 'Entra Connect Sync (replaced by Cloud Sync)' : 'Entra Connect', collapsed: cloudOn, note: cloudOn ? 'Cloud Sync now writes to Entra. Connect server, version and counts below are what Connect last reported before the move, not current.' : undefined, columns: ['Setting', 'Value'], rows: [
    ['Last sync cycle', when(org.onPremisesLastSyncDateTime, now)],
    ['Last password hash sync', org.onPremisesLastPasswordSyncDateTime ? when(org.onPremisesLastPasswordSyncDateTime, now) : 'Not returned'],
    ['Connect server', exp.clientMachineName || 'Not returned'],
    ['Connect version', cfg.synchronizationClientVersion || 'Not returned'],
    ['Sync interval', cfg.synchronizationInterval || cfg.customerRequestedSynchronizationInterval || 'Not returned'],
    ['Source anchor', cfg.anchorAttribute || 'Not returned'],
    ['Sync service account', exp.serviceAccount || 'Not returned'],
    ['Synced users', String(users.length)], ['Synced groups', String(groups.length)],
  ] });
  if (sync) tables.push({ title: 'Sync features', collapsed: cloudOn, note: cloudOn ? 'Tenant-wide sync settings last written by the Entra Connect wizard. Cloud Sync has its own settings under Entra Connect > Cloud sync.' : 'Turned on or off in the Entra Connect wizard on the Connect server.', columns: ['Feature', 'On'], rows: [
    ['Password hash sync', yesNo(f.passwordSyncEnabled)], ['Password writeback', yesNo(f.passwordWritebackEnabled)],
    ['Group writeback', yesNo(f.groupWriteBackEnabled)], ['Microsoft 365 group writeback', yesNo(f.unifiedGroupWritebackEnabled)], ['Device writeback', yesNo(f.deviceWritebackEnabled)],
    ['User writeback', yesNo(f.userWritebackEnabled)], ['Soft match on UPN', yesNo(f.softMatchOnUpnEnabled)],
    ['Block soft match', yesNo(f.blockSoftMatchEnabled)], ['Block cloud objects taking over on-premises objects', yesNo(f.blockCloudObjectTakeoverThroughHardMatchEnabled)],
    ['Directory extensions', yesNo(f.directoryExtensionsEnabled)], ['Quarantine on duplicate UPN', yesNo(f.quarantineUponUpnConflictEnabled)], ['Quarantine on duplicate proxy address', yesNo(f.quarantineUponProxyAddressesConflictEnabled)], ['Accidental delete threshold', String(cfg.accidentalDeletionPrevention?.alertThreshold ?? 'Not returned')],
  ] });
  if (errors?.length) tables.push({ title: 'Objects with sync errors', note: 'Fix the value in on-premises AD (or remove the clashing cloud value); the error clears on the next sync cycle.', columns: ['Object', 'Type', 'Error'],
    rows: errors.map(o => [{ text: o.displayName || o.userPrincipalName, link: o.kind === 'User' ? LINKS.user(o.id) : LINKS.group(o.id) }, o.kind, errorText(o[PROVISIONING])]) });
  tables.push({ title: 'Synced users', note: 'Users whose source of authority is on-premises AD. Change them in AD, not in Entra.', columns: ['User', 'SAM account', 'Domain', 'OU path', 'Enabled', 'Last changed by sync'],
    rows: users.map(u => [{ text: u.displayName || u.userPrincipalName, link: LINKS.user(u.id) }, u.onPremisesSamAccountName || '', u.onPremisesDomainName || '', ouPath(u.onPremisesDistinguishedName), yesNo(u.accountEnabled), when(u.onPremisesLastSyncDateTime, now)]) });
  if (cloud?.denied) notes.push(`Cloud Sync job status (last run, quarantine, objects in scope) needs the delegated permission ${CLOUD_SYNC_SCOPE} (read-only).`);
  if (!sync) notes.push(`Connect version, server, features and pending changes need the delegated permission ${SYNC_SCOPE} (read-only). The health checks above still run without it.`);
  else if (!beta && !exp.clientMachineName) notes.push('The Connect server name, version, source anchor and pending export counts are only in Microsoft Graph beta. Set ENABLE_GRAPH_BETA=true to show them.');
  notes.push('Groups and users outside the sync scope are not in Entra, so they do not appear here. Only objects in the OUs Entra Connect syncs are visible.');
  return tables;
}
// "OU=SyncPilot,DC=corp,DC=contoso,DC=com" from "CN=Ann,OU=SyncPilot,DC=corp,DC=contoso,DC=com".
export const ouPath = dn => String(dn || '').replace(/^CN=(?:[^,\\]|\\.)*,/i, '');

async function groupsPage(api, { notes, now = Date.now() }) {
  const org = (await api.request(ORG_URL)).value?.[0] || {};
  if (org.onPremisesSyncEnabled !== true) {
    notes.push('This tenant does not sync from on-premises AD, so there are no on-premises groups to show.');
    return [{ title: 'Groups synced from on-premises AD', columns: ['Group'], rows: [] }];
  }
  const groups = (await api.pages(SYNCED_GROUPS_URL)).rows.sort((a, b) => String(a.displayName).localeCompare(String(b.displayName)));
  const shown = groups.slice(0, GROUP_LIMIT);
  const members = {}, apps = {};
  let appsDenied = false;
  for (const g of shown) {
    members[g.id] = await api.pages(`/v1.0/groups/${g.id}/members?$top=999&$select=id,displayName,userPrincipalName,onPremisesSyncEnabled`).then(r => r.rows, () => null);
    if (!appsDenied) apps[g.id] = await api.pages(`/v1.0/groups/${g.id}/appRoleAssignments?$select=resourceDisplayName,appRoleId`).then(r => r.rows, e => { if (e?.status === 403) appsDenied = true; return null; });
  }
  if (groups.length > GROUP_LIMIT) notes.push(`Showing the first ${GROUP_LIMIT} of ${groups.length} synced groups, A to Z.`);
  if (appsDenied) notes.push('App access granted to these groups could not be read with the current permissions.');
  const kind = g => [g.securityEnabled && 'Security', g.mailEnabled && (g.securityEnabled ? 'mail-enabled' : 'Distribution')].filter(Boolean).join(', ') || 'Not returned';
  const names = list => list == null ? 'Could not read' : list.length ? list.slice(0, 10).map(m => m.displayName || m.userPrincipalName).join(', ') + (list.length > 10 ? ` and ${list.length - 10} more` : '') : 'No members';
  const withErrors = groups.filter(g => (g[PROVISIONING] || []).length);
  return [
    { title: 'Groups synced from on-premises AD', note: `${groups.length} groups. Membership is managed in on-premises AD; changes reach Entra on the next sync cycle.`, link: LINKS.allGroups,
      columns: ['Group', 'Type', 'SAM account', 'Domain', 'SID', 'Members', 'Who', 'App access', 'Last changed by sync', 'Sync error'],
      rows: shown.map(g => [{ text: g.displayName || g.onPremisesSamAccountName || g.id, link: LINKS.group(g.id) }, kind(g), g.onPremisesSamAccountName || '', g.onPremisesNetBiosName || g.onPremisesDomainName || '', g.onPremisesSecurityIdentifier || '',
        members[g.id] == null ? 'Could not read' : { text: String(members[g.id].length), link: LINKS.members(g.id) }, names(members[g.id]),
        apps[g.id] == null ? (appsDenied ? 'Not readable' : '') : apps[g.id].length ? [...new Set(apps[g.id].map(a => a.resourceDisplayName))].join(', ') : 'None',
        when(g.onPremisesLastSyncDateTime, now), errorText(g[PROVISIONING]) || 'None']) },
    withErrors.length && { title: 'Groups with sync errors', columns: ['Group', 'Error'], rows: withErrors.map(g => [{ text: g.displayName, link: LINKS.group(g.id) }, errorText(g[PROVISIONING])]) },
  ];
}

export const ONPREM_PAGES = {
  'h-sync': { section: 'ON-PREM AD', title: 'Sync health', load: syncPage },
  'h-groups': { section: 'ON-PREM AD', title: 'Groups', load: groupsPage },
};
