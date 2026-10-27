import { signInStatus } from '../public/signin-columns.js';
import { SOURCE, fail, describeError, odata, queryUrl, policyLink } from './model.mjs';
import { entities, profiles } from './demo.mjs';

export const LAB_SIGNIN_USERS = ['labentra1@contoso.com', 'labentra2@contoso.com', 'labentra3@contoso.com'];

export function lookupOptions(input, now = Date.now()) {
  if (!input || typeof input !== 'object') throw fail('Enter users and a lookback period.');
  const hours = input.hours ?? 3;
  if (typeof hours !== 'number' || !Number.isFinite(hours) || hours < 0.25 || hours > 2160) throw fail('Look back between 0.25 and 2,160 hours (90 days).');
  const raw = Array.isArray(input.users) ? input.users : typeof input.users === 'string' ? [input.users] : [];
  if (raw.some(u => typeof u !== 'string')) throw fail('Enter user principal names as text.');
  const users = [...new Set(raw.flatMap(u => u.split(/[,;\r\n]+/)).map(u => u.trim().toLowerCase()).filter(Boolean))];
  if (!users.length || users.length > 10 || users.some(u => u.length > 254 || !/^[^\s@]+@[^\s@]+$/.test(u) || /[\x00-\x1f\x7f]/.test(u))) throw fail('Enter 1–10 valid user principal names, separated by commas or new lines.');
  for (const key of ['beta', 'nonInteractive', 'allPolicies', 'detail']) if (input[key] !== undefined && typeof input[key] !== 'boolean') throw fail('Invalid sign-in option.');
  return { users, hours, beta: input.beta === true || input.nonInteractive === true, nonInteractive: input.nonInteractive === true, allPolicies: input.allPolicies === true, detail: input.detail === true, range: { from: new Date(now - hours * 3600000).toISOString(), to: new Date(now).toISOString() } };
}

export function normalizeSignIn(s, user, version) {
  const device = s.deviceDetail || {};
  const policiesReturned = Array.isArray(s.appliedConditionalAccessPolicies);
  const nonInteractive = s.isInteractive === false || s.signInEventTypes?.includes('nonInteractiveUser');
  const code = typeof s.status?.errorCode === 'number' ? s.status.errorCode : null;
  const policies = (s.appliedConditionalAccessPolicies || []).map(p => ({ id: p.id, name: p.displayName || p.id || 'Unnamed policy', status: p.result || 'Not returned', detail: (p.enforcedGrantControls || []).join(', '), link: p.id ? policyLink(p.id) : SOURCE.policies.url }));
  return {
    id: s.id || null, user, time: new Date(s.createdDateTime).toISOString(), app: s.appDisplayName || 'Not returned', resource: s.resourceDisplayName || 'Not returned', appId: s.appId || '', resourceId: s.resourceId || s.resourceServicePrincipalId || '',
    kind: nonInteractive ? 'Noninteractive' : s.isInteractive === true || s.signInEventTypes?.includes('interactiveUser') ? 'Interactive' : 'Not returned',
    device: { id: device.deviceId || '', name: device.displayName || '', os: device.operatingSystem || '', browser: device.browser || '', compliant: device.isCompliant ?? null, managed: device.isManaged ?? null },
    code, result: code === 0 ? 'Success' : code === null ? 'Not returned' : 'Not completed', reason: s.status?.failureReason || '', conditionalAccess: s.conditionalAccessStatus || 'Not returned', policies, policiesReturned,
    methods: (s.authenticationDetails || []).map(a => ({ method: a.authenticationMethod || 'Not returned', detail: a.authenticationMethodDetail || '', succeeded: a.succeeded ?? null, result: a.authenticationStepResultDetail || '', time: a.authenticationStepDateTime || '' })),
    sessions: (s.sessionLifetimePolicies || []).map(p => ({ requirement: p.expirationRequirement || 'Not returned', detail: p.detail || '' })),
    version, ip: s.ipAddress || '', userDisplayName: s.userDisplayName || '', status: signInStatus(code), location: [s.location?.city, s.location?.state, s.location?.countryOrRegion].filter(Boolean).join(', '), correlationId: s.correlationId || '', agentType: s.agent?.agentType || '', authRequirement: s.authenticationRequirement || '', link: SOURCE.signin.url, evidence: s,
  };
}

function groupKey(e) {
  // Keep differing failure reasons, devices, IPs and hidden policy outcomes separate.
  // Unique IDs, timestamps and correlation IDs are preserved in each group's events.
  return JSON.stringify([e.user, e.appId, e.app, e.resourceId, e.resource, e.kind, e.device, e.code, e.reason, e.conditionalAccess, e.policiesReturned, e.policies, e.methods.map(({ time, ...method }) => method), e.sessions, e.ip, e.version]);
}
export function groupSignIns(events, { detail = false } = {}) {
  const groups = [];
  // Group within each user, chronologically, before ordering groups newest first.
  const users = [...new Set(events.map(e => e.user))];
  for (const user of users) {
    let previous = null;
    for (const event of events.filter(e => e.user === user).sort((a, b) => a.time.localeCompare(b.time))) {
      const key = groupKey(event);
      if (!detail && previous?.key === key) { previous.events.push(event); previous.last = event.time; previous.count++; }
      else { previous = { key, first: event.time, last: event.time, count: 1, event, events: [event] }; groups.push(previous); }
    }
  }
  return groups.sort((a, b) => b.last.localeCompare(a.last)).map(({ key, ...group }) => group);
}

function makeReport(options, users, events, sourceVisible, mode) {
  return { mode, options, range: options.range, users, totalEvents: events.length, groups: groupSignIns(events, options), sources: sourceVisible ? [SOURCE.signin] : [], partial: users.some(u => u.status !== 'complete'), partialReasons: users.filter(u => u.status !== 'complete').flatMap(u => (u.reasons || [u.status === 'unavailable' ? 'no query succeeded' : 'incomplete']).map(reason => ({ source: u.user, reason }))), updatedAt: new Date().toISOString() };
}

export async function signInLookup(api, options) {
  const results = [];
  for (let offset = 0; offset < options.users.length; offset += 3) {
    const batch = await Promise.all(options.users.slice(offset, offset + 3).map(async user => {
      const baseFilter = `userPrincipalName eq '${odata(user)}' and createdDateTime ge ${options.range.from} and createdDateTime le ${options.range.to}`;
      const state = { user, status: 'complete', count: 0, notes: [], versions: [], succeeded: false, events: [], skipped: 0 };
      const read = async (version, nonInteractive = false) => {
        const filter = baseFilter + (version === 'beta' ? ` and signInEventTypes/any(t: t eq '${nonInteractive ? 'nonInteractiveUser' : 'interactiveUser'}')` : '');
        try {
          const result = await api.pages(queryUrl(`/${version}/auditLogs/signIns`, { '$filter': filter, '$top': '100' }));
          state.succeeded = true;
          state.versions.push(version);
          if (result.truncated) { state.status = 'partial'; state.notes.push('Page limit reached. Narrow the lookback to retrieve remaining records.'); }
          for (const row of result.rows) {
            // Ignore invalid/out-of-window records rather than allowing a malformed row to break the batch.
            const stamp = new Date(row.createdDateTime);
            // Rows outside the window or for another account are dropped; that does not make the result incomplete.
            if (!Number.isFinite(+stamp) || stamp < new Date(options.range.from) || stamp > new Date(options.range.to)) { state.skipped++; continue; }
            if (row.userPrincipalName && row.userPrincipalName.toLowerCase() !== user.toLowerCase()) { state.skipped++; continue; }
            state.events.push(normalizeSignIn(row, user, version));
          }
          return result.rows.length;
        } catch (error) {
          state.status = 'partial';
          state.reasons = [...(state.reasons || []), `${version}${nonInteractive ? ' noninteractive' : ''} query: ${describeError(error)}`];
          state.notes.push(error.status === 401 ? 'Sign in again to renew your access.' : [403, 404].includes(error.status) ? 'The requested records were not available to this signed-in viewer.' : 'A query could not finish. Retry or shorten the lookback.');
          return null;
        }
      };
      const count = await read(options.beta ? 'beta' : 'v1.0');
      if (options.beta && count === 0) {
        state.notes.push('The beta query returned no interactive events; v1.0 was queried as a fallback. Each event identifies its API version.');
        await read('v1.0');
      }
      if (options.nonInteractive) await read('beta', true);
      const seen = new Set();
      state.events = state.events.filter(event => {
        if (!event.id) return true;
        if (seen.has(event.id)) return false;
        seen.add(event.id); return true;
      });
      state.count = state.events.length;
      state.versions = [...new Set(state.versions)];
      state.notes = [...new Set(state.notes)];
      if (state.skipped) state.notes.push(`${state.skipped} returned record${state.skipped === 1 ? ' was' : 's were'} outside the window or for another account and ${state.skipped === 1 ? 'was' : 'were'} ignored.`);
      if (state.status === 'partial' && !state.reasons) state.reasons = ['page limit reached (1,000 records); shorten the lookback'];
      if (!state.succeeded) state.status = 'unavailable';
      if (!state.count && state.succeeded) state.notes.push('No observed sign-ins in the successful queries. Logs may arrive a few minutes late, and retention may limit the result.');
      return state;
    }));
    results.push(...batch);
  }
  const visible = results.some(r => r.succeeded);
  const events = results.flatMap(r => r.events);
  const users = results.map(({ events, succeeded, ...user }) => user);
  return makeReport(options, users, events, visible, 'live');
}

export function demoSignInLookup(options, profile = 'analyst') {
  const policyAccess = profiles[profile]?.allowed.includes('policies');
  const events = [];
  const users = options.users.map(user => {
    const entity = entities.find(e => e.type === 'user' && e.subtitle.toLowerCase() === user);
    if (!entity) return { user, status: 'unavailable', count: 0, versions: [], notes: ['This user is not included in the fictional demo. Use Alex Morgan or Jordan Lee, or connect Microsoft for real users.'] };
    const base = Date.parse(options.range.to);
    const rows = [
      ...[10, 12, 14].map(minutes => ({ minutes, appDisplayName: 'Finance Portal', resourceDisplayName: 'Finance API', appId: 'demo-finance-app', status: { errorCode: 53000, failureReason: 'Device is not compliant.' }, conditionalAccessStatus: 'failure', isInteractive: true })),
      { minutes: 40, appDisplayName: 'Microsoft 365', resourceDisplayName: 'Microsoft Graph', appId: 'demo-m365-app', status: { errorCode: 0 }, conditionalAccessStatus: 'success', isInteractive: true },
      { minutes: 120, appDisplayName: 'Azure CLI', resourceDisplayName: 'Azure Resource Manager', appId: 'demo-cli-app', status: { errorCode: 0 }, conditionalAccessStatus: 'success', isInteractive: false },
      { minutes: 300, appDisplayName: 'Microsoft 365', resourceDisplayName: 'Microsoft Graph', appId: 'demo-m365-app', status: { errorCode: 0 }, conditionalAccessStatus: 'success', isInteractive: true },
    ];
    const before = events.length;
    for (const row of rows) {
      if (!row.isInteractive && !options.nonInteractive) continue;
      const createdDateTime = new Date(base - row.minutes * 60000).toISOString();
      if (createdDateTime < options.range.from) continue;
      const failure = row.status.errorCode !== 0;
      const event = {
        ...row, id: `demo-lookup-${entity.id}-${row.minutes}`, userPrincipalName: user, createdDateTime, correlationId: `demo-correlation-${row.minutes}`, ipAddress: '192.0.2.42',
        deviceDetail: { deviceId: 'demo-device', displayName: 'LAPTOP-LAB-01', operatingSystem: 'Windows 11', browser: 'Edge', isCompliant: !failure, isManaged: true },
        ...(policyAccess ? { appliedConditionalAccessPolicies: [
          { id: 'demo-mfa', displayName: 'Require MFA', result: 'success', enforcedGrantControls: ['Mfa'] },
          { id: 'demo-compliance', displayName: 'Require compliant device', result: failure ? 'failure' : 'success', enforcedGrantControls: ['CompliantDevice'] },
          { id: 'demo-location', displayName: 'Restrict outside trusted locations', result: 'notApplied', enforcedGrantControls: ['Block'] },
        ] } : {}),
        ...(options.beta ? { authenticationDetails: [{ authenticationMethod: 'Previously satisfied', authenticationMethodDetail: 'MFA satisfied by claim in token', succeeded: true, authenticationStepDateTime: createdDateTime }], sessionLifetimePolicies: [{ expirationRequirement: 'signInFrequency', detail: 'Reauthentication every 8 hours (demo)' }] } : {}),
      };
      const normalized = normalizeSignIn(event, user, options.beta ? 'beta' : 'v1.0');
      normalized.policies.forEach(p => { p.link = SOURCE.policies.url; });
      events.push(normalized);
    }
    return { user, status: 'complete', count: events.length - before, versions: [options.beta ? 'beta' : 'v1.0'], notes: ['Fictional sign-ins. Microsoft portal links open entry points; these records do not exist.'] };
  });
  return makeReport(options, users, events, users.some(u => u.status === 'complete'), 'demo');
}
