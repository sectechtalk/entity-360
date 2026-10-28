// Coverage bucket 2 and the My access Granted fix.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { pimTiming } from '../server/access.mjs';
import { roleTiming } from '../public/group-types.js';
import { normalizeSignIn } from '../server/signins.mjs';
import { signInCells, tenantLabel, eventTypeLabel, sessionLabel, BETA_ONLY } from '../public/signin-columns.js';
import { accountState, licensePaths, rolePermissions, permissionSummary, activationSummary } from '../server/bucket2.mjs';
import { accountCardText } from '../public/account-state.js';
import { roleExtras } from '../server/live.mjs';
import { myPimGroups } from '../server/my-roles.mjs';
import { joinTypeLabel } from '../public/device-links.js';
const read = f => readFileSync(new URL(`../${f}`, import.meta.url), 'utf8');

test('Granted is the schedule startDateTime, not the duration (no more 31 Dec 23:59 UTC)', () => {
  const t = pimTiming('2026-10-20T08:00:00Z', '2027-10-20T08:00:00Z', Date.parse('2026-10-28T00:00:00Z'));
  assert.equal(t.granted, '2026-10-20T08:00:00.000Z');
  assert.match(t.text, /^Granted 365d/);
  const r = roleTiming({ kind: 'Group', pim: true, membership: 'Eligible', granted: t.granted, remaining: t.remaining });
  assert.equal(r.granted, '20 Oct, 08:00 UTC');
  assert.doesNotMatch(r.granted, /31 Dec/);
  assert.equal(pimTiming('2026-10-20T08:00:00Z', null).granted, '2026-10-20T08:00:00.000Z', 'permanent eligibility keeps its start');
  assert.equal(pimTiming(null, '2027-01-01T00:00:00Z').granted, null);
  assert.equal(roleTiming({ kind: 'Directory role', membership: 'Eligible', granted: null }).granted, '', 'fallback is blank');
});

test('My access PIM group rows (group and role) carry the eligibility startDateTime', async () => {
  const api = {
    pages: async u => u.includes('eligibilityScheduleInstances') ? { rows: [{ id: 'g1', groupId: 'grp', accessId: 'member', startDateTime: '2026-10-18T07:00:00Z', endDateTime: '2027-04-18T07:00:00Z' }] } : { rows: [{ id: 'ra', roleDefinitionId: 'rd', roleDefinition: { displayName: 'Intune Administrator' }, directoryScopeId: '/' }] },
    request: async () => ({ displayName: 'sg-e360-billing', isAssignableToRole: true }),
  };
  const { rows } = await myPimGroups(api, { id: 'me' });
  assert.equal(rows.length, 2);
  for (const r of rows) assert.equal(r.granted, '2026-10-18T07:00:00.000Z');
});

test('sign-ins: Tenant (v1.0), Sign-in type and Session (beta only)', () => {
  const raw = { id: 'x', createdDateTime: '2026-10-28T00:00:00Z', status: { errorCode: 0 }, crossTenantAccessType: 'b2bCollaboration', homeTenantId: 'aaaaaaaa-1111', resourceTenantId: 'bbbbbbbb-2222', signInEventTypes: ['interactiveUser'], tokenProtectionStatusDetails: { signInSessionStatus: 'bound' }, globalSecureAccessIpAddress: '198.51.100.7' };
  const v1 = signInCells(normalizeSignIn(raw, 'u', 'v1.0'));
  assert.equal(v1.tenant, 'B2B collaboration (home aaaaaaaa)');
  assert.equal(v1.type, BETA_ONLY); assert.equal(v1.session, BETA_ONLY);
  const b = signInCells(normalizeSignIn(raw, 'u', 'beta'));
  assert.equal(b.type, 'Interactive user'); assert.equal(b.session, 'Token bound · GSA 198.51.100.7');
  assert.equal(tenantLabel({ access: 'none' }), 'Same tenant');
  assert.equal(eventTypeLabel([]), 'n/a'); assert.equal(sessionLabel({}), 'n/a');
  assert.match(read('public/signins.js'), /colspan="14"/);
});

test('account state card: enabled, user type, sync and session revocation', () => {
  const a = accountState({ accountEnabled: false, userType: 'Guest', signInSessionsValidFromDateTime: '2026-10-27T10:00:00Z', onPremisesSyncEnabled: true, onPremisesLastSyncDateTime: '2026-10-28T01:00:00Z' });
  const t = accountCardText(a);
  assert.equal(t.value, 'Disabled');
  assert.match(t.note, /Guest · Synced from on-premises AD · Sessions revoked\/valid from 2026-10-27T10:00:00Z · Last AD sync/);
  assert.equal(accountCardText(null).value, 'n/a');
  assert.match(read('server/live.mjs'), /signInSessionsValidFromDateTime|ACCOUNT_SELECT/);
});

test('license path: direct vs group and the group-licensing error', async () => {
  const m = await licensePaths([{ skuId: 's1', assignedByGroup: null, state: 'Active', error: 'None' }, { skuId: 's1', assignedByGroup: 'g1', state: 'Error', error: 'CountViolation' }], async () => 'sg-licensing');
  assert.deepEqual(m.get('s1').map(x => [x.via, x.state, x.error]), [['Direct', 'Active', null], ['Group: sg-licensing', 'Error', 'CountViolation']]);
  assert.match(read('server/licenses.mjs'), /licenseAssignmentStates/);
});

test('device join type in Investigate device cards', () => {
  assert.equal(joinTypeLabel('ServerAd'), 'Hybrid joined');
  assert.match(read('public/app.js'), /<dt>Join type<\/dt><dd>\$\{esc\(joinTypeLabel\(p\.trustType\)\)\}/);
  assert.match(read('server/live.mjs'), /trustType: joinOf\.get\(d\.id\)/);
});

test('admin roles: effective permissions and PIM activation rules', async () => {
  const acts = rolePermissions({ rolePermissions: [{ allowedResourceActions: ['a/read', 'b/read', 'c/update', 'd/delete'] }] });
  assert.equal(permissionSummary(acts), '4 actions: a/read, b/read, c/update, …');
  const pol = { rules: [{ id: 'Expiration_EndUser_Assignment', maximumDuration: 'PT8H' }, { id: 'Enablement_EndUser_Assignment', enabledRules: ['MultiFactorAuthentication', 'Justification'] }, { id: 'Approval_EndUser_Assignment', setting: { isApprovalRequired: true } }] };
  assert.equal(activationSummary(pol), 'Max 8h, MFA, Justification, Approval required');
  const roles = [{ status: 'Eligible', assignment: 'Direct PIM eligibility', evidence: { roleDefinitionId: 'r1', roleDefinition: { rolePermissions: [] } } }, { status: 'Eligible', assignment: 'Eligible via PIM group G', evidence: {} }];
  await roleExtras({ pages: async () => ({ rows: [{ roleDefinitionId: 'r1', policy: pol }] }) }, roles, { notes: [] });
  assert.equal(roles[0].activation, 'Max 8h, MFA, Justification, Approval required');
  assert.equal(roles[0].permissionText, 'None returned');
  assert.match(roles[1].activation, /RoleManagementPolicy\.Read\.AzureADGroup/);
  const denied = [{ status: 'Eligible', assignment: 'Direct', evidence: {} }], rep = { notes: [] };
  await roleExtras({ pages: async () => { const e = new Error('no'); e.status = 403; throw e; } }, denied, rep);
  assert.match(denied[0].activation, /^Not readable/); assert.equal(rep.notes.length, 1);
});

test('bucket 2 stays delegated-only, no demo mode, one .btn style', () => {
  const src = ['server/bucket2.mjs', 'public/account-state.js'].map(read).join('\n');
  assert.doesNotMatch(src, /demo/i); assert.doesNotMatch(src, /client_credentials|clientSecret/);
  assert.doesNotMatch(read('public/app.js'), /class="btn-/);
});
