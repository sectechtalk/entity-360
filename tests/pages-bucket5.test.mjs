// Coverage bucket 5: tenant-wide pages. Server pages and client views stay in step.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { B5_PAGES, B5_DEFERRED, loadPage } from '../server/bucket5.mjs';
import { B5_VIEWS, pageHtml } from '../public/bucket5.js';
const read = f => readFileSync(new URL(`../${f}`, import.meta.url), 'utf8');
const esc = v => String(v ?? '').replace(/[&<>"']/g, c => `&#${c.charCodeAt(0)};`);
const h = { esc, external: (u, l) => `<a class="btn" href="${u}">${esc(l)}</a>`, emptyBox: t => `<div class="inline-empty">${esc(t)}</div>` };

// Generic fake: every list is empty, every object read returns {} unless a fixture matches.
export function fakeApi(fixtures = {}) {
  const calls = [];
  const hit = u => Object.entries(fixtures).find(([k]) => u.includes(k))?.[1];
  return { calls,
    request: async (u, o = {}) => { calls.push(u); const f = hit(u); if (f instanceof Error) throw f; return f ?? {}; },
    pages: async u => { calls.push(u); const f = hit(u); if (f instanceof Error) throw f; return { rows: f?.value || f || [] }; } };
}

test('every server page has a nav item, a view title and no write call', () => {
  const html = read('public/index.html');
  assert.deepEqual(Object.keys(B5_VIEWS).sort(), Object.keys(B5_PAGES).sort());
  for (const k of Object.keys(B5_PAGES)) assert.match(html, new RegExp(`data-view="${k}"`));
  for (const f of ['server/bucket5.mjs', ...['tenant', 'auth', 'external', 'governance', 'apps'].map(s => `server/pages/${s}.mjs`)]) assert.doesNotMatch(read(f), /method:\s*'(POST|PATCH|PUT|DELETE)'/);
  for (const [, page] of B5_DEFERRED) assert.ok(!Object.values(B5_VIEWS).some(([t]) => t === page));
});

test('every page renders tables from an empty tenant without throwing', async () => {
  for (const key of Object.keys(B5_PAGES)) {
    const d = await loadPage(fakeApi({ '/organization?': { value: [{ id: 'o1', verifiedDomains: [] }] } }), key, { azure: true });
    assert.ok(Array.isArray(d.tables), key);
    assert.match(pageHtml(key, { data: d }, h), /<h2>/);
  }
});

test('a failed part becomes a note and the page still loads', async () => {
  const d = await loadPage(fakeApi({ deviceRegistrationPolicy: Object.assign(new Error('x'), { status: 403 }), authorizationPolicy: { allowInvitesFrom: 'everyone', defaultUserRolePermissions: { allowedToCreateApps: false } } }), 't-settings');
  assert.equal(d.tables[0].title, 'User settings');
  assert.ok(d.notes.some(n => n.startsWith('Device registration policy')));
  const html = pageHtml('t-settings', { data: d }, h);
  assert.match(html, /Users can register applications<\/td><td>No/);
});

test('roles counts assignments and lists AU scoped admins', async () => {
  const d = await loadPage(fakeApi({
    roleDefinitions: [{ id: 'r1', displayName: 'Global Administrator', isBuiltIn: true, isEnabled: true }, { id: 'r2', displayName: 'Unused', isBuiltIn: true }, { id: 'r3', displayName: 'My role', isBuiltIn: false }],
    roleAssignments: [{ roleDefinitionId: 'r1' }, { roleDefinitionId: 'r1' }], roleEligibilitySchedules: [{ roleDefinitionId: 'r1' }],
    '/scopedRoleMembers': [{ roleId: 'r1', roleMemberInfo: { displayName: 'Ann' } }], '/members?': [{ id: 'm' }],
    administrativeUnits: [{ id: 'au1', displayName: 'West' }] }), 't-roles');
  const [roles, aus] = d.tables;
  assert.deepEqual(roles.rows.map(r => r[0].text), ['Global Administrator', 'My role']);
  assert.deepEqual(roles.rows[0].slice(3), ['2', '1']);
  assert.equal(aus.rows[0][4], 'Ann (Global Administrator)');
});

test('CA inventory counts states and registration lists admins first', async () => {
  const d = await loadPage(fakeApi({ 'conditionalAccess/policies': [{ displayName: 'MFA', state: 'enabledForReportingButNotEnforced', conditions: { users: { includeUsers: ['All'], excludeUsers: ['x'] }, applications: { includeApplications: ['All'] } }, grantControls: { operator: 'OR', builtInControls: ['mfa'] } }] }), 'a-ca');
  assert.match(d.tables[0].note, /1 report-only/);
  assert.deepEqual(d.tables[0].rows[0].slice(1, 4), ['Report-only', 'All', '1']);
  const r = await loadPage(fakeApi({ userRegistrationDetails: [{ userPrincipalName: 'u@x', isMfaRegistered: false }, { userPrincipalName: 'a@x', isAdmin: true, isMfaRegistered: false }, { userPrincipalName: 'ok@x', isMfaRegistered: true, isMfaCapable: true }] }), 'a-registration');
  assert.equal(r.tables[1].rows[0][0], 'a@x');
  assert.equal(r.tables[0].rows.find(x => x[0] === 'Admins without MFA')[1], '1');
});

test('guests sorts stale first and groups by domain', async () => {
  const d = await loadPage(fakeApi({ "userType eq 'Guest'": [
    { id: '1', displayName: 'New', mail: 'n@a.com', userPrincipalName: 'n_a.com#EXT#@t', signInActivity: { lastSignInDateTime: new Date().toISOString() } },
    { id: '2', displayName: 'Old', mail: 'o@a.com', userPrincipalName: 'o_a.com#EXT#@t', externalUserState: 'PendingAcceptance' }] }), 'x-guests');
  assert.equal(d.tables[1].rows[0][0].text, 'Old');
  assert.deepEqual(d.tables[0].rows.map(r => r[1]), ['2', '1', '0', '1']);
  assert.deepEqual(d.tables[2].rows, [['a.com', '2']]);
});

test('PIM settings show rules for roles in use; PIM Azure reads ARM', async () => {
  const d = await loadPage(fakeApi({ roleDefinitions: [{ id: 'r1', displayName: 'Global Administrator' }], roleEligibilitySchedules: [{ roleDefinitionId: 'r1' }],
    roleManagementPolicyAssignments: [{ roleDefinitionId: 'r1', policy: { rules: [{ id: 'Expiration_EndUser_Assignment', maximumDuration: 'PT8H' }, { id: 'Enablement_EndUser_Assignment', enabledRules: ['MultiFactorAuthentication', 'Justification'] }, { id: 'Approval_EndUser_Assignment', setting: { isApprovalRequired: false } }] } }, { roleDefinitionId: 'unused', policy: {} }] }), 'g-pim');
  assert.deepEqual(d.tables[0].rows, [['Global Administrator', 'PT8H', 'Yes', 'Yes', 'No', 'No', 'Not returned']]);
  const api = fakeApi({ '/subscriptions?': { value: [{ subscriptionId: 's1', displayName: 'Sub' }] }, roleEligibilityScheduleInstances: { value: [{ properties: { principalId: 'p', expandedProperties: { principal: { displayName: 'Aaron', type: 'User' }, roleDefinition: { displayName: 'Owner' }, scope: { displayName: 'Sub' } } } }] } });
  const z = await loadPage(api, 'g-pim-azure', { azure: true });
  assert.deepEqual(z.tables[0].rows[0].slice(0, 5), ['Aaron', 'User', 'Owner', 'Sub', 'Eligible']);
});

test('app registrations flag expired and soon-expiring credentials', async () => {
  const past = new Date(Date.now() - 864e5).toISOString(), soon = new Date(Date.now() + 5 * 864e5).toISOString(), later = new Date(Date.now() + 400 * 864e5).toISOString();
  const d = await loadPage(fakeApi({ '/applications?': [{ appId: 'a', displayName: 'A', passwordCredentials: [{ endDateTime: later }, { endDateTime: past }], keyCredentials: [{ endDateTime: soon }] }, { appId: 'b', displayName: 'B' }] }), 'p-registrations');
  assert.deepEqual(d.tables[0].rows.map(r => r[1]), ['2', '1', '1', '1']);
  assert.deepEqual(d.tables[1].rows.map(r => r[4]), ['Expired', 'Expires in 30 days', 'Valid']);
  const c = await loadPage(fakeApi({ adminConsentRequestPolicy: { isEnabled: true, reviewers: [{}] } }), 'p-consent');
  assert.ok(c.notes.some(n => n.includes('ConsentRequest.Read.All')));
});

test('azure pages ask for Azure; unknown pages 404; UI text has no em dash', async () => {
  await assert.rejects(loadPage(fakeApi(), 'nope'), e => e.status === 404);
  for (const [k, p] of Object.entries(B5_PAGES)) if (p.azure) await assert.rejects(loadPage(fakeApi(), k, {}), e => e.status === 409);
  assert.doesNotMatch(read('public/bucket5.js') + Object.values(B5_VIEWS).flat().join(''), /\u2014/);
});
