// Findings overview: ranking, each check, failed reads, playbook links, and the page markup.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { findingsOverview, rank, CATALOGUE, credentialFindings, staleGuestFindings, openAppFindings, mfaFindings, breakGlassFindings } from '../server/findings.mjs';
import { roleForPath } from '../server/authflow.mjs';
import { VIEW_ROLES } from '../public/access-denied.js';
import { findingsHtml } from '../public/findings.js';

const read = f => readFileSync(new URL(`../${f}`, import.meta.url), 'utf8');
const esc = v => String(v ?? '').replace(/[&<>"']/g, c => `&#${c.charCodeAt(0)};`);
const h = { esc, external: (u, l, c = 'btn') => `<a class="${c}" href="${u}">${esc(l)}</a>`, emptyBox: t => `<div class="inline-empty">${esc(t)}</div>` };
// Same shape as the bucket 5 fake: lists come back through pages(), objects through request().
function fakeApi(fixtures = {}) {
  const calls = [];
  const hit = u => Object.entries(fixtures).find(([k]) => u.includes(k))?.[1];
  return { calls,
    request: async u => { calls.push(u); const f = hit(u); if (f instanceof Error) throw f; return f ?? {}; },
    pages: async u => { calls.push(u); const f = hit(u); if (f instanceof Error) throw f; return { rows: f?.value || f || [] }; } };
}
const NOW = Date.parse('2026-11-14T00:00:00Z');
const ago = d => new Date(NOW - d * 864e5).toISOString();
const ORG = '44444444-4444-4444-4444-444444444444';
const GA = '62e90394-69f5-4237-9190-012177145e10';

function tenant(over = {}) {
  return fakeApi({
    '/v1.0/applications?': [
      { id: 'a1', appId: 'app-1', displayName: 'Payroll sync', passwordCredentials: [{ displayName: 'old', endDateTime: ago(10) }, { displayName: 'new', endDateTime: ago(-400) }] },
      { id: 'a2', appId: 'app-2', displayName: 'HR portal', keyCredentials: [{ endDateTime: ago(-5) }] },
    ],
    servicePrincipals: [
      { id: 's1', appId: 'app-1', displayName: 'Payroll sync', accountEnabled: true, appRoleAssignmentRequired: false, appOwnerOrganizationId: ORG },
      { id: 's2', appId: 'x', displayName: 'Vendor app', accountEnabled: true, appRoleAssignmentRequired: false, appOwnerOrganizationId: 'other' },
      { id: 's3', appId: 'y', displayName: 'Locked app', accountEnabled: true, appRoleAssignmentRequired: true },
      { id: 's4', appId: 'z', displayName: 'Disabled app', accountEnabled: false, appRoleAssignmentRequired: false },
    ],
    '/organization?': { value: [{ id: ORG }] },
    "userType eq 'Guest'": [
      { id: 'g1', displayName: 'Old guest', createdDateTime: ago(400), accountEnabled: true, signInActivity: { lastSignInDateTime: ago(200) } },
      { id: 'g2', displayName: 'Active guest', createdDateTime: ago(400), accountEnabled: true, signInActivity: { lastSignInDateTime: ago(3) } },
      { id: 'g3', displayName: 'Pending guest', createdDateTime: ago(60), externalUserState: 'PendingAcceptance', externalUserStateChangeDateTime: ago(60), accountEnabled: true },
      { id: 'g4', displayName: 'Disabled guest', createdDateTime: ago(400), accountEnabled: false },
    ],
    userRegistrationDetails: [
      { id: 'u1', userPrincipalName: 'admin@x', isAdmin: true, isMfaRegistered: false, userType: 'member' },
      { id: 'u2', userPrincipalName: 'user@x', isAdmin: false, isMfaRegistered: false, userType: 'member' },
      { id: 'u3', userPrincipalName: 'guest@x', isAdmin: false, isMfaRegistered: false, userType: 'guest' },
      { id: 'u4', userPrincipalName: 'ok@x', isMfaRegistered: true },
    ],
    'conditionalAccess/policies': [],
    roleAssignments: [],
    ...over,
  });
}

test('route and nav item need E360.Reader, and the page writes nothing', () => {
  assert.equal(roleForPath('/api/findings'), 'E360.Reader');
  assert.equal(VIEW_ROLES.findings, 'E360.Reader');
  assert.match(read('public/index.html'), /data-view="findings"/);
  assert.match(read('public/index.html'), /id="findings-panel"/);
  assert.doesNotMatch(read('server/findings.mjs'), /method:\s*'(POST|PATCH|PUT|DELETE)'/);
});

test('covers the five areas and reads only scopes other pages already use', async () => {
  const ids = CATALOGUE.map(c => c.id);
  for (const id of ['app-credentials', 'open-apps', 'stale-guests', 'users-no-mfa', 'admins-no-mfa', 'break-glass']) assert.ok(ids.includes(id), id);
  const api = tenant();
  await findingsOverview(api, { now: NOW });
  for (const u of api.calls) assert.match(u, /^\/v1\.0\/(applications|servicePrincipals|organization|users|reports\/authenticationMethods|identity\/conditionalAccess|roleManagement\/directory)/, u);
});

test('every finding has steps, an Entra fix link, Microsoft guidance and an in-app page', () => {
  const views = read('public/index.html');
  for (const c of CATALOGUE) {
    assert.ok(c.steps.length >= 3, c.id);
    assert.match(c.fix[1], /^https:\/\/(entra\.microsoft\.com|portal\.azure\.com)\//, c.id);
    assert.match(c.guidance, /^https:\/\/learn\.microsoft\.com\/entra\//, c.id);
    assert.match(views, new RegExp(`data-view="${c.view[0]}"`), c.id);
  }
});

test('ranks open findings by severity then count, then could-not-check, then passing', async () => {
  const d = await findingsOverview(tenant(), { now: NOW });
  const byId = Object.fromEntries(d.findings.map(f => [f.id, f]));
  assert.equal(d.findings[0].id, 'admins-no-mfa');
  assert.equal(d.findings[0].rank, 1);
  assert.equal(byId['admins-no-mfa'].count, 1);
  assert.equal(byId['users-no-mfa'].count, 1, 'guests are not counted');
  assert.equal(byId['app-credentials'].count, 2);
  assert.match(byId['app-credentials'].note, /1 expired, 1 expiring/);
  assert.equal(byId['open-apps'].count, 2);
  assert.equal(byId['open-apps'].items[0].text, 'Payroll sync', 'apps from this tenant first');
  assert.deepEqual(byId['stale-guests'].items.map(i => i.text).sort(), ['Old guest', 'Pending guest']);
  assert.equal(byId['break-glass'].items[0].text, 'No emergency access account found');
  const sev = { critical: 4, high: 3, medium: 2, low: 1 };
  const open = d.findings.filter(f => f.status === 'open');
  for (let i = 1; i < open.length; i++) assert.ok(sev[open[i - 1].severity] >= sev[open[i].severity]);
});

test('a failed read becomes Could not check with the reason; the rest still loads', async () => {
  const d = await findingsOverview(tenant({ userRegistrationDetails: Object.assign(new Error('Forbidden'), { status: 403 }) }), { now: NOW });
  const mfa = d.findings.filter(f => f.id.includes('mfa'));
  assert.ok(mfa.every(f => f.status === 'unavailable' && f.reason && f.rank === null));
  assert.equal(d.findings.find(f => f.id === 'app-credentials').status, 'open');
  const html = findingsHtml({ data: d }, h);
  assert.match(html, /Could not check/);
});

test('nothing to fix shows passing and no fix buttons', () => {
  const f = rank([{ id: 'open-apps', title: 'Apps open to everyone', severity: 'medium', status: 'pass', count: 0, items: [], why: 'w', playbook: CATALOGUE.at(-1) && { steps: ['a'], fix: { label: 'Fix', url: 'https://entra.microsoft.com/#view/x' }, guidance: 'https://learn.microsoft.com/entra/x', view: { key: 'p-enterprise', label: 'APPS' } } }]);
  const html = findingsHtml({ data: { generated: new Date(NOW).toISOString(), findings: f } }, h);
  assert.match(html, /Nothing open/);
  assert.match(html, /Passing/);
  assert.doesNotMatch(html, /Playbook/);
});

test('page markup: ranked cards with fix link, playbook steps and affected items', async () => {
  const d = await findingsOverview(tenant(), { now: NOW });
  const html = findingsHtml({ data: d }, h);
  assert.match(html, /#1<\/span><span class="finding-sev">Critical<\/span><h3>Admins without MFA/);
  assert.match(html, /data-go="a-registration"/);
  assert.match(html, /href="https:\/\/entra\.microsoft\.com\/#view\/Microsoft_AAD_RegisteredApps\/ApplicationMenuBlade\/~\/Credentials\/appId\/app-1"/);
  assert.match(html, /<ol><li>/);
  assert.match(html, /Affected \(2\)/);
  assert.equal(findingsHtml({ loading: true }, h).includes('Checking the tenant'), true);
});

test('checks on their own', () => {
  assert.equal(credentialFindings([{ appId: 'a', displayName: 'A', passwordCredentials: [{ endDateTime: ago(-90) }] }], NOW).count, 0);
  assert.equal(staleGuestFindings([{ id: 'n', createdDateTime: ago(10), accountEnabled: true }], NOW).count, 0, 'a new guest who has not signed in yet is not stale');
  assert.equal(staleGuestFindings([{ id: 'n', createdDateTime: ago(120), accountEnabled: true }], NOW).items[0].detail.startsWith('Never signed in'), true);
  assert.equal(openAppFindings([{ id: 's', appId: 'a', accountEnabled: true }], ORG).count, 0, 'unknown assignment setting is not flagged');
  assert.equal(mfaFindings([{ isMfaRegistered: undefined }]).users.count, 0);
  const one = breakGlassFindings({ rows: [{ upn: 'bg@x', findings: ['Not excluded from 2 active policies'], link: 'l' }] });
  assert.deepEqual(one.items.map(i => i.text), ['Only one emergency access account', 'bg@x']);
  assert.equal(breakGlassFindings({ rows: [{ upn: 'a', findings: [] }, { upn: 'b', findings: [] }] }).count, 0);
});

test('break-glass finds an excluded account with no Global Administrator role', async () => {
  const BG = '55555555-5555-5555-5555-555555555555';
  const d = await findingsOverview(tenant({
    'conditionalAccess/policies': [{ displayName: 'MFA all', state: 'enabled', conditions: { users: { includeUsers: ['All'], excludeUsers: [BG] } } }],
    [`/v1.0/users/${BG}?`]: { id: BG, displayName: 'Break glass 1', userPrincipalName: 'bg1@x.onmicrosoft.com', accountEnabled: true },
    [`roleDefinitionId eq '${GA}'`]: [],
  }), { now: NOW });
  const bg = d.findings.find(f => f.id === 'break-glass');
  assert.ok(bg.items.some(i => i.text === 'bg1@x.onmicrosoft.com' && /Global Administrator/.test(i.detail)));
});
