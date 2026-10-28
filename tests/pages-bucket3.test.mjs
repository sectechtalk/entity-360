// Coverage bucket 3: new tables on existing pages.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { tabTable, whatIf, B3_DEFERRED, B3_TABLES } from '../server/bucket3.mjs';
import { whatIfConditions, suppliedInputs, unknownInputs } from '../server/access.mjs';
import { B3_TABS, b3Panel, b3Url, actionLabel, whatIfForm, whatIfResult, diagnosticsPanel, groupEligibilityTable, PIM_GROUP_ACTIVATE } from '../public/tab-tables.js';
const read = f => readFileSync(new URL(`../${f}`, import.meta.url), 'utf8');
const ID = '11111111-2222-3333-4444-555555555555';
const esc = v => String(v ?? '').replace(/[&<>"']/g, c => `&#${c.charCodeAt(0)};`);
const h = { esc, fmtTime: t => t ? `T(${t})` : '', resultBadge: v => `<b>${esc(v)}</b>`, linkBtn: (u, l) => `<a class="btn" href="${u}">${l}</a>`, emptyBox: t => `<div class="inline-empty">${esc(t)}</div>`, external: (u, l) => `<a class="btn" href="${u}">${l}</a>` };
const fake = (routes) => { const calls = []; return { calls, pages: async u => { calls.push(u); for (const [k, v] of routes) if (u.includes(k)) { if (v instanceof Error) throw v; return { rows: v }; } return { rows: [] }; }, request: async (u, o) => { calls.push(u); for (const [k, v] of routes) if (u.includes(k)) { if (v instanceof Error) throw v; return v; } return {}; } }; };
const denied = () => Object.assign(new Error('Access not granted.'), { status: 403 });

test('admin units: name, membership type and roles scoped to the unit', async () => {
  const api = fake([['scopedRoleMembers', [{ roleId: 'r1', roleMemberInfo: { displayName: 'Helpdesk Ann' } }]], ['administrativeUnit', [{ id: 'au1', displayName: 'Seattle', membershipType: 'Dynamic' }]]]);
  const { rows } = await tabTable(api, 'adminUnits', { id: ID, type: 'user' });
  assert.equal(rows[0].name, 'Seattle'); assert.equal(rows[0].membership, 'Dynamic');
  assert.equal(rows[0].roles, 'Helpdesk Ann (role r1)');
  assert.match(api.calls[0], /users\/.+\/memberOf\/microsoft\.graph\.administrativeUnit/);
});

test('PIM requests: role, action, status, approver, justification, newest first', async () => {
  const api = fake([['roleAssignmentScheduleRequests', [{ id: 'a', action: 'selfActivate', status: 'Provisioned', justification: 'ticket 1', createdDateTime: '2026-10-01T00:00:00Z', roleDefinition: { displayName: 'User Administrator' } }, { id: 'b', action: 'adminAssign', status: 'PendingApproval', approvalId: 'x', createdDateTime: '2026-10-20T00:00:00Z', roleDefinitionId: 'rd' }]]]);
  const { rows } = await tabTable(api, 'pimRequests', { id: ID });
  assert.deepEqual(rows.map(r => r.id), ['b', 'a']);
  assert.equal(rows[0].approver, 'Approval required (approver not returned)');
  assert.equal(actionLabel(rows[1].action), 'Self activate');
  assert.match(decodeURIComponent(api.calls[0]), /principalId eq '11111111/);
});

test('Entra audit merges actor and target, flags PIM, and fails only when both reads fail', async () => {
  const ev = { id: 'e1', activityDateTime: '2026-10-27T00:00:00Z', activityDisplayName: 'Add member to role completed (PIM activation)', category: 'RoleManagement', result: 'success', initiatedBy: { user: { userPrincipalName: 'aaron@x' } }, targetResources: [{ displayName: 'Global Reader' }] };
  const { rows } = await tabTable(fake([['directoryAudits', [ev]]]), 'entraAudit', { id: ID, type: 'user', now: Date.parse('2026-10-28T00:00:00Z') });
  assert.equal(rows.length, 1); assert.equal(rows[0].role, 'Actor & Target'); assert.equal(rows[0].pim, true);
  await assert.rejects(tabTable(fake([['directoryAudits', denied()]]), 'entraAudit', { id: ID }), /Access not granted/);
});

test('provisioning: app, action, status and error; user filter uses source or target identity', async () => {
  const api = fake([['provisioning', [{ id: 'p', activityDateTime: '2026-10-27T00:00:00Z', servicePrincipal: { displayName: 'ServiceNow' }, provisioningAction: 'update', provisioningStatusInfo: { status: 'failure', errorInformation: { reason: 'Attribute mismatch' } }, targetIdentity: { displayName: 'aaron' } }]]]);
  const { rows } = await tabTable(api, 'provisioning', { id: ID, type: 'user' });
  assert.deepEqual([rows[0].app, rows[0].action, rows[0].status, rows[0].error], ['ServiceNow', 'update', 'Failed', 'Attribute mismatch']);
  assert.match(decodeURIComponent(api.calls[0]), /sourceIdentity\/id eq .+ or targetIdentity\/id eq/);
});

test('app roles and SSO: roles defined, SSO mode, reply URLs; users rejected', async () => {
  const api = fake([['servicePrincipals', { appRoles: [{ id: 'r', displayName: 'Reader', value: 'Data.Read', allowedMemberTypes: ['User'] }], preferredSingleSignOnMode: 'saml', replyUrls: ['https://app.example/acs'] }]]);
  const d = await tabTable(api, 'appSso', { id: ID, type: 'application' });
  assert.equal(d.sso.mode, 'SAML'); assert.deepEqual(d.sso.replyUrls, ['https://app.example/acs']); assert.equal(d.rows[0].value, 'Data.Read');
  await assert.rejects(tabTable(api, 'appSso', { id: ID, type: 'user' }), /applications only/);
  const html = b3Panel('sso', { data: d }, h);
  assert.match(html, /SSO mode<\/dt><dd>SAML/); assert.match(html, /<th>App role<\/th>/);
});

test('diagnostic settings: destinations and enabled categories via ARM', async () => {
  let origin;
  const api = { request: async (u, o) => { origin = o.origin; return { value: [{ name: 'to-law', properties: { workspaceId: '/subscriptions/s/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/law-e360', logs: [{ category: 'SignInLogs', enabled: true }, { category: 'AuditLogs', enabled: true }, { category: 'RiskyUsers', enabled: false }] } }] }; } };
  const d = await tabTable(api, 'diagnostics', {});
  assert.equal(origin, 'https://management.azure.com');
  assert.deepEqual(d.rows[0], { id: undefined, name: 'to-law', destinations: 'Log Analytics: law-e360', categories: 'SignInLogs, AuditLogs' });
  assert.match(diagnosticsPanel({ data: d }, h), /law-e360/);
  assert.match(diagnosticsPanel({ data: { rows: [] } }, h), /No Entra diagnostic settings/);
});

test('CA What If inputs: only known values pass and supplied inputs stop counting as unknown', async () => {
  assert.deepEqual(whatIfConditions({ devicePlatform: 'iOS', clientAppType: 'browser', signInRiskLevel: 'bogus', country: 'US', ipAddress: '1.2.3.4; drop' }), { devicePlatform: 'iOS', clientAppType: 'browser', country: 'US' });
  assert.deepEqual(suppliedInputs({ devicePlatform: 'iOS', country: 'US' }), ['platforms', 'locations']);
  const pol = { conditions: { platforms: { includePlatforms: ['iOS'] }, locations: { includeLocations: ['All'] } } };
  assert.deepEqual(unknownInputs(pol), ['device platform', 'location']);
  assert.deepEqual(unknownInputs(pol, ['platforms']), ['location']);
  let body;
  const api = { pages: async () => ({ rows: [] }), request: async (u, o) => { body = o.body; return { value: [{ id: 'p1', displayName: 'Block iOS', state: 'enabled', grantControls: { builtInControls: ['block'] }, conditions: pol.conditions }] }; } };
  const d = await whatIf(api, { id: ID, input: { devicePlatform: 'iOS' } });
  assert.deepEqual(body.signInConditions, { devicePlatform: 'iOS' });
  assert.deepEqual(d.rows[0].missing, ['location']);
  assert.match(whatIfResult({ data: d }, h), /Block iOS/);
  assert.match(whatIfForm({ devicePlatform: 'iOS' }, esc), /<option value="iOS" selected>/);
});

test('PIM for Groups elevation: eligible groups listed with an Activate link', () => {
  const html = groupEligibilityTable([{ kind: 'Group', pim: true, membership: 'Eligible', name: 'sg-e360-billing', source: 'PIM for Groups (member)', granted: '2026-10-18T07:00:00Z', end: null }, { kind: 'Group', membership: 'Member', name: 'not-pim' }], h);
  assert.match(html, /sg-e360-billing/); assert.doesNotMatch(html, /not-pim/);
  assert.match(html, /T\(2026-10-18T07:00:00Z\)/); assert.match(html, /Permanent/);
  assert.ok(html.includes(PIM_GROUP_ACTIVATE)); assert.match(PIM_GROUP_ACTIVATE, /aadgroup$/);
  assert.match(read('public/account.js'), /groupEligibilityTable\(/);
});

test('tabs, routes and errors are wired; deferred rows name their scope', async () => {
  const html = read('public/index.html');
  for (const k of Object.keys(B3_TABS)) assert.match(html, new RegExp(`data-tab="${k}"`));
  assert.match(html, /id="diag-panel"/);
  const idx = read('server/index.mjs');
  assert.match(idx, /app\.get\('\/api\/tab-table'/); assert.match(idx, /app\.post\('\/api\/ca\/whatif'/);
  assert.equal(b3Url('au', { id: ID, type: 'user' }), `/api/tab-table?table=adminUnits&id=${ID}&type=user&appId=`);
  assert.match(b3Panel('au', { error: 'Access not granted.' }, h), /needs AdministrativeUnit\.Read\.All/);
  assert.deepEqual(B3_DEFERRED.map(d => d[1]), ['AgreementAcceptance.Read', 'UserAuthenticationMethod.Read.All', 'IdentityRiskyUser.Read.All, IdentityRiskEvent.Read.All', 'IdentityRiskyServicePrincipal.Read.All', 'AccessReview.Read.All']);
  await assert.rejects(tabTable({}, 'riskyUsers', { id: ID }), /Unknown table/);
  assert.equal(B3_TABLES.length, 6);
});

test('bucket 3 stays delegated, no demo, one .btn style', () => {
  const src = ['server/bucket3.mjs', 'public/tab-tables.js'].map(read).join('\n');
  assert.doesNotMatch(src, /demo/i); assert.doesNotMatch(src, /client_credentials|clientSecret/i);
  assert.doesNotMatch(src, /class="btn-|style="/);
  const scopes = read('.env.example').match(/^GRAPH_SCOPES=(.*)$/m)[1].split(',');
  for (const s of ['AdministrativeUnit.Read.All', 'RoleManagement.Read.Directory', 'AuditLog.Read.All', 'Application.Read.All', 'Policy.Read.All', 'PrivilegedEligibilitySchedule.Read.AzureADGroup']) assert.ok(scopes.includes(s), s);
  for (const [, s] of B3_DEFERRED) for (const x of s.split(', ')) assert.ok(!scopes.includes(x), x);
});
