// Coverage plan, bucket 1 (new values in existing columns), 2026-10-28.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { governanceKind } from '../public/group-types.js';
import { caResultLabel } from '../public/signin-columns.js';
import { joinTypeLabel } from '../public/device-links.js';
import { normalizeSignIn } from '../server/signins.mjs';
import { policyLabel, accessPackages } from '../server/entitlements.mjs';
import { ingressLabel, hostingIngress } from '../server/hosting.mjs';
import { myRoles } from '../server/my-roles.mjs';

const read = p => readFileSync(new URL(`../${p}`, import.meta.url), 'utf8');

test('Groups Kind shows Role-assignable, Dynamic and Synced from on-prem', () => {
  assert.equal(governanceKind({}), 'Group');
  assert.equal(governanceKind({ isAssignableToRole: true }), 'Group · Role-assignable');
  assert.equal(governanceKind({ groupTypes: ['DynamicMembership'] }), 'Group · Dynamic');
  assert.equal(governanceKind({ membershipRule: 'user.department -eq "x"', onPremisesSyncEnabled: true }), 'Group · Dynamic · Synced from on-prem');
  const live = read('server/live.mjs');
  assert.match(live, /transitiveMemberOf\/microsoft\.graph\.group\?\$select=id,displayName,groupTypes,membershipRule,isAssignableToRole,onPremisesSyncEnabled/);
  assert.match(live, /kind: governanceKind\(g\)/);
});

test('Sign-in CA results: report-only outcomes and auth strength not met', () => {
  assert.equal(caResultLabel({ result: 'reportOnlyFailure' }), 'Report-only: would block');
  assert.equal(caResultLabel({ result: 'reportOnlyInterrupted' }), 'Report-only: would prompt');
  assert.equal(caResultLabel({ result: 'success' }), 'Applied: passed');
  assert.equal(caResultLabel({ result: 'failure', authenticationStrength: { displayName: 'Phishing-resistant MFA', authenticationStrengthResult: 'cannotSatisfy' } }), 'Applied: blocked; Auth strength not met: Phishing-resistant MFA');
  assert.equal(caResultLabel({ result: 'success', authenticationStrength: { authenticationStrengthResult: 'satisfied' } }), 'Applied: passed');
  const e = normalizeSignIn({ id: 'r', createdDateTime: '2026-10-28T10:00:00Z', appliedConditionalAccessPolicies: [{ id: 'p', displayName: 'MFA', result: 'reportOnlyFailure' }] }, 'u@x.test', 'beta');
  assert.equal(e.policies[0].status, 'reportOnlyFailure', 'raw status kept for filtering');
  assert.equal(e.policies[0].label, 'Report-only: would block');
  assert.match(read('public/signins.js'), /esc\(p\.label \|\| p\.status\)/);
});

test('Device join type from trustType', () => {
  assert.equal(joinTypeLabel('AzureAd'), 'Entra joined');
  assert.equal(joinTypeLabel('ServerAd'), 'Hybrid joined');
  assert.equal(joinTypeLabel('Workplace'), 'Registered');
  assert.equal(joinTypeLabel(''), 'Join type not returned');
  assert.match(read('public/account.js'), /Join type: \$\{esc\(joinTypeLabel\(d\.trust\)\)\}/);
});

test('Hosting ingress: open, IP-restricted, internal, unreadable', async () => {
  assert.equal(ingressLabel({ properties: { configuration: { ingress: { external: true } } } }), 'Ingress: open');
  assert.equal(ingressLabel({ properties: { configuration: { ingress: { external: true, ipSecurityRestrictions: [{ action: 'Allow', ipAddressRange: '203.0.113.5/32' }] } } } }), 'Ingress: IP-restricted (203.0.113.5/32)');
  assert.equal(ingressLabel({ properties: { configuration: { ingress: { external: false } } } }), 'Ingress: internal only');
  let seen;
  const ok = await hostingIngress({ async request(p, o) { seen = [p, o.origin]; return { properties: { configuration: { ingress: { external: true } } } }; } }, {});
  assert.equal(ok, 'Ingress: open');
  assert.match(seen[0], /^\/subscriptions\/[0-9a-f-]+\/resourceGroups\/rg-e360\/providers\/Microsoft\.App\/containerApps\/app-e360\?api-version=/);
  assert.equal(seen[1], 'https://management.azure.com');
  assert.equal(await hostingIngress({ async request() { throw Object.assign(new Error('x'), { status: 403 }); } }, {}), 'Ingress: not readable (needs Reader on the Container App)');
  assert.match(read('server/index.mjs'), /hostingIngress\(liveApi\(s\)\)/);
});

test('My access shows Admin unit: <name> for AU-scoped roles', async () => {
  const au = 'aaaaaaaa-1111-2222-3333-444444444444';
  const api = {
    async pages(p) { if (p.includes('roleAssignmentScheduleInstances') && p.includes('roleDefinition')) return { rows: [{ id: 'x', roleDefinitionId: 'r', roleDefinition: { displayName: 'User Administrator' }, directoryScopeId: `/administrativeUnits/${au}` }] }; if (p.includes('roleManagement')) return { rows: [] }; throw Object.assign(new Error('no'), { status: 403 }); },
    async request(p) { if (p.includes(`administrativeUnits/${au}`)) return { displayName: 'Seattle' }; throw Object.assign(new Error('no'), { status: 403 }); },
  };
  const r = await myRoles(api, { id: 'me' }, []);
  assert.equal(r.rows.find(x => x.name === 'User Administrator').scope, 'Admin unit: Seattle');
});

test('Access packages Policy names connected organizations for external policies', async () => {
  assert.equal(policyLabel(null), 'Not returned');
  assert.equal(policyLabel({ displayName: 'Internal' }), 'Internal');
  assert.equal(policyLabel({ displayName: 'Partners', allowedTargetScope: 'specificConnectedOrganizationUsers', specificAllowedTargets: [{ '@odata.type': '#microsoft.graph.connectedOrganizationMembers', connectedOrganizationId: 'o1' }] }, new Map([['o1', 'Fabrikam']])), 'Partners · For connected org: Fabrikam');
  assert.equal(policyLabel({ displayName: 'All partners', allowedTargetScope: 'allConfiguredConnectedOrganizationUsers' }), 'All partners · For connected org: all configured');
  assert.equal(policyLabel({ displayName: 'Anyone', allowedTargetScope: 'allExternalUsers' }), 'Anyone · For external users: any organization');
  const api = {
    async pages(p) { return p.includes('/assignments') ? { rows: [{ id: 'a', state: 'delivered', accessPackage: { id: 'k', displayName: 'Pkg' }, assignmentPolicy: { displayName: 'Partners', specificAllowedTargets: [{ '@odata.type': '#microsoft.graph.connectedOrganizationMembers', connectedOrganizationId: 'o1' }] } }] } : { rows: [] }; },
    async request(p) { return p.includes('connectedOrganizations/o1') ? { displayName: 'Fabrikam' } : { displayName: 'Pkg' }; },
  };
  const r = await accessPackages(api, 'u');
  assert.equal(r.rows[0].policy, 'Partners · For connected org: Fabrikam');
});

test('delegated read-only scopes only, one .btn style, no demo mode added', () => {
  const env = read('.env.example').match(/^GRAPH_SCOPES=(.*)$/m)[1].split(',');
  assert.ok(!env.some(s => /ReadWrite/.test(s)), 'no write scopes');
  for (const f of ['server/hosting.mjs', 'server/entitlements.mjs', 'public/device-links.js']) assert.doesNotMatch(read(f), /demo/i);
  assert.doesNotMatch(read('public/app.js') + read('public/account.js'), /class="btn-[a-z]/);
});
