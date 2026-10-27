import test from 'node:test';
import assert from 'node:assert/strict';
import { describeError } from '../server/model.mjs';
import { appRoleName, assignmentLink, permissionsLink, resolveScopes } from '../server/live.mjs';
import { accountReport } from '../server/account.mjs';
import { signInLookup } from '../server/signins.mjs';
import { hostingLinks } from '../server/hosting.mjs';
import { portalFor, CHECK_PORTALS } from '../server/intune.mjs';
import { partialMessage, APP_LEGEND } from '../public/access-text.js';

const U = '00000000-0000-4000-8000-0000000000a5', A = 'aaaaaaaa-1111-2222-3333-444444444444', R = 'bbbbbbbb-1111-2222-3333-444444444444';
const err = (status, extra = {}) => Object.assign(new Error('upstream SECRET'), { status, ...extra });

test('describeError names timeouts, throttling, bad queries and denials in plain words', () => {
  assert.match(describeError(err(502, { reason: 'timed out after 25 seconds' })), /timed out/);
  assert.match(describeError(err(429)), /throttled/);
  assert.match(describeError(err(400, { upstreamCode: 'BadRequest' })), /rejected.*BadRequest/);
  assert.match(describeError(err(403)), /not granted/);
  assert.ok(!describeError(err(403)).includes('SECRET'));
});

test('app assignment links open the specific assignment, and roles resolve to names', () => {
  const a = { id: 'asg1', principalId: U, principalType: 'User', resourceId: R };
  assert.equal(assignmentLink(a), `https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AssignmentDetailBlade/objectId/${U}/isUser~/true/assignmentObjectId/asg1/spObjectId/${R}/principalId/${U}`);
  assert.match(assignmentLink({ ...a, principalType: 'Group' }), /isUser~\/false/);
  assert.equal(permissionsLink(R, A), `https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ManagedAppMenuBlade/~/Permissions/objectId/${R}/appId/${A}`);
  assert.equal(appRoleName(null, '00000000-0000-0000-0000-000000000000'), 'Default Access');
  assert.equal(appRoleName({ appRoles: [{ id: A, displayName: 'Reader' }] }, A), 'Reader');
  assert.match(appRoleName(null, A), /not readable/);
});

test('directory role scopes resolve administrative unit names, and a denied lookup says which scope is needed', async () => {
  const au = '/administrativeUnits/' + A;
  const ok = { async request(p) { if (p.includes('administrativeUnits')) return { displayName: 'Seattle' }; return { displayName: 'App X', '@odata.type': '#microsoft.graph.application' }; } };
  const pols = [{ evidence: { directoryScopeId: '/' } }, { evidence: { directoryScopeId: au } }, { evidence: { directoryScopeId: '/' + R } }];
  await resolveScopes(ok, pols, { unavailable: [] });
  assert.deepEqual(pols.map(p => p.scopeName), ['Directory (tenant-wide)', 'Administrative unit: Seattle', 'App registration: App X']);
  assert.match(pols[1].scopeLink, /AdministrativeUnitMenuBlade/);
  const report = { unavailable: [] }, denied = [{ evidence: { directoryScopeId: au } }];
  await resolveScopes({ async request() { throw err(403); } }, denied, report);
  assert.equal(denied[0].scopeName, `Administrative unit ${A}`);
  assert.match(report.unavailable[0].reason, /AdministrativeUnit.Read.All/);
});

test('My access: a timeout is partial and named; a 403 is only listed as not available', async () => {
  const api = {
    async request(p) { if (p.startsWith('/v1.0/me?')) return { id: U, displayName: 'Viewer', userPrincipalName: 'v@example.test' }; return { value: [] }; },
    async pages(p) {
      if (p.includes('authentication/methods')) throw err(403);
      if (p.includes('licenseDetails')) throw err(502, { reason: 'timed out after 25 seconds' });
      return { rows: [], truncated: false };
    },
  };
  const r = await accountReport(api, { tenant: U });
  assert.equal(r.partial, true);
  assert.deepEqual(r.partialReasons, [{ source: 'My Microsoft 365 licenses', reason: 'timed out after 25 seconds' }]);
  assert.equal(r.unavailable[0].source, 'My registered authentication methods');
  assert.match(partialMessage(r), /My Microsoft 365 licenses: timed out.*Not available: My registered authentication methods/);
});

test('Sign-ins lookup: out-of-window rows are ignored without flagging partial; a failure names the user and reason', async () => {
  const range = { from: new Date(Date.now() - 86400000).toISOString(), to: new Date().toISOString() };
  const api = { async pages(p) {
    if (decodeURIComponent(p).includes('bad@example.test')) throw err(400, { upstreamCode: 'BadRequest' });
    return { rows: [{ id: '1', createdDateTime: new Date(Date.now() - 3600000).toISOString(), userPrincipalName: 'Ok@Example.test' }, { id: '2', createdDateTime: '2000-01-01T00:00:00Z' }], truncated: false };
  } };
  const r = await signInLookup(api, { users: ['ok@example.test', 'bad@example.test'], range, beta: false, nonInteractive: false });
  const ok = r.users.find(u => u.user === 'ok@example.test');
  assert.equal(ok.status, 'complete');
  assert.equal(ok.count, 1);
  assert.ok(ok.notes.some(n => /ignored/.test(n)));
  assert.equal(r.partialReasons.length, 1);
  assert.equal(r.partialReasons[0].source, 'bad@example.test');
  assert.match(r.partialReasons[0].reason, /rejected/);
});

test('every Kind and Status on the App permissions tab has a plain-language meaning', () => {
  for (const k of ['Application assignment', 'API permission', 'Delegated permission', 'Credential', 'Assigned', 'Granted', 'Consented', 'Configured', 'Expired']) assert.ok(APP_LEGEND[k], k);
});

test('health checks carry direct portal links; client checks explain why they have none', () => {
  for (const id of ['lic-intune', 'mdm-scope', 'ca-compliant', 'compliance-basis', 'joined-enrolled', 'sync-fresh', 'xcheck', 'entra-writeback', 'defender-only', 'user-identity']) assert.match(CHECK_PORTALS[id].url, /^https:\/\//, id);
  assert.ok(!portalFor('client-prt').url);
  assert.match(portalFor('client-prt').reason, /this computer/);
});

test('hosting links point at the exact resources and can be overridden', () => {
  const groups = hostingLinks({});
  const urls = groups.flatMap(g => g.links.map(l => l.url)).filter(Boolean);
  assert.ok(urls.some(u => u.endsWith('/resourceGroups/rg-e360/providers/Microsoft.App/containerApps/app-e360/revisionManagement')));
  assert.ok(urls.some(u => u.includes('/vaults/kv-e360-auth-xxxxx/keys')));
  assert.ok(urls.some(u => u.includes('ApplicationMenuBlade/~/Credentials/appId/00000000-0000-4000-8000-0000000000a3')));
  assert.ok(groups.find(g => g.group === 'Logs').links[0].reason);
  assert.ok(hostingLinks({ E360_HOST_CONTAINER_APP: 'app-x' }).flatMap(g => g.links).some(l => l.url?.includes('containerApps/app-x/')));
  assert.ok(!JSON.stringify(groups).match(/secret=|password|client_secret/i));
});

test('deployment log loads once; switching views does not refetch, Refresh does', async () => {
  const el = () => ({ innerHTML: '', onchange: null });
  globalThis.document = { querySelector: () => el() };
  let calls = 0;
  globalThis.fetch = async () => { calls++; return { ok: true, json: async () => ({ title: 't', note: 'n', machines: [], steps: [], status: { columns: [], rows: {} } }) }; };
  const { createDeploymentView } = await import('../public/deployment.js');
  const v = createDeploymentView({ esc: String });
  v.setActive(true); await new Promise(r => setTimeout(r, 10));
  v.setActive(false); v.setActive(true); await new Promise(r => setTimeout(r, 10));
  assert.equal(calls, 1);
  await v.refresh();
  assert.equal(calls, 2);
});

test('page load preloads every live view once and the Partial banner is source-specific', async () => {
  const { readFile } = await import('node:fs/promises');
  const app = await readFile(new URL('../public/app.js', import.meta.url), 'utf8');
  assert.match(app, /\['account', 'intune', 'licenses', 'billing'\]\.map\(k => Promise\.resolve\(\)\.then\(\(\) => autoRunView\(k\)\)\)/);
  assert.match(app, /bannerFor\(state\.report, v\)/);
  assert.ok(!/notice\(partialMessage\(report\)\)/.test(app), 'the Partial banner is no longer global');
  assert.ok(!/Some queries reached a limit or could not finish/.test(app));
});
