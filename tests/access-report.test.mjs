// GOVERNANCE > Access report: group, role and user scopes, last sign-in, audit line, E360.Admin gate, CSV, page.
// Fictional Contoso data only.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { accessReport, searchScope, auditLine, SOURCES } from '../server/access-report.mjs';
import { roleForPath } from '../server/authflow.mjs';
import { VIEW_ROLES } from '../public/access-denied.js';
import { reportCsv, csvName, REPORT_COLUMNS } from '../public/access-report.js';
import { startHarness } from './e360-browser-harness.mjs';

const G = 'aaaaaaaa-1111-2222-3333-444444444444', R = 'bbbbbbbb-1111-2222-3333-444444444444', U = 'dddddddd-1111-2222-3333-444444444444', U2 = 'eeeeeeee-1111-2222-3333-444444444444', NG = '00000000-0000-0000-0000-000000000001';
const megan = { '@odata.type': '#microsoft.graph.user', id: U, displayName: 'Megan Bowen', userPrincipalName: 'meganb@contoso.example' };
const alex = { '@odata.type': '#microsoft.graph.user', id: U2, displayName: 'Alex Wilber', userPrincipalName: 'alexw@contoso.example' };
function fake({ signInDenied = false } = {}) {
  return {
    calls: [],
    async pages(p) {
      const d = decodeURIComponent(p); this.calls.push(d);
      if (d.includes(`/groups/${G}/members`)) return { rows: [megan] };
      if (d.includes(`/groups/${G}/transitiveMembers`)) return { rows: [megan, alex, { '@odata.type': '#microsoft.graph.group', id: NG, displayName: 'Contoso Nested' }] };
      if (d.includes(`group/eligibilityScheduleInstances?$filter=groupId eq '${G}'`)) return { rows: [{ principalId: U2, principal: alex, accessId: 'member', endDateTime: '2027-01-31T00:00:00Z' }] };
      if (d.includes(`group/assignmentScheduleInstances?$filter=groupId eq '${G}'`)) return { rows: [{ principalId: U, principal: megan, accessId: 'member', assignmentType: 'assigned' }, { principalId: U2, principal: alex, accessId: 'member', assignmentType: 'activated', endDateTime: '2026-11-01T02:00:00Z' }] };
      if (d.includes(`roleEligibilityScheduleInstances?$filter=roleDefinitionId eq '${R}'`)) return { rows: [{ principalId: U2, principal: alex, directoryScopeId: '/', endDateTime: null }] };
      if (d.includes(`roleAssignmentScheduleInstances?$filter=roleDefinitionId eq '${R}'`)) return { rows: [{ principalId: U, principal: megan, directoryScopeId: '/', assignmentType: 'Assigned' }] };
      if (d.includes(`/users/${U}/memberOf/`)) return { rows: [{ id: G }] };
      if (d.includes(`/users/${U}/transitiveMemberOf/`)) return { rows: [{ id: G, displayName: 'Contoso Finance' }, { id: NG, displayName: 'Contoso Nested' }] };
      if (d.includes('roleDefinitions?')) return { rows: [{ id: R, displayName: 'Global Reader', isBuiltIn: true }, { id: 'x', displayName: 'Groups Administrator', isBuiltIn: true }] };
      if (d.includes('/v1.0/groups?')) return { rows: [{ id: G, displayName: 'Contoso Finance', securityEnabled: true }] };
      return { rows: [] };
    },
    async request(p) {
      this.calls.push(p);
      if (p.startsWith(`/v1.0/groups/${G}?`)) return { id: G, displayName: 'Contoso Finance' };
      if (p.includes(`roleDefinitions/${R}?`)) return { id: R, displayName: 'Global Reader' };
      if (p.includes('signInActivity')) { if (signInDenied) throw Object.assign(new Error('d'), { status: 403 }); return p.includes(U2) ? { signInActivity: { lastSignInDateTime: '2026-10-29T08:00:00Z' } } : { signInActivity: null }; }
      if (p.startsWith(`/v1.0/users/${U}?`)) return megan;
      throw Object.assign(new Error('nf'), { status: 404 });
    },
  };
}

test('group scope: direct and nested members, PIM eligible and PIM active (standing PIM members not doubled), last sign-in', async () => {
  const r = await accessReport(fake(), 'group', G);
  assert.equal(r.scope.name, 'Contoso Finance');
  const by = r.rows.map(x => [x.name, x.source, x.via, x.lastSignIn]);
  assert.deepEqual(by, [
    ['Alex Wilber', SOURCES.nested, 'Contoso Finance', '2026-10-29T08:00:00Z'],
    ['Alex Wilber', SOURCES.eligible, 'Contoso Finance (member)', '2026-10-29T08:00:00Z'],
    ['Alex Wilber', SOURCES.active, 'Contoso Finance (member)', '2026-10-29T08:00:00Z'],
    ['Megan Bowen', SOURCES.member, 'Contoso Finance', 'Never'],
  ]);
  assert.ok(!r.rows.some(x => x.objectType === 'Group'), 'nested groups themselves are not rows');
  assert.equal(r.problems.length, 0);
});

test('role scope: standing assignment and PIM eligibility, with principals expanded', async () => {
  const api = fake(), r = await accessReport(api, 'role', R);
  assert.deepEqual(r.rows.map(x => [x.name, x.source, x.via]), [['Alex Wilber', SOURCES.eligible, 'Global Reader'], ['Megan Bowen', SOURCES.role, 'Global Reader']]);
  assert.ok(api.calls.some(c => c.includes('$expand=principal')));
});

test('user scope: group memberships (direct, nested) and the INVESTIGATE > PIM reads', async () => {
  const r = await accessReport(fake(), 'user', U);
  assert.equal(r.scope.name, 'Megan Bowen');
  assert.deepEqual(r.rows.map(x => [x.source, x.via]), [[SOURCES.member, 'Contoso Finance'], [SOURCES.nested, 'Contoso Nested']]);
});

test('last sign-in refused: rows still returned, one plain problem line', async () => {
  const r = await accessReport(fake({ signInDenied: true }), 'group', G);
  assert.equal(r.rows.length, 4);
  assert.equal(r.problems.filter(p => p.startsWith('Last sign-in:')).length, 1);
  assert.ok(r.rows.every(x => x.lastSignIn === null));
});

test('input checks, search, and the audit line carries no user data', async () => {
  await assert.rejects(accessReport(fake(), 'tenant', G), /Pick group, role or user/);
  await assert.rejects(accessReport(fake(), 'group', 'not-a-guid'), /Pick a group, role or user/);
  assert.deepEqual((await searchScope(fake(), 'role', 'global')).map(x => x.name), ['Global Reader']);
  await assert.rejects(searchScope(fake(), 'group', '  '), /Type the start/);
  const user = JSON.parse(auditLine({ requester: { upn: 'admin@contoso.example', objectId: 'o' }, kind: 'user', scopeId: U, rows: 3, outcome: 'ok', ms: 10 }).replace(/^E360_AUDIT /, ''));
  assert.equal(user.type, 'access-report'); assert.equal(user.scopeId, null, 'a user scope id is not logged'); assert.equal(user.rows, 3);
  const grp = JSON.parse(auditLine({ requester: {}, kind: 'group', scopeId: G, rows: 4, outcome: 'ok' }).slice(11));
  assert.equal(grp.scopeId, G);
});

test('gate: /api/access-report needs E360.Admin; the page is locked to E360.Admin; nav under GOVERNANCE', () => {
  assert.equal(roleForPath('/api/access-report/run'), 'E360.Admin');
  assert.equal(roleForPath('/api/access-report/search'), 'E360.Admin');
  assert.equal(VIEW_ROLES['g-access-report'], 'E360.Admin');
  const html = readFileSync(new URL('../public/index.html', import.meta.url), 'utf8');
  const gov = html.indexOf('data-section="governance"'), apps = html.indexOf('data-section="apps"'), btn = html.indexOf('data-view="g-access-report"');
  assert.ok(gov < btn && btn < apps);
});

test('CSV: clear columns, formula guard, file name', () => {
  const csv = reportCsv([{ name: '=cmd', upn: 'meganb@contoso.example', objectType: 'User', source: SOURCES.eligible, via: 'Contoso Finance (member)', end: '2027-01-31T00:00:00Z', lastSignIn: 'Never' }]);
  const lines = csv.replace(/^﻿/, '').split('\r\n');
  assert.equal(lines[0], REPORT_COLUMNS.map(([, l]) => `"${l}"`).join(','));
  assert.equal(lines[0], '"User","UPN","Object type","Source","Group or role","End date","Last sign-in (UTC)"');
  assert.equal(lines[1], `"'=cmd","meganb@contoso.example","User","PIM eligible","Contoso Finance (member)","2027-01-31 00:00:00Z","Never"`);
  assert.match(csvName({ kind: 'group', name: 'Contoso Finance' }, new Date('2026-10-31T06:30:00Z')), /^entity-360-access-report-group-Contoso_Finance-202610310630\.csv$/);
});

test('browser: search, pick, run with progress, table, Export CSV (header Export too)', async t => {
  const h = await startHarness(t, { port: 3711, roles: ['E360.Admin', 'E360.Reader'] }); if (!h) return;
  try {
    const { ctx, page, errors } = await h.open({ before: async p => {
      await p.route('**/api/access-report/search**', r => r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ results: [{ id: G, name: 'Contoso Finance', detail: 'Security group' }] }) }));
      await p.route('**/api/access-report/run', async r => { await new Promise(x => setTimeout(x, 1200)); r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ scope: { kind: 'group', id: G, name: 'Contoso Finance' }, rows: [{ id: U, name: 'Megan Bowen', upn: 'meganb@contoso.example', objectType: 'User', source: 'Group member', via: 'Contoso Finance', end: null, lastSignIn: 'Never' }, { id: U2, name: 'Alex Wilber', upn: 'alexw@contoso.example', objectType: 'User', source: 'PIM eligible', via: 'Contoso Finance (member)', end: '2027-01-31T00:00:00Z', lastSignIn: '2026-10-29T08:00:00Z' }], problems: [], notes: [], readAt: new Date().toISOString(), ms: 1200 }) }); });
    } });
    await page.click('#navigation [data-view="g-access-report"]');
    await page.waitForSelector('#access-report-panel:not([hidden])');
    assert.equal(await page.isDisabled('#ar-run'), true);
    await page.fill('#ar-q', 'Contoso'); await page.click('#ar-search-form button[type=submit]');
    await page.click(`[data-ar-pick="${G}"]`);
    assert.match(await page.textContent('#ar-picked'), /Contoso Finance/);
    await page.click('#ar-run');
    await page.waitForFunction(() => /Reading Contoso Finance/.test(document.querySelector('#ar-status')?.textContent || ''));
    await page.waitForFunction(() => document.querySelectorAll('#ar-table tbody tr').length === 2, null, { timeout: 10000 });
    assert.equal(await page.textContent('#ar-count'), '2');
    assert.match(await page.textContent('#ar-status'), /2 rows for Contoso Finance.*Nothing was stored/);
    const [dl] = await Promise.all([page.waitForEvent('download'), page.click('#ar-export')]);
    const csv = readFileSync(await dl.path(), 'utf8').replace(/^﻿/, '').split('\r\n');
    assert.equal(csv.length, 3); assert.match(csv[2], /"Alex Wilber","alexw@contoso.example","User","PIM eligible"/);
    const [dl2] = await Promise.all([page.waitForEvent('download'), page.click('#header-export')]);
    assert.match(dl2.suggestedFilename(), /^entity-360-access-report-group-Contoso_Finance-/);
    assert.deepEqual(errors, []); await ctx.close();
  } finally { await h.close(); }
});

test('browser: without E360.Admin the page shows the access denial', async t => {
  const h = await startHarness(t, { port: 3712, roles: ['E360.Reader'] }); if (!h) return;
  try {
    const { ctx, page } = await h.open();
    await page.click('#navigation [data-view="g-access-report"]');
    await page.waitForSelector('#denied-panel:not([hidden])');
    assert.match(await page.textContent('#denied-panel'), /E360\.Admin/);
    assert.equal(await page.isHidden('#access-report-panel'), true);
    await ctx.close();
  } finally { await h.close(); }
});
