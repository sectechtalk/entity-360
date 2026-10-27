import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { queryUrl, describeError } from '../server/model.mjs';
import { MicrosoftApi, liveReport, withFallback, azurePim, defenderReport, defenderQuery, innerCode, upstreamText } from '../server/live.mjs';
import { accountReport } from '../server/account.mjs';
import { pageSlice, pagerHtml, sizeSelect, PAGE_SIZES } from '../public/paging.js';
import { bannerFor, sourcesForView } from '../public/access-text.js';
import { entraDeviceLink, intuneDeviceLink, intuneMatch } from '../public/device-links.js';

const U = '00000000-0000-4000-8000-0000000000a5', D = 'dddddddd-1111-2222-3333-444444444444', M = 'eeeeeeee-1111-2222-3333-444444444444';
const err = (status, extra = {}) => Object.assign(new Error('x'), { status, ...extra });
const range = { from: '2026-10-24T00:00:00.000Z', to: '2026-10-25T00:00:00.000Z' };
const read = f => readFile(new URL(`../${f}`, import.meta.url), 'utf8');

test('queryUrl encodes spaces as %20, never +, and keeps $ in parameter names', () => {
  const u = queryUrl('/v1.0/x', { '$filter': `principalId eq '${U}'`, '$expand': 'roleDefinition', 'api-version': '2020-10-01' });
  assert.ok(!u.includes('+'));
  assert.match(u, /\?\$filter=principalId%20eq%20'/);
  assert.match(u, /&\$expand=roleDefinition&api-version=2020-10-01$/);
  assert.equal(new URL(u, 'https://graph.microsoft.com').searchParams.get('$filter'), `principalId eq '${U}'`);
});

test('errors carry Microsoft\'s inner code and message, including Graph UnknownError wrappers', async () => {
  const wrapped = { code: 'UnknownError', message: JSON.stringify({ error: { code: 'BadRequest', message: "The query specified in the URI is not valid." } }) };
  assert.equal(innerCode(wrapped), 'UnknownError: BadRequest');
  assert.match(upstreamText(wrapped), /not valid/);
  const api = new MicrosoftApi(async () => 't', { fetcher: async () => Response.json({ error: wrapped }, { status: 400 }) });
  const e = await api.request('/v1.0/x').catch(x => x);
  assert.equal(e.status, 400);
  assert.match(describeError(e), /HTTP 400 \(UnknownError: BadRequest: The query specified in the URI is not valid/);
});

test('Entra roles: a 400 on PIM schedule instances falls back to the standard role list with a note', async () => {
  const calls = [];
  const api = { async pages(p) { calls.push(p); if (p.includes('ScheduleInstances')) throw err(400, { upstreamCode: 'UnknownError' }); return { rows: [{ id: 'r1' }], truncated: false }; } };
  const report = { notes: [] };
  const r = await withFallback(api, queryUrl('/v1.0/roleManagement/directory/roleAssignmentScheduleInstances', { '$filter': `principalId eq '${U}'` }), queryUrl('/v1.0/roleManagement/directory/roleAssignments', { '$filter': `principalId eq '${U}'` }), report, 'Entra roles & PIM');
  assert.equal(r.rows[0].id, 'r1');
  assert.match(calls[1], /directory\/roleAssignments\?/);
  assert.match(report.notes[0], /standard role list/);
  await assert.rejects(withFallback({ async pages() { throw err(403); } }, 'a', 'b', report, 'x'), e => e.status === 403);
});

test('Azure PIM: assignedTo() first, principalId filter when a subscription rejects it', async () => {
  const urls = [];
  const api = { async pages(p, o) { urls.push(p); assert.equal(o.origin, 'https://management.azure.com'); if (p.includes('assignedTo')) throw err(400); return { rows: [], truncated: false }; } };
  await azurePim(api, 'sub', 'roleEligibilityScheduleInstances', U);
  assert.match(urls[0], /\$filter=assignedTo\('/);
  assert.match(urls[1], /\$filter=principalId%20eq%20'/);
});

test('live report: Intune uses /users/{id}/managedDevices, directory failures name the exact call, Defender is not in the report', async () => {
  const urls = [];
  const api = {
    async request(url) { urls.push(url); if (url === `/v1.0/users/${U}`) return { id: U, displayName: 'Aaron', userPrincipalName: 'a@example.test' }; throw err(403); },
    async pages(url) {
      urls.push(url);
      if (url.includes('oauth2PermissionGrants')) throw err(403, { upstreamCode: 'Authorization_RequestDenied' });
      if (url.includes('managedDevices')) return { rows: [], truncated: false };
      if (url.includes('memberOf')) return { rows: [], truncated: false };
      throw err(403);
    },
  };
  const report = await liveReport(api, U, 'user', range, { tenant: 't' });
  assert.ok(urls.some(u => u.startsWith(`/v1.0/users/${U}/managedDevices?`)));
  assert.ok(!urls.some(u => u.includes('deviceManagement/managedDevices')));
  assert.ok(!urls.some(u => u.includes('runHuntingQuery')));
  assert.ok(report.unavailable.some(u => u.source === 'Entra directory (delegated consents)' && /Authorization_RequestDenied/.test(u.reason)));
});

test('My device: Intune devices come from /me/managedDevices', async () => {
  const urls = [];
  const api = { async request(p) { if (p.startsWith('/v1.0/me?')) return { id: U, displayName: 'V', userPrincipalName: 'v@x.test' }; return { value: [] }; }, async pages(p) { urls.push(p); return { rows: [], truncated: false }; } };
  await accountReport(api, { tenant: U });
  assert.ok(urls.some(u => u.startsWith('/v1.0/me/managedDevices?$select=')));
  assert.ok(!urls.some(u => u.includes('deviceManagement/managedDevices')));
});

test('Defender report: chosen timeframe, 1,000 cap is partial on its own report, 403 is not available', async () => {
  let body;
  const rows = Array.from({ length: 1000 }, (_, i) => ({ Timestamp: range.to, DeviceName: 'PC', DeviceId: 'd', ReportId: i, FileName: 'cmd.exe', ProcessCommandLine: 'cmd /c', AccountUpn: 'a@example.test' }));
  const api = { async request(p, o) { if (p.startsWith(`/v1.0/users/${U}`)) return { id: U, userPrincipalName: 'a@example.test' }; body = o.body; return { results: rows }; } };
  const r = await defenderReport(api, U, 3, { now: Date.parse(range.to) });
  assert.equal(body.Timespan, 'P3D');
  assert.equal(r.events.length, 1000); assert.equal(r.partial, true);
  assert.match(r.partialReasons[0].reason, /shorter timeframe/);
  await assert.rejects(defenderReport(api, U, 90), /Timeframe must be one of/);
  const denied = { async request(p) { if (p.startsWith('/v1.0/users/')) return { id: U, userPrincipalName: 'a@x' }; throw err(403); } };
  const d = await defenderReport(denied, U, 1);
  assert.equal(d.partial, false); assert.equal(d.unavailable[0].source, 'Defender hunting');
  assert.match(defenderQuery('a"b@x', range), /AccountUpn =~ "a\\"b@x"/);
});

test('pageSlice: 20/50/100 rows per page, clamps the page, reports the range', () => {
  const rows = Array.from({ length: 130 }, (_, i) => i);
  assert.deepEqual(PAGE_SIZES, [20, 50, 100]);
  let s = pageSlice(rows, 0, 20); assert.equal(s.rows.length, 20); assert.equal(s.pages, 7); assert.ok(s.first);
  s = pageSlice(rows, 9, 50); assert.equal(s.page, 2); assert.equal(s.rows.length, 30); assert.equal(s.from, 101); assert.equal(s.to, 130); assert.ok(s.last);
  s = pageSlice(rows, 0, 7); assert.equal(s.size, 20, 'unknown sizes fall back to 20');
  assert.equal(pageSlice([], 3, 100).from, 0);
  assert.match(sizeSelect('x', 50), /<option value="50" selected>/);
  assert.match(pagerHtml('p', pageSlice(rows, 0, 20), 'events'), /id="p-prev"[^>]*disabled/);
});

test('every multi-event table has a page-size dropdown, a sticky-header scroll container and paging', async () => {
  const html = await read('public/index.html'), css = await read('public/styles.css'), app = await read('public/app.js'), defender = await read('public/defender.js');
  for (const id of ['activity-page-size', 'signin-page-size', 'signin-table-pager']) assert.match(html, new RegExp(`id="${id}"`));
  assert.ok((html.match(/table-wrap table-scroll/g) || []).length >= 3);
  assert.match(css, /\.table-scroll\{max-height:\d+px;overflow:auto\}\.table-scroll thead th\{position:sticky;top:0/);
  assert.match(app, /pagerHtml\('signin-table'/);
  assert.match(defender, /pagerHtml\('defender'/);
  assert.match(defender, /table-scroll/);
  assert.ok(!/const pageSize = 6/.test(app));
});

test('Partial results banner shows only on the tab whose data is affected, listing only that tab\'s sources', () => {
  const r = { partial: true, partialReasons: [{ source: 'Entra roles & PIM', reason: 'HTTP 400' }, { source: 'Intune devices', reason: 'HTTP 400' }, { source: 'Entra directory (app role assignments)', reason: 'timed out' }], unavailable: [{ source: 'Entra directory (delegated consents)', reason: 'not granted' }, { source: 'Azure PIM', reason: 'not granted' }] };
  for (const v of ['billing', 'deployment', 'portals', 'defender', 'licenses']) assert.equal(bannerFor(r, v), '', v);
  const access = bannerFor(r, 'access');
  assert.match(access, /Entra roles & PIM/); assert.match(access, /app role assignments/); assert.match(access, /delegated consents/);
  assert.ok(!access.includes('Intune'));
  assert.match(bannerFor(r, 'devices'), /^Partial results\. Intune devices: HTTP 400\.$/);
  assert.equal(bannerFor(r, 'signins'), '');
  assert.match(bannerFor(r, 'summary'), /Entra roles.*Intune/s);
  assert.equal(sourcesForView('billing').length, 0);
  assert.equal(bannerFor({ partialReasons: [], unavailable: [{ source: 'Intune devices', reason: 'x' }] }, 'devices'), '', 'not-granted alone is not a partial result');
});

test('My device: each Entra device opens its own Entra page, and its Intune page when managed', () => {
  const d = { id: D, deviceId: '11111111-2222-3333-4444-555555555555', managed: true };
  assert.equal(entraDeviceLink(d), `https://entra.microsoft.com/#view/Microsoft_AAD_Devices/DeviceDetailsMenuBlade/~/Properties/objectId/${D}/deviceId/11111111-2222-3333-4444-555555555555`);
  assert.equal(entraDeviceLink({ id: 'bad' }), null);
  const m = intuneMatch(d, [{ id: M, deviceId: '11111111-2222-3333-4444-555555555555'.toUpperCase() }]);
  assert.equal(m.id, M);
  assert.equal(intuneDeviceLink(m.id), `https://intune.microsoft.com/#view/Microsoft_Intune_Devices/DeviceSettingsMenuBlade/~/overview/mdmDeviceId/${M}`);
  assert.equal(intuneMatch({ deviceId: null }, [{ id: M, deviceId: null }]), null);
});

test('Defender loads on the Defender tab only, with a timeframe selector; Activity does not repeat Defender rows', async () => {
  const app = await read('public/app.js'), defender = await read('public/defender.js'), index = await read('server/index.mjs');
  assert.match(app, /defenderEvents\.setActive\(v === 'defender'\)/);
  assert.match(app, /e\.source !== 'defender'/);
  assert.match(defender, /id="defender-days"/);
  assert.match(defender, /DEFENDER_DAYS = \[1, 3, 7, 14, 30\]/);
  assert.match(index, /app\.get\('\/api\/defender'/);
});
