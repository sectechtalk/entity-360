import test from 'node:test';
import assert from 'node:assert/strict';
import { parseOutput, deviceRow, remediationResults, scriptIdFrom, SCRIPT_ID_ENV } from '../server/remediation-results.mjs';
import { filterDevices, sortDevices, devicesCsv, tableHtml, passTotal } from '../public/remediation-results.js';
import { roleForPath, decide } from '../server/authflow.mjs';
import { VIEW_ROLES } from '../public/access-denied.js';

const ID = '11111111-2222-3333-4444-555555555555';
const good = JSON.stringify({ v: 1, kind: 'e360-net', ok: true, host: 'PC1', at: '2026-10-30T10:00:00Z', dur: 900, pre: { ps: '5.1', net: true, nic: 1, ok: true }, lat: { min: 10, max: 40, avg: 22 }, pass: 6, total: 6, issues: [], r: [{ t: 'login.microsoftonline.com', dns: true, ip: '1.2.3.4', tcp: true, ms: 20, dnsMs: 3 }] });
const bad = JSON.stringify({ v: 1, kind: 'e360-net', ok: false, host: 'PC2', pass: 4, total: 6, lat: null, issues: ['graph.microsoft.com: TCP 443 failed', 'dns slow'], r: [], trunc: 'r' });
const states = [
  { id: 's1', detectionState: 'success', lastStateUpdateDateTime: '2026-10-30T10:01:00Z', preRemediationDetectionScriptOutput: good, managedDevice: { id: 'd1', deviceName: 'PC1', userPrincipalName: 'a@x.com' } },
  { id: 's2', detectionState: 'fail', lastStateUpdateDateTime: '2026-10-30T09:00:00Z', preRemediationDetectionScriptOutput: bad, managedDevice: { id: 'd2', deviceName: 'PC2' } },
  { id: 's3', detectionState: 'scriptError', preRemediationDetectionScriptOutput: '{not json', preRemediationDetectionScriptError: 'boom' },
  { id: 's4', detectionState: 'pending' },
];

test('parseOutput handles good, failing, malformed, missing and foreign output', () => {
  assert.equal(parseOutput(good).ok, true); assert.equal(parseOutput(good).lat.avg, 22);
  const b = parseOutput(bad); assert.equal(b.ok, false); assert.equal(b.lat, null); assert.equal(b.truncated, 'r'); assert.equal(b.issues.length, 2);
  assert.match(parseOutput('{x').error, /not valid JSON/); assert.match(parseOutput(undefined).error, /No output/); assert.match(parseOutput('').error, /No output/);
  assert.match(parseOutput('[1]').error, /not a result/); assert.match(parseOutput('{"kind":"other"}').error, /Unexpected/);
  assert.equal(parseOutput(`noise\n${good}`).ok, true);
});

test('deviceRow maps status and fields', () => {
  const [a, b, c, d] = states.map(deviceRow);
  assert.deepEqual([a.status, b.status, c.status, d.status], ['ok', 'problem', 'unknown', 'unknown']);
  assert.equal(a.device, 'PC1'); assert.equal(a.avgMs, 22); assert.equal(passTotal(b), '4/6'); assert.match(b.issues, /TCP 443/);
  assert.equal(c.scriptError, 'boom'); assert.match(c.issues, /not valid JSON/); assert.equal(d.device, 'Unknown device');
});

test('remediationResults calls beta deviceRunStates with $expand and falls back on 400', async () => {
  const urls = [];
  const api = { pages: async url => { urls.push(url); return { rows: states, truncated: false }; } };
  const r = await remediationResults(api, ID);
  assert.equal(urls[0], `/beta/deviceManagement/deviceHealthScripts/${ID}/deviceRunStates?$expand=${encodeURIComponent('managedDevice($select=deviceName,id,userPrincipalName)')}`);
  assert.equal(r.configured, true); assert.equal(r.expanded, true); assert.equal(r.rows.length, 4);
  const calls = []; const api2 = { pages: async url => { calls.push(url); if (url.includes('$expand')) throw Object.assign(new Error('bad'), { status: 400 }); return { rows: [states[0]], truncated: true }; } };
  const r2 = await remediationResults(api2, ID);
  assert.equal(calls.length, 2); assert.equal(r2.expanded, false); assert.equal(r2.truncated, true);
});

test('403 names the missing scope; other errors pass through; not configured needs no Graph', async () => {
  const deny = { pages: async () => { throw Object.assign(new Error('Forbidden'), { status: 403 }); } };
  await assert.rejects(remediationResults(deny, ID), e => e.status === 403 && /DeviceManagementScripts\.Read\.All/.test(e.reason));
  const boom = { pages: async () => { throw Object.assign(new Error('x'), { status: 500 }); } };
  await assert.rejects(remediationResults(boom, ID), e => e.status === 500 && !e.reason);
  const none = await remediationResults({ pages: () => assert.fail('no call') }, null);
  assert.equal(none.configured, false); assert.match(none.note, new RegExp(SCRIPT_ID_ENV));
  await assert.rejects(remediationResults({ pages: async () => ({ rows: [] }) }, 'nope'), e => e.status === 400);
});

test('script id comes from env and must be a GUID', () => {
  assert.equal(scriptIdFrom({ [SCRIPT_ID_ENV]: ` ${ID} ` }), ID);
  assert.equal(scriptIdFrom({ [SCRIPT_ID_ENV]: 'abc' }), null); assert.equal(scriptIdFrom({}), null);
});

test('route and view are gated to E360.Intune with no fallback', () => {
  assert.equal(roleForPath('/api/intune/remediation-results'), 'E360.Intune');
  assert.equal(VIEW_ROLES.remediation, 'E360.Intune');
  const d = decide({ mode: 'live', path: '/api/intune/remediation-results', roles: ['E360.Reader', 'E360.SignIns'], enforce: true });
  assert.equal(d.allowed, false); assert.equal(d.needed, 'E360.Intune');
  assert.equal(decide({ mode: 'live', path: '/api/intune/remediation-results', roles: ['E360.Intune'], enforce: true }).allowed, true);
});

test('client filter, sort, CSV and table', () => {
  const rows = states.map(deviceRow);
  assert.equal(filterDevices(rows, 'ok').length, 1); assert.equal(filterDevices(rows, 'problem').length, 3); assert.equal(filterDevices(rows, 'all').length, 4);
  assert.equal(sortDevices(rows)[0].status, 'problem');
  assert.equal(sortDevices(rows, { key: 'avgMs', dir: 'desc' })[0].device, 'PC1');
  const csv = devicesCsv([{ ...rows[1], device: '=cmd' }]);
  assert.ok(csv.startsWith('\ufeff"Device"')); assert.match(csv, /"'=cmd"/); assert.match(csv, /"4\/6"/);
  const esc = s => String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]);
  const html = tableHtml([{ ...rows[0], device: '<b>' }], { key: 'status', dir: 'asc' }, esc);
  assert.match(html, /&lt;b&gt;/); assert.match(html, /aria-sort="ascending"/); assert.match(html, /result success/); assert.doesNotMatch(html, /\u2014/);
});
