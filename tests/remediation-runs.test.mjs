import test from 'node:test';
import assert from 'node:assert/strict';
import { RunAudit, requestRun, checkReason, RUN_SCOPE, AUDIT_PREFIX, REASON_MAX } from '../server/remediation-runs.mjs';
import { runsCsv, runsTableHtml, tableHtml, runFormHtml } from '../public/remediation-results.js';
import { roleForPath, decide } from '../server/authflow.mjs';
import { readFileSync } from 'node:fs';

const SCRIPT = '11111111-2222-3333-4444-555555555555';
const DEV = 'aaaaaaaa-1111-2222-3333-444444444444';
const states = [{ id: 's1', detectionState: 'success', managedDevice: { id: DEV, deviceName: 'PC1', userPrincipalName: 'a@x.com' } }];
const who = { upn: 'admin@x.com', objectId: 'bbbbbbbb-1111-2222-3333-444444444444' };
const mkAudit = () => { const lines = []; return { audit: new RunAudit({ write: l => lines.push(l) }), lines }; };
const mkApi = (post = async () => ({})) => { const calls = []; return { calls, pages: async () => ({ rows: states, truncated: false }), request: async (url, o) => { calls.push([url, o]); return post(url, o); } }; };

test('run routes need E360.Admin; E360.Intune alone is denied; results route unchanged', () => {
  for (const p of ['/api/intune/remediation-run', '/api/intune/remediation-runs']) {
    assert.equal(roleForPath(p), 'E360.Admin');
    const d = decide({ mode: 'live', path: p, roles: ['E360.Intune', 'E360.Reader'], enforce: true });
    assert.equal(d.allowed, false); assert.equal(d.needed, 'E360.Admin');
    assert.equal(decide({ mode: 'live', path: p, roles: ['E360.Admin'], enforce: true }).allowed, true);
  }
  assert.equal(roleForPath('/api/intune/remediation-results'), 'E360.Intune');
});

test('scope is in the default Graph scopes and the route is a CSRF-checked POST', () => {
  const src = readFileSync(new URL('../server/index.mjs', import.meta.url), 'utf8');
  assert.match(src, /GRAPH_SCOPES \|\| '[^']*DeviceManagementManagedDevices\.PrivilegedOperations\.All'/);
  assert.match(src, /app\.post\('\/api\/intune\/remediation-run'/);
  assert.match(src, /x-csrf-token/);
});

test('reason is required, trimmed and bounded', async () => {
  assert.equal(checkReason('  fix VPN  '), 'fix VPN');
  assert.throws(() => checkReason('   '), /required/); assert.throws(() => checkReason(undefined), /required/);
  assert.throws(() => checkReason('x'.repeat(REASON_MAX + 1)), /500/);
  const { audit } = mkAudit(); const api = mkApi();
  await assert.rejects(requestRun({ api, scriptId: SCRIPT, managedDeviceId: DEV, reason: ' ', requester: who, audit }), e => e.status === 400 && e.audit.result === 'denied');
  assert.equal(api.calls.length, 0);
});

test('unknown or malformed device is rejected without calling Intune', async () => {
  const { audit } = mkAudit(); const api = mkApi();
  await assert.rejects(requestRun({ api, scriptId: SCRIPT, managedDeviceId: 'dddddddd-1111-2222-3333-444444444444', reason: 'r', requester: who, audit }), e => e.status === 404 && /not in the Remediation results/.test(e.message));
  await assert.rejects(requestRun({ api, scriptId: SCRIPT, managedDeviceId: '../x', reason: 'r', requester: who, audit }), e => e.status === 400);
  await assert.rejects(requestRun({ api, scriptId: null, managedDeviceId: DEV, reason: 'r', requester: who, audit }), e => e.status === 409);
  assert.equal(api.calls.length, 0); assert.equal(audit.list().length, 3); assert.ok(audit.list().every(r => r.result === 'denied'));
});

test('accepted run posts to Intune with the script id and records a full audit row and stdout line', async () => {
  const { audit, lines } = mkAudit(); const api = mkApi();
  const row = await requestRun({ api, scriptId: SCRIPT, managedDeviceId: DEV.toUpperCase(), reason: '  user reports no VPN ', requester: who, audit });
  assert.deepEqual(api.calls[0], [`/beta/deviceManagement/managedDevices/${DEV}/initiateOnDemandProactiveRemediation`, { method: 'POST', body: { scriptPolicyId: SCRIPT } }]);
  assert.deepEqual(Object.keys(row).sort(), ['device', 'error', 'id', 'managedDeviceId', 'reason', 'requester', 'result', 'scriptId', 'time', 'user'].sort());
  assert.equal(row.result, 'accepted'); assert.equal(row.reason, 'user reports no VPN'); assert.equal(row.device, 'PC1'); assert.equal(row.user, 'a@x.com');
  assert.deepEqual(row.requester, who); assert.equal(row.scriptId, SCRIPT); assert.match(row.time, /^\d{4}-\d\d-\d\dT.*Z$/);
  assert.equal(lines.length, 1); assert.ok(lines[0].startsWith(AUDIT_PREFIX)); assert.ok(!lines[0].includes('\n'));
  const j = JSON.parse(lines[0].slice(AUDIT_PREFIX.length)); assert.equal(j.type, 'remediation-run'); assert.equal(j.id, row.id);
});

test('Graph 403 names the scope and Intune role; other errors are failed; newest first', async () => {
  const { audit } = mkAudit();
  const deny = mkApi(async () => { throw Object.assign(new Error('Access not granted.'), { status: 403, upstreamCode: 'Forbidden', upstreamMessage: 'no perms' }); });
  await assert.rejects(requestRun({ api: deny, scriptId: SCRIPT, managedDeviceId: DEV, reason: 'r1', requester: who, audit }), e => e.status === 403 && e.scope === RUN_SCOPE && e.message.includes(RUN_SCOPE) && /Intune Administrator/.test(e.message) && e.audit.result === 'denied');
  const boom = mkApi(async () => { throw Object.assign(new Error('x'), { status: 500, upstreamMessage: 'busy' }); });
  await assert.rejects(requestRun({ api: boom, scriptId: SCRIPT, managedDeviceId: DEV, reason: 'r2', requester: who, audit }), e => e.status === 502 && e.audit.result === 'failed' && /busy/.test(e.audit.error));
  assert.deepEqual(audit.list().map(r => r.reason), ['r2', 'r1']);
  const small = new RunAudit({ limit: 2, write: () => {} }); for (const n of [1, 2, 3]) small.add({ reason: String(n), result: 'accepted' });
  assert.deepEqual(small.list().map(r => r.reason), ['3', '2']);
});

test('run requests CSV escapes formulas and quotes; table and form are escaped and use btn', () => {
  const rows = [{ time: '2026-10-30T20:00:00.000Z', requester: { upn: '=admin@x.com' }, device: '+PC1', user: '@u', reason: 'say "hi"', result: 'denied', error: '-bad' }];
  const csv = runsCsv(rows);
  assert.ok(csv.startsWith('\ufeff"Time (UTC)","Requester","Device","User","Reason","Result"'));
  assert.match(csv, /"'=admin@x\.com"/); assert.match(csv, /"'\+PC1"/); assert.match(csv, /"'@u"/); assert.match(csv, /"say ""hi"""/); assert.match(csv, /"Denied: -bad"/);
  const esc = s => String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]);
  assert.match(runsTableHtml([{ ...rows[0], device: '<i>' }], esc), /&lt;i&gt;/);
  const dev = { device: '<b>', deviceId: DEV, status: 'ok' };
  assert.match(tableHtml([dev], { key: 'status', dir: 'asc' }, esc, { canRun: true }), /class="btn" data-rem-run="/);
  assert.doesNotMatch(tableHtml([dev], { key: 'status', dir: 'asc' }, esc), /Run now/);
  const form = runFormHtml(dev, esc); assert.match(form, /&lt;b&gt;/); assert.match(form, /required/); assert.doesNotMatch(form, /\u2014/);
});
