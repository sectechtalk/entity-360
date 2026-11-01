// Phase 4.8: admin-requested single-device Remediation runs ("Run now") and their audit trail.
// POST /beta/deviceManagement/managedDevices/{id}/initiateOnDemandProactiveRemediation with the signed-in admin's
// own delegated token. Delegated only: never app-only, never another identity. Only devices that already report a
// result for the Entity 360 Remediation (the pilot) can be targeted; the id is checked against those rows server-side.
import { randomUUID } from 'node:crypto';
import { remediationResults } from './remediation-results.mjs';

export const RUN_SCOPE = 'DeviceManagementManagedDevices.PrivilegedOperations.All';
export const RUN_SCOPE_NEEDED = `running a Remediation on demand needs the ${RUN_SCOPE} delegated scope (consented for Entity 360) and an Intune role that allows remote tasks, such as Intune Administrator or a custom Intune role with Remote tasks: Run Remediation`;
export const REASON_MAX = 500;
export const AUDIT_PREFIX = 'E360_AUDIT ';
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const bad = (message, status = 400) => Object.assign(new Error(message), { status });

export function checkReason(raw) {
  const reason = typeof raw === 'string' ? raw.trim() : '';
  if (!reason) throw bad('A reason is required.');
  if (reason.length > REASON_MAX) throw bad(`The reason must be ${REASON_MAX} characters or fewer.`);
  return reason;
}

// In memory with a bound, like the authorization decision log, and one JSON line per record on stdout so the
// Container Apps console log keeps it after a restart. No tokens.
export class RunAudit {
  constructor({ limit = 500, write = line => process.stdout.write(line + '\n') } = {}) { this.limit = limit; this.write = write; this.rows = []; }
  add(fields) {
    const row = {
      id: randomUUID(), time: new Date().toISOString(),
      requester: { upn: fields.requester?.upn || null, objectId: fields.requester?.objectId || null },
      reason: fields.reason ?? null, device: fields.device ?? null, managedDeviceId: fields.managedDeviceId ?? null,
      user: fields.user ?? null, scriptId: fields.scriptId ?? null, result: fields.result, error: fields.error ? String(fields.error).slice(0, 500) : null,
    };
    this.rows.push(row);
    if (this.rows.length > this.limit) this.rows.shift();
    try { this.write(AUDIT_PREFIX + JSON.stringify({ type: 'remediation-run', ...row })); } catch { /* logging must not fail the request */ }
    return row;
  }
  list(n = 200) { return this.rows.slice(-n).reverse(); }
}

// Validates, records exactly one audit row (accepted / denied / failed) and returns it. Throws only for input errors
// before any device is known (no reason, bad id), which are recorded as denied too.
export async function requestRun({ api, scriptId, managedDeviceId, reason: rawReason, requester, audit }) {
  const base = { requester, scriptId, managedDeviceId: typeof managedDeviceId === 'string' ? managedDeviceId.slice(0, 40) : null, reason: typeof rawReason === 'string' ? rawReason.trim().slice(0, REASON_MAX) : null };
  const deny = (message, status, extra = {}) => { const row = audit.add({ ...base, ...extra, result: 'denied', error: message }); throw Object.assign(bad(message, status), { audit: row }); };
  if (!scriptId) deny('The Remediation is not configured.', 409);
  let reason;
  try { reason = checkReason(rawReason); } catch (e) { deny(e.message, 400); }
  if (!GUID.test(base.managedDeviceId || '')) deny('Choose a device from the Remediation results.', 400);
  let rows;
  try { rows = (await remediationResults(api, scriptId)).rows; }
  catch (e) { const row = audit.add({ ...base, result: 'failed', error: e.reason || e.upstreamMessage || e.message }); throw Object.assign(e, { audit: row }); }
  const target = rows.find(r => r.deviceId && r.deviceId.toLowerCase() === base.managedDeviceId.toLowerCase());
  if (!target) deny('That device is not in the Remediation results, so it cannot be targeted.', 404);
  const known = { device: target.device, user: target.user || null, managedDeviceId: target.deviceId };
  try {
    await api.request(`/beta/deviceManagement/managedDevices/${target.deviceId}/initiateOnDemandProactiveRemediation`, { method: 'POST', body: { scriptPolicyId: scriptId } });
  } catch (e) {
    const detail = [e.upstreamCode, e.upstreamMessage].filter(Boolean).join(': ');
    const message = e?.status === 403 ? `Access denied: ${RUN_SCOPE_NEEDED}${detail ? ` (${detail})` : ''}` : `Intune did not accept the run request${detail ? `: ${detail}` : '.'}`;
    const row = audit.add({ ...base, ...known, reason, result: e?.status === 403 ? 'denied' : 'failed', error: message });
    throw Object.assign(bad(message, e?.status === 403 ? 403 : 502), { audit: row, scope: e?.status === 403 ? RUN_SCOPE : undefined });
  }
  return audit.add({ ...base, ...known, reason, result: 'accepted' });
}
