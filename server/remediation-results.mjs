// Phase 4.7: per-device results of the Entity 360 network connectivity Remediation
// (remediations/Detect-E360NetworkConnectivity.ps1). Read-only, delegated only, Graph beta:
// GET /beta/deviceManagement/deviceHealthScripts/{id}/deviceRunStates?$expand=managedDevice(...)
// Microsoft documents DeviceManagementScripts.Read.All (delegated) for this call; DeviceManagementConfiguration.Read.All
// does not cover it. A 403 is reported with that scope named; nothing falls back to another identity.
export const SCRIPT_ID_ENV = 'E360_REMEDIATION_SCRIPT_ID';
export const SCRIPTS_SCOPE = 'DeviceManagementScripts.Read.All';
export const SCOPE_NEEDED = `reading Remediation results needs the ${SCRIPTS_SCOPE} delegated scope (not requested by this app) and an Intune role that can read device scripts, such as Intune Administrator, Global Reader or a custom Intune role with Remediations read`;
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const BASE = '/beta/deviceManagement/deviceHealthScripts';
const EXPAND = 'managedDevice($select=deviceName,id,userPrincipalName)';

export function scriptIdFrom(env = process.env) {
  const id = String(env[SCRIPT_ID_ENV] || '').trim();
  return GUID.test(id) ? id : null;
}

const num = v => (typeof v === 'number' && Number.isFinite(v) ? v : null);
// Parse the one-line JSON the detection script writes. Never throws: malformed, missing or foreign output
// becomes { error } so the device row still renders.
export function parseOutput(raw) {
  const text = typeof raw === 'string' ? raw.trim() : '';
  if (!text) return { error: 'No output reported' };
  let j;
  try { j = JSON.parse(text.split(/\r?\n/).filter(Boolean).pop()); } catch { return { error: 'Output is not valid JSON' }; }
  if (!j || typeof j !== 'object' || Array.isArray(j)) return { error: 'Output is not a result object' };
  if (j.kind !== undefined && j.kind !== 'e360-net') return { error: `Unexpected output kind: ${String(j.kind).slice(0, 40)}` };
  const issues = Array.isArray(j.issues) ? j.issues.map(String).slice(0, 10) : [];
  const targets = Array.isArray(j.r) ? j.r.filter(x => x && typeof x === 'object').map(x => ({ target: String(x.t ?? ''), dns: x.dns ?? null, ip: x.ip ?? null, tcp: x.tcp ?? null, ms: num(x.ms), dnsMs: num(x.dnsMs) })) : [];
  return {
    ok: typeof j.ok === 'boolean' ? j.ok : null, host: j.host ? String(j.host) : null, at: j.at ? String(j.at) : null, dur: num(j.dur),
    pre: j.pre && typeof j.pre === 'object' ? { ok: j.pre.ok ?? null, ps: j.pre.ps ?? null, net: j.pre.net ?? null, nic: num(j.pre.nic) } : null,
    lat: j.lat && typeof j.lat === 'object' ? { min: num(j.lat.min), max: num(j.lat.max), avg: num(j.lat.avg) } : null,
    pass: num(j.pass), total: num(j.total), issues, targets, truncated: j.trunc ? String(j.trunc) : (j.truncated ? String(j.truncated) : null),
  };
}

export function deviceRow(s) {
  const p = parseOutput(s.preRemediationDetectionScriptOutput);
  const d = s.managedDevice || {};
  const status = p.error ? 'unknown' : p.ok === true ? 'ok' : p.ok === false ? 'problem' : 'unknown';
  return {
    id: s.id, deviceId: d.id || null, device: d.deviceName || p.host || 'Unknown device', user: d.userPrincipalName || '',
    status, pass: p.error ? null : p.pass, total: p.error ? null : p.total, avgMs: p.error ? null : p.lat?.avg ?? null,
    issues: p.error ? p.error : p.issues.join('; '), lastRun: s.lastStateUpdateDateTime || p.at || null, scriptAt: p.at || null,
    detectionState: s.detectionState || '', scriptError: s.preRemediationDetectionScriptError ? String(s.preRemediationDetectionScriptError).slice(0, 300) : '',
    truncated: p.truncated || null, outputError: p.error || null, targets: p.targets || [], prereqOk: p.pre?.ok ?? null,
  };
}

export async function remediationResults(api, scriptId) {
  if (!scriptId) return { configured: false, rows: [], note: `Set ${SCRIPT_ID_ENV} to the Remediation (device health script) id to show results.` };
  if (!GUID.test(scriptId)) throw Object.assign(new Error('Invalid script id.'), { status: 400 });
  const url = `${BASE}/${scriptId}/deviceRunStates`;
  let result, expanded = true;
  try {
    try { result = await api.pages(`${url}?$expand=${encodeURIComponent(EXPAND)}`); }
    catch (e) { if (e?.status !== 400) throw e; expanded = false; result = await api.pages(url); }
  } catch (e) {
    if (e?.status === 403) e.reason = `Access denied: ${SCOPE_NEEDED}${e.upstreamCode ? ` (${e.upstreamCode})` : ''}`;
    throw e;
  }
  const rows = result.rows.map(deviceRow);
  return { configured: true, scriptId, expanded, rows, truncated: Boolean(result.truncated), link: `https://intune.microsoft.com/#view/Microsoft_Intune_Enrollment/UXAnalyticsScriptMenu/~/overview/id/${scriptId}` };
}
