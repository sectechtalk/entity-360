// Live on-premises Active Directory group membership, read straight from a domain controller by a read-only
// PowerShell script on the Entity 360 host (server/ad/Get-E360AdGroups.ps1). Graph only sees groups that sync to
// Entra; this adds the rest: Domain Users, Domain Admins, BUILTIN groups, groups outside the sync scope and domain
// local groups in other domains of the forest. Windows hosts only.
//   E360_AD_SERVER      domain controller or domain DNS name (optional on a domain-joined host)
//   E360_AD_CREDENTIAL  path to a PSCredential saved with Export-Clixml by Set-E360AdReader.ps1 (optional on a domain-joined host)
//   E360_AD_ENABLED     'false' turns the live AD read off
//   E360_HOSTING        'cloud' marks a cloud-hosted copy; Azure Container Apps (CONTAINER_APP_NAME) and App Service
//                       (WEBSITE_SITE_NAME) are detected without it, 'local' overrides the detection
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const AD_SCRIPT = path.join(root, 'server', 'ad', 'Get-E360AdGroups.ps1');
export const AD_TIMEOUT_MS = 45000;
const SID = /^S-1-5-21-\d+-\d+-\d+-\d+$/;
const STATUSES = new Set(['live', 'notConfigured', 'unreachable', 'denied', 'notFound', 'error']);
export const CLOUD_AD_MESSAGE = 'Entity 360 is hosted in the cloud, and a cloud-hosted copy cannot reach on-premises Active Directory by design: domain controllers sit on your private network and are not exposed to the internet. Only groups that sync to Entra are shown. Groups that never sync, such as Domain Users, Domain Admins, built-in groups and groups outside the sync scope, are missing from this list. Run Entity 360 on a Windows computer on the same network as a domain controller to see them.';
export function cloudHosted(env = process.env) {
  const h = String(env.E360_HOSTING || '').toLowerCase();
  if (h === 'local') return false;
  return h === 'cloud' || !!env.CONTAINER_APP_NAME || !!env.WEBSITE_SITE_NAME;
}

export function adConfig(env = process.env, platform = process.platform) {
  const cloud = cloudHosted(env);
  return { enabled: env.E360_AD_ENABLED !== 'false' && platform === 'win32' && !cloud, cloud, server: env.E360_AD_SERVER || '', credential: env.E360_AD_CREDENTIAL || '', platform };
}

// Default runner: Windows PowerShell 5.1, no profile, JSON on stdout. Args are passed as an array, never through a shell.
export function runPowerShell(args, { timeout = AD_TIMEOUT_MS, script = AD_SCRIPT } = {}) {
  const exe = path.join(process.env.WINDIR || 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
  return new Promise((resolve, reject) => execFile(exe, ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', script, ...args], { timeout, maxBuffer: 16 * 1024 * 1024, windowsHide: true },
    (err, stdout, stderr) => (err && !String(stdout).trim() ? reject(Object.assign(err, { stderr: String(stderr || '') })) : resolve(String(stdout)))));
}

const text = (v, max = 400) => (typeof v === 'string' ? v.slice(0, max) : '');
function normalizeGroup(g) {
  if (!g || !SID.test(g.sid) && !/^S-1-5-32-\d+$/.test(g.sid)) return null;
  return { sid: g.sid, dn: text(g.dn, 1000), name: text(g.name, 256) || g.sid, sam: text(g.sam, 256), domain: text(g.domain, 256), netbios: text(g.netbios, 64),
    scope: ['Global', 'Domain local', 'Universal', 'Builtin'].includes(g.scope) ? g.scope : 'Unknown', description: text(g.description),
    membership: ['Direct', 'Nested', 'Primary'].includes(g.membership) ? g.membership : 'Nested', via: Array.isArray(g.via) ? g.via.map(v => text(v, 256)).filter(Boolean) : [], pathKnown: g.pathKnown !== false };
}

// Parses and bounds the script output. Anything unexpected becomes an error result rather than a thrown exception.
export function parseAdResult(stdout) {
  let r;
  try { r = JSON.parse(String(stdout).replace(/^\uFEFF/, '').trim()); } catch { return { status: 'error', message: 'The AD query returned output Entity 360 could not read.', groups: [], notes: [] }; }
  const status = STATUSES.has(r?.status) ? r.status : 'error';
  return { status, server: text(r.server, 256), forest: text(r.forest, 256), message: text(r.message, 600),
    user: r.user ? { dn: text(r.user.dn, 1000), sam: text(r.user.sam, 256), domain: text(r.user.domain, 256) } : null,
    domains: Array.isArray(r.domains) ? r.domains.slice(0, 50).map(d => ({ name: text(d.name, 256), netbios: text(d.netbios, 64), reachable: d.reachable !== false })) : [],
    groups: Array.isArray(r.groups) ? r.groups.slice(0, 1000).map(normalizeGroup).filter(Boolean) : [], notes: Array.isArray(r.notes) ? r.notes.slice(0, 20).map(n => text(n)) : [] };
}

export async function forestGroups(sid, { config = adConfig(), run = runPowerShell } = {}) {
  if (config.cloud) return { status: 'cloud', message: CLOUD_AD_MESSAGE, groups: [], notes: [] };
  if (!config.enabled) return { status: 'off', message: config.platform !== 'win32' ? 'Live AD lookups need Entity 360 running on Windows. Only groups that sync to Entra are shown.' : 'Live AD lookups are turned off (E360_AD_ENABLED=false).', groups: [], notes: [] };
  if (!SID.test(String(sid))) return { status: 'error', message: 'The user has no on-premises security identifier in Entra.', groups: [], notes: [] };
  const args = ['-UserSid', sid];
  if (config.server) args.push('-Server', config.server);
  if (config.credential) args.push('-CredentialPath', config.credential);
  try { return parseAdResult(await run(args)); }
  catch (e) { return { status: 'error', message: e?.killed ? `The AD query timed out after ${AD_TIMEOUT_MS / 1000} seconds.` : 'The AD query did not complete on this host.', groups: [], notes: [] }; }
}

// Joins the live AD list with the Graph rows: one row per group, keyed by SID. Synced groups keep their Entra link.
export function mergeAdRows(graphRows, ad) {
  const bySid = new Map(graphRows.filter(r => r.sid).map(r => [r.sid.toUpperCase(), r]));
  const rows = ad.groups.map(g => {
    const synced = bySid.get(g.sid.toUpperCase());
    if (synced) bySid.delete(g.sid.toUpperCase());
    return { id: synced?.id || g.sid, name: g.name, sam: g.sam ? `${g.netbios ? `${g.netbios}\\` : ''}${g.sam}` : synced?.sam || '', sid: g.sid, type: g.scope === 'Builtin' ? 'Security, built-in' : `Security, ${g.scope.toLowerCase()}`,
      scope: g.scope, domain: g.domain, membership: g.membership, via: g.membership === 'Nested' ? (g.pathKnown ? g.via.join(' > ') : 'Path not returned') : g.membership === 'Primary' ? 'Primary group (primaryGroupID)' : '',
      inEntra: synced ? 'Synced' : 'AD only', link: synced?.link || '', description: g.description };
  });
  // Synced in Entra but not returned by AD (removed in AD and not synced yet, or a domain this host cannot reach).
  for (const r of bySid.values()) rows.push({ ...r, inEntra: 'Synced', scope: '', domain: '', note: 'In Entra, not returned by AD' });
  const order = { Direct: 0, Primary: 1, Nested: 2 };
  return rows.sort((a, b) => (order[a.membership] ?? 3) - (order[b.membership] ?? 3) || a.name.localeCompare(b.name));
}
