// AD posture (TENANT > Findings > AD posture): Active Directory and AD CS hardening findings for every domain in the
// on-premises forest, read live from a domain controller by server/ad/Get-E360AdPosture.ps1 over the same read-only
// connection as the AD groups tab (E360_AD_SERVER + the reader credential saved by Set-E360AdReader.ps1).
// The script returns raw directory facts; everything that decides "weak" lives here, so it is testable and explainable.
// Each domain gets findings with playbooks and a score (share of checked controls passing, weighted by severity).
// One score per domain per day is kept on the Entity 360 host so the trend can go into the posture PDF.
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { adConfig, runPowerShell, CLOUD_AD_MESSAGE } from './ad-forest.mjs';
import { SEVERITY, rank } from './findings.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const POSTURE_SCRIPT = path.join(root, 'server', 'ad', 'Get-E360AdPosture.ps1');
export const POSTURE_TIMEOUT_MS = 180000;
export const OLD_PASSWORD_DAYS = 365;
export const KRBTGT_DAYS = 180;
export const ITEM_LIMIT = 50;
export const WEIGHT = { critical: 10, high: 6, medium: 3, low: 1 };
const DAY = 864e5;
const LEARN = 'https://learn.microsoft.com/';

// --------------------------------------------------------------------------------------------- constants
export const EKU = { clientAuth: '1.3.6.1.5.5.7.3.2', pkinit: '1.3.6.1.5.2.3.4', smartCard: '1.3.6.1.4.1.311.20.2.2', any: '2.5.29.37.0', agent: '1.3.6.1.4.1.311.20.2.1' };
export const FLAG = { suppliesSubject: 0x1, suppliesSan: 0x10000, pendAll: 0x2, noSecurityExt: 0x80000 };
const RIGHT = { enroll: '0e10c968-78fb-11d2-90d4-00c04f79dc55', autoEnroll: 'a05b8cc2-17bc-4802-a710-e7c15ab866a2', all: '00000000-0000-0000-0000-000000000000' };
export const TRUST = { nonTransitive: 0x1, quarantined: 0x4, forest: 0x8, selectiveAuth: 0x10, withinForest: 0x20, treatAsExternal: 0x40, noTgtDelegation: 0x200, tgtDelegation: 0x800 };
// Principals that mean "almost everyone". Domain-relative ones end in a RID.
const WELL_KNOWN = { 'S-1-1-0': 'Everyone', 'S-1-5-11': 'Authenticated Users', 'S-1-5-7': 'Anonymous Logon', 'S-1-5-32-545': 'BUILTIN\\Users', 'S-1-5-32-544': 'BUILTIN\\Administrators', 'S-1-5-18': 'SYSTEM', 'S-1-3-0': 'Creator Owner', 'S-1-5-9': 'Enterprise Domain Controllers' };
const FOREST_WIDE = new Set(['S-1-1-0', 'S-1-5-11', 'S-1-5-7', 'S-1-5-32-545']);
const BROAD_RID = { 513: 'Domain Users', 514: 'Domain Guests', 515: 'Domain Computers' };
const PRIV_RID = { 512: 'Domain Admins', 519: 'Enterprise Admins', 516: 'Domain Controllers', 518: 'Schema Admins', 517: 'Cert Publishers', 498: 'Enterprise Read-only Domain Controllers', 521: 'Read-only Domain Controllers' };
const FUNCTIONAL = { 0: 'Windows 2000', 1: 'Windows Server 2003 interim', 2: 'Windows Server 2003', 3: 'Windows Server 2008', 4: 'Windows Server 2008 R2', 5: 'Windows Server 2012', 6: 'Windows Server 2012 R2', 7: 'Windows Server 2016', 10: 'Windows Server 2025' };

// What this connection cannot see, said once on the page and in the PDF rather than guessed.
export const GAPS = [
  { what: 'CA registry flags: ESC6 (EDITF_ATTRIBUTESUBJECTALTNAME2) and ESC11 (IF_ENFORCEENCRYPTICERTREQUEST off)', why: 'They live in the CA server\'s registry, which LDAP does not expose and the Domain Users reader cannot read remotely.', path: 'Run certutil -getreg policy\\EditFlags and certutil -getreg CA\\InterfaceFlags on the CA, or a collector that runs there as a CA admin.' },
  { what: 'CA officer and manager rights (ESC7)', why: 'The CA\'s own security descriptor is held by the CA service, not in the directory.', path: 'Run certutil -getreg CA\\Security on the CA, or review the Security tab of the CA in certsrv.msc.' },
  { what: 'Effective DC registry values', why: 'Entity 360 reads what Group Policy sets (SYSVOL) and tests LDAP signing live. A value set by hand in a DC\'s registry, or by a GPO linked to a site, is not visible.', path: 'Run Get-ItemProperty on each DC through WinRM as an admin, or check gpresult /h on a DC.' },
  { what: 'Windows LAPS passwords stored in Entra ID', why: 'Devices that back up their LAPS password to Entra ID (not AD) carry no expiry time in AD, so they count as missing here.', path: 'Check Intune > Devices > Local admin password, or the deviceLocalCredentials Graph API.' },
];

// --------------------------------------------------------------------------------------------- parsing
const text = (v, max = 400) => (typeof v === 'string' ? v.slice(0, max) : '');
const int = v => (Number.isFinite(Number(v)) ? Number(v) : 0);
const iso = v => (typeof v === 'string' && Number.isFinite(Date.parse(v)) ? v : null);
const arr = (v, n = 2000) => (Array.isArray(v) ? v.slice(0, n) : v == null ? [] : [v]);
const STATUSES = new Set(['live', 'notConfigured', 'unreachable', 'denied', 'error']);

export function parsePosture(stdout) {
  let r;
  try { r = JSON.parse(String(stdout).replace(/^﻿/, '').trim()); } catch { return { status: 'error', message: 'The AD posture query returned output Entity 360 could not read.', domains: [] }; }
  const status = STATUSES.has(r?.status) ? r.status : 'error';
  if (status !== 'live') return { status, message: text(r?.message, 600), server: text(r?.server, 256), domains: [] };
  const gpo = g => g ? { status: ['read', 'partial', 'unavailable'].includes(g.status) ? g.status : 'unavailable', message: text(g.message, 400),
    values: Object.fromEntries(Object.entries(g.values || {}).filter(([k]) => ['ldapServerIntegrity', 'ldapChannelBinding', 'smbServerSigning', 'lmCompatibilityLevel'].includes(k)).map(([k, v]) => [k, { value: text(String(v?.value ?? ''), 20), gpo: text(v?.gpo, 256), level: text(v?.level, 64) }])),
    gpos: arr(g.gpos, 50).map(x => ({ name: text(x?.name, 256), linkedTo: text(x?.linkedTo, 64), enforced: !!x?.enforced, sets: arr(x?.sets, 10).map(s => text(s, 64)) })) } : { status: 'unavailable', message: 'Group Policy was not read.', values: {}, gpos: [] };
  const domains = arr(r.domains, 50).map(d => ({
    name: text(d.name, 256), netbios: text(d.netbios, 64), sid: /^S-1-5-21-\d+-\d+-\d+$/.test(d.sid) ? d.sid : '', root: !!d.root, reachable: d.reachable !== false, message: text(d.message, 400), functionalLevel: text(String(d.functionalLevel ?? ''), 4),
    dcs: arr(d.dcs, 200).map(x => ({ name: text(x.name, 64), host: text(x.host, 256), os: text(x.os, 128), osVersion: text(x.osVersion, 64), ldapSigning: ['required', 'notRequired'].includes(x.ldapSigning) ? x.ldapSigning : 'unknown', ldapSigningDetail: text(x.ldapSigningDetail, 300) })),
    trusts: arr(d.trusts, 200).map(t => ({ partner: text(t.partner, 256), flatName: text(t.flatName, 64), direction: int(t.direction), type: int(t.type), attributes: int(t.attributes), created: iso(t.created), changed: iso(t.changed) })),
    spnAccounts: arr(d.spnAccounts).map(a => ({ sam: text(a.sam, 256), dn: text(a.dn, 1000), spns: arr(a.spns, 5).map(s => text(s, 256)), spnCount: int(a.spnCount), pwdLastSet: iso(a.pwdLastSet), lastLogon: iso(a.lastLogon), adminCount: int(a.adminCount), encTypes: a.encTypes == null ? null : int(a.encTypes), description: text(a.description, 200) })),
    asrepAccounts: arr(d.asrepAccounts).map(a => ({ sam: text(a.sam, 256), dn: text(a.dn, 1000), pwdLastSet: iso(a.pwdLastSet), adminCount: int(a.adminCount) })),
    delegation: arr(d.delegation).map(a => ({ sam: text(a.sam, 256), dn: text(a.dn, 1000), kind: a.kind === 'User' ? 'User' : 'Computer', os: text(a.os, 128) })),
    krbtgt: d.krbtgt ? { pwdLastSet: iso(d.krbtgt.pwdLastSet) } : null, gmsaCount: d.gmsaCount == null ? null : int(d.gmsaCount),
    laps: { legacySchema: !!d.laps?.legacySchema, windowsSchema: !!d.laps?.windowsSchema, total: int(d.laps?.total), computers: arr(d.laps?.computers).map(c => ({ name: text(c.name, 64), os: text(c.os, 128), lastLogon: iso(c.lastLogon), legacyExpiry: iso(c.legacyExpiry), windowsExpiry: iso(c.windowsExpiry) })) },
    gpo: gpo(d.gpo), errors: arr(d.errors, 20).map(e => ({ check: text(e.check, 32), message: text(e.message, 300) })),
  }));
  const p = r.pki || {};
  const pki = { status: p.status === 'read' ? 'read' : 'unavailable', message: text(p.message, 400),
    cas: arr(p.cas, 20).map(c => ({ name: text(c.name, 128), host: text(c.host, 256), templates: arr(c.templates, 500).map(t => text(t, 128)), webEnrollment: ['http', 'none'].includes(c.webEnrollment) ? c.webEnrollment : 'unknown', webDetail: text(c.webDetail, 200) })),
    templates: arr(p.templates, 500).map(t => ({ name: text(t.name, 128), displayName: text(t.displayName, 256), nameFlag: int(t.nameFlag), enrollFlag: int(t.enrollFlag), raSignatures: int(t.raSignatures), ekus: arr(t.ekus, 30).map(e => text(e, 64)), appPolicies: arr(t.appPolicies, 30).map(e => text(e, 64)),
      schemaVersion: int(t.schemaVersion), owner: text(t.owner, 100), daclRead: t.daclRead !== false, changed: iso(t.changed), aces: arr(t.aces, 200).map(a => ({ sid: text(a.sid, 100), type: a.type === 'Deny' ? 'Deny' : 'Allow', rights: text(a.rights, 300), objectType: text(a.objectType, 40).toLowerCase() })) })),
    names: Object.fromEntries(Object.entries(p.names || {}).slice(0, 2000).map(([k, v]) => [text(k, 100), text(v, 256)])) };
  return { status, server: text(r.server, 256), forest: text(r.forest, 256), forestLevel: text(String(r.forestLevel ?? ''), 4), domains, pki, notes: arr(r.notes, 20).map(n => text(n)) };
}

// --------------------------------------------------------------------------------------------- helpers
const day = t => (t ? String(t).slice(0, 10) : '');
const ageDays = (t, now) => (t ? Math.floor((now - Date.parse(t)) / DAY) : null);
const domainSidOf = sid => (/^S-1-5-21-\d+-\d+-\d+-\d+$/.test(sid) ? sid.replace(/-\d+$/, '') : null);
const ridOf = sid => Number(String(sid).split('-').pop());

export function principalName(sid, forest) {
  if (WELL_KNOWN[sid]) return WELL_KNOWN[sid];
  if (forest.pki?.names?.[sid]) return forest.pki.names[sid];
  const dom = forest.domains.find(d => d.sid && d.sid === domainSidOf(sid));
  const rid = ridOf(sid), label = BROAD_RID[rid] || PRIV_RID[rid];
  return dom && label ? `${dom.netbios}\\${label}` : sid;
}
// Broad principal → which domains it covers ('*' = every domain in the forest), or null when not broad.
export function broadScope(sid, forest) {
  if (FOREST_WIDE.has(sid)) return '*';
  const ds = domainSidOf(sid);
  if (ds && BROAD_RID[ridOf(sid)]) return forest.domains.find(d => d.sid === ds)?.name || null;
  return null;
}
const hasRight = (rights, name) => String(rights).split(/,\s*/).includes(name);
export function aceGrants(a) {
  const all = !a.objectType || a.objectType === RIGHT.all;
  const full = hasRight(a.rights, 'GenericAll');
  return {
    enroll: full || (hasRight(a.rights, 'ExtendedRight') && (all || a.objectType === RIGHT.enroll || a.objectType === RIGHT.autoEnroll)),
    write: full || hasRight(a.rights, 'GenericWrite') || hasRight(a.rights, 'WriteDacl') || hasRight(a.rights, 'WriteOwner') || hasRight(a.rights, 'WriteProperty'),
  };
}

// One template → its facts and every broad principal that can enroll in or change it (deny ACEs cancel allows).
export function templateFacts(t, forest) {
  const ekus = [...new Set([...t.ekus, ...t.appPolicies])];
  const noEku = ekus.length === 0;
  const auth = noEku || [EKU.clientAuth, EKU.pkinit, EKU.smartCard, EKU.any].some(e => ekus.includes(e));
  const enroll = new Map(), write = new Map(), denyEnroll = new Set(), denyWrite = new Set();
  for (const a of t.aces) {
    const g = aceGrants(a);
    if (a.type === 'Deny') { if (g.enroll) denyEnroll.add(a.sid); if (g.write) denyWrite.add(a.sid); continue; }
    const scope = broadScope(a.sid, forest);
    if (!scope) continue;
    if (g.enroll) enroll.set(a.sid, scope);
    if (g.write) write.set(a.sid, scope);
  }
  if (t.owner && broadScope(t.owner, forest)) write.set(t.owner, broadScope(t.owner, forest));
  for (const s of denyEnroll) enroll.delete(s);
  for (const s of denyWrite) write.delete(s);
  const cas = forest.pki.cas.filter(c => c.templates.includes(t.name)).map(c => c.name);
  return { name: t.name, displayName: t.displayName || t.name, ekus, noEku, auth, anyPurpose: ekus.includes(EKU.any), agent: ekus.includes(EKU.agent),
    suppliesSubject: !!(t.nameFlag & FLAG.suppliesSubject) || !!(t.nameFlag & FLAG.suppliesSan), approval: !!(t.enrollFlag & FLAG.pendAll), raSignatures: t.raSignatures,
    noSecurityExt: !!(t.enrollFlag & FLAG.noSecurityExt), schemaVersion: t.schemaVersion, published: cas.length > 0, cas, daclRead: t.daclRead,
    enroll: [...enroll].map(([sid, scope]) => ({ sid, scope, name: principalName(sid, forest) })), write: [...write].map(([sid, scope]) => ({ sid, scope, name: principalName(sid, forest) })) };
}
const inDomain = (list, domain) => list.filter(p => p.scope === '*' || p.scope === domain);
const names = list => [...new Set(list.map(p => p.name))].join(', ');

// ESC patterns per domain. Each returns the templates that match, with why.
export function escMatches(facts, domain) {
  const unguarded = f => !f.approval && f.raSignatures === 0;
  const out = { esc1: [], esc2: [], esc3: [], esc4: [], esc9: [], esc15: [] };
  for (const f of facts) {
    const who = inDomain(f.enroll, domain), writers = inDomain(f.write, domain);
    const caText = f.cas.length ? `published on ${f.cas.join(', ')}` : 'not published on any CA';
    if (writers.length) out.esc4.push({ text: f.displayName, detail: `${names(writers)} can change the template (${caText}). Anyone in that group can turn it into an ESC1 template.` });
    if (!f.published || !who.length || !unguarded(f)) continue;
    const base = `${names(who)} can enroll · ${caText} · no manager approval`;
    if (f.auth && f.suppliesSubject) out.esc1.push({ text: f.displayName, detail: `${base} · requester supplies the subject · ${f.noEku ? 'no EKU (any purpose)' : 'client authentication EKU'}` });
    if (f.anyPurpose || f.noEku) out.esc2.push({ text: f.displayName, detail: `${base} · ${f.noEku ? 'no EKU' : 'Any Purpose EKU'}: the certificate works for client authentication and as an enrollment agent` });
    if (f.agent) out.esc3.push({ text: f.displayName, detail: `${base} · Certificate Request Agent EKU: the holder can request certificates on behalf of other users` });
    if (f.noSecurityExt && f.auth) out.esc9.push({ text: f.displayName, detail: `${base} · CT_FLAG_NO_SECURITY_EXTENSION set: the certificate carries no SID, so strong certificate mapping cannot bind it to the account` });
    if (f.schemaVersion === 1 && f.suppliesSubject) out.esc15.push({ text: f.displayName, detail: `${base} · schema version 1 with requester-supplied subject: unpatched CAs accept any application policy in the request (CVE-2024-49019)` });
  }
  return out;
}

const DIRECTION = { 0: 'Disabled', 1: 'Inbound (the partner trusts this domain)', 2: 'Outbound (this domain trusts the partner)', 3: 'Two-way' };
export function trustInfo(t) {
  const a = t.attributes, within = !!(a & TRUST.withinForest), forest = !!(a & TRUST.forest), mit = t.type === 3;
  const kind = within ? 'Same forest (parent-child or tree root)' : mit ? 'MIT Kerberos realm' : forest ? 'Forest trust' : t.type === 1 ? 'External (Windows NT 4 style)' : 'External';
  const trustsPartner = t.direction === 2 || t.direction === 3;   // partner accounts can reach resources here
  const sidFiltering = within ? 'Not applied (same forest, by design)' : mit ? 'Not applicable' : forest ? (a & TRUST.treatAsExternal ? 'Relaxed: SID history accepted (TREAT_AS_EXTERNAL)' : 'On (forest SID filtering)') : (a & TRUST.quarantined ? 'On (quarantined)' : 'Off');
  const auth = within || mit ? 'Not applicable' : a & TRUST.selectiveAuth ? 'Selective authentication' : forest ? 'Forest-wide authentication' : 'Domain-wide authentication';
  const risks = [];
  if (!within && !mit && trustsPartner) {
    if (!forest && !(a & TRUST.quarantined)) risks.push('SID filtering is off: an admin in the partner domain can forge SID history and become an admin here');
    if (forest && a & TRUST.treatAsExternal) risks.push('SID history from the partner forest is accepted');
    if (!(a & TRUST.selectiveAuth)) risks.push('every partner account can authenticate to every computer here (no selective authentication)');
  }
  if (!within && a & TRUST.tgtDelegation) risks.push('TGT delegation across the trust is enabled: unconstrained delegation hosts here can capture partner TGTs');
  return { partner: t.partner, kind, direction: DIRECTION[t.direction] || String(t.direction), transitive: within || forest ? 'Yes' : a & TRUST.nonTransitive ? 'No' : 'Yes', sidFiltering, authentication: auth, created: day(t.created), risks };
}

const encText = e => (e == null || e === 0 ? 'RC4 allowed (no encryption types set)' : e & 0x4 ? 'RC4 allowed' : e & 0x18 ? 'AES only' : 'DES only');
const lmText = v => ({ 0: 'level 0: sends LM and NTLM', 1: 'level 1: LM and NTLM, NTLMv2 session security if negotiated', 2: 'level 2: sends NTLM only', 3: 'level 3: sends NTLMv2 only, still accepts LM and NTLM', 4: 'level 4: refuses LM, still accepts NTLM' }[v] || `level ${v}`);
const is2025 = os => /2025/.test(os || '');

// --------------------------------------------------------------------------------------------- catalogue
// Each check: id, title, severity, why, steps, guidance, and evaluate(ctx) -> { count, items, note } | { unavailable: reason }.
const unavailable = reason => ({ unavailable: reason });
const pkiCheck = (fn) => ctx => (ctx.forest.pki.status !== 'read' ? unavailable(ctx.forest.pki.message || 'AD CS objects could not be read.') : !ctx.forest.pki.cas.length ? { count: 0, items: [], note: 'No enterprise CA is registered in this forest, so no template can be requested.' } : fn(ctx));
const escCheck = key => pkiCheck(ctx => { const items = ctx.esc[key]; const unread = ctx.facts.filter(f => !f.daclRead).length; return { count: items.length, items, note: unread ? `${unread} template ACL(s) could not be read and were skipped.` : `${ctx.facts.length} templates checked, ${ctx.facts.filter(f => f.published).length} published.` }; });
const gpoValue = (ctx, key) => ctx.domain.gpo.values[key];
const gpoSource = v => (v ? `set to ${v.value} by GPO "${v.gpo}" (${v.level})` : 'not set by any GPO linked to the domain or the Domain Controllers OU');
const gpoCheck = (key, pass, describe) => ctx => {
  const g = ctx.domain.gpo;
  if (g.status === 'unavailable') return unavailable(g.message || 'Group Policy (SYSVOL) could not be read.');
  if (!ctx.domain.dcs.length) return unavailable('No domain controllers were returned for this domain.');
  const v = gpoValue(ctx, key);
  const items = ctx.domain.dcs.filter(dc => !pass(v, dc)).map(dc => ({ text: dc.name, detail: `${dc.os || 'Unknown OS'} · ${describe(v, dc)}` }));
  return { count: items.length, items, note: `Group Policy: ${gpoSource(v)}.${g.status === 'partial' ? ` ${g.message}` : ''}` };
};

export const CHECKS = [
  { id: 'adcs-esc1', title: 'Certificate templates anyone can use to become anyone (ESC1)', severity: 'critical', area: 'AD CS',
    why: 'A template that lets a broad group enroll, supply its own subject and use the certificate for logon lets any member request a certificate as a Domain Admin and sign in as them.',
    guidance: `${LEARN}defender-for-identity/security-assessment-prevent-users-request-certificate`,
    steps: ['Open certtmpl.msc on a CA or admin workstation and open each template listed.', 'Subject Name tab: choose Build from this Active Directory information (turns off Supply in the request).', 'If the requester really must supply the name, Issuance Requirements tab: tick CA certificate manager approval.', 'Security tab: remove Enroll from Domain Users, Domain Computers and Authenticated Users; grant it to a specific group.', 'If nobody uses the template, remove it from every CA (certsrv.msc > Certificate Templates > Delete).', 'Refresh this page: the template drops off once the change replicates.'],
    evaluate: escCheck('esc1') },
  { id: 'adcs-esc4', title: 'Certificate templates broad groups can modify (ESC4)', severity: 'critical', area: 'AD CS',
    why: 'Write access to a template is as good as ESC1: the attacker edits the template to allow a supplied subject, requests a certificate as an admin, then puts it back.',
    guidance: `${LEARN}defender-for-identity/security-assessment-edit-misconfigured-acl`,
    steps: ['Open certtmpl.msc, open the template, Security tab.', 'Remove Full Control, Write and Modify owner from Domain Users, Domain Computers, Authenticated Users and Everyone.', 'Keep write access for Enterprise Admins and a dedicated PKI admin group only.', 'Check the template owner (Advanced > Owner) is a PKI admin group, not a user or broad group.'],
    evaluate: escCheck('esc4') },
  { id: 'adcs-esc2', title: 'Any-purpose certificate templates (ESC2)', severity: 'high', area: 'AD CS',
    why: 'A certificate with the Any Purpose EKU, or no EKU at all, can be used for client authentication and as an enrollment agent, whatever the template was meant for.',
    guidance: `${LEARN}defender-for-identity/security-assessment-edit-overly-permissive-template`,
    steps: ['Open each listed template in certtmpl.msc, Extensions tab > Application Policies.', 'Replace Any Purpose (or the empty list) with only the EKUs the template needs.', 'If broad enrollment is not needed, remove Enroll from the broad groups on the Security tab.'],
    evaluate: escCheck('esc2') },
  { id: 'adcs-esc3', title: 'Enrollment agent templates open to broad groups (ESC3)', severity: 'high', area: 'AD CS',
    why: 'An enrollment agent certificate lets its holder request certificates on behalf of other users, including admins.',
    guidance: `${LEARN}defender-for-identity/security-assessment-edit-misconfigured-enrollment-agent`,
    steps: ['Limit Enroll on the Enrollment Agent template to the smart card or badge team.', 'On the CA (certsrv.msc > CA properties > Enrollment Agents), restrict which agents may enroll for which users and templates.', 'Turn on CA certificate manager approval for the agent template.'],
    evaluate: escCheck('esc3') },
  { id: 'adcs-esc15', title: 'Version 1 templates with a supplied subject (ESC15)', severity: 'high', area: 'AD CS',
    why: 'On a CA without the November 2024 update, a version 1 template that takes a supplied subject accepts any application policy in the request, so it can mint a logon certificate for anyone.',
    guidance: 'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49019',
    steps: ['Install the November 2024 (or later) cumulative update on every CA.', 'Duplicate the template (the copy is version 2 or later), set Build from this Active Directory information, and publish the copy instead.', 'Remove the version 1 template from the CA.'],
    evaluate: escCheck('esc15') },
  { id: 'adcs-esc9', title: 'Templates without the security extension (ESC9)', severity: 'medium', area: 'AD CS',
    why: 'Without the SID security extension, certificate mapping falls back to the UPN, which a user with write access to another account can change to impersonate an admin.',
    guidance: `${LEARN}troubleshoot/windows-server/windows-security/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers`,
    steps: ['Clear CT_FLAG_NO_SECURITY_EXTENSION: certutil -dstemplate <template name> msPKI-Enrollment-Flag -0x80000 (run as an Enterprise Admin).', 'Make sure DCs run in Full Enforcement mode for strong certificate mapping (StrongCertificateBindingEnforcement = 2, the default since September 2025).'],
    evaluate: escCheck('esc9') },
  { id: 'adcs-esc8', title: 'Web enrollment over plain HTTP (ESC8)', severity: 'high', area: 'AD CS',
    why: 'Certificate web enrollment over HTTP accepts relayed NTLM: an attacker who coerces a DC to authenticate can relay it here and get a certificate for the DC.',
    guidance: `${LEARN}defender-for-identity/security-assessment-enforce-https-on-adcs`,
    steps: ['If nobody uses web enrollment, remove the role service: Uninstall-AdcsWebEnrollment on the CA.', 'Otherwise, in IIS Manager on the CA: require SSL on CertSrv and turn on Extended Protection for Authentication (Required).', 'Remove the HTTP binding so only HTTPS answers.', 'Turn off NTLM for the site where possible (Negotiate:Kerberos only).'],
    evaluate: pkiCheck(ctx => { const cas = ctx.forest.pki.cas; const items = cas.filter(c => c.webEnrollment === 'http').map(c => ({ text: c.name, detail: `http://${c.host}/certsrv/ answered (${c.webDetail}). Extended Protection cannot be seen from outside.` })); const unknown = cas.filter(c => c.webEnrollment === 'unknown'); return { count: items.length, items, note: unknown.length ? `${unknown.map(c => `${c.name}: ${c.webDetail || 'no answer'}`).join('; ')}.` : `${cas.length} CA(s) probed on port 80.` }; }) },
  { id: 'adcs-ca-side', title: 'CA server settings (ESC6, ESC7, ESC11)', severity: 'high', area: 'AD CS',
    why: 'These sit on the CA server itself, not in the directory.',
    guidance: `${LEARN}windows-server/identity/ad-cs/`,
    steps: ['On each CA, as a CA admin: certutil -getreg policy\\EditFlags. If EDITF_ATTRIBUTESUBJECTALTNAME2 is listed, run certutil -setreg policy\\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2 and restart certsvc (ESC6).', 'certutil -getreg CA\\InterfaceFlags: IF_ENFORCEENCRYPTICERTREQUEST must be set (ESC11).', 'certsrv.msc > CA properties > Security: only PKI admins hold Manage CA and Issue and Manage Certificates (ESC7).'],
    evaluate: pkiCheck(() => unavailable('Not readable over the read-only LDAP connection: these settings are in the CA server\'s registry and security descriptor. Run the playbook commands on the CA.')) },
  { id: 'dc-ldap-signing', title: 'Domain controllers that do not require LDAP signing', severity: 'high', area: 'Domain controllers',
    why: 'Without required signing, an attacker can relay NTLM to LDAP on the DC and change the directory as the victim, for example to add themselves to Domain Admins.',
    guidance: `${LEARN}troubleshoot/windows-server/active-directory/enable-ldap-signing-in-windows-server`,
    steps: ['First find clients that bind unsigned: on each DC set HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Diagnostics "16 LDAP Interface Events" = 2 and watch Directory Service event 2889 for a week.', 'Fix or replace those clients.', 'In the Default Domain Controllers Policy: Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options > Domain controller: LDAP server signing requirements = Require signing.', 'Run gpupdate /force on the DCs and refresh this page: the live bind test should now be refused.'],
    evaluate: ctx => {
      const dcs = ctx.domain.dcs;
      if (!dcs.length) return unavailable('No domain controllers were returned for this domain.');
      const known = dcs.filter(d => d.ldapSigning !== 'unknown');
      if (!known.length) return unavailable(`The live bind test did not complete on any DC: ${dcs[0].ldapSigningDetail}`);
      const items = known.filter(d => d.ldapSigning === 'notRequired').map(d => ({ text: d.name, detail: `${d.os || 'Unknown OS'} · ${d.ldapSigningDetail}` }));
      const v = gpoValue(ctx, 'ldapServerIntegrity');
      return { count: items.length, items, note: `Live test: an unsigned SASL bind was tried on each DC. Group Policy: ${gpoSource(v)}.${known.length < dcs.length ? ` ${dcs.length - known.length} DC(s) could not be tested.` : ''}` };
    } },
  { id: 'dc-channel-binding', title: 'LDAP channel binding not enforced', severity: 'high', area: 'Domain controllers',
    why: 'Channel binding ties an LDAPS session to its TLS channel, so a relayed authentication cannot be replayed over LDAPS. Signing alone does not cover LDAPS.',
    guidance: `${LEARN}troubleshoot/windows-server/active-directory/ldap-channel-binding-and-ldap-signing-requirements-update`,
    steps: ['Find clients that would break: watch Directory Service event 3039 on each DC (enable "16 LDAP Interface Events" = 2).', 'Set Domain controller: LDAP server channel binding token requirements = When supported in the Default Domain Controllers Policy, then Always once event 3039 stays quiet.', 'Run gpupdate /force on the DCs and refresh this page.'],
    evaluate: gpoCheck('ldapChannelBinding', v => v?.value === '2', v => v?.value === '1' ? 'When supported only (clients that do not send a token are still accepted)' : v?.value === '0' ? 'Never' : 'not set by Group Policy, so the DC uses its built-in default, which is not Always') },
  { id: 'dc-smb-signing', title: 'Domain controllers that do not require SMB signing', severity: 'high', area: 'Domain controllers',
    why: 'Unsigned SMB to a DC can be relayed or tampered with, including SYSVOL and NETLOGON traffic that every computer trusts.',
    guidance: `${LEARN}windows-server/storage/file-server/smb-signing`,
    steps: ['In the Default Domain Controllers Policy: Security Options > Microsoft network server: Digitally sign communications (always) = Enabled.', 'Run gpupdate /force on the DCs and refresh this page.'],
    evaluate: gpoCheck('smbServerSigning', (v, dc) => v?.value === '1' || (!v && is2025(dc.os)), v => v?.value === '0' ? 'Disabled by Group Policy' : 'not set by Group Policy, and only Windows Server 2025 requires it by default') },
  { id: 'dc-ntlm', title: 'Domain controllers that still accept LM and NTLMv1', severity: 'high', area: 'Domain controllers',
    why: 'NTLMv1 and LM responses can be cracked or downgraded quickly; a DC below level 5 still accepts them from any client.',
    guidance: `${LEARN}windows/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level`,
    steps: ['Audit first: in the Default Domain Policy set Network security: Restrict NTLM: Audit NTLM authentication in this domain = Enable all, and check event 4624 for "Package Name (NTLM only): NTLM V1".', 'Fix or retire the systems that use NTLMv1.', 'Default Domain Controllers Policy: Network security: LAN Manager authentication level = Send NTLMv2 response only. Refuse LM & NTLM (level 5).', 'Run gpupdate /force on the DCs and refresh this page.'],
    evaluate: gpoCheck('lmCompatibilityLevel', v => v?.value === '5', v => v ? lmText(Number(v.value)) : 'not set by Group Policy (Windows default is level 3, which still accepts LM and NTLM)') },
  { id: 'kerberoastable', title: 'Kerberoastable service accounts (gMSA candidates)', severity: 'high', area: 'Accounts',
    why: 'Any domain user can request a Kerberos ticket for an account with an SPN and crack its password offline. Old human-set passwords crack fastest. A gMSA has a 120-character password that rotates every 30 days.',
    guidance: `${LEARN}windows-server/identity/ad-ds/manage/group-managed-service-accounts/group-managed-service-accounts/group-managed-service-accounts-overview`,
    steps: ['For each account, find the service that uses it (the SPN names the host and service).', 'Create a gMSA: New-ADServiceAccount -Name gmsa-<service> -DNSHostName <host FQDN> -PrincipalsAllowedToRetrieveManagedPassword <host or group>, and run Install-ADServiceAccount on the host.', 'Move the service to the gMSA, move the SPN (setspn -D on the old account, setspn -S on the gMSA), and disable the old account.', 'Where a gMSA is not possible: set a random password of 25+ characters and set msDS-SupportedEncryptionTypes to AES only (24).', 'Remove privileged accounts (adminCount 1) from the list first.'],
    evaluate: ctx => {
      const now = ctx.now, list = [...ctx.domain.spnAccounts].sort((a, b) => b.adminCount - a.adminCount || String(a.pwdLastSet).localeCompare(String(b.pwdLastSet)));
      const items = list.map(a => { const age = ageDays(a.pwdLastSet, now); return { text: a.sam, detail: `${a.adminCount ? 'Privileged (adminCount 1) · ' : ''}password set ${a.pwdLastSet ? `${day(a.pwdLastSet)} (${age} days)` : 'never'}${age > OLD_PASSWORD_DAYS ? ' · old' : ''} · ${encText(a.encTypes)} · ${a.spnCount} SPN(s): ${a.spns.join(', ')}` }; });
      const old = list.filter(a => ageDays(a.pwdLastSet, now) > OLD_PASSWORD_DAYS).length, priv = list.filter(a => a.adminCount).length;
      return { count: items.length, items, severity: priv ? 'critical' : 'high', note: `${old} with a password older than ${OLD_PASSWORD_DAYS} days, ${priv} privileged. gMSAs in this domain: ${ctx.domain.gmsaCount ?? 'not read'}.` };
    } },
  { id: 'asrep-roastable', title: 'Accounts without Kerberos pre-authentication (AS-REP roastable)', severity: 'high', area: 'Accounts',
    why: 'Anyone on the network can ask the DC for a response encrypted with these accounts\' passwords and crack it offline, without even having an account.',
    guidance: `${LEARN}defender-for-identity/security-assessment-weak-kerberos-encryption`,
    steps: ['Open each account in Active Directory Users and Computers > Account tab.', 'Clear Do not require Kerberos preauthentication, or run Set-ADAccountControl <account> -DoesNotRequirePreAuth $false.', 'Reset the password of any account that had it set, since its hash may already have been captured.'],
    evaluate: ctx => ({ count: ctx.domain.asrepAccounts.length, items: ctx.domain.asrepAccounts.map(a => ({ text: a.sam, detail: `${a.adminCount ? 'Privileged (adminCount 1) · ' : ''}password set ${day(a.pwdLastSet) || 'never'}` })) }) },
  { id: 'unconstrained-delegation', title: 'Unconstrained delegation outside the DCs', severity: 'high', area: 'Accounts',
    why: 'A computer or account trusted for unconstrained delegation keeps the TGT of everyone who connects to it. Coerce a DC to connect and the attacker holds a DC ticket.',
    guidance: `${LEARN}defender-for-identity/security-assessment-unconstrained-kerberos`,
    steps: ['Find what needs delegation on each listed object (usually an old IIS or SQL setup).', 'Switch it to constrained delegation (Delegation tab > Trust this computer for delegation to specified services only) or resource-based constrained delegation.', 'Add admin accounts to Protected Users or tick Account is sensitive and cannot be delegated.'],
    evaluate: ctx => ({ count: ctx.domain.delegation.length, items: ctx.domain.delegation.map(a => ({ text: a.sam, detail: `${a.kind}${a.os ? ` · ${a.os}` : ''} · ${a.dn}` })) }) },
  { id: 'laps-missing', title: 'Computers without a LAPS password', severity: 'high', area: 'Computers',
    why: 'Without LAPS, local administrator passwords are often the same on many machines, so one compromised workstation opens the rest.',
    guidance: `${LEARN}windows-server/identity/laps/laps-overview`,
    steps: ['Extend the schema once for Windows LAPS: Update-LapsADSchema (as a Schema Admin).', 'Let computers write their password: Set-LapsADComputerSelfPermission -Identity "<OU distinguished name>".', 'Create a GPO (or Intune policy) under Computer Configuration > Administrative Templates > System > LAPS: Configure password backup directory = Active Directory; enable password complexity and length 15+.', 'Link it to the computer OUs, run gpupdate on a test machine and confirm with Get-LapsADPassword -Identity <computer>.', 'Refresh this page: computers drop off once they have written their first password.'],
    evaluate: ctx => {
      const l = ctx.domain.laps;
      if (!l.total) return { count: 0, items: [], note: 'No enabled member computers in this domain.' };
      const missing = l.computers.filter(c => !c.legacyExpiry && !c.windowsExpiry);
      const items = missing.map(c => ({ text: c.name, detail: `${c.os || 'Unknown OS'} · last logon ${day(c.lastLogon) || 'never'}${c.lastLogon && ageDays(c.lastLogon, ctx.now) > 90 ? ' (stale: consider disabling)' : ''}` }));
      const schema = !l.legacySchema && !l.windowsSchema ? 'Neither LAPS schema extension is installed, so no computer can store a LAPS password in AD.' : `Schema: ${[l.legacySchema && 'Microsoft LAPS (legacy)', l.windowsSchema && 'Windows LAPS'].filter(Boolean).join(' and ')}.`;
      const cap = ctx.domain.errors.find(e => e.check === 'lapsLimit');
      return { count: items.length, items, note: `${cap ? `${cap.message} ` : ''}${l.total - missing.length} of ${l.total} enabled member computers have a LAPS password. ${schema}${(l.legacySchema || l.windowsSchema) && missing.length === l.total ? ' If LAPS is deployed, the reader account may not be allowed to read the expiry attribute.' : ''}` };
    } },
  { id: 'krbtgt-age', title: 'krbtgt password not rotated', severity: 'medium', area: 'Accounts',
    why: 'Every Kerberos ticket is signed with the krbtgt key. If it ever leaked, a forged "golden ticket" works until the password is reset twice.',
    guidance: `${LEARN}windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password`,
    steps: ['Reset the krbtgt password once (Microsoft\'s New-KrbtgtKeys.ps1 script checks replication for you).', 'Wait for replication and at least the maximum ticket lifetime (10 hours by default).', 'Reset it a second time.', 'Repeat on a schedule (every 180 days is common) and after any admin compromise.'],
    evaluate: ctx => {
      const k = ctx.domain.krbtgt;
      if (!k) return unavailable('The krbtgt account was not returned.');
      const age = ageDays(k.pwdLastSet, ctx.now);
      return age > KRBTGT_DAYS ? { count: 1, items: [{ text: 'krbtgt', detail: `Password last set ${day(k.pwdLastSet)} (${age} days ago)` }] } : { count: 0, items: [], note: `Password last set ${day(k.pwdLastSet)} (${age} days ago).` };
    } },
  { id: 'trusts', title: 'Domain trusts to review', severity: 'medium', area: 'Trusts',
    why: 'A trust lets the partner\'s accounts into this domain. Without SID filtering or selective authentication, a compromise of the partner becomes a compromise here.',
    guidance: `${LEARN}entra/identity/domain-services/concepts-forest-trust`,
    steps: ['Confirm each trust is still needed with its owner; remove the ones that are not (Active Directory Domains and Trusts, or netdom trust /remove).', 'Turn SID filtering on for external trusts: netdom trust <this domain> /domain:<partner> /quarantine:yes.', 'Use selective authentication for trusts to other organisations, then grant Allowed to authenticate only on the servers they need.', 'Turn off TGT delegation across trusts: netdom trust <this domain> /domain:<partner> /EnableTGTDelegation:No.'],
    evaluate: ctx => {
      const all = ctx.domain.trusts.map(trustInfo);
      const items = all.filter(t => t.risks.length).map(t => ({ text: t.partner, detail: `${t.kind} · ${t.direction} · ${t.risks.join('; ')}` }));
      return { count: items.length, items, note: all.length ? `${all.length} trust(s) in total; every trust is listed in the trust table below.` : 'This domain has no trusts.' };
    } },
];

// --------------------------------------------------------------------------------------------- evaluation
export function scoreOf(findings) {
  const checked = findings.filter(f => f.status !== 'unavailable');
  const total = checked.reduce((s, f) => s + WEIGHT[f.severity], 0);
  const passed = checked.filter(f => f.status === 'pass').reduce((s, f) => s + WEIGHT[f.severity], 0);
  return total ? Math.round((100 * passed) / total) : null;
}
const tally = findings => Object.fromEntries(Object.keys(SEVERITY).map(s => [s, findings.filter(f => f.status === 'open' && f.severity === s).length]));

export function evaluateDomain(domain, forest, { now = Date.now(), facts = forest.pki.templates.map(t => templateFacts(t, forest)) } = {}) {
  if (!domain.reachable) return { name: domain.name, netbios: domain.netbios, reachable: false, message: domain.message, findings: [], score: null, tally: tally([]), dcs: [], trusts: [] };
  const ctx = { domain, forest, now, facts, esc: escMatches(facts, domain.name) };
  const errorFor = id => domain.errors.find(e => ({ kerberoastable: 'spn', 'asrep-roastable': 'asrep', 'unconstrained-delegation': 'delegation', 'laps-missing': 'laps', 'krbtgt-age': 'krbtgt', trusts: 'trusts', 'dc-ldap-signing': 'dcs' })[id] === e.check);
  const findings = CHECKS.map(c => {
    const base = { id: c.id, title: c.title, severity: c.severity, area: c.area, why: c.why, domain: domain.name, playbook: { steps: c.steps, guidance: c.guidance } };
    const err = errorFor(c.id);
    let r;
    try { r = err ? unavailable(`Could not be read: ${err.message}`) : c.evaluate(ctx); } catch (e) { r = unavailable(`Could not be evaluated: ${e.message}`); }
    if (r.unavailable) return { ...base, status: 'unavailable', count: null, reason: r.unavailable, items: [] };
    return { ...base, severity: r.count && r.severity ? r.severity : c.severity, status: r.count ? 'open' : 'pass', count: r.count, note: r.note || null, items: r.items.slice(0, ITEM_LIMIT), more: Math.max(0, r.items.length - ITEM_LIMIT) };
  });
  const ranked = rank(findings);
  return { name: domain.name, netbios: domain.netbios, root: domain.root, reachable: true, functionalLevel: FUNCTIONAL[domain.functionalLevel] || domain.functionalLevel || '',
    score: scoreOf(ranked), tally: tally(ranked), findings: ranked,
    dcs: domain.dcs.map(d => ({ name: d.name, os: d.os, ldapSigning: d.ldapSigning === 'required' ? 'Required' : d.ldapSigning === 'notRequired' ? 'Not required' : 'Not tested', detail: d.ldapSigningDetail })),
    trusts: domain.trusts.map(trustInfo), gpos: domain.gpo.gpos, gpoStatus: domain.gpo.status, gpoMessage: domain.gpo.message };
}

export function evaluatePosture(forest, { now = Date.now() } = {}) {
  const facts = forest.pki.templates.map(t => templateFacts(t, forest));
  const domains = forest.domains.map(d => evaluateDomain(d, forest, { now, facts }));
  return { status: 'live', generated: new Date(now).toISOString(), server: forest.server, forest: forest.forest, domains,
    pki: { status: forest.pki.status, message: forest.pki.message, cas: forest.pki.cas.map(c => ({ name: c.name, host: c.host, templates: c.templates.length, webEnrollment: c.webEnrollment })), templates: facts.length, published: facts.filter(f => f.published).length },
    gaps: GAPS, notes: forest.notes };
}

// --------------------------------------------------------------------------------------------- collection
export async function collectPosture({ config = adConfig(), run = (args, o) => runPowerShell(args, { ...o, script: POSTURE_SCRIPT }), now = Date.now() } = {}) {
  if (config.cloud) return { status: 'cloud', message: CLOUD_AD_MESSAGE.replace('Only groups that sync to Entra are shown. Groups that never sync, such as Domain Users, Domain Admins, built-in groups and groups outside the sync scope, are missing from this list. ', '').replace('to see them', 'to read AD posture'), domains: [] };
  if (!config.enabled) return { status: 'off', message: config.platform !== 'win32' ? 'AD posture needs Entity 360 running on Windows on the same network as a domain controller.' : 'Live AD reads are turned off (E360_AD_ENABLED=false).', domains: [] };
  const args = [];
  if (config.server) args.push('-Server', config.server);
  if (config.credential) args.push('-CredentialPath', config.credential);
  let raw;
  try { raw = parsePosture(await run(args, { timeout: POSTURE_TIMEOUT_MS })); }
  catch (e) { return { status: 'error', message: e?.killed ? `The AD posture read timed out after ${POSTURE_TIMEOUT_MS / 1000} seconds.` : 'The AD posture read did not complete on this host.', domains: [] }; }
  if (raw.status !== 'live') return { status: raw.status, message: raw.message, domains: [] };
  return evaluatePosture(raw, { now });
}

// --------------------------------------------------------------------------------------------- score history
// One row per domain per UTC day ({ date, domain, score, open }), the last read of the day wins. JSON file on the host.
export const HISTORY_KEEP_DAYS = 800;
export function historyFile(env = process.env) {
  if (env.E360_POSTURE_HISTORY) return env.E360_POSTURE_HISTORY;
  return env.LOCALAPPDATA ? path.join(env.LOCALAPPDATA, 'Entity360', 'posture-history.json') : path.join(os.homedir(), '.entity360', 'posture-history.json');
}
export function addToHistory(rows, posture) {
  const date = posture.generated.slice(0, 10);
  const fresh = posture.domains.filter(d => d.reachable && d.score != null).map(d => ({ date, domain: d.name, score: d.score, open: d.tally }));
  const keep = new Date(Date.parse(posture.generated) - HISTORY_KEEP_DAYS * DAY).toISOString().slice(0, 10);
  const out = rows.filter(r => r.date >= keep && !fresh.some(f => f.date === r.date && f.domain === r.domain)).concat(fresh);
  return out.sort((a, b) => a.date.localeCompare(b.date) || a.domain.localeCompare(b.domain));
}
export function createHistoryStore(file = historyFile()) {
  let chain = Promise.resolve();
  const load = async () => { try { const v = JSON.parse(await readFile(file, 'utf8')); return Array.isArray(v) ? v.filter(r => r && /^\d{4}-\d{2}-\d{2}$/.test(r.date) && typeof r.domain === 'string' && Number.isFinite(r.score)) : []; } catch { return []; } };
  return {
    file, load,
    record(posture) {
      chain = chain.then(async () => { const rows = addToHistory(await load(), posture); await mkdir(path.dirname(file), { recursive: true }); await writeFile(`${file}.tmp`, JSON.stringify(rows)); await rename(`${file}.tmp`, file); return rows; });
      return chain.catch(() => null);
    },
  };
}
export const historyFor = (rows, domain) => rows.filter(r => r.domain === domain).map(r => ({ date: r.date, score: r.score, open: r.open }));

// --------------------------------------------------------------------------------------------- PDF
const SEV = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' };
export function postureDocument(posture, history, { domain = '', viewer = '' } = {}) {
  const picked = posture.domains.filter(d => !domain || d.name === domain);
  const sections = [];
  sections.push({ title: 'Score by domain', status: 'ok', blocks: [
    { type: 'text', text: 'Score = share of the checked controls that pass, weighted by severity (critical 10, high 6, medium 3, low 1). Controls that could not be read are left out of the score and listed as not read.', style: 'muted' },
    { type: 'table', columns: [{ label: 'Domain', w: 3 }, { label: 'Score', w: 1 }, { label: 'Critical', w: 1 }, { label: 'High', w: 1 }, { label: 'Medium', w: 1 }, { label: 'Not read', w: 1 }],
      rows: picked.map(d => [d.name, d.score == null ? 'n/a' : `${d.score}`, `${d.tally.critical}`, `${d.tally.high}`, `${d.tally.medium}`, `${d.findings.filter(f => f.status === 'unavailable').length}`]) }] });
  for (const d of picked) {
    const h = historyFor(history, d.name);
    sections.push({ title: `${d.name}: score trend`, status: h.length ? 'ok' : 'empty', summary: h.length ? `${h.length} reading(s)` : 'No history yet', blocks: h.length ? [
      { type: 'table', columns: [{ label: 'Date', w: 2 }, { label: 'Score', w: 1 }, { label: 'Critical', w: 1 }, { label: 'High', w: 1 }, { label: 'Medium', w: 1 }], rows: h.slice(-24).map(r => [r.date, `${r.score}`, `${r.open?.critical ?? ''}`, `${r.open?.high ?? ''}`, `${r.open?.medium ?? ''}`]) },
      h.length > 24 ? { type: 'text', text: `Latest 24 of ${h.length} readings.`, style: 'muted' } : null].filter(Boolean) : [{ type: 'text', text: 'Entity 360 records one score per domain per day each time AD posture is read. Open the page again on another day to start the trend.' }] });
    if (!d.reachable) { sections.push({ title: `${d.name}: findings`, status: 'unavailable', reason: d.message, blocks: [] }); continue; }
    const open = d.findings.filter(f => f.status === 'open');
    sections.push({ title: `${d.name}: findings`, status: 'ok', summary: `${open.length} open`, blocks: [
      { type: 'table', columns: [{ label: '#', w: 0.5 }, { label: 'Finding', w: 5 }, { label: 'Severity', w: 1.2 }, { label: 'Status', w: 1.5 }],
        rows: d.findings.map(f => [f.rank ? `${f.rank}` : '', f.title, SEV[f.severity], f.status === 'open' ? `${f.count} affected` : f.status === 'pass' ? 'Passing' : 'Not read']) },
      ...open.flatMap(f => [{ type: 'heading', text: `${f.title} (${f.count})` }, { type: 'text', text: f.why }, f.note ? { type: 'text', text: f.note, style: 'muted' } : null,
        { type: 'table', columns: [{ label: 'Name', w: 2 }, { label: 'Detail', w: 6 }], rows: f.items.map(i => [i.text, i.detail]) },
        f.more ? { type: 'text', text: `${f.more} more not shown.`, style: 'muted' } : null, { type: 'list', items: f.playbook.steps }].filter(Boolean)),
      ...d.findings.filter(f => f.status === 'unavailable').map(f => ({ type: 'callout', tone: 'warn', text: `${f.title}: not read. ${f.reason}` })),
    ] });
    if (d.trusts.length) sections.push({ title: `${d.name}: trusts`, status: 'ok', blocks: [{ type: 'table', columns: [{ label: 'Partner', w: 2 }, { label: 'Type', w: 2 }, { label: 'Direction', w: 2 }, { label: 'SID filtering', w: 2 }, { label: 'Authentication', w: 2 }], rows: d.trusts.map(t => [t.partner, t.kind, t.direction, t.sidFiltering, t.authentication]) }] });
  }
  sections.push({ title: 'Not readable over this connection', status: 'ok', blocks: [{ type: 'table', columns: [{ label: 'What', w: 3 }, { label: 'Why', w: 3 }, { label: 'How to collect it', w: 3 }], rows: posture.gaps.map(g => [g.what, g.why, g.path]) }] });
  return { title: `AD posture: ${domain || posture.forest || 'forest'}`, subtitle: 'Active Directory and AD CS hardening findings', meta: [['Forest', posture.forest], ['Read from', posture.server], ['Read at', `${posture.generated.slice(0, 16).replace('T', ' ')} UTC`], ['Requested by', viewer]], sections, footer: `Entity 360 · AD posture · ${posture.forest || ''}` };
}

// --------------------------------------------------------------------------------------------- demo
// Fictional two-domain forest (ad.northwind.example + emea child) with an external partner trust, for demo mode.
export function demoPostureRaw(now = Date.now()) {
  const ago = d => new Date(now - d * DAY).toISOString(), ROOT = 'S-1-5-21-1111-2222-3333', EMEA = 'S-1-5-21-4444-5555-6666';
  const ace = (sid, rights, objectType = RIGHT.all) => ({ sid, type: 'Allow', rights, objectType });
  const admins = [ace(`${ROOT}-512`, 'GenericAll'), ace(`${ROOT}-519`, 'GenericAll')];
  const gpo = (values, gpos) => ({ status: 'read', message: '', values, gpos });
  const root = { name: 'ad.northwind.example', netbios: 'NORTHWIND', sid: ROOT, root: true, reachable: true, functionalLevel: '7',
    dcs: [{ name: 'NWDC01', host: 'nwdc01.ad.northwind.example', os: 'Windows Server 2022 Datacenter', ldapSigning: 'notRequired', ldapSigningDetail: 'An unsigned bind was accepted.' }, { name: 'NWDC02', host: 'nwdc02.ad.northwind.example', os: 'Windows Server 2025 Datacenter', ldapSigning: 'required', ldapSigningDetail: 'An unsigned bind was refused (strongerAuthRequired).' }],
    trusts: [{ partner: 'emea.ad.northwind.example', flatName: 'EMEA', direction: 3, type: 2, attributes: TRUST.withinForest, created: ago(900) }, { partner: 'partner.example', flatName: 'PARTNER', direction: 2, type: 2, attributes: 0, created: ago(1400) }],
    spnAccounts: [{ sam: 'svc-sql01', dn: 'CN=svc-sql01,OU=Service Accounts,DC=ad,DC=northwind,DC=example', spns: ['MSSQLSvc/sql01.ad.northwind.example:1433'], spnCount: 1, pwdLastSet: ago(1210), lastLogon: ago(1), adminCount: 1, encTypes: null },
      { sam: 'svc-iis-intranet', dn: 'CN=svc-iis-intranet,OU=Service Accounts,DC=ad,DC=northwind,DC=example', spns: ['HTTP/intranet.ad.northwind.example'], spnCount: 1, pwdLastSet: ago(640), lastLogon: ago(2), adminCount: 0, encTypes: 28 },
      { sam: 'svc-backup', dn: 'CN=svc-backup,OU=Service Accounts,DC=ad,DC=northwind,DC=example', spns: ['backup/bk01.ad.northwind.example'], spnCount: 1, pwdLastSet: ago(80), lastLogon: ago(1), adminCount: 0, encTypes: 24 }],
    asrepAccounts: [{ sam: 'scanner-legacy', dn: 'CN=scanner-legacy,OU=Devices,DC=ad,DC=northwind,DC=example', pwdLastSet: ago(2000), adminCount: 0 }],
    delegation: [{ sam: 'APP-OLD01$', dn: 'CN=APP-OLD01,OU=Servers,DC=ad,DC=northwind,DC=example', kind: 'Computer', os: 'Windows Server 2012 R2 Standard' }],
    krbtgt: { pwdLastSet: ago(1500) }, gmsaCount: 2,
    laps: { legacySchema: false, windowsSchema: true, total: 6, computers: [
      { name: 'NW-WS-0142', os: 'Windows 11 Enterprise', lastLogon: ago(1), windowsExpiry: ago(-20) }, { name: 'NW-WS-0143', os: 'Windows 11 Enterprise', lastLogon: ago(3), windowsExpiry: ago(-12) },
      { name: 'NW-WS-0088', os: 'Windows 10 Enterprise', lastLogon: ago(2), windowsExpiry: null }, { name: 'APP-OLD01', os: 'Windows Server 2012 R2 Standard', lastLogon: ago(1), windowsExpiry: null },
      { name: 'FS01', os: 'Windows Server 2022 Standard', lastLogon: ago(1), windowsExpiry: ago(-25) }, { name: 'NW-WS-0031', os: 'Windows 10 Enterprise', lastLogon: ago(160), windowsExpiry: null }] },
    gpo: gpo({ ldapServerIntegrity: { value: '1', gpo: 'Default Domain Controllers Policy', level: 'Domain Controllers OU' }, smbServerSigning: { value: '1', gpo: 'Default Domain Controllers Policy', level: 'Domain Controllers OU' }, lmCompatibilityLevel: { value: '3', gpo: 'Default Domain Policy', level: 'Domain' } },
      [{ name: 'Default Domain Policy', linkedTo: 'Domain', enforced: false, sets: ['lmCompatibilityLevel'] }, { name: 'Default Domain Controllers Policy', linkedTo: 'Domain Controllers OU', enforced: false, sets: ['ldapServerIntegrity', 'smbServerSigning'] }]), errors: [] };
  const emea = { name: 'emea.ad.northwind.example', netbios: 'EMEA', sid: EMEA, root: false, reachable: true, functionalLevel: '7',
    dcs: [{ name: 'EMDC01', host: 'emdc01.emea.ad.northwind.example', os: 'Windows Server 2025 Standard', ldapSigning: 'required', ldapSigningDetail: 'An unsigned bind was refused (strongerAuthRequired).' }],
    trusts: [{ partner: 'ad.northwind.example', flatName: 'NORTHWIND', direction: 3, type: 2, attributes: TRUST.withinForest, created: ago(900) }],
    spnAccounts: [], asrepAccounts: [], delegation: [], krbtgt: { pwdLastSet: ago(40) }, gmsaCount: 5,
    laps: { legacySchema: false, windowsSchema: true, total: 3, computers: [{ name: 'EM-WS-0001', os: 'Windows 11 Enterprise', lastLogon: ago(1), windowsExpiry: ago(-10) }, { name: 'EM-WS-0002', os: 'Windows 11 Enterprise', lastLogon: ago(1), windowsExpiry: ago(-11) }, { name: 'EM-FS01', os: 'Windows Server 2025 Standard', lastLogon: ago(1), windowsExpiry: ago(-5) }] },
    gpo: gpo({ ldapServerIntegrity: { value: '2', gpo: 'EMEA DC Hardening', level: 'Domain Controllers OU' }, ldapChannelBinding: { value: '2', gpo: 'EMEA DC Hardening', level: 'Domain Controllers OU' }, smbServerSigning: { value: '1', gpo: 'EMEA DC Hardening', level: 'Domain Controllers OU' }, lmCompatibilityLevel: { value: '5', gpo: 'EMEA DC Hardening', level: 'Domain Controllers OU' } },
      [{ name: 'EMEA DC Hardening', linkedTo: 'Domain Controllers OU', enforced: true, sets: ['ldapServerIntegrity', 'ldapChannelBinding', 'smbServerSigning', 'lmCompatibilityLevel'] }]), errors: [] };
  const tpl = (name, o = {}) => ({ name, displayName: o.displayName || name, nameFlag: 0, enrollFlag: 0, raSignatures: 0, ekus: [], appPolicies: [], schemaVersion: 2, owner: `${ROOT}-519`, daclRead: true, changed: ago(300), aces: admins, ...o, aces: [...admins, ...(o.aces || [])] });
  const templates = [
    tpl('User', { schemaVersion: 1, nameFlag: 0x82000000, ekus: [EKU.clientAuth, '1.3.6.1.4.1.311.10.3.4', '1.3.6.1.5.5.7.3.4'], aces: [ace(`${ROOT}-513`, 'ReadProperty, ExtendedRight', RIGHT.enroll)] }),
    tpl('NW-VPNUser', { displayName: 'NW VPN User', nameFlag: FLAG.suppliesSubject, ekus: [EKU.clientAuth], aces: [ace(`${ROOT}-513`, 'ReadProperty, ExtendedRight', RIGHT.enroll)] }),
    tpl('NW-WebServer', { displayName: 'NW Web Server', nameFlag: FLAG.suppliesSubject, ekus: ['1.3.6.1.5.5.7.3.1'], aces: [ace(`${ROOT}-515`, 'ReadProperty, ExtendedRight', RIGHT.enroll)] }),
    tpl('NW-LegacyCodeSign', { displayName: 'NW Legacy Code Signing', ekus: ['1.3.6.1.5.5.7.3.3'], aces: [ace('S-1-5-11', 'ReadProperty, WriteProperty, ExtendedRight')] }),
    tpl('EnrollmentAgent', { displayName: 'Enrollment Agent', ekus: [EKU.agent], aces: [ace(`${ROOT}-512`, 'ExtendedRight', RIGHT.enroll)] }),
    tpl('NW-EMEA-Laptop', { displayName: 'EMEA Laptop', ekus: [EKU.clientAuth], enrollFlag: FLAG.noSecurityExt, aces: [ace(`${EMEA}-515`, 'ReadProperty, ExtendedRight', RIGHT.autoEnroll)] }),
  ];
  return { status: 'live', server: 'nwdc01.ad.northwind.example', forest: 'ad.northwind.example', forestLevel: '7', domains: [root, emea],
    pki: { status: 'read', message: '', cas: [{ name: 'Northwind Issuing CA 01', host: 'nwca01.ad.northwind.example', templates: ['User', 'NW-VPNUser', 'NW-WebServer', 'NW-EMEA-Laptop', 'EnrollmentAgent'], webEnrollment: 'http', webDetail: 'HTTP 401, offers Negotiate,NTLM' }], templates, names: {} }, notes: [] };
}
export function demoHistory(now = Date.now()) {
  const rows = [];
  const series = { 'ad.northwind.example': [9, 12, 12, 17, 21], 'emea.ad.northwind.example': [52, 60, 66, 73, 77] };
  for (const [domain, scores] of Object.entries(series)) scores.forEach((score, i) => rows.push({ date: new Date(now - (scores.length - i) * 30 * DAY).toISOString().slice(0, 10), domain, score, open: { critical: 0, high: 0, medium: 0, low: 0 } }));
  return rows;
}
