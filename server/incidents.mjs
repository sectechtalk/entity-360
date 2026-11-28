// Incident queue (INVESTIGATE > Incidents): what Microsoft's own security tools have raised, on one ranked page.
// Four delegated, read-only Microsoft Graph sources, each read with the viewer's own token:
//   Defender XDR incidents   /security/incidents                    SecurityIncident.Read.All
//   Defender XDR alerts      /security/alerts_v2                    SecurityAlert.Read.All
//   Risky users              /identityProtection/riskyUsers         IdentityRiskyUser.Read.All
//   Risk detections          /identityProtection/riskDetections     IdentityRiskEvent.Read.All
// Each source fails on its own: a missing scope, role or license becomes a source row that names what is needed, and
// the other sources still load. Nothing here writes to Microsoft; classifying or closing stays in the Defender portal.
// Every item names the users and devices it touches so the page can open them in Entity 360 (Summary, Device lookup).
import { describeError, queryUrl, GUID } from './model.mjs';

const DAY = 864e5;
export const QUEUE_DAYS = 30;
export const ITEM_LIMIT = 200;
export const SEVERITY = { high: 4, medium: 3, low: 2, informational: 1, unknown: 0 };
const ENTRA = 'https://entra.microsoft.com/#view/';

// What each source needs. `role` and `license` are shown when Microsoft refuses the read.
export const SOURCES = [
  { id: 'incidents', label: 'Defender XDR incidents', scope: 'SecurityIncident.Read.All',
    role: 'Security Reader, Global Reader, Security Operator or Security Administrator',
    license: 'Microsoft Defender XDR (any Defender for Endpoint, Office 365, Identity or Cloud Apps plan)' },
  { id: 'alerts', label: 'Defender XDR alerts', scope: 'SecurityAlert.Read.All',
    role: 'Security Reader, Global Reader, Security Operator or Security Administrator',
    license: 'Microsoft Defender XDR (any Defender for Endpoint, Office 365, Identity or Cloud Apps plan)' },
  { id: 'riskyUsers', label: 'Identity Protection risky users', scope: 'IdentityRiskyUser.Read.All',
    role: 'Security Reader, Global Reader, Security Operator or Security Administrator',
    license: 'Microsoft Entra ID P2 (P1 returns limited data)' },
  { id: 'riskDetections', label: 'Identity Protection risk detections', scope: 'IdentityRiskEvent.Read.All',
    role: 'Security Reader, Global Reader, Security Operator or Security Administrator',
    license: 'Microsoft Entra ID P2' },
];
export const QUEUE_SCOPES = SOURCES.map(s => s.scope);

// Portal pages for the identity items. Defender items use the incidentWebUrl / alertWebUrl Microsoft returns.
// Risky users verified in a signed-in browser 2026-11-27 (opens "Security | Risky users"). The Entra admin center no
// longer has a Risk detections page (ID Protection > Report lists risky agents, users, workload identities and
// sign-ins), so detection-only items open Risky users too, where each user's risk history lists the detections.
export const LINKS = {
  riskyUsers: `${ENTRA}Microsoft_AAD_IAM/SecurityMenuBlade/~/RiskyUsers`,
  defenderIncidents: 'https://security.microsoft.com/incidents',
};

const sev = s => (s in SEVERITY ? s : 'unknown');
// Identity Protection says "hidden" when the viewer cannot see the level, and "none" for no risk.
const riskSev = level => ({ high: 'high', medium: 'medium', low: 'low' })[String(level || '').toLowerCase()] || 'unknown';
const iso = (now, days) => new Date(now - days * DAY).toISOString().replace(/\.\d{3}Z$/, 'Z');
const words = s => String(s || '').replace(/([a-z])([A-Z])/g, '$1 $2').replace(/^./, c => c.toUpperCase());
const clip = (s, n = 400) => { const t = String(s || '').replace(/\s+/g, ' ').trim(); return t.length > n ? `${t.slice(0, n - 1)}…` : t; };

// ------------------------------------------------------------------ entities named by Defender evidence
const userKey = u => (u.id ? `id:${u.id}` : u.upn ? `upn:${u.upn.toLowerCase()}` : `name:${String(u.name).toLowerCase()}`);
const deviceKey = d => (d.entraId ? `entra:${d.entraId}` : `name:${String(d.name).toLowerCase()}`);

// One user or device per distinct identity. Only Entra object ids open in Entity 360; a local account (no
// azureAdUserId) is still listed so the analyst sees it, but it has no Open button.
export function evidenceEntities(evidence = []) {
  const users = new Map(), devices = new Map(), ips = new Set();
  const addUser = a => {
    if (!a) return;
    const u = { id: GUID.test(a.azureAdUserId || '') ? a.azureAdUserId : null, upn: a.userPrincipalName || null,
      name: a.displayName || a.userPrincipalName || (a.accountName ? `${a.domainName ? `${a.domainName}\\` : ''}${a.accountName}` : null) };
    if (!u.name && !u.id) return;
    u.name ||= u.id;
    const k = userKey(u);
    if (!users.has(k)) users.set(k, u);
  };
  for (const e of evidence) {
    const t = String(e?.['@odata.type'] || '');
    if (t.endsWith('userEvidence')) addUser(e.userAccount);
    else if (t.endsWith('deviceEvidence')) {
      const d = { entraId: GUID.test(e.azureAdDeviceId || '') ? e.azureAdDeviceId : null, name: e.deviceDnsName || e.hostName || e.mdeDeviceId || null, os: [e.osPlatform, e.version].filter(Boolean).join(' ') || null, risk: e.riskScore || null };
      if (d.name || d.entraId) { d.name ||= d.entraId; const k = deviceKey(d); if (!devices.has(k)) devices.set(k, d); }
      for (const u of e.loggedOnUsers || []) addUser({ accountName: u.accountName, domainName: u.domainName });
    } else if (t.endsWith('ipEvidence') && e.ipAddress && !/^(fe80:|::1$|127\.)/i.test(e.ipAddress)) ips.add(e.ipAddress);
    else if (t.endsWith('mailboxEvidence')) addUser({ userPrincipalName: e.primaryAddress, displayName: e.displayName, azureAdUserId: e.userAccount?.azureAdUserId });
    else if (t.endsWith('processEvidence') || t.endsWith('cloudLogonSessionEvidence')) addUser(e.userAccount || e.account);
  }
  return { users: [...users.values()], devices: [...devices.values()], ips: [...ips] };
}

function mergeEntities(list) {
  const users = new Map(), devices = new Map(), ips = new Set();
  for (const x of list) {
    for (const u of x.users || []) { const k = userKey(u); const had = users.get(k); users.set(k, had ? { ...u, ...had, id: had.id || u.id, upn: had.upn || u.upn } : u); }
    for (const d of x.devices || []) { const k = deviceKey(d); if (!devices.has(k)) devices.set(k, d); }
    for (const ip of x.ips || []) ips.add(ip);
  }
  return { users: [...users.values()], devices: [...devices.values()], ips: [...ips] };
}

// ------------------------------------------------------------------ shaping each source into queue items
export function alertSummary(a) {
  return { id: a.id, title: a.title || 'Alert', severity: sev(a.severity), status: words(a.status), product: a.productName || words(a.serviceSource),
    category: a.category || null, mitre: a.mitreTechniques || [], created: a.createdDateTime || null, link: a.alertWebUrl || null,
    recommended: clip(a.recommendedActions, 600) || null, ...evidenceEntities(a.evidence) };
}

export function incidentItems(incidents, alerts) {
  const byIncident = new Map();
  for (const a of alerts) { const k = String(a.incidentId ?? ''); if (!byIncident.has(k)) byIncident.set(k, []); byIncident.get(k).push(alertSummary(a)); }
  const seen = new Set();
  const items = incidents.map(i => {
    const own = (byIncident.get(String(i.id)) || []).sort((x, y) => SEVERITY[y.severity] - SEVERITY[x.severity]);
    seen.add(String(i.id));
    return { kind: 'incident', id: `incident:${i.id}`, title: i.displayName || `Incident ${i.id}`, severity: sev(i.severity), status: words(i.status),
      active: !['resolved', 'redirected'].includes(String(i.status).toLowerCase()), created: i.createdDateTime || null, updated: i.lastUpdateDateTime || i.createdDateTime || null,
      source: 'Defender XDR incident', link: i.incidentWebUrl || LINKS.defenderIncidents, assignedTo: i.assignedTo || null,
      classification: i.classification && i.classification !== 'unknown' ? words(i.classification) : null, determination: i.determination && i.determination !== 'unknown' ? words(i.determination) : null,
      detail: clip(i.summary || i.description) || null, tags: [...(i.customTags || []), ...(i.systemTags || [])],
      mitre: [...new Set(own.flatMap(a => a.mitre))], alerts: own, ...mergeEntities(own) };
  });
  // Alerts whose incident is outside the window (or unreadable) still show, each as its own item.
  for (const [k, list] of byIncident) if (!seen.has(k)) for (const a of list) {
    items.push({ kind: 'alert', id: `alert:${a.id}`, title: a.title, severity: a.severity, status: a.status, active: !/resolved/i.test(a.status),
      created: a.created, updated: a.created, source: `${a.product || 'Defender XDR'} alert`, link: a.link, detail: a.recommended, mitre: a.mitre,
      incidentId: k || null, alerts: [a], users: a.users, devices: a.devices, ips: a.ips });
  }
  return items;
}

export function detectionSummary(d) {
  const where = [d.location?.city, d.location?.state, d.location?.countryOrRegion].filter(Boolean).join(', ');
  return { id: d.id, type: words(d.riskEventType), level: riskSev(d.riskLevel), state: words(d.riskState), when: d.detectedDateTime || d.activityDateTime || null,
    activity: words(d.activity), timing: words(d.detectionTimingType), source: d.source || null, ip: d.ipAddress || null, location: where || null, detail: d.riskDetail && d.riskDetail !== 'none' ? words(d.riskDetail) : null };
}

const atRisk = s => ['atrisk', 'confirmedcompromised'].includes(String(s || '').toLowerCase());
export function riskItems(riskyUsers, detections) {
  const byUser = new Map();
  for (const d of detections) { if (!d.userId) continue; if (!byUser.has(d.userId)) byUser.set(d.userId, []); byUser.get(d.userId).push(d); }
  const items = [], covered = new Set();
  for (const u of riskyUsers) {
    if (!atRisk(u.riskState)) continue;
    covered.add(u.id);
    const own = (byUser.get(u.id) || []).sort((a, b) => String(b.detectedDateTime).localeCompare(String(a.detectedDateTime))).map(detectionSummary);
    const confirmed = String(u.riskState).toLowerCase() === 'confirmedcompromised';
    items.push({ kind: 'risky-user', id: `risky:${u.id}`, title: `${confirmed ? 'Confirmed compromised' : 'Risky user'}: ${u.userDisplayName || u.userPrincipalName || u.id}`,
      severity: confirmed ? 'high' : riskSev(u.riskLevel), status: words(u.riskState), active: true, created: own.at(-1)?.when || u.riskLastUpdatedDateTime || null,
      updated: u.riskLastUpdatedDateTime || own[0]?.when || null, source: 'Identity Protection', link: LINKS.riskyUsers,
      detail: [u.riskDetail && u.riskDetail !== 'none' ? words(u.riskDetail) : null, own.length ? `${own.length} risk detection${own.length === 1 ? '' : 's'} in the window` : null].filter(Boolean).join(' · ') || null,
      mitre: [], detections: own, users: [{ id: GUID.test(u.id || '') ? u.id : null, upn: u.userPrincipalName || null, name: u.userDisplayName || u.userPrincipalName || u.id }], devices: [], ips: [...new Set(own.map(d => d.ip).filter(Boolean))] });
  }
  // Detections still at risk for users not in the risky list (for example a P1 tenant that hides the list).
  for (const [userId, list] of byUser) {
    if (covered.has(userId)) continue;
    for (const d of list.filter(x => atRisk(x.riskState))) {
      const s = detectionSummary(d);
      items.push({ kind: 'risk-detection', id: `detection:${d.id}`, title: `${s.type}: ${d.userDisplayName || d.userPrincipalName || userId}`, severity: s.level, status: s.state, active: true,
        created: s.when, updated: s.when, source: 'Identity Protection', link: LINKS.riskyUsers, detail: [s.activity, s.location, s.ip].filter(Boolean).join(' · ') || null, mitre: [],
        detections: [s], users: [{ id: GUID.test(userId) ? userId : null, upn: d.userPrincipalName || null, name: d.userDisplayName || d.userPrincipalName || userId }], devices: [], ips: s.ip ? [s.ip] : [] });
    }
  }
  return items;
}

// Active first, then severity, then most recently updated.
export function rankItems(items) {
  return [...items].sort((a, b) => (b.active - a.active) || (SEVERITY[b.severity] - SEVERITY[a.severity]) || String(b.updated || '').localeCompare(String(a.updated || '')));
}

// A refused read names the scope, the role and the license. Other failures keep Microsoft's reason.
export function sourceError(src, e) {
  const reason = describeError(e);
  if (e?.status === 403) return { status: 'denied', reason, needs: `Delegated permission ${src.scope} (run Grant-E360IncidentScopes.ps1), the ${src.role} role on your account, and ${src.license}.` };
  if (e?.status === 404 || /not licensed|license/i.test(e?.upstreamMessage || '')) return { status: 'unavailable', reason, needs: `${src.license}.` };
  return { status: 'failed', reason, needs: null };
}

// ------------------------------------------------------------------ the read
export async function incidentQueue(api, { now = Date.now(), days = QUEUE_DAYS } = {}) {
  const since = iso(now, days);
  const reads = {
    incidents: () => api.pages(queryUrl('/v1.0/security/incidents', { '$filter': `lastUpdateDateTime ge ${since}`, '$top': '50' }), { maxPages: 4 }),
    alerts: () => api.pages(queryUrl('/v1.0/security/alerts_v2', { '$filter': `lastUpdateDateTime ge ${since}`, '$top': '100' }), { maxPages: 4 }),
    riskyUsers: () => api.pages(queryUrl('/v1.0/identityProtection/riskyUsers', { '$filter': "riskState eq 'atRisk' or riskState eq 'confirmedCompromised'", '$top': '100' }), { maxPages: 4 }),
    riskDetections: () => api.pages(queryUrl('/v1.0/identityProtection/riskDetections', { '$filter': `detectedDateTime ge ${since}`, '$top': '200' }), { maxPages: 4 }),
  };
  const settled = await Promise.allSettled(SOURCES.map(s => reads[s.id]()));
  const rows = {}, sources = [];
  SOURCES.forEach((src, i) => {
    const r = settled[i];
    if (r.status === 'fulfilled') {
      rows[src.id] = r.value.rows || [];
      sources.push({ id: src.id, label: src.label, scope: src.scope, status: 'ok', count: rows[src.id].length, truncated: !!r.value.truncated });
    } else {
      rows[src.id] = [];
      sources.push({ id: src.id, label: src.label, scope: src.scope, count: 0, ...sourceError(src, r.reason) });
    }
  });
  const all = rankItems([...incidentItems(rows.incidents, rows.alerts), ...riskItems(rows.riskyUsers, rows.riskDetections)]);
  // Correlation: items that name the same Entra user or device, so an analyst sees one attack raised by two tools.
  const keys = i => [...i.users.filter(u => u.id).map(u => `u:${u.id}`), ...i.devices.filter(d => d.entraId).map(d => `d:${d.entraId}`)];
  for (const i of all) { const mine = new Set(keys(i)); i.related = all.filter(o => o !== i && keys(o).some(k => mine.has(k))).map(o => ({ id: o.id, title: o.title, source: o.source })); }
  const open = all.filter(i => i.active);
  const tally = Object.fromEntries(['high', 'medium', 'low', 'informational', 'unknown'].map(s => [s, open.filter(i => i.severity === s).length]));
  return { generated: new Date(now).toISOString(), days, since, sources, tally, total: all.length, more: Math.max(0, all.length - ITEM_LIMIT), items: all.slice(0, ITEM_LIMIT) };
}

// ------------------------------------------------------------------ demo (fictional Contoso data, DEMO_MODE only)
const DEMO_TENANT = '00000000-0000-0000-0000-00000000c0de';
const DEMO_USERS = { megan: ['5f1b2c3d-1111-4a2b-9c3d-000000000001', 'Megan Bowen', 'meganb@contoso.example'], adele: ['5f1b2c3d-2222-4a2b-9c3d-000000000002', 'Adele Vance', 'adelev@contoso.example'], lee: ['5f1b2c3d-3333-4a2b-9c3d-000000000003', 'Lee Gu', 'leeg@contoso.example'] };
const demoUser = k => { const [id, name, upn] = DEMO_USERS[k]; return { '@odata.type': '#microsoft.graph.security.userEvidence', userAccount: { azureAdUserId: id, displayName: name, userPrincipalName: upn, accountName: upn.split('@')[0], domainName: 'CONTOSO' } }; };
const demoDevice = (name, entra) => ({ '@odata.type': '#microsoft.graph.security.deviceEvidence', deviceDnsName: name, azureAdDeviceId: entra, osPlatform: 'Windows11', version: '24H2', riskScore: 'high' });
const demoIp = ip => ({ '@odata.type': '#microsoft.graph.security.ipEvidence', ipAddress: ip });
export function demoQueueRows() {
  const portal = (kind, id) => `https://security.microsoft.com/${kind}/${id}?tid=${DEMO_TENANT}`;
  return {
    incidents: [
      { id: '41', displayName: 'Multi-stage incident involving Initial access & Credential access involving one user', severity: 'high', status: 'active', createdDateTime: '2026-11-20T14:02:00Z', lastUpdateDateTime: '2026-11-20T16:40:00Z', incidentWebUrl: portal('incident2', '41/overview'), assignedTo: null, classification: 'unknown', determination: 'unknown', summary: 'An adversary-in-the-middle phishing page captured a session cookie for Megan Bowen, then signed in from a new country and added an inbox rule.', customTags: [], systemTags: ['AiTM'] },
      { id: '38', displayName: 'Suspicious PowerShell on one endpoint', severity: 'medium', status: 'inProgress', createdDateTime: '2026-11-19T09:15:00Z', lastUpdateDateTime: '2026-11-20T08:05:00Z', incidentWebUrl: portal('incident2', '38/overview'), assignedTo: 'analyst@contoso.example', classification: 'unknown', determination: 'unknown', description: 'Encoded PowerShell started from an Office document on CONTOSO-LT-114.', customTags: ['Tier 1'], systemTags: [] },
      { id: '33', displayName: 'Password spray against several accounts', severity: 'low', status: 'resolved', createdDateTime: '2026-11-12T03:30:00Z', lastUpdateDateTime: '2026-11-13T17:00:00Z', incidentWebUrl: portal('incident2', '33/overview'), assignedTo: 'analyst@contoso.example', classification: 'truePositive', determination: 'compromisedAccount', summary: 'Blocked by smart lockout; no successful sign-in.', customTags: [], systemTags: [] },
    ],
    alerts: [
      { id: 'da41-1', incidentId: '41', title: 'Stolen session cookie was used', severity: 'high', status: 'new', productName: 'Microsoft Defender XDR', category: 'CredentialAccess', mitreTechniques: ['T1539', 'T1550.004'], createdDateTime: '2026-11-20T14:02:00Z', alertWebUrl: portal('alerts', 'da41-1'), recommendedActions: 'Revoke the user\'s sessions, reset the password, and review sign-ins from the attacker IP.', evidence: [demoUser('megan'), demoIp('203.0.113.45')] },
      { id: 'da41-2', incidentId: '41', title: 'Suspicious inbox manipulation rule', severity: 'medium', status: 'new', productName: 'Microsoft Defender for Office 365', category: 'DefenseEvasion', mitreTechniques: ['T1564.008'], createdDateTime: '2026-11-20T14:20:00Z', alertWebUrl: portal('alerts', 'da41-2'), evidence: [demoUser('megan')] },
      { id: 'da38-1', incidentId: '38', title: 'Suspicious PowerShell command line', severity: 'medium', status: 'inProgress', productName: 'Microsoft Defender for Endpoint', category: 'Execution', mitreTechniques: ['T1059.001'], createdDateTime: '2026-11-19T09:15:00Z', alertWebUrl: portal('alerts', 'da38-1'), recommendedActions: 'Isolate the device if the command line is not expected, and collect an investigation package.', evidence: [demoDevice('CONTOSO-LT-114', '7a1c0d2e-4444-4b5c-8d9e-000000000114'), demoUser('adele')] },
      { id: 'da33-1', incidentId: '33', title: 'Password spray', severity: 'low', status: 'resolved', productName: 'Microsoft Entra ID Protection', category: 'CredentialAccess', mitreTechniques: ['T1110.003'], createdDateTime: '2026-11-12T03:30:00Z', alertWebUrl: portal('alerts', 'da33-1'), evidence: [demoIp('198.51.100.7')] },
    ],
    riskyUsers: [
      { id: DEMO_USERS.megan[0], userDisplayName: 'Megan Bowen', userPrincipalName: DEMO_USERS.megan[2], riskLevel: 'high', riskState: 'atRisk', riskDetail: 'none', riskLastUpdatedDateTime: '2026-11-20T14:05:00Z' },
      { id: DEMO_USERS.lee[0], userDisplayName: 'Lee Gu', userPrincipalName: DEMO_USERS.lee[2], riskLevel: 'medium', riskState: 'atRisk', riskDetail: 'none', riskLastUpdatedDateTime: '2026-11-18T22:10:00Z' },
    ],
    riskDetections: [
      { id: 'rd-1', userId: DEMO_USERS.megan[0], userDisplayName: 'Megan Bowen', userPrincipalName: DEMO_USERS.megan[2], riskEventType: 'anomalousToken', riskLevel: 'high', riskState: 'atRisk', detectedDateTime: '2026-11-20T14:01:00Z', activity: 'signin', detectionTimingType: 'realtime', source: 'IdentityProtection', ipAddress: '203.0.113.45', location: { city: 'Lagos', countryOrRegion: 'NG' } },
      { id: 'rd-2', userId: DEMO_USERS.megan[0], userDisplayName: 'Megan Bowen', userPrincipalName: DEMO_USERS.megan[2], riskEventType: 'unfamiliarFeatures', riskLevel: 'medium', riskState: 'atRisk', detectedDateTime: '2026-11-20T13:58:00Z', activity: 'signin', detectionTimingType: 'realtime', source: 'IdentityProtection', ipAddress: '203.0.113.45', location: { city: 'Lagos', countryOrRegion: 'NG' } },
      { id: 'rd-3', userId: DEMO_USERS.lee[0], userDisplayName: 'Lee Gu', userPrincipalName: DEMO_USERS.lee[2], riskEventType: 'impossibleTravel', riskLevel: 'medium', riskState: 'atRisk', detectedDateTime: '2026-11-18T22:00:00Z', activity: 'signin', detectionTimingType: 'offline', source: 'MicrosoftCloudAppSecurity', ipAddress: '192.0.2.80', location: { city: 'Frankfurt', countryOrRegion: 'DE' } },
      { id: 'rd-4', userId: DEMO_USERS.adele[0], userDisplayName: 'Adele Vance', userPrincipalName: DEMO_USERS.adele[2], riskEventType: 'unlikelyTravel', riskLevel: 'low', riskState: 'remediated', detectedDateTime: '2026-11-15T07:00:00Z', activity: 'signin', detectionTimingType: 'offline', source: 'IdentityProtection', ipAddress: '192.0.2.10' },
    ],
  };
}
// The same reader as live, over the fictional rows, so demo exercises the real shaping code.
export function demoQueueApi() {
  const rows = demoQueueRows();
  const pick = u => (u.includes('/security/incidents') ? rows.incidents : u.includes('/security/alerts_v2') ? rows.alerts : u.includes('/riskyUsers') ? rows.riskyUsers : u.includes('/riskDetections') ? rows.riskDetections : []);
  return { pages: async u => ({ rows: pick(u), truncated: false }), request: async () => ({}) };
}
