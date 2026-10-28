// Sign-ins table columns (Aaron, 2026-10-25): Date, Request ID, Application, Status, Sign-in error code, IP address,
// Location, Conditional Access, Risk, Agent type, Authentication requirement; bucket 2 adds Tenant, Sign-in type and Session. Risk is riskLevelDuringSignIn + riskState (v1.0). Agent type (signIn.agent.agentType) and
// authenticationRequirement exist only in Graph beta; v1.0 rows show an em dash. filter:false = not a category (no header filter).
export const SIGNIN_HEADERS = ['Date', 'Request ID', 'Application', 'Status', 'Sign-in error code', 'IP address', 'Location', 'Conditional Access', 'Risk', 'Agent type', 'Authentication requirement', 'Tenant', 'Sign-in type', 'Session'];
export const BETA_ONLY = '\u2014';
// Entra error codes the portal reports as "Interrupted" (an extra step was needed, e.g. MFA or a prompt).
export const INTERRUPT_CODES = new Set([50055, 50057, 50058, 50059, 50072, 50074, 50076, 50079, 50097, 50125, 50129, 50140, 50143, 50144, 50158, 50199, 51006, 52004, 65001, 81010, 81012, 16000, 16001, 16003]);
export function signInStatus(code) {
  if (code === 0) return 'Success';
  if (code === null || code === undefined) return 'n/a';
  return INTERRUPT_CODES.has(Number(code)) ? 'Interrupted' : 'Failure';
}
const CA = { success: 'Success', failure: 'Failure', notApplied: 'Not Applied', unknownFutureValue: 'n/a' };
export const caLabel = v => CA[v] || (v && v !== 'Not returned' ? v : 'n/a');
const AUTH = { singleFactorAuthentication: 'Single-factor authentication', multiFactorAuthentication: 'Multifactor authentication' };
export const words = v => String(v).replace(/([a-z])([A-Z])/g, '$1 $2').replace(/^./, c => c.toUpperCase()).replace(/ (\w)/g, (m, c) => ' ' + c.toLowerCase());
export const authLabel = v => (v ? AUTH[v] || words(v) : 'n/a');
export const agentLabel = v => (v ? words(v) : 'n/a');
// Sign-in method from authenticationDetails (beta): the distinct methods that succeeded, short names for the common ones.
const METHOD = { 'X.509 Certificate': 'Certificate', 'Temporary Access Pass': 'TAP', 'Previously satisfied': '' };
export function methodLabel(methods = []) {
  const ok = methods.filter(m => m && m.succeeded !== false && m.method && m.method !== 'Not returned');
  const names = [...new Set(ok.map(m => (m.method in METHOD ? METHOD[m.method] : m.method)).filter(Boolean))];
  if (names.length) return names.join(' + ');
  return ok.length ? 'Previously satisfied' : '';
}
// Risk at sign-in time. 'hidden' means the viewer's tenant or role cannot see risk detail (Entra ID P2 needed).
const RISK = { none: 'None', low: 'Low', medium: 'Medium', high: 'High', hidden: 'Hidden (needs Entra ID P2)' };
export function riskLabel(risk) {
  const level = risk?.level || '', state = risk?.state || '';
  if (!level || level === 'unknownFutureValue') return 'n/a';
  const l = RISK[level] || words(level);
  return state && state !== 'none' && level !== 'none' ? `${l} (${words(state)})` : l;
}
// Bucket 2. Tenant: crossTenantAccessType (v1.0) plus home tenant when it differs from the resource tenant.
const XT = { none: 'Same tenant', b2bCollaboration: 'B2B collaboration', b2bDirectConnect: 'B2B direct connect', microsoftSupport: 'Microsoft support', serviceProvider: 'Service provider', passthrough: 'Passthrough' };
export function tenantLabel(t = {}) {
  if (!t.access || t.access === 'unknownFutureValue') return 'n/a';
  const base = XT[t.access] || words(t.access);
  return t.home && t.resource && t.home.toLowerCase() !== t.resource.toLowerCase() ? `${base} (home ${t.home.slice(0, 8)})` : base;
}
// Sign-in type: signInEventTypes (beta only).
export const eventTypeLabel = (types = []) => types.filter(x => x && x !== 'unknownFutureValue').map(words).join(', ') || 'n/a';
// Session: token protection binding and Global Secure Access source IP (beta only).
export function sessionLabel(s = {}) {
  const b = s.binding && s.binding !== 'unknownFutureValue' ? `Token ${s.binding}` : '';
  return [b, s.gsaIp ? `GSA ${s.gsaIp}` : ''].filter(Boolean).join(' · ') || 'n/a';
}
const day = iso => (iso ? String(iso).slice(0, 10) : 'n/a');
export const signInCells = e => {
  const beta = e.version === 'beta';
  return {
    requestId: e.id || 'n/a', user: e.userDisplayName || e.user || 'n/a', app: e.app || 'n/a', status: e.status || signInStatus(e.code),
    code: e.code === null || e.code === undefined ? 'n/a' : String(e.code),
    ip: e.ip || 'n/a', location: e.location || 'n/a', ca: caLabel(e.conditionalAccess),
    agent: beta ? agentLabel(e.agentType) : BETA_ONLY, authReq: beta ? [authLabel(e.authRequirement), methodLabel(e.methods)].filter(Boolean).join(': ') : BETA_ONLY,
    risk: riskLabel(e.risk), tenant: tenantLabel(e.tenant),
    type: beta ? eventTypeLabel(e.eventTypes) : BETA_ONLY, session: beta ? sessionLabel(e.session) : BETA_ONLY,
  };
};
// Columns over sign-in groups ({ last, event }). Date sorts by time.
export function signInColumns() {
  const c = g => signInCells(g.event);
  return [
    { key: 'si.date', label: 'Date', get: g => day(g.last), sortValue: g => g.last || 'n/a', filter: false },
    { key: 'si.request', label: 'Request ID', get: g => c(g).requestId, filter: false },
    { key: 'si.app', label: 'Application', get: g => c(g).app },
    { key: 'si.status', label: 'Status', get: g => c(g).status },
    { key: 'si.code', label: 'Sign-in error code', get: g => c(g).code },
    { key: 'si.ip', label: 'IP address', get: g => c(g).ip, filter: false },
    { key: 'si.location', label: 'Location', get: g => c(g).location },
    { key: 'si.ca', label: 'Conditional Access', get: g => c(g).ca },
    { key: 'si.risk', label: 'Risk', get: g => c(g).risk },
    { key: 'si.agent', label: 'Agent type', get: g => c(g).agent },
    { key: 'si.auth', label: 'Authentication requirement', get: g => c(g).authReq },
    { key: 'si.tenant', label: 'Tenant', get: g => c(g).tenant },
    { key: 'si.type', label: 'Sign-in type', get: g => c(g).type },
    { key: 'si.session', label: 'Session', get: g => c(g).session },
  ];
}

// Sign-ins > Detailed lookup > Conditional Access: plain result per policy, incl. report-only outcomes and auth strength.
const CA_RESULT = { success: 'Applied: passed', failure: 'Applied: blocked', notApplied: 'Not applied', notEnabled: 'Off', reportOnlySuccess: 'Report-only: would pass', reportOnlyFailure: 'Report-only: would block', reportOnlyInterrupted: 'Report-only: would prompt', reportOnlyNotApplied: 'Report-only: not applied' };
export function caResultLabel(p = {}) {
  const base = CA_RESULT[p.result] || p.result || 'Not returned';
  const s = p.authenticationStrength || p.authenticationStrengths?.[0];
  const r = s?.authenticationStrengthResult;
  const notMet = r && !['satisfied', 'notSet', 'skippedForProofUp', 'unknownFutureValue'].includes(r);
  return notMet ? `${base}; Auth strength not met${s.displayName ? `: ${s.displayName}` : ''}` : base;
}
