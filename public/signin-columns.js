// Sign-ins table columns (Aaron, 2026-10-25): Date, Request ID, Application, Status, Sign-in error code, IP address,
// Location, Conditional Access, Agent type, Authentication requirement. Agent type (signIn.agent.agentType) and
// authenticationRequirement exist only in Graph beta; v1.0 rows show an em dash. filter:false = not a category (no header filter).
export const SIGNIN_HEADERS = ['Date', 'Request ID', 'Application', 'Status', 'Sign-in error code', 'IP address', 'Location', 'Conditional Access', 'Agent type', 'Authentication requirement'];
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
const day = iso => (iso ? String(iso).slice(0, 10) : 'n/a');
export const signInCells = e => {
  const beta = e.version === 'beta';
  return {
    requestId: e.id || 'n/a', user: e.userDisplayName || e.user || 'n/a', app: e.app || 'n/a', status: e.status || signInStatus(e.code),
    code: e.code === null || e.code === undefined ? 'n/a' : String(e.code),
    ip: e.ip || 'n/a', location: e.location || 'n/a', ca: caLabel(e.conditionalAccess),
    agent: beta ? agentLabel(e.agentType) : BETA_ONLY, authReq: beta ? authLabel(e.authRequirement) : BETA_ONLY,
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
    { key: 'si.agent', label: 'Agent type', get: g => c(g).agent },
    { key: 'si.auth', label: 'Authentication requirement', get: g => c(g).authReq },
  ];
}
