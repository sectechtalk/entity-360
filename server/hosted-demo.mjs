import { GUID, fail } from './model.mjs';
import { CONSUMER_TENANT } from './connections.mjs';

// Hosted demo (E360_HOSTED_DEMO=true): one public Entity 360 that anyone can sign in to with their OWN Entra tenant.
// Rules, all enforced here or in server/index.mjs:
//   - sign-in goes through /organizations; the visitor's tenant comes from the token (tid) and is checked against iss
//   - one tenant per browser session; no switching or adding tenants; no device code; no portfolio discovery
//   - read-only: write scopes are never requested and write routes answer 403
//   - nothing about a visitor is kept: tokens live only in this process's memory, sessions end after 60 idle minutes,
//     the durable audit store is off and audit lines carry no user names
//   - nothing about the host's own tenant is shown (hosting links, lab users, fleet deployment log, default tenant)
export const HOSTED_IDLE_MS = 60 * 60 * 1000;
export const HOSTED_TENANT_LIMIT = 600; // API requests per minute per visitor tenant

export const isHostedDemo = (env = process.env) => env.E360_HOSTED_DEMO === 'true';

// Delegated scopes that can change something are dropped: ReadWrite, Write, and Intune privileged device actions.
const WRITE_SCOPE = /(ReadWrite|\.Write\b|PrivilegedOperations)/i;
export const readOnlyScopes = scopes => scopes.filter(s => !WRITE_SCOPE.test(s));

// Routes that write, act on the server host, read the host's own data, or mix tenants. Prefix match.
export const HOSTED_BLOCKED = [
  ['POST', '/api/me/pim/request', 'PIM activation changes your tenant.'],
  ['POST', '/api/intune/remediation-run', 'Running a remediation changes a device.'],
  ['GET', '/api/intune/remediation-runs', 'The run log is not kept in the hosted demo.'],
  ['GET', '/api/authz', 'The authorization log is not kept in the hosted demo.'],
  ['POST', '/api/device/collect', 'Collection would run on the demo server, not your computer.'],
  ['POST', '/api/portfolio/discover', 'The hosted demo reads one tenant per session.'],
  ['POST', '/api/auth/start', 'Sign out and sign in again to use another account or tenant.'],
  ['POST', '/api/connections/switch', 'The hosted demo reads one tenant per session.'],
  ['GET', '/api/deployment-log', 'The fleet deployment log belongs to the demo host.'],
];

export function hostedBlock(method, path) {
  const hit = HOSTED_BLOCKED.find(([m, prefix]) => m === method && (path === prefix || path.startsWith(prefix + '/')));
  return hit ? hit[2] : null;
}

// The visitor's tenant, from an MSAL authorization-code result. MSAL already checked the nonce and that the ID token
// came from the token endpoint; this ties tid, iss and the account together (Microsoft identity platform token
// validation for multitenant apps: iss must be https://login.microsoftonline.com/{tid}/v2.0).
export function visitorTenant(result) {
  const claims = result?.idTokenClaims || {};
  const tid = String(claims.tid || '').toLowerCase();
  if (!GUID.test(tid)) throw fail('wrong_tenant', 401);
  if (tid === CONSUMER_TENANT) throw fail('personal_account', 401);
  if (claims.iss !== `https://login.microsoftonline.com/${tid}/v2.0`) throw fail('wrong_issuer', 401);
  if (String(result?.account?.tenantId || '').toLowerCase() !== tid) throw fail('wrong_tenant', 401);
  return tid;
}

// Audit lines in the hosted demo keep what happened and in which tenant, never who (no UPN, name or email).
const PERSONAL = new Set(['user', 'upn', 'username', 'email', 'name', 'requester']);
export function redactAudit(entry) {
  const out = {};
  for (const [k, v] of Object.entries(entry || {})) if (!PERSONAL.has(k)) out[k] = v;
  return out;
}

export function hostedAudit(audit) {
  const record = audit.record.bind(audit);
  audit.record = entry => record(redactAudit(entry));
  return audit;
}

// Messages a visitor sees when sign-in stops at consent. AADSTS65001: consent missing; AADSTS90094 / 90095: admin approval needed.
export function hostedSignInError(detail, consentUrl) {
  if (/AADSTS(65001|90094|90095|65004)/.test(detail || '') || /consent_required|interaction_required/.test(detail || ''))
    return `Your organization has not approved Entity 360 yet. A Global Administrator or Privileged Role Administrator of your tenant opens ${consentUrl} once and accepts for the organization; then sign in again. (${detail})`;
  return null;
}
