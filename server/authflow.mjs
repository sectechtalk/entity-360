import { randomBytes } from 'node:crypto';

// Feature authorization for Entity 360 itself. App roles say which Entity 360 features a person may open. They never
// grant access to a source: each backend call still runs with the viewer's own delegated token, and the source
// decides. A denial is final; nothing in this module (or its callers) retries a denied read with another identity.

export const APP_ROLES = ['E360.Reader', 'E360.SignIns', 'E360.Intune', 'E360.Billing'];

// Backend route prefix -> the app role that opens it. Longest prefix wins. Routes not listed need only a session.
export const ROUTE_ROLES = [
  ['/api/signins', 'E360.SignIns'],
  ['/api/intune', 'E360.Intune'],
  ['/api/billing', 'E360.Billing'],
  ['/api/portfolio', 'E360.Billing'],
  ['/api/licenses', 'E360.Reader'],
  ['/api/account', 'E360.Reader'],
  ['/api/entities', 'E360.Reader'],
  ['/api/investigate', 'E360.Reader'],
  ['/api/activity', 'E360.Reader'],
  ['/api/device', 'E360.Reader'],
];
export const roleForPath = path => ROUTE_ROLES.filter(([prefix]) => path === prefix || path.startsWith(prefix + '/')).sort((a, b) => b[0].length - a[0].length)[0]?.[1] ?? null;

// Roles come only from claims of a token that MSAL validated for Entity 360's own registration (the ID token).
// Unknown role names are dropped so a stray claim cannot widen access.
export function rolesFromClaims(claims) {
  const raw = Array.isArray(claims?.roles) ? claims.roles : [];
  return [...new Set(raw.filter(r => typeof r === 'string' && APP_ROLES.includes(r)))];
}

// Decision for one request. mode: 'demo' (fictional data, always allowed), 'live' (real sources).
export function decide({ mode, path, roles, enforce }) {
  const needed = roleForPath(path);
  if (mode === 'demo') return { allowed: true, needed, reason: 'demo data' };
  if (!needed) return { allowed: true, needed: null, reason: 'no feature role required' };
  if (!enforce) return { allowed: true, needed, reason: 'app roles not enforced for this sign-in type' };
  // E360.Billing and the others do not imply each other; only an exact role opens a feature.
  return roles.includes(needed) ? { allowed: true, needed, reason: 'role present' } : { allowed: false, needed, reason: 'role missing' };
}

// Authorization decision log: every allow, deny and unknown. Kept in memory with a bound; optionally appended to a
// file by the caller. No tokens, no query text.
export class DecisionLog {
  constructor(limit = 500) { this.limit = limit; this.rows = []; }
  add({ user, tenant, source, path, outcome, reason, needed }) {
    const row = { time: new Date().toISOString(), user: user || null, tenant: tenant || null, source: source || 'entity360', path, outcome, reason, role: needed || null };
    this.rows.push(row);
    if (this.rows.length > this.limit) this.rows.shift();
    return row;
  }
  list(n = 100) { return this.rows.slice(-n).reverse(); }
}

// Authorization-code + PKCE: one pending request per browser session, single use, short lived.
export function newPending(crypto, now = Date.now()) {
  return { state: randomBytes(24).toString('hex'), nonce: randomBytes(16).toString('hex'), verifier: crypto.verifier, challenge: crypto.challenge, created: now };
}
export const PENDING_TTL = 10 * 60 * 1000;
export function checkCallback(pending, query, now = Date.now()) {
  if (!pending) return 'No sign-in is in progress. Start again.';
  if (now - pending.created > PENDING_TTL) return 'The sign-in expired. Start again.';
  if (query.error) return 'Microsoft did not complete the sign-in.';
  if (typeof query.state !== 'string' || query.state !== pending.state) return 'The sign-in response did not match this browser session.';
  if (typeof query.code !== 'string' || query.code.length < 10) return 'The sign-in response had no authorization code.';
  return null;
}

// Conditional Access / continuous access evaluation can answer a Graph call with 401 and a claims challenge. Surface it
// as a re-authentication requirement, never as "no data".
export function claimsChallenge(wwwAuthenticate) {
  const m = /claims="([^"]+)"/i.exec(String(wwwAuthenticate || ''));
  if (!m) return null;
  try { return Buffer.from(m[1], 'base64').toString('utf8'); } catch { return null; }
}
