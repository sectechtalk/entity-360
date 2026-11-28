// In-session access re-check, the HeatMap 360 pattern. Entity 360 app roles come only from a validated ID token, and
// until now that token was read once at sign-in, so a role removed in Entra (or a PIM for Groups activation that ended)
// kept working for the rest of the 8-hour rolling session. Now a signed-in session asks Entra for a fresh ID token at
// most every ROLE_RECHECK_MS and takes its roles claim as the new truth:
//   - roles changed            -> the session's roles change at once (removed roles stop working on this request)
//   - Entra refuses the token  -> the sign-in is no longer valid (account disabled, assignment removed, password reset,
//                                 sessions revoked): the session ends and the browser is sent to sign in again
//   - Entra cannot be reached  -> roles are unconfirmed: role-gated features fail closed until a re-check succeeds,
//                                 retried at most every RECHECK_RETRY_MS
// The fresh token is requested with the session's own refresh token (delegated, same account). Nothing is retried with
// another identity.
import { rolesFromClaims } from './authflow.mjs';

export const ROLE_RECHECK_MS = 5 * 60 * 1000;
export const RECHECK_RETRY_MS = 30 * 1000;
// A forced re-check ("Check my roles again") is still limited, so a button cannot hammer the token endpoint.
export const FORCED_RECHECK_MS = 10 * 1000;

// MSAL error codes (and Entra suberrors) that mean the refresh token can no longer be used: the person has to sign in.
const SIGN_IN_REQUIRED = new Set(['invalid_grant', 'interaction_required', 'login_required', 'consent_required', 'bad_token', 'no_tokens_found',
  'refresh_token_expired', 'user_password_expired', 'basic_action', 'additional_action', 'message_only', 'no_account_in_silent_request']);

export function signInRequired(error) {
  return error?.name === 'InteractionRequiredAuthError' || SIGN_IN_REQUIRED.has(error?.errorCode) || SIGN_IN_REQUIRED.has(error?.subError);
}

// Entra's own codes, kept so a disabled account can be told apart from a network problem. No token text.
export function errorDetail(error) {
  const aadsts = /AADSTS\d+/.exec(String(error?.errorMessage || error?.message || ''))?.[0];
  return [error?.errorCode, error?.subError, aadsts].filter(Boolean).join(' / ') || String(error?.message || 'unknown error').slice(0, 120);
}

export function roleChange(before = [], after = []) {
  return { added: after.filter(r => !before.includes(r)), removed: before.filter(r => !after.includes(r)) };
}

const usable = s => s?.authType === 'confidential' && s.mode === 'live' && Boolean(s.msal) && Boolean(s.account);

// Should this request re-check first? Only confidential (hosted) live sessions carry app roles that can change.
export function recheckDue(s, now = Date.now(), { force = false, interval = ROLE_RECHECK_MS } = {}) {
  if (!usable(s)) return false;
  const c = s.rolesCheck || {};
  if (c.inflight) return true;
  if (force) return now - (c.attemptedAt ?? 0) >= FORCED_RECHECK_MS;
  if (c.failedAt) return now - c.failedAt >= RECHECK_RETRY_MS;
  return now - (c.at ?? 0) >= interval;
}

// Roles are unconfirmed after a failed re-check until one succeeds. Role-gated features then fail closed.
export const rolesUnconfirmed = s => usable(s) && Boolean(s.rolesCheck?.failedAt);

// Called once at sign-in: the ID token just redeemed is the first check.
export const markChecked = (s, now = Date.now()) => { s.rolesCheck = { at: now }; };

// One re-check. Concurrent requests of the same session share it; those that joined get `joined: true` so only the
// request that started the check logs it. Returns
//   { status: 'unchanged' | 'changed', added, removed, roles }
//   { status: 'ended', reason }        the sign-in is no longer valid; the caller ends the session
//   { status: 'unavailable', reason }  Entra did not answer usefully; roles stay as they were but are unconfirmed
export function recheckRoles(s, { scopes, tenantId, clientId, now = Date.now() }) {
  if (s.rolesCheck?.inflight) return s.rolesCheck.inflight.then(r => ({ ...r, joined: true }));
  const prior = s.rolesCheck || {};
  const inflight = (async () => {
    const fail = reason => { s.rolesCheck = { ...prior, attemptedAt: now, failedAt: now, error: reason }; return { status: 'unavailable', reason }; };
    let result;
    try { result = await s.msal.acquireTokenSilent({ account: s.account, scopes, forceRefresh: true }); }
    catch (e) {
      const reason = errorDetail(e);
      if (signInRequired(e)) { s.rolesCheck = { ...prior, attemptedAt: now, ended: true }; return { status: 'ended', reason }; }
      return fail(reason);
    }
    const claims = result?.idTokenClaims || {};
    const oid = s.account.idTokenClaims?.oid || s.account.localAccountId;
    // The fresh ID token must be for the same person, tenant and app. Anything else ends the session.
    if (!result?.account || result.account.homeAccountId !== s.account.homeAccountId) { s.rolesCheck = { ...prior, attemptedAt: now, ended: true }; return { status: 'ended', reason: 'the renewed token is for a different account' }; }
    // No new ID token in the answer: nothing to compare, so the roles cannot be confirmed.
    if (!claims.tid || !claims.oid || !claims.iat) return fail('Entra returned no new ID token');
    if (String(claims.tid).toLowerCase() !== String(tenantId).toLowerCase() || (clientId && claims.aud && claims.aud !== clientId) || (oid && String(claims.oid).toLowerCase() !== String(oid).toLowerCase())) {
      s.rolesCheck = { ...prior, attemptedAt: now, ended: true };
      return { status: 'ended', reason: 'the renewed token does not match the signed-in account' };
    }
    const before = s.appRoles || [], roles = rolesFromClaims(claims);
    const { added, removed } = roleChange(before, roles);
    s.appRoles = roles;
    s.account = result.account;
    const conn = s.connections?.get?.(s.connectionKey);
    if (conn) conn.account = result.account;
    s.rolesCheck = { at: now, attemptedAt: now };
    return { status: added.length || removed.length ? 'changed' : 'unchanged', added, removed, roles };
  })();
  s.rolesCheck = { ...prior, inflight };
  return inflight.finally(() => { if (s.rolesCheck?.inflight === inflight) delete s.rolesCheck.inflight; });
}
