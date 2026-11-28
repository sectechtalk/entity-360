// Which Entity 360 app roles include another. Shared by the server (feature authorization) and the browser (nav locks
// and the denial card), so both always agree. E360.Admin includes E360.Reader: an administrator who can read everyone's
// authorization decisions can also open the reader pages. Nothing else is included: Admin does not open Sign-ins
// (E360.SignIns), Intune (E360.Intune) or Billing (E360.Billing), and no role includes Admin.
export const ROLE_INCLUDES = Object.freeze({ 'E360.Admin': Object.freeze(['E360.Reader']) });

// Does a person holding `roles` (from the validated ID token) have `role`, directly or through ROLE_INCLUDES?
export function hasRole(roles, role) {
  const held = Array.isArray(roles) ? roles : [];
  return held.includes(role) || held.some(r => (ROLE_INCLUDES[r] || []).includes(role));
}
