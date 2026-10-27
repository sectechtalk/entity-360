// Shared wording for the App permissions tab and the Partial results banner (no DOM, so it is unit-tested).
// Names each incomplete source and why; sources not granted are listed separately because they are missing, not incomplete.
export function partialMessage(r) {
  const reasons = (r.partialReasons || []).map(x => `${x.source}: ${x.reason}`);
  const missing = (r.unavailable || []).map(x => `${x.source} (${x.reason})`);
  return `Partial results. ${reasons.length ? reasons.join('. ') + '.' : 'A query reached a limit or could not finish.'}${missing.length ? ` Not available: ${missing.join('; ')}.` : ''}`;
}
// Plain-language meaning of each Kind and Status on the App permissions tab.
export const APP_LEGEND = {
  'Application assignment': 'The user (directly or through a group) is assigned to an enterprise app, usually with an app role. It controls who may sign in to that app or what role the app sees.',
  'API permission': 'An application permission (app-only) granted to this app on another API; it works without a signed-in user.',
  'Delegated permission': 'Consent letting an app act as a signed-in user with the listed scopes, for one user or for all users (admin consent).',
  Credential: 'A client secret or certificate on the app registration, used by the app to prove its identity.',
  Assigned: 'The assignment exists now.', Granted: 'Admin consent for the application permission exists now.', Consented: 'The delegated consent exists now.',
  Configured: 'The credential is present and not expired.', Expired: 'The credential end date has passed; it no longer works.',
};

// Which tab shows which source's data. The Partial results banner appears only on the tab whose data is affected and
// lists only that tab's sources; Summary and Health checks cover every source. Unlisted tabs never show it.
export const TAB_SOURCES = {
  signins: ['Entra sign-ins'],
  access: ['Entra directory', 'Entra roles & PIM', 'Azure PIM', 'Azure Monitor & IAM', 'Conditional Access'],
  devices: ['Intune devices'],
  activity: ['Entra audit', 'Azure Monitor & IAM', 'Graph request logs', 'Microsoft 365 audit logs', 'Application Insights', 'Purview audit'],
};
const ALL_TABS = ['summary', 'health'];
// A source like 'Entra directory (delegated consents)' belongs to the tab of 'Entra directory'.
const baseName = source => String(source).replace(/\s*\(.*\)$/, '');
export function sourcesForView(view) { return ALL_TABS.includes(view) ? null : TAB_SOURCES[view] || []; }
export function bannerFor(r, view) {
  if (!r) return '';
  const allowed = sourcesForView(view);
  const keep = x => allowed === null || allowed.includes(baseName(x.source));
  const scoped = { partialReasons: (r.partialReasons || []).filter(keep), unavailable: (r.unavailable || []).filter(keep) };
  // Shown only when this tab has an incomplete source; missing (not granted) sources are listed alongside it.
  return scoped.partialReasons.length ? partialMessage(scoped) : '';
}
