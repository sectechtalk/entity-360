// Coverage bucket 5: tenant-wide pages in new nav sections. Delegated Graph and ARM reads only.
// Each page returns { tables: [{ title, note, columns, rows }], notes }. A cell is text or { text, link }.
import { fail, describeError } from './model.mjs';
import { TENANT_PAGES } from './pages/tenant.mjs';
import { AUTH_PAGES } from './pages/auth.mjs';
import { EXTERNAL_PAGES } from './pages/external.mjs';
import { GOVERNANCE_PAGES } from './pages/governance.mjs';
import { APPS_PAGES } from './pages/apps.mjs';

export const B5_PAGES = { ...TENANT_PAGES, ...AUTH_PAGES, ...EXTERNAL_PAGES, ...GOVERNANCE_PAGES, ...APPS_PAGES };
// Pages that stay out of the nav until their scope is consented. Write scopes are never requested.
export const B5_DEFERRED = [
  ['TENANT', 'Attributes', 'CustomSecAttributeDefinition.Read.All'],
  ['AUTHENTICATION', 'Passwords', 'Directory.Read.All (password protection and lockout settings) and Domain.Read.All (password expiry)'],
  ['EXTERNAL', 'Cross-tenant sync', 'Synchronization.Read.All'],
  ['EXTERNAL', 'Identity providers', 'IdentityProvider.Read.All'],
  ['GOVERNANCE', 'Terms of use', 'Agreement.Read.All'],
  ['GOVERNANCE', 'Access reviews', 'AccessReview.Read.All'],
  ['GOVERNANCE', 'PIM for Groups', 'PrivilegedAssignmentSchedule.Read.AzureADGroup and RoleManagementPolicy.Read.AzureADGroup (eligibility alone needs a group ID filter)'],
  ['GOVERNANCE', 'Lifecycle', 'LifecycleWorkflows.Read.All'],
  ['APPS', 'App Proxy', 'OnPremisesPublishingProfiles.ReadWrite.All (write scope, excluded; no read-only scope exists)'],
  ['APPS', 'Cloud Apps', 'Defender for Cloud Apps API token (not Graph, excluded)'],
];
// Partial pages: the page ships, one part waits for a scope.
export const B5_PARTIAL = [
  ['TENANT', 'Domains', 'Domain.Read.All (federation settings and DNS records)'],
  ['TENANT', 'Hybrid', 'OnPremDirectorySynchronization.Read.All (sync feature flags)'],
  ['GOVERNANCE', 'PIM', 'RoleManagementAlert.Read.Directory (PIM alerts)'],
  ['APPS', 'Consent', 'ConsentRequest.Read.All (pending admin consent requests)'],
];

export async function loadPage(api, key, ctx = {}) {
  const page = B5_PAGES[key];
  if (!page) throw fail('Unknown page.', 404);
  if (page.azure && !ctx.azure) throw fail('Connect Azure to load this page.', 409);
  const notes = [];
  const tables = (await page.load(api, { ...ctx, notes })).filter(Boolean);
  return { key, title: page.title, tables, notes };
}
// One table whose read failed becomes a note; the rest of the page still loads.
export async function part(notes, label, fn) {
  try { return await fn(); } catch (e) { notes.push(`${label}: ${describeError(e)}`); return null; }
}
export const yesNo = v => v === true ? 'Yes' : v === false ? 'No' : 'Not returned';
export const day = t => t ? String(t).slice(0, 10) : '';
