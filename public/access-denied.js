// Friendly in-page denial for pages the signed-in user lacks an app role for.
// Roles granted through a PIM-for-Groups group: activate the group, then sign in again so the token carries the role.
export const ROLE_GROUPS = { 'E360.Reader': 'sg-e360-reader', 'E360.Billing': 'sg-e360-billing', 'E360.Admin': 'sg-e360-admin' };
import { PIM_ACTIVATION_LINKS } from './device-links.js';
// The app keeps PIM activation links in one place (device-links.js); reuse its Groups tab.
export const PIM_GROUPS_URL = PIM_ACTIVATION_LINKS.find(([label]) => label === 'Groups')[1];
// Pages whose data needs a specific role (server ROUTE_ROLES is the source of truth; this drives the nav lock).
export const VIEW_ROLES = {
  signins: 'E360.SignIns', health: 'E360.Intune', remediation: 'E360.Intune', billing: 'E360.Billing', licenses: 'E360.Reader',
  'my-summary': 'E360.Reader', 'my-signins': 'E360.Reader', 'my-access': 'E360.Reader', 'my-device': 'E360.Reader', pim: 'E360.Reader', authz: 'E360.Admin', 'g-access-report': 'E360.Admin',
};

export function missingRole(session, view) {
  const role = VIEW_ROLES[view];
  if (!role || !session?.rolesEnforced) return null;
  return (session.appRoles || []).includes(role) ? null : role;
}

const escape = value => String(value ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

export function deniedHtml(role) {
  const group = ROLE_GROUPS[role];
  const how = group
    ? `<p>${escape(role)} is granted through the group <strong>${escape(group)}</strong>. If you are eligible, activate it on MY ACCOUNT &gt; My PIM. Then sign out and back in after activating so Entity 360 sees the new role.</p>
<div class="card-actions"><button type="button" class="btn" data-go="my-pim">Activate in PIM (groups)</button><a class="btn" href="${PIM_GROUPS_URL}" target="_blank" rel="noopener noreferrer">Microsoft PIM portal</a><button type="button" class="btn" data-denied-signin>Sign in again</button></div>
<p class="muted">Not eligible? Ask your administrator to add you to ${escape(group)}.</p>`
    : `<p>Ask your administrator to assign you the ${escape(role)} app role for Entity 360. After it is assigned, sign in again so Entity 360 sees it.</p>
<div class="card-actions"><button type="button" class="btn" data-denied-signin>Sign in again</button></div>`;
  return `<section class="panel denied-card" role="alert"><h2><span class="denied-lock" aria-hidden="true"></span>You don't have access to this page</h2><p>This page needs the <strong>${escape(role)}</strong> role, and your current sign-in does not include it.</p>${how}</section>`;
}