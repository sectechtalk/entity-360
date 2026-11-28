// NEW HIRE pages: written for someone on their first week who has heard of Entra ID, Intune and Defender but has never
// used Entity 360. Static content only (no API, no role needed), built as DOM nodes (no innerHTML).
// License facts were checked against Microsoft Learn on 2026-11-16: Entra licensing, sign-in log API (P1), log retention,
// PIM and entitlement management (P2 or ID Governance), Intune Remediations (Windows Enterprise E3/E5 class).

export const NEWHIRE_VIEWS = {
  start: ['Start here', 'What Entity 360 is, where everything lives, and what to do in your first 15 minutes.'],
  needs: ['What it needs', 'Which Entity 360 role, Entra role and license each page needs, so you know why a page is empty or locked.'],
};

// [step, what to do, page to open]
export const FIRST_STEPS = [
  ['Look at yourself first', 'Open My account > Summary. It reads your own account with your own sign-in, so it always works and shows you what every other page looks like for a real person.', 'my-summary'],
  ['Pick a person', 'Press / (or use Change user at the top) and type a name, email, app ID, device name or serial number. Summary then shows counts for that person; each count opens the page with the rows.', 'summary'],
  ['Answer "why was I blocked?"', 'Open Sign-ins and select a failed sign-in. Entity 360 shows the error, the Conditional Access policies that applied and what to change.', 'signins'],
  ['Answer "what can this person reach?"', 'Open Access: Conditional Access, admin roles and groups for the selected person. Need it for a whole group or role? Governance > Access report.', 'access'],
  ['Work the security queue', 'Open Incidents: what Defender XDR and Identity Protection raised in the last 30 days, ranked. Open person or Open device starts the investigation from the alert.', 'incidents'],
  ['Find a device', 'Device lookup takes a device name, serial number or ID and shows the device and the people who use it.', 'device'],
  ['Decode an error code', 'Tools > Error code lookup turns an AADSTS or Intune error number into plain words.', null],
];

// [menu section, what it is for]
export const MENU_MAP = [
  ['INVESTIGATE', 'The Incidents queue, then everything about one selected person, app or device: sign-ins, access, PIM, devices, Azure activity, Intune health.'],
  ['MY ACCOUNT', 'The same views for you, plus My PIM, where you turn on your own eligible roles.'],
  ['MORE TOOLS', 'Licenses, billing, onboarding steps, links to every admin portal, Defender, break-glass (emergency access) accounts and saved log queries.'],
  ['TENANT', 'Tenant-wide settings: findings, user and guest settings, domains, roles and admin units.'],
  ['ON-PREM AD', 'Whether accounts from the on-premises Active Directory are syncing to Entra ID, and the synced groups.'],
  ['AUTHENTICATION', 'Which sign-in methods are allowed, who has registered MFA, and the Conditional Access policies.'],
  ['EXTERNAL', 'Guest accounts and cross-tenant access settings.'],
  ['GOVERNANCE', 'Access packages, PIM across Entra and Azure, and the on-demand access report.'],
  ['APPS', 'Enterprise apps, app registrations and the permissions people and admins have consented to.'],
  ['TOOLS', 'Error code lookup.'],
];

export const GLOSSARY = [
  ['Entra ID', 'Microsoft\'s identity service (formerly Azure AD). Every user, group, app and sign-in Entity 360 shows comes from here.'],
  ['Conditional Access', 'Entra rules that decide whether a sign-in is allowed, needs MFA or is blocked. Most "why was I blocked?" answers are a Conditional Access policy.'],
  ['PIM', 'Privileged Identity Management. Admin roles are "eligible" and switched on for a few hours only when needed, instead of being held all the time.'],
  ['Intune', 'Microsoft\'s device management service. Entity 360 reads device compliance, health and remediation results from it.'],
  ['Defender', 'Microsoft Defender for Endpoint and the other Defender products. Entity 360 links to the Defender portals; it does not take actions there.'],
  ['Cloud Sync', 'The agent that copies on-premises Active Directory users and groups into Entra ID. ON-PREM AD > Sync health shows whether it is working.'],
  ['Enterprise app vs app registration', 'An app registration is the app\'s definition (usually owned by your company). An enterprise app is that app, or a vendor\'s app, as it exists in this tenant, with its users and permissions.'],
  ['Break-glass account', 'An emergency admin account kept out of normal policies so you can still get in if Conditional Access or MFA breaks. MORE TOOLS > Emergency access checks them.'],
];

// [question someone will ask you, where to look]
export const QUESTIONS = [
  ['"I can\'t sign in" or "it keeps asking for MFA"', 'Pick the person, then Sign-ins. Select the failed row.'],
  ['"Does this person have admin rights?"', 'Pick the person, then Access (roles) and PIM (eligible roles).'],
  ['"Who can get into this app?"', 'APPS > Enterprise apps, or GOVERNANCE > Access report for a group or role.'],
  ['"Is this laptop compliant?"', 'Device lookup, or pick the person and open Devices.'],
  ['"Did my AD change reach the cloud?"', 'ON-PREM AD > Sync health.'],
  ['"Who changed this in Azure?"', 'Pick the person, then Azure activity.'],
];

// [Entity 360 app role, how you get it, what it opens]
export const APP_ROLES = [
  ['E360.Reader', 'Group sg-e360-reader (eligible through PIM)', 'Nearly every page: INVESTIGATE, MY ACCOUNT, Licenses, Deployment, Findings and the tenant pages.'],
  ['E360.SignIns', 'App role assigned by an administrator', 'Sign-ins.'],
  ['E360.Intune', 'App role assigned by an administrator', 'Health checks and Remediation results.'],
  ['E360.Billing', 'Group sg-e360-billing (eligible through PIM)', 'Billing.'],
  ['E360.Admin', 'Group sg-e360-admin (eligible through PIM)', 'Authorization log and Access report. Includes E360.Reader.'],
];

// [Entity 360 feature, the tenant needs, your own account needs]
export const FEATURE_NEEDS = [
  ['Users, groups, roles, apps, tenant settings', 'Entra ID Free is enough.', 'A directory role that can read. Global Reader covers nearly every page.'],
  ['Sign-ins (and Last sign-in in the Access report)', 'Entra ID P1 or P2. Microsoft only returns sign-in logs through its API to P1 or P2 tenants. Logs go back 30 days (7 on Free).', 'Reports Reader, Security Reader or Global Reader.'],
  ['Conditional Access (Access tab, AUTHENTICATION > Conditional Access)', 'Entra ID P1 or P2.', 'Security Reader, Global Reader or Conditional Access Administrator.'],
  ['PIM, My PIM, GOVERNANCE > PIM', 'Entra ID P2 or Entra ID Governance.', 'To read: Global Reader or Security Reader. To activate: an eligible assignment for yourself.'],
  ['GOVERNANCE > Entitlements (access packages)', 'Entra ID P2 or Entra ID Governance (or EMS E5).', 'Global Reader or Identity Governance Administrator.'],
  ['Devices, Device lookup, Health checks', 'Intune for managed devices; Entra ID alone shows registered and joined devices.', 'An Intune role that can read (Intune Administrator or a read-only Intune role).'],
  ['Remediation results', 'Intune Remediations, which needs Windows Enterprise E3 or E5 for the device\'s user (Microsoft 365 E3, E5, F3, A3, A5 or Windows VDA).', 'An Intune role that can read.'],
  ['Azure activity, Billing, Logs', 'An Azure subscription. Logs need a Log Analytics workspace (pay as you go).', 'Reader (Azure activity), Cost Management Reader or Billing Reader (Billing), Log Analytics Reader (Logs) on the subscription.'],
  ['Defender and Azure Portals', 'Nothing in Entity 360: these pages are links. Each portal checks your own license and role.', 'Whatever the portal you open asks for.'],
  ['INVESTIGATE > Incidents', 'Microsoft Defender XDR for incidents and alerts; Entra ID P2 for risky users and risk detections. Each source works on its own.', 'Security Reader, Global Reader, Security Operator or Security Administrator. An administrator runs Grant-E360IncidentScopes.ps1 once.'],
  ['ON-PREM AD > Sync health', 'Cloud Sync or Connect Sync, which are included with Entra ID.', 'Global Reader or Hybrid Identity Administrator.'],
];

const linkTo = (el, view, label) => view ? el('a', { href: `#${view}`, textContent: label }) : el('strong', { textContent: label });
const table = (el, head, rows) => el('div', { className: 'table-wrap newhire-table' }, el('table', {},
  el('thead', {}, el('tr', {}, ...head.map(h => el('th', { scope: 'col', textContent: h })))),
  el('tbody', {}, ...rows.map(r => el('tr', {}, el('th', { scope: 'row', textContent: r[0] }), ...r.slice(1).map(c => el('td', { textContent: c })))))));

export function startPage(el) {
  return [
    el('div', { className: 'panel newhire-lead' },
      el('h2', { textContent: 'Welcome to Entity 360' }),
      el('p', { textContent: 'Entity 360 answers three questions about any person, app or device in this company: who or what is it, what can it reach, and why did that sign-in work or fail. It reads Entra ID, Intune, Defender and Azure with your own sign-in and puts the answers on one page, so you do not have to open five admin portals.' }),
      el('p', { textContent: 'It only reads. The one exception is My PIM, where you switch on your own eligible roles. Nothing you click here changes another person\'s account.' })),
    el('div', { className: 'panel' },
      el('h2', { textContent: 'Your first 15 minutes' }),
      el('ol', { className: 'newhire-steps' }, ...FIRST_STEPS.map(([title, text, view]) => el('li', {}, linkTo(el, view, title), el('span', { textContent: ` ${text}` }))))),
    el('div', { className: 'panel' },
      el('h2', { textContent: 'Questions you will be asked, and where to look' }),
      table(el, ['When someone says', 'Look here'], QUESTIONS)),
    el('div', { className: 'panel' },
      el('h2', { textContent: 'What each menu section is for' }),
      table(el, ['Section', 'What it is for'], MENU_MAP)),
    el('div', { className: 'panel' },
      el('h2', { textContent: 'Words you will hear' }),
      el('dl', { className: 'newhire-terms' }, ...GLOSSARY.flatMap(([k, v]) => [el('dt', { textContent: k }), el('dd', { textContent: v })]))),
    el('p', { className: 'muted' }, 'A page is locked or empty? ', linkTo(el, 'needs', 'What it needs'), el('span', { textContent: ' says which role or license it is waiting for.' })),
  ];
}

export function needsPage(el) {
  return [
    el('div', { className: 'panel newhire-lead' },
      el('h2', { textContent: 'Three things decide what you can see' }),
      el('ol', {},
        el('li', { textContent: 'An Entity 360 app role, which unlocks the page in Entity 360.' }),
        el('li', { textContent: 'A role on your own account (in Entra, Intune or Azure), because Entity 360 reads with your sign-in and Microsoft only returns what you are allowed to see.' }),
        el('li', { textContent: 'The tenant\'s licenses, because some data only exists with Entra ID P1, P2 or Intune.' })),
      el('p', { textContent: 'A locked page in the menu is missing (1). A page that opens but says access was refused is missing (2). A page that says the feature is not licensed is missing (3).' })),
    el('div', { className: 'panel' },
      el('h2', { textContent: 'Entity 360 app roles' }),
      table(el, ['Role', 'How you get it', 'What it opens'], APP_ROLES),
      el('p', { className: 'muted' }, 'Roles that come from a group are eligible through PIM: activate the group on ', linkTo(el, 'my-pim', 'My PIM'), el('span', { textContent: ', then select Check my roles again on the locked page.' }))),
    el('div', { className: 'panel' },
      el('h2', { textContent: 'Licenses and roles by feature' }),
      table(el, ['Entity 360 feature', 'The tenant needs', 'Your own account needs'], FEATURE_NEEDS)),
    el('div', { className: 'panel' },
      el('h2', { textContent: 'Where Entra ID licenses fit' }),
      el('dl', { className: 'newhire-terms' },
        el('dt', { textContent: 'Entra ID Free' }), el('dd', { textContent: 'Included with every Microsoft 365 and Azure subscription. Users, groups, apps, roles and tenant settings all work.' }),
        el('dt', { textContent: 'Entra ID P1' }), el('dd', { textContent: 'Adds sign-in logs through the API, 30 days of logs and Conditional Access. Included in Microsoft 365 E3, E5 and Business Premium.' }),
        el('dt', { textContent: 'Entra ID P2' }), el('dd', { textContent: 'Adds PIM, access packages and access reviews. Included in Microsoft 365 E5. Entra ID Governance is the newer add-on with the same governance features and more.' }))),
  ];
}

// Small DOM builder: properties are assigned (textContent, href, className), never parsed as HTML.
export const el = (tag, props = {}, ...kids) => { const n = Object.assign(document.createElement(tag), props); n.append(...kids.filter(k => k != null)); return n; };

export function createNewHireUi({ root }) {
  const show = (id, build) => root(id).replaceChildren(el('div', { className: 'newhire' }, ...build(el)));
  return { start: () => show('start', startPage), needs: () => show('needs', needsPage) };
}
