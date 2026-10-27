// Azure and Microsoft 365 portal index. Static links only: nothing here calls a Microsoft API.
// Deep links open the right blade once the browser is signed in; the portal itself enforces access.
const GROUPS = [
  { title: 'Admin centers', links: [
    ['Azure portal', 'https://portal.azure.com/', 'Subscriptions, resources, Arc, Key Vault, cost'],
    ['Microsoft Entra admin center', 'https://entra.microsoft.com/', 'Users, groups, apps, Conditional Access, sign-in logs'],
    ['Microsoft 365 admin center', 'https://admin.microsoft.com/', 'Users, licenses, billing, service health'],
    ['Microsoft Intune admin center', 'https://intune.microsoft.com/', 'Devices, compliance, configuration'],
    ['Microsoft Defender portal', 'https://security.microsoft.com/', 'Incidents, advanced hunting, Defender for Office/Endpoint'],
    ['Microsoft Purview portal', 'https://purview.microsoft.com/', 'DLP, sensitivity labels, retention, audit'],
    ['Exchange admin center', 'https://admin.exchange.microsoft.com/', 'Mailboxes, mail flow, connectors'],
    ['Teams admin center', 'https://admin.teams.microsoft.com/', 'Teams policies and devices'],
    ['SharePoint admin center', 'https://sectechtalk-admin.sharepoint.com/', 'Sites and sharing (SecTechTalk tenant)'],
    ['Power Platform admin center', 'https://admin.powerplatform.microsoft.com/', 'Environments and data policies'],
  ] },
  { title: 'Azure resources', links: [
    ['Subscriptions', 'https://portal.azure.com/#browse/Microsoft.Resources%2Fsubscriptions', 'Free Azure Trial and Azure subscription 1'],
    ['Resource groups', 'https://portal.azure.com/#browse/resourcegroups', 'rg-fleet, rg-entity360, rg-example, labs'],
    ['Azure Arc machines', 'https://portal.azure.com/#browse/Microsoft.HybridCompute%2Fmachines', 'DEVICE01, DEVICE03, DEVICE02, DEVICE04'],
    ['Azure Arc center', 'https://portal.azure.com/#view/Microsoft_Azure_HybridCompute/AzureArcCenterBlade/~/overview', 'Arc overview: servers, Kubernetes, data services'],
    ['Key vaults', 'https://portal.azure.com/#browse/Microsoft.KeyVault%2Fvaults', 'kv-e360-auth-xxxxx (Entity 360 sign-in certificate)'],
    ['App Services', 'https://portal.azure.com/#browse/Microsoft.Web%2Fsites', 'Lab web apps'],
    ['Log Analytics workspaces', 'https://portal.azure.com/#browse/Microsoft.OperationalInsights%2Fworkspaces', 'law-breakglass'],
    ['Azure Cloud Shell', 'https://shell.azure.com/', 'Browser shell with Azure CLI and PowerShell'],
  ] },
  { title: 'Identity and Conditional Access', links: [
    ['Conditional Access policies', 'https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies', 'E360 - Require MFA and others'],
    ['Sign-in logs', 'https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/SignIns', 'Authentication details, Conditional Access, Report-only'],
    ['Audit logs', 'https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/Audit', 'Who changed what'],
    ['Devices', 'https://entra.microsoft.com/#view/Microsoft_AAD_Devices/DevicesMenuBlade/~/Devices', 'Entra joined and registered devices'],
    ['Privileged Identity Management', 'https://entra.microsoft.com/#view/Microsoft_Azure_PIMCommon/CommonMenuBlade/~/quickStart', 'Eligible roles and PIM for Groups'],
    ['Mobility (MDM and MAM)', 'https://entra.microsoft.com/#view/Microsoft_AAD_IAM/MobilityManagementMenuBlade/~/MobilityManagement', 'Intune enrollment scope'],
    ['Intune tenant status', 'https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/TenantAdminMenu/~/tenantStatus', 'Tenant health and MDM authority'],
  ] },
  { title: 'Billing and cost', links: [
    ['Cost Management + Billing', 'https://portal.azure.com/#view/Microsoft_Azure_Billing/ModernBillingMenuBlade/~/Overview', 'Billing accounts, invoices, cost analysis, budgets'],
    ['Microsoft 365 billing', 'https://admin.microsoft.com/#/subscriptions', 'Microsoft 365 subscriptions and invoices'],
    ['Licenses', 'https://admin.microsoft.com/#/licenses', 'Assigned and available seats per product'],
    ['Buy licenses', 'https://admin.microsoft.com/#/catalog', 'Purchase services, e.g. Microsoft Entra ID P2'],
    ['Microsoft account billing', 'https://account.microsoft.com/billing/orders', 'Personal Microsoft account orders'],
    ['Azure subscriptions (cost and budgets)', 'https://portal.azure.com/#browse/Microsoft.Resources%2Fsubscriptions', 'Open a subscription, then Cost analysis or Budgets'],
  ] },
  { title: 'Your own account', links: [
    ['My Account', 'https://myaccount.microsoft.com/', 'Profile, devices, organizations'],
    ['Security info', 'https://mysignins.microsoft.com/security-info', 'Authenticator, passkeys, sign-in methods'],
    ['My Apps', 'https://myapps.microsoft.com/', 'Apps assigned to you'],
    ['My Access', 'https://myaccess.microsoft.com/', 'Access packages and access reviews'],
    ['My Groups', 'https://mygroups.microsoft.com/', 'Groups you own or belong to'],
  ] },
  { title: 'Developer and status', links: [
    ['Azure DevOps', 'https://dev.azure.com/', 'All your Azure DevOps organizations'],
    ['Azure DevOps: sectechtalk-e360', 'https://dev.azure.com/sectechtalk-e360', 'Entity 360 organization'],
    ['Azure DevOps: SecTechTalk', 'https://dev.azure.com/SecTechTalk', 'SecTechTalk organization'],
    ['Graph Explorer', 'https://developer.microsoft.com/graph/graph-explorer', 'Try Microsoft Graph queries'],
    ['Microsoft 365 service health', 'https://admin.microsoft.com/#/servicehealth', 'Incidents and advisories for this tenant'],
    ['Azure status', 'https://azure.status.microsoft/', 'Public Azure status'],
    ['Microsoft Learn', 'https://learn.microsoft.com/', 'Documentation'],
  ] },
];

// Defender workloads. Most now live inside the Defender portal; each note names the menu path in case a deep link moves.
const DEFENDER = [
  { title: 'Microsoft Defender portals', links: [
    ['Microsoft Defender for Identity', 'https://security.microsoft.com/settings/identities', 'Defender portal > Settings > Identities (sensors, health, exclusions)'],
    ['Microsoft Defender for Cloud Apps', 'https://security.microsoft.com/cloudapps', 'Defender portal > Cloud apps (discovery, app governance, policies)'],
    ['Microsoft Defender for Cloud', 'https://portal.azure.com/#view/Microsoft_Azure_Security/SecurityMenuBlade/~/0', 'Azure portal > Microsoft Defender for Cloud (also Defender portal > Cloud security)'],
    ['Microsoft Defender for IoT', 'https://portal.azure.com/#view/Microsoft_Azure_IoT_Defender/IoTDefenderDashboard/~/Getting_started', 'Azure portal > Microsoft Defender for IoT (enterprise IoT also in Defender portal > Assets > Devices)'],
    ['Microsoft Defender Vulnerability Management', 'https://security.microsoft.com/tvm_dashboard', 'Defender portal > Exposure management > Vulnerability management'],
    ['Microsoft Defender for Business', 'https://security.microsoft.com/', 'Defender portal home (Defender for Business uses the same portal)'],
  ] },
];

function linkView(groups, selector, { esc, external }) {
  let rendered = false;
  function render() {
    if (rendered) return;
    rendered = true;
    document.querySelector(selector).innerHTML = groups.map(g => `<section class="panel account-card"><div class="panel-heading"><h2>${esc(g.title)}</h2></div><ul class="portal-links">${g.links.map(([name, url, note]) => `<li>${external(url, name)}<small>${esc(note)}</small></li>`).join('')}</ul></section>`).join('');
  }
  return { setActive(value) { if (value) render(); } };
}
export const createPortalsView = helpers => linkView(GROUPS, '#portals-list', helpers);
export const createDefenderView = helpers => linkView(DEFENDER, '#defender-list', helpers);
