// Direct Azure and Entra portal links for the resources that host Entity 360.
// Defaults describe the current deployment; every value can be overridden with an E360_HOST_* setting.
export function hostingLinks(env = process.env) {
  const v = (k, d) => (env[k] ?? d) || '';
  const tenant = v('E360_HOST_TENANT', '00000000-0000-4000-8000-0000000000a1');
  const sub = v('E360_HOST_SUBSCRIPTION', '00000000-0000-4000-8000-0000000000a2');
  const appRg = v('E360_HOST_APP_RG', 'rg-e360'), app = v('E360_HOST_CONTAINER_APP', 'app-e360'), envName = v('E360_HOST_ENVIRONMENT', 'cae-e360');
  const kvRg = v('E360_HOST_KEYVAULT_RG', 'rg-entity360'), kv = v('E360_HOST_KEYVAULT', 'kv-e360-auth-xxxxx');
  const appId = v('E360_HOST_APP_ID', '00000000-0000-4000-8000-0000000000a3'), spId = v('E360_HOST_SP_ID', '00000000-0000-4000-8000-0000000000a4');
  const workspace = v('E360_HOST_LOG_WORKSPACE', '');
  const res = (rg, type, name, blade = 'overview') => `https://portal.azure.com/#@${tenant}/resource/subscriptions/${sub}/resourceGroups/${rg}/providers/${type}/${name}/${blade}`;
  const reg = tab => `https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/${tab}/appId/${appId}`;
  const ent = tab => `https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ManagedAppMenuBlade/~/${tab}/objectId/${spId}/appId/${appId}`;
  const CA = 'Microsoft.App/containerApps', KV = 'Microsoft.KeyVault/vaults';
  return [
    { group: 'Container App', name: app, links: [
      { label: 'Overview', url: res(appRg, CA, app) },
      { label: 'Revisions', url: res(appRg, CA, app, 'revisionManagement') },
      { label: 'Log stream', url: res(appRg, CA, app, 'logstream') },
      { label: 'Managed identity', url: res(appRg, CA, app, 'identity') },
      { label: 'Environment', url: res(appRg, 'Microsoft.App/managedEnvironments', envName) },
    ] },
    { group: 'Key Vault', name: kv, links: [
      { label: 'Keys', url: res(kvRg, KV, kv, 'keys') },
      { label: 'Access control', url: res(kvRg, KV, kv, 'users') },
    ] },
    { group: 'App registration', name: 'Entity 360', links: [
      { label: 'Overview', url: reg('Overview') },
      { label: 'Certificates & secrets', url: reg('Credentials') },
      { label: 'API permissions', url: reg('CallAnAPI') },
      { label: 'App roles', url: reg('AppRoles') },
    ] },
    { group: 'Enterprise application', name: 'Entity 360', links: [
      { label: 'Users and groups', url: ent('Users') },
      { label: 'Permissions (consent)', url: ent('Permissions') },
      { label: 'Sign-in logs', url: ent('SignIns') },
    ] },
    { group: 'Logs', name: workspace ? workspace.split('/').pop() : 'Log Analytics', links: workspace
      ? [{ label: 'Logs', url: `https://portal.azure.com/#@${tenant}/resource${workspace}/logs` }]
      : [{ label: 'Not configured', reason: `The ${envName} environment sends logs nowhere, so past container logs are not kept. Use Log stream for live output.` }] },
  ];
}
