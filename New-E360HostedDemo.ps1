<#
.SYNOPSIS
  Create (or remove) the hosted Entity 360 demo that anyone can sign in to with their OWN Entra tenant. Dry run by default.
.DESCRIPTION
  Default: read-only lookups, then prints every az command it WOULD run. -Apply runs them. -Remove -Apply undoes them.

  What it creates (nothing else is touched; your private app-e360 and its registration stay as they are):
    1. App registration "Entity 360 (hosted demo)", multi-tenant (AzureADMultipleOrgs), delegated Microsoft Graph READ
       scopes only, and the existing Key Vault certificate (same key, no new secret) as its credential.
    2. Container app app-e360-demo in the existing environment cae-e360: consumption plan, min 0 / max 1 replica,
       0.25 vCPU / 0.5 GiB, system-assigned managed identity, external HTTPS ingress, E360_HOSTED_DEMO=true.
    3. Key Vault Crypto User for that identity on the certificate key only (or keys get,sign on an access-policy vault).
    4. Redirect URI https://<fqdn>/auth/callback on the new registration, then PUBLIC_BASE_URL on the app.
  With -Apply it verifies: the home page shows the hosted demo welcome page and /auth/login redirects to
  login.microsoftonline.com/organizations.

  COST (estimate): $0 a month while use stays inside the Container Apps free grant (180,000 vCPU-seconds and
  360,000 GiB-seconds per subscription per month, about 200 active hours at this size, shared with any other container
  app in the subscription). Above that, about $0.03 per active hour. No Log Analytics workspace is created. The app
  registration, managed identity and role assignment are free. Key Vault signing is about $0.03 per 10,000 sign-ins.

  The image must contain the hosted demo code (the Entity 360 hosted demo release). -Image omitted: the newest dated tag in
  GHCR is used, so build and push first with C:\path\to\scripts\Build-E360Image.ps1 -Apply -Push.
.EXAMPLE
  .\New-E360HostedDemo.ps1                 # dry run
  .\New-E360HostedDemo.ps1 -Apply          # create and verify
  .\New-E360HostedDemo.ps1 -Remove -Apply  # delete the demo container app and the demo app registration
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive operator console script')]
[CmdletBinding()]
param(
  [switch]$Apply,
  [switch]$Remove,
  [string]$ResourceGroup = 'rg-e360',
  [string]$EnvironmentName = 'cae-e360',
  [string]$AppName = 'app-e360-demo',
  [string]$DisplayName = 'Entity 360 (hosted demo)',
  [string]$Image = '',
  [string]$ImageRepo = 'ghcr.io/your-org/entity-360',
  [string]$VaultName = 'kv-e360-auth-xxxxx',
  [string]$CertName = 'entity360-auth'
)
$ErrorActionPreference = 'Stop'
$mode = if ($Apply) { 'APPLY' } else { 'DRY RUN' }
$graphApi = '00000003-0000-0000-c000-000000000000'
# Delegated Microsoft Graph scopes the hosted demo asks for. Read only: no ReadWrite, Write or PrivilegedOperations scope.
$scopes = @('User.Read','User.Read.All','Application.Read.All','GroupMember.Read.All','AuditLog.Read.All','Policy.Read.All',
  'RoleManagement.Read.Directory','DeviceManagementManagedDevices.Read.All','DeviceManagementScripts.Read.All','ThreatHunting.Read.All',
  'Device.Read.All','Organization.Read.All','DeviceManagementConfiguration.Read.All','DeviceManagementServiceConfig.Read.All',
  'EntitlementManagement.Read.All','AdministrativeUnit.Read.All','PrivilegedEligibilitySchedule.Read.AzureADGroup',
  'RoleEligibilitySchedule.Read.Directory','RoleAssignmentSchedule.Read.Directory','RoleManagementPolicy.Read.Directory',
  'RoleManagementPolicy.Read.AzureADGroup')

function Format-Az([string[]]$a) { 'az ' + (($a | ForEach-Object { if ($_ -match '[\s;|&]') { "'$_'" } else { $_ } }) -join ' ') }
function Get-Az([string[]]$a) {
  $out = & az @a 2>$null
  if ($LASTEXITCODE -ne 0) { return '' }
  return (($out | Out-String).Trim())
}
function Invoke-Az([string[]]$a) {
  Write-Host "   $(Format-Az $a)" -ForegroundColor DarkGray
  if (-not $Apply) { return '' }
  $out = & az @a
  if ($LASTEXITCODE -ne 0) { throw "az failed: $(Format-Az $a)" }
  return (($out | Out-String).Trim())
}
function Get-NewestTag([string]$repo) {
  $path = $repo -replace '^ghcr\.io/', ''
  $token = (Invoke-RestMethod "https://ghcr.io/token?scope=repository:${path}:pull").token
  $tags = (Invoke-RestMethod "https://ghcr.io/v2/$path/tags/list?n=1000" -Headers @{ Authorization = "Bearer $token" }).tags
  return @($tags | Where-Object { $_ -match '^\d{8}-?\d{4}$' } | Sort-Object { $_ -replace '-', '' } -Descending)[0]
}

Write-Host "Entity 360 hosted demo - $(if ($Remove) { 'REMOVE' } else { 'CREATE' }) - $mode" -ForegroundColor Cyan
$account = Get-Az @('account','show','--query','{name:name,user:user.name,tenant:tenantId}','-o','json') | ConvertFrom-Json
if (-not $account) { throw 'Run az login first.' }
Write-Host "  az signed in as $($account.user), subscription '$($account.name)', tenant $($account.tenant)"
$tenantId = $account.tenant
$appId = Get-Az @('ad','app','list','--display-name',$DisplayName,'--query','[0].appId','-o','tsv')
$appExists = [bool](Get-Az @('containerapp','show','-g',$ResourceGroup,'-n',$AppName,'--query','name','-o','tsv'))
Write-Host "  App registration '$DisplayName': $(if ($appId) { $appId } else { 'not created yet' })"
Write-Host "  Container app ${AppName}: $(if ($appExists) { 'exists' } else { 'not created yet' })"

if ($Remove) {
  if ($appExists) { Write-Host "1. Delete container app $AppName (its managed identity and role assignment go with it)"; Invoke-Az @('containerapp','delete','-g',$ResourceGroup,'-n',$AppName,'--yes','-o','none') | Out-Null }
  else { Write-Host "1. Container app $AppName not found - nothing to delete." }
  if ($appId) { Write-Host "2. Delete app registration '$DisplayName' ($appId). Visitors' tenants keep an inert enterprise app until they delete it."; Invoke-Az @('ad','app','delete','--id',$appId) | Out-Null }
  else { Write-Host "2. App registration '$DisplayName' not found - nothing to delete." }
  Write-Host "Done ($mode).$(if (-not $Apply) { ' Nothing was changed. Re-run with -Apply to execute.' })" -ForegroundColor Green
  return
}

# Prerequisites: the environment and the vault certificate already exist from the private Entity 360 deployment.
if (-not (Get-Az @('containerapp','env','show','-g',$ResourceGroup,'-n',$EnvironmentName,'--query','name','-o','tsv'))) { throw "Container Apps environment $EnvironmentName was not found in $ResourceGroup." }
$thumb = Get-Az @('keyvault','certificate','show','--vault-name',$VaultName,'-n',$CertName,'--query','x509ThumbprintHex','-o','tsv')
if ($thumb -notmatch '^[0-9A-Fa-f]{40}$') { throw "Certificate $CertName was not found in Key Vault $VaultName (or you cannot read it)." }
$vault = Get-Az @('keyvault','show','-n',$VaultName,'--query','{id:id,rbac:properties.enableRbacAuthorization}','-o','json') | ConvertFrom-Json
Write-Host "  Key Vault $VaultName certificate $CertName thumbprint $thumb ($(if ($vault.rbac) { 'RBAC vault' } else { 'access-policy vault' }))"
if (-not $Image) {
  $tag = Get-NewestTag $ImageRepo
  if (-not $tag) { throw "No dated tag found in $ImageRepo. Build and push first: C:\path\to\scripts\Build-E360Image.ps1 -Apply -Push" }
  $Image = "${ImageRepo}:$tag"
}
if ($Image -notmatch ':\d{8}-?\d{4}$') { throw "Use a dated image tag (for example ${ImageRepo}:20261117-0500), never :latest." }
Write-Host "  Image $Image (must be built after the hosted demo PR merged)"
Write-Host ''
Write-Host 'Cost: $0 a month inside the Container Apps free grant (about 200 active hours a month at 0.25 vCPU / 0.5 GiB);' -ForegroundColor Yellow
Write-Host '      about $0.03 per active hour above it. Scales to zero when nobody is signed in. No Log Analytics workspace.' -ForegroundColor Yellow
Write-Host ''

Write-Host "1. Multi-tenant app registration '$DisplayName'"
if ($appId) { Write-Host '   Exists - kept.' }
else {
  $created = Invoke-Az @('ad','app','create','--display-name',$DisplayName,'--sign-in-audience','AzureADMultipleOrgs','--query','appId','-o','tsv')
  $appId = if ($Apply) { $created } else { '<new appId>' }
}

Write-Host "2. Delegated Microsoft Graph read scopes ($($scopes.Count)) on the registration"
$graphScopes = Get-Az @('ad','sp','show','--id',$graphApi,'--query','oauth2PermissionScopes[].{v:value,id:id}','-o','json') | ConvertFrom-Json
$perms = foreach ($s in $scopes) { $hit = $graphScopes | Where-Object { $_.v -eq $s } | Select-Object -First 1; if (-not $hit) { throw "Graph scope $s was not found." }; "$($hit.id)=Scope" }
Invoke-Az (@('ad','app','permission','add','--id',$appId,'--api',$graphApi,'--api-permissions') + $perms) | Out-Null

Write-Host "3. Credential: the existing Key Vault certificate $CertName (public part only; the key never leaves the vault)"
Invoke-Az @('ad','app','credential','reset','--id',$appId,'--keyvault',$VaultName,'--cert',$CertName,'--append','-o','none') | Out-Null

Write-Host "4. Container app $AppName (min 0 / max 1, 0.25 vCPU / 0.5 GiB, E360_HOSTED_DEMO=true)"
$envVars = @('PORT=8080','HOST=0.0.0.0','NODE_ENV=production','E360_HOSTED_DEMO=true','ENTITY360_REQUIRE_APP_ROLES=false','ENABLE_GRAPH_BETA=true',
  "ENTRA_TENANT_ID=$tenantId","ENTRA_CLIENT_ID=$appId","ENTRA_CERT_THUMBPRINT=$thumb","ENTRA_KEYVAULT_URI=https://$VaultName.vault.azure.net","ENTRA_KEYVAULT_CERT_NAME=$CertName")
if ($appExists) { Write-Host '   Exists - updating image and settings.'; Invoke-Az (@('containerapp','update','-g',$ResourceGroup,'-n',$AppName,'--image',$Image,'--min-replicas','0','--max-replicas','1','-o','none','--set-env-vars') + $envVars) | Out-Null }
else { Invoke-Az (@('containerapp','create','-g',$ResourceGroup,'-n',$AppName,'--environment',$EnvironmentName,'--image',$Image,'--ingress','external','--target-port','8080','--min-replicas','0','--max-replicas','1','--cpu','0.25','--memory','0.5Gi','--system-assigned','-o','none','--env-vars') + $envVars) | Out-Null }

$fqdn = if ($Apply) { Get-Az @('containerapp','show','-g',$ResourceGroup,'-n',$AppName,'--query','properties.configuration.ingress.fqdn','-o','tsv') } else { '<fqdn>' }
$principalId = if ($Apply) { Get-Az @('containerapp','show','-g',$ResourceGroup,'-n',$AppName,'--query','identity.principalId','-o','tsv') } else { '<principalId>' }
$base = "https://$fqdn"

Write-Host "5. Key Vault signing permission for the demo app's identity"
if ($vault.rbac) { Invoke-Az @('role','assignment','create','--assignee-object-id',$principalId,'--assignee-principal-type','ServicePrincipal','--role','Key Vault Crypto User','--scope',"$($vault.id)/keys/$CertName",'-o','none') | Out-Null }
else { Invoke-Az @('keyvault','set-policy','-n',$VaultName,'--object-id',$principalId,'--key-permissions','get','sign','--certificate-permissions','get','-o','none') | Out-Null }

Write-Host "6. Redirect URI $base/auth/callback on the registration, PUBLIC_BASE_URL on the app"
Invoke-Az @('ad','app','update','--id',$appId,'--web-redirect-uris',"$base/auth/callback") | Out-Null
Invoke-Az @('containerapp','update','-g',$ResourceGroup,'-n',$AppName,'--set-env-vars',"PUBLIC_BASE_URL=$base",'-o','none') | Out-Null

if (-not $Apply) {
  Write-Host "Done ($mode). Nothing was changed. Re-run with -Apply to execute." -ForegroundColor Cyan
  return
}

Write-Host '7. Verify (the first request wakes the app from zero; allow up to a minute)' -ForegroundColor Cyan
$checks = @()
$page = $null; $login = $null
for ($i = 0; $i -lt 6 -and -not $page; $i++) {
  try { $page = Invoke-WebRequest "$base/" -UseBasicParsing -TimeoutSec 30 } catch { Start-Sleep -Seconds 10 }
}
$checks += [pscustomobject]@{ Check = "Home page $base"; Result = $(if ($page -and $page.Content -match 'hosted demo') { 'PASS' } else { 'FAIL' }); Detail = $(if ($page) { "HTTP $($page.StatusCode)" } else { 'no answer' }) }
try { $login = Invoke-WebRequest "$base/auth/login" -UseBasicParsing -MaximumRedirection 0 -ErrorAction SilentlyContinue } catch { $login = $_.Exception.Response }
$where = if ($login) { [string]$login.Headers.Location } else { '' }
$checks += [pscustomobject]@{ Check = '/auth/login redirect'; Result = $(if ($where -like 'https://login.microsoftonline.com/organizations/*') { 'PASS' } else { 'FAIL' }); Detail = $(if ($where.Length -gt 90) { $where.Substring(0, 90) + '...' } else { $where }) }
$checks | Format-Table -AutoSize
if ($checks.Result -contains 'FAIL') { Write-Host "VERIFICATION FAILED. Logs: az containerapp logs show -g $ResourceGroup -n $AppName --tail 50" -ForegroundColor Red; exit 1 }
Write-Host "Done. Hosted demo: $base" -ForegroundColor Green
Write-Host "Visitors' admins approve it once at: $base/auth/login?consent=1" -ForegroundColor Green
