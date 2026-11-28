<#
.SYNOPSIS
  Adds the read-only delegated Graph permission OnPremDirectorySynchronization.Read.All to the Entity 360
  app registration and grants tenant-wide admin consent for that one scope.

.DESCRIPTION
  Entity 360 > ON-PREM AD > Sync health uses it to read Entra Connect's feature flags, version, server and
  pending export counts (/directory/onPremisesSynchronization). Nothing else changes:
    1. Declares the scope on app 00000000-0000-4000-8000-0000000000a3 (requiredResourceAccess).
    2. Appends the scope to the existing AllPrincipals delegated grant for Microsoft Graph. The other
       consented scopes are kept exactly as they are; the old scope string is backed up first.
  It does NOT run "az ad app permission admin-consent", which would consent every declared scope at once.

  Default is a dry run that shows what would change. Add -Apply to make the change.
  Undo: -Remove -Apply (takes the scope out of the grant and the registration again).

.EXAMPLE
  .\Grant-E360OnPremSyncScope.ps1            # dry run
  .\Grant-E360OnPremSyncScope.ps1 -Apply     # make the change
#>
[CmdletBinding()]
param([switch]$Apply, [switch]$Remove)
$ErrorActionPreference = 'Stop'

$AppId      = '00000000-0000-4000-8000-0000000000a3'   # Entity 360
$GraphAppId = '00000003-0000-0000-c000-000000000000'   # Microsoft Graph
$ScopeName  = 'OnPremDirectorySynchronization.Read.All'
$ScopeId    = 'f6609722-4100-44eb-b747-e6ca0536989d'   # delegated permission id (Microsoft Graph permissions reference)
$Tenant     = '00000000-0000-4000-8000-0000000000a1'
$BackupDir  = 'C:\path\to\scripts'

$account = az account show --query "{tenant:tenantId,user:user.name}" -o json | ConvertFrom-Json
if ($account.tenant -ne $Tenant) { throw "az is signed in to tenant $($account.tenant), not $Tenant. Run: az login --tenant $Tenant" }
Write-Host "Signed in as $($account.user) in $Tenant"

$spId      = az ad sp show --id $AppId --query id -o tsv
$graphSpId = az ad sp show --id $GraphAppId --query id -o tsv
$filter    = [uri]::EscapeDataString("clientId eq '$spId' and resourceId eq '$graphSpId' and consentType eq 'AllPrincipals'")
$grant     = (az rest --method GET --uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?`$filter=$filter" | ConvertFrom-Json).value | Select-Object -First 1
if (-not $grant) { throw 'No tenant-wide (AllPrincipals) Microsoft Graph grant found for Entity 360. Stop: that is not the expected state.' }

$scopes   = @($grant.scope -split ' ' | Where-Object { $_ })
$declared = az ad app show --id $AppId --query "requiredResourceAccess[?resourceAppId=='$GraphAppId'].resourceAccess[] | [?id=='$ScopeId'] | length(@)" -o tsv
$inGrant  = $scopes -contains $ScopeName
Write-Host "Declared on the registration: $([bool][int]$declared)   In the admin-consent grant: $inGrant   ($($scopes.Count) scopes consented now)"

$newScopes = if ($Remove) { $scopes | Where-Object { $_ -ne $ScopeName } } else { @($scopes) + $(if ($inGrant) { @() } else { $ScopeName }) }
$changeGrant = ($newScopes -join ' ') -ne ($scopes -join ' ')
$changeDecl  = if ($Remove) { [int]$declared -gt 0 } else { [int]$declared -eq 0 }
if (-not $changeGrant -and -not $changeDecl) { Write-Host 'Nothing to change.' -ForegroundColor Green; return }

Write-Host ($(if ($Remove) { 'Would REMOVE' } else { 'Would ADD' }) + " $ScopeName" + $(if ($changeDecl) { ' [registration]' }) + $(if ($changeGrant) { ' [admin consent]' })) -ForegroundColor Yellow
if (-not $Apply) { Write-Host 'Dry run only. Re-run with -Apply to make the change.'; return }

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$backup = Join-Path $BackupDir "e360-grant-scope-backup-$stamp.txt"
Set-Content -Path $backup -Value $grant.scope -Encoding utf8
Write-Host "Backed up the current consented scopes to $backup"

if ($changeDecl) {
  if ($Remove) { az ad app permission delete --id $AppId --api $GraphAppId --api-permissions $ScopeId | Out-Null }
  else { az ad app permission add --id $AppId --api $GraphAppId --api-permissions "$ScopeId=Scope" 2>$null | Out-Null }
}
if ($changeGrant) {
  $body = Join-Path $env:TEMP "e360-grant-$stamp.json"
  @{ scope = ($newScopes -join ' ') } | ConvertTo-Json | Set-Content -Path $body -Encoding utf8
  az rest --method PATCH --uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants/$($grant.id)" --headers 'Content-Type=application/json' --body "@$body" | Out-Null
  Remove-Item $body
}

$after = (az rest --method GET --uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants/$($grant.id)" | ConvertFrom-Json).scope -split ' '
$ok = if ($Remove) { $after -notcontains $ScopeName } else { $after -contains $ScopeName }
if ($ok) { Write-Host "Done. $($after.Count) scopes consented. Sign out of Entity 360 and sign in again so the new token carries it." -ForegroundColor Green }
else { throw "The grant does not show the expected change. Previous scopes are in $backup." }
