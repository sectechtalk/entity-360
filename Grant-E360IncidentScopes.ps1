<#
.SYNOPSIS
  Adds four read-only delegated Graph permissions for INVESTIGATE > Incidents to the Entity 360 app registration and
  grants tenant-wide admin consent for those four scopes only.

.DESCRIPTION
  Entity 360 > INVESTIGATE > Incidents reads, with the signed-in person's own token:
    SecurityIncident.Read.All    Defender XDR incidents      (/security/incidents)
    SecurityAlert.Read.All       Defender XDR alerts         (/security/alerts_v2)
    IdentityRiskyUser.Read.All   risky users                 (/identityProtection/riskyUsers)
    IdentityRiskEvent.Read.All   risk detections             (/identityProtection/riskDetections)
  All four are read-only: they cannot classify, assign, close or dismiss anything. Delegated means a person still
  sees only what their own role allows (Security Reader or higher). Nothing else changes:
    1. Declares the scopes on app 00000000-0000-4000-8000-0000000000a3 (requiredResourceAccess). Each permission id is
       read from the Microsoft Graph service principal at run time, not typed in here.
    2. Appends the scopes to the existing AllPrincipals delegated grant for Microsoft Graph. The other consented
       scopes are kept exactly as they are; the old scope string is backed up first.
  It does NOT run "az ad app permission admin-consent", which would consent every declared scope at once.

  Default is a dry run that shows what would change. Add -Apply to make the change.
  Undo: -Remove -Apply (takes the four scopes out of the grant and the registration again).

.EXAMPLE
  .\Grant-E360IncidentScopes.ps1            # dry run
  .\Grant-E360IncidentScopes.ps1 -Apply     # make the change
  .\Grant-E360IncidentScopes.ps1 -Remove -Apply
#>
[CmdletBinding()]
param([switch]$Apply, [switch]$Remove)
$ErrorActionPreference = 'Stop'

$AppId      = '00000000-0000-4000-8000-0000000000a3'   # Entity 360
$GraphAppId = '00000003-0000-0000-c000-000000000000'   # Microsoft Graph
$ScopeNames = @('SecurityIncident.Read.All', 'SecurityAlert.Read.All', 'IdentityRiskyUser.Read.All', 'IdentityRiskEvent.Read.All')
$Tenant     = '00000000-0000-4000-8000-0000000000a1'
$BackupDir  = 'C:\path\to\scripts'

$account = az account show --query "{tenant:tenantId,user:user.name}" -o json | ConvertFrom-Json
if ($account.tenant -ne $Tenant) { throw "az is signed in to tenant $($account.tenant), not $Tenant. Run: az login --tenant $Tenant" }
Write-Host "Signed in as $($account.user) in $Tenant"

# Delegated permission ids, straight from Microsoft Graph's own service principal.
$graphScopes = az ad sp show --id $GraphAppId --query "oauth2PermissionScopes[].{value:value,id:id}" -o json | ConvertFrom-Json
$ScopeIds = @{}
foreach ($name in $ScopeNames) {
  $id = ($graphScopes | Where-Object { $_.value -eq $name } | Select-Object -First 1).id
  if (-not $id) { throw "Microsoft Graph does not publish a delegated permission named $name. Stop." }
  $ScopeIds[$name] = $id
}

$spId      = az ad sp show --id $AppId --query id -o tsv
$graphSpId = az ad sp show --id $GraphAppId --query id -o tsv
$filter    = [uri]::EscapeDataString("clientId eq '$spId' and resourceId eq '$graphSpId' and consentType eq 'AllPrincipals'")
$grant     = (az rest --method GET --uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?`$filter=$filter" | ConvertFrom-Json).value | Select-Object -First 1
if (-not $grant) { throw 'No tenant-wide (AllPrincipals) Microsoft Graph grant found for Entity 360. Stop: that is not the expected state.' }

$scopes   = @($grant.scope -split ' ' | Where-Object { $_ })
$declaredIds = @(az ad app show --id $AppId --query "requiredResourceAccess[?resourceAppId=='$GraphAppId'].resourceAccess[].id" -o json | ConvertFrom-Json)

$plan = foreach ($name in $ScopeNames) {
  [pscustomobject]@{ Scope = $name; Declared = $declaredIds -contains $ScopeIds[$name]; Consented = $scopes -contains $name }
}
$plan | Format-Table -AutoSize | Out-String | Write-Host
Write-Host "$($scopes.Count) scopes consented now."

$newScopes = if ($Remove) { @($scopes | Where-Object { $ScopeNames -notcontains $_ }) } else { @($scopes) + @($ScopeNames | Where-Object { $scopes -notcontains $_ }) }
$changeGrant = ($newScopes -join ' ') -ne ($scopes -join ' ')
$declChanges = @($plan | Where-Object { if ($Remove) { $_.Declared } else { -not $_.Declared } })
if (-not $changeGrant -and -not $declChanges.Count) { Write-Host 'Nothing to change.' -ForegroundColor Green; return }

$verb = if ($Remove) { 'Would REMOVE' } else { 'Would ADD' }
foreach ($p in $plan) {
  $where = @()
  if ($declChanges.Scope -contains $p.Scope) { $where += 'registration' }
  if (($Remove -and $p.Consented) -or (-not $Remove -and -not $p.Consented)) { $where += 'admin consent' }
  if ($where.Count) { Write-Host "$verb $($p.Scope) [$($where -join ', ')]" -ForegroundColor Yellow }
}
if (-not $Apply) { Write-Host 'Dry run only. Re-run with -Apply to make the change.'; return }

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
if (-not (Test-Path $BackupDir)) { New-Item -ItemType Directory -Path $BackupDir | Out-Null }
$backup = Join-Path $BackupDir "e360-grant-scope-backup-$stamp.txt"
Set-Content -Path $backup -Value $grant.scope -Encoding utf8
Write-Host "Backed up the current consented scopes to $backup"

foreach ($p in $declChanges) {
  $id = $ScopeIds[$p.Scope]
  if ($Remove) { az ad app permission delete --id $AppId --api $GraphAppId --api-permissions $id | Out-Null }
  else { az ad app permission add --id $AppId --api $GraphAppId --api-permissions "$id=Scope" 2>$null | Out-Null }
}
if ($changeGrant) {
  $body = Join-Path $env:TEMP "e360-grant-$stamp.json"
  @{ scope = ($newScopes -join ' ') } | ConvertTo-Json | Set-Content -Path $body -Encoding utf8
  az rest --method PATCH --uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants/$($grant.id)" --headers 'Content-Type=application/json' --body "@$body" | Out-Null
  Remove-Item $body
}

$after = (az rest --method GET --uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants/$($grant.id)" | ConvertFrom-Json).scope -split ' '
$missing = if ($Remove) { @($ScopeNames | Where-Object { $after -contains $_ }) } else { @($ScopeNames | Where-Object { $after -notcontains $_ }) }
if (-not $missing.Count) { Write-Host "Done. $($after.Count) scopes consented. Sign out of Entity 360 and sign in again so the new token carries them." -ForegroundColor Green }
else { throw "The grant does not show the expected change for: $($missing -join ', '). Previous scopes are in $backup." }
