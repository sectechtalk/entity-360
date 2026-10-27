param(
    [Parameter(Mandatory=$true)][guid]$TenantId,
    [Parameter(Mandatory=$true)][guid]$ClientId
)
$ErrorActionPreference = 'Stop'
$configPath = Join-Path $PSScriptRoot '.env'
if (-not (Test-Path -LiteralPath $configPath)) {
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot '.env.example') -Destination $configPath
}
$configText = Get-Content -LiteralPath $configPath -Raw
$configText = [regex]::Replace($configText, '(?m)^ENTRA_TENANT_ID=.*$', "ENTRA_TENANT_ID=$TenantId")
$configText = [regex]::Replace($configText, '(?m)^ENTRA_CLIENT_ID=.*$', "ENTRA_CLIENT_ID=$ClientId")
Set-Content -LiteralPath $configPath -Value $configText -Encoding utf8
Write-Host 'Tenant and client IDs saved locally. Restart Entity 360, then sign in from Connection & setup.'
