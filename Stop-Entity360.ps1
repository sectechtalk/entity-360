$ErrorActionPreference = 'Stop'
$pidFile = Join-Path $PSScriptRoot '.runtime\server.pid'
if (-not (Test-Path -LiteralPath $pidFile)) { Write-Host 'No recorded background instance. Use Ctrl+C in the server window.'; return }
$entityProcessId = [int](Get-Content -LiteralPath $pidFile -Raw)
$entityProcess = Get-CimInstance Win32_Process -Filter "ProcessId = $entityProcessId"
if ($entityProcess -and $entityProcess.Name -eq 'node.exe' -and $entityProcess.CommandLine -match 'server[/\\]index\.mjs') {
    Stop-Process -Id $entityProcessId
    Write-Host 'Entity 360 background server stopped.'
} else { Write-Host 'The recorded Entity 360 process is no longer running.' }
