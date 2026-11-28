<#
.SYNOPSIS
  Connect AI clients to the Entity 360 MCP server on this PC. Dry run by default.
.DESCRIPTION
  The MCP server (server/mcp.mjs) gives an AI client Entity 360's read-only lookups: search, investigate, device,
  findings, signins, emergency_access, find_group_or_role and access_report. It runs from the local Entity 360 copy
  (C:\e360-local) with the same .env, signs in as you, checks your E360 app roles, and writes every call to the
  Entity 360 audit trail.

  Steps this script does (each only with -Apply):
  1. Sign the MCP server in once (browser opens; same app registration and Key Vault key as the web app). Skipped when
     already signed in. The cached sign-in is DPAPI-encrypted under %LOCALAPPDATA%\Entity360\mcp.
  2. Register it with each client you name:
     - ClaudeCode     claude mcp add e360 --scope user (stdio)
     - ClaudeDesktop  adds "e360" to claude_desktop_config.json (stdio), including the Microsoft Store build's own copy.
                      Quit and reopen Claude Desktop afterwards, then use a normal chat on this PC.
     - LMStudio       adds "e360" to %USERPROFILE%\.lmstudio\mcp.json (stdio). Restart LM Studio afterwards.
     - OpenWebUI      starts the HTTP server at logon (scheduled task "Entity 360 MCP (local)", http://127.0.0.1:3601/mcp
                      with a bearer key) and prints the URL and key to paste into Open WebUI.
  A backup is written next to every config file it changes. Nothing in Azure or the app registration is changed.
.EXAMPLE
  .\Connect-E360Mcp.ps1                                   # dry run for Claude Code, Claude Desktop and LM Studio
  .\Connect-E360Mcp.ps1 -Apply                            # sign in and connect those three
  .\Connect-E360Mcp.ps1 -Client OpenWebUI -Apply          # HTTP server at logon, for Open WebUI with Ollama
  .\Connect-E360Mcp.ps1 -Client ClaudeCode -Demo -Apply   # fictional demo data only, no sign-in
  .\Connect-E360Mcp.ps1 -Remove -Apply                    # remove e360 from every client and the HTTP task
#>
#Requires -Version 7.0
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive operator console script')]
[CmdletBinding()]
param(
  [ValidateSet('ClaudeCode', 'ClaudeDesktop', 'LMStudio', 'OpenWebUI')]
  [string[]]$Client = @('ClaudeCode', 'ClaudeDesktop', 'LMStudio'),
  [switch]$Apply,
  [switch]$Remove,
  [switch]$Demo,
  [string]$RunDir = 'C:\e360-local',
  [string]$Name = 'e360',
  [string]$TaskName = 'Entity 360 MCP (local)',
  [int]$Port = 3601
)
$ErrorActionPreference = 'Stop'
if ($Remove -and -not $PSBoundParameters.ContainsKey('Client')) { $Client = @('ClaudeCode', 'ClaudeDesktop', 'LMStudio', 'OpenWebUI') }
Write-Host ("Entity 360 MCP - " + $(if ($Remove) { 'REMOVE' } else { 'CONNECT' }) + ' - ' + $(if ($Apply) { 'APPLY' } else { 'DRY RUN' }) + " - $($Client -join ', ')") -ForegroundColor Cyan
function Step([string]$Text) { Write-Host "  $Text" -ForegroundColor Yellow }

$node = (Get-Command node -ErrorAction SilentlyContinue).Source
$server = Join-Path $RunDir 'server\mcp.mjs'
$envFile = Join-Path $RunDir '.env'
$problems = @()
if (-not $node) { $problems += 'Node.js is not on PATH. Install Node.js 22 or later.' }
if (-not (Test-Path -LiteralPath $server)) { $problems += "$server not found. Update the local copy first: C:\path\to\scripts\Install-E360Local.ps1 -Update -Apply" }
if (-not $Demo -and -not (Test-Path -LiteralPath $envFile)) { $problems += "$envFile not found." }
if (-not (Test-Path -LiteralPath (Join-Path $RunDir 'node_modules\@modelcontextprotocol\sdk'))) { $problems += "MCP SDK not installed in $RunDir. Run: C:\path\to\scripts\Install-E360Local.ps1 -Update -Apply" }
if ($problems -and -not $Remove) { $problems | ForEach-Object { Write-Host "  PROBLEM: $_" -ForegroundColor Red }; exit 1 }

# The command every stdio client runs. The .env path is absolute, so the client's working folder does not matter.
$nodeArgs = if ($Demo) { @($server, '--demo') } else { @("--env-file=$envFile", $server) }

function Invoke-Mcp([string[]]$McpArgs) {
  Push-Location -LiteralPath $RunDir
  try { $out = & $node "--env-file=$envFile" $server @McpArgs; if ($LASTEXITCODE -ne 0) { throw "mcp.mjs $($McpArgs -join ' ') failed with exit code $LASTEXITCODE" }; return $out }
  finally { Pop-Location }
}

# Merge (or remove) mcpServers.<Name> in a JSON config file, keeping everything else. Backup first.
function Set-McpJson([string]$Path, [hashtable]$Entry) {
  Step $(if ($Entry) { "Set mcpServers.$Name in $Path" } else { "Remove mcpServers.$Name from $Path" })
  if (-not $Apply) { return }
  $config = if (Test-Path -LiteralPath $Path) { Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -AsHashtable } else { $null }
  if (-not $config) { $config = @{} }
  if (Test-Path -LiteralPath $Path) { Copy-Item -LiteralPath $Path -Destination "$Path.pre-e360mcp-$(Get-Date -Format yyyyMMdd-HHmmss)" }
  if (-not $config.ContainsKey('mcpServers') -or $null -eq $config.mcpServers) { $config.mcpServers = @{} }
  if ($Entry) { $config.mcpServers[$Name] = $Entry } else { $config.mcpServers.Remove($Name) | Out-Null }
  New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Path) | Out-Null
  Set-Content -LiteralPath $Path -Value ($config | ConvertTo-Json -Depth 20) -Encoding utf8NoBOM
}
$stdioEntry = if ($Remove) { $null } else { @{ command = $node; args = $nodeArgs } }

# 1. Sign in once (not for demo, not for remove).
if (-not $Remove -and -not $Demo) {
  $status = Invoke-Mcp @('status') | Out-String | ConvertFrom-Json
  if (-not $status.configured) { Write-Host "  PROBLEM: confidential sign-in is not configured in $envFile." -ForegroundColor Red; exit 1 }
  if ($status.signedIn) { Step "Already signed in as $($status.account) (cache: $($status.cacheProtection))" }
  else {
    Step "Sign in: $node --env-file=$envFile $server sign-in   (a browser tab opens; pick your admin account)"
    if ($Apply) { Invoke-Mcp @('sign-in') | Write-Host }
  }
}

# 2. Clients.
foreach ($c in $Client) {
  switch ($c) {
    'ClaudeCode' {
      $claude = (Get-Command claude -ErrorAction SilentlyContinue).Source
      if (-not $claude) { Step 'Claude Code (claude) is not on PATH: skipped.'; continue }
      Step "claude mcp remove $Name --scope user"
      if ($Apply) { & $claude mcp remove $Name --scope user 2>$null | Out-Null }
      if (-not $Remove) {
        Step "claude mcp add $Name --scope user -- $node $($nodeArgs -join ' ')"
        if ($Apply) { & $claude mcp add $Name --scope user -- $node @nodeArgs; if ($LASTEXITCODE -ne 0) { throw 'claude mcp add failed.' } }
      }
    }
    'ClaudeDesktop' {
      # Claude Desktop has kept this file in three places. Current builds read %LOCALAPPDATA%\Claude-Data\claude_*\
      # (verified on DEVICE01, 2026-11-22). Older Store (MSIX) builds read Packages\Claude_*\LocalCache\Roaming\Claude,
      # and the classic installer reads %APPDATA%\Claude. Every location that exists is written; the Store folder is
      # created when the package is installed. Quit Claude Desktop first: it rewrites the file when it exits.
      $data = @(Get-ChildItem -Path (Join-Path $env:LOCALAPPDATA 'Claude-Data') -Directory -Filter 'claude_*' -ErrorAction SilentlyContinue | ForEach-Object { Join-Path $_.FullName 'claude_desktop_config.json' })
      $store = @(Get-ChildItem -Path (Join-Path $env:LOCALAPPDATA 'Packages') -Directory -Filter 'Claude_*' -ErrorAction SilentlyContinue | ForEach-Object { Join-Path $_.FullName 'LocalCache\Roaming\Claude\claude_desktop_config.json' })
      $classic = Join-Path $env:APPDATA 'Claude\claude_desktop_config.json'
      $targets = @($data) + @($store) + @(if (Test-Path -LiteralPath (Split-Path -Parent $classic)) { $classic })
      # Only the desktop app: Claude Code's CLI is also claude.exe and must not be matched.
      $desktop = @(Get-Process claude -ErrorAction SilentlyContinue | Where-Object { $_.Path -match '\\WindowsApps\\Claude_|\\AnthropicClaude\\' })
      if ($Apply -and $desktop) {
        Write-Host '  PROBLEM: Claude Desktop is running and would overwrite the change when it exits. Quit it first, then run this again:' -ForegroundColor Red
        Write-Host '    Get-Process claude -ErrorAction SilentlyContinue | Where-Object { $_.Path -match ''\\WindowsApps\\Claude_|\\AnthropicClaude\\'' } | Stop-Process -Force'
        exit 1
      }
      if (-not $targets) { Step 'Claude Desktop is not installed for this Windows user: skipped.'; continue }
      foreach ($p in $targets) { Set-McpJson $p $stdioEntry }
      if ($Apply) {
        Write-Host '  Open Claude Desktop again to load the change:' -ForegroundColor Green
        Write-Host '    Start-Process (Get-StartApps | Where-Object Name -eq ''Claude'' | Select-Object -First 1 | ForEach-Object { "shell:AppsFolder\$($_.AppID)" })'
        Write-Host '  Then open a normal chat on this PC (not Cowork, not Code) and check that e360 is listed under the tools (+) menu.' -ForegroundColor Green
      }
    }
    'LMStudio' {
      $dir = Join-Path $env:USERPROFILE '.lmstudio'
      if (-not (Test-Path -LiteralPath $dir)) { Step 'LM Studio (~\.lmstudio) not found: skipped.'; continue }
      Set-McpJson (Join-Path $dir 'mcp.json') $stdioEntry
      if ($Apply) { Write-Host '  Restart LM Studio, load a model that supports tool use, and turn on the e360 tools in the chat.' -ForegroundColor Green }
    }
    'OpenWebUI' {
      if ($Remove) { Step "Stop and remove scheduled task '$TaskName'" } else { Step "Scheduled task '$TaskName': at logon, $node $(if ($Demo) { '' } else { "--env-file=$envFile " })$server --http --port $Port$(if ($Demo) { ' --demo' })" }
      if ($Apply) {
        if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) { Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue; Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false }
      }
      if (-not $Remove -and $Apply) {
        $user = "$env:USERDOMAIN\$env:USERNAME"
        $httpArgs = (@($nodeArgs | ForEach-Object { "`"$_`"" }) + @('--http', '--port', $Port)) -join ' '
        $action = New-ScheduledTaskAction -Execute $node -Argument $httpArgs -WorkingDirectory $RunDir
        $trigger = New-ScheduledTaskTrigger -AtLogOn -User $user
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew
        $principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description "Entity 360 MCP on http://127.0.0.1:$Port/mcp (local only). Managed by $RunDir\Connect-E360Mcp.ps1" | Out-Null
        Start-ScheduledTask -TaskName $TaskName
        $key = (Invoke-Mcp @('key') | Out-String).Trim()
        Write-Host ''
        Write-Host '  Open WebUI > Admin Panel > Settings > External Tools > + (this step is UI-only in Open WebUI):' -ForegroundColor Green
        Write-Host "    Type: MCP (Streamable HTTP)"
        Write-Host "    URL:  http://host.docker.internal:$Port/mcp   (Open WebUI in Docker)  or  http://127.0.0.1:$Port/mcp   (installed with pip)"
        Write-Host "    Auth: Bearer   Key: $key"
      }
    }
  }
}
if ($Remove -and $Apply -and -not $Demo) { Step "Sign-out: $node --env-file=$envFile $server sign-out"; Invoke-Mcp @('sign-out') | Write-Host }
if (-not $Apply) { Write-Host 'Dry run only. Re-run with -Apply.' -ForegroundColor Cyan }
