<# Entity 360 Intune Remediation: network connectivity DETECTION script (Phase 4.6).
 Runs as the logged-on user in Windows PowerShell 5.1. Read-only: no writes, no admin rights, no sign-in.
 For each target: DNS resolution, then a TCP connect (Test-NetConnection style) with latency.
 Output: exactly one line of compact JSON under 2,048 characters (Intune keeps 2,048 for detection output).
 Exit 0 = healthy, 1 = problem. Entity 360 reads the line from deviceRunStates.preRemediationDetectionScriptOutput.
 Intune runs it without parameters; -Targets and the timeouts exist for local testing.
#>
param(
  # Configurable target list: 'host:port'.
  [string[]]$Targets = @(
    'login.microsoftonline.com:443',
    'graph.microsoft.com:443',
    'manage.microsoft.com:443'
  ),
  [int]$DnsTimeoutMs = 3000,
  [int]$TcpTimeoutMs = 3000,
  [int]$OverallTimeoutMs = 25000,
  [int]$SlowMs = 1000,
  [int]$MaxChars = 2000
)
$ErrorActionPreference = 'Stop'
$clock = [System.Diagnostics.Stopwatch]::StartNew()
$problems = New-Object System.Collections.Generic.List[string]
$results = New-Object System.Collections.Generic.List[object]

function Get-Left { [int]($OverallTimeoutMs - $clock.ElapsedMilliseconds) }
function Limit([int]$ms) { $left = Get-Left; if ($left -lt $ms) { if ($left -lt 0) { return 0 }; return $left }; return $ms }
function Short([string]$s, [int]$n) { if ($null -eq $s) { return '' }; $s = ($s -replace '\s+', ' ').Trim(); if ($s.Length -gt $n) { return $s.Substring(0, $n) }; return $s }

# Prerequisite checks.
$pre = [ordered]@{ ps = $PSVersionTable.PSVersion.ToString(); net = $false; nic = 0; ok = $true }
if ($PSVersionTable.PSVersion.Major -lt 5) { $pre.ok = $false; $problems.Add('prereq: PowerShell 5.1 or later required') }
try { $pre.net = [System.Net.NetworkInformation.NetworkInterface]::GetIsNetworkAvailable() } catch { $pre.net = $false }
try {
  $pre.nic = @([System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() | Where-Object {
    $_.OperationalStatus -eq 'Up' -and $_.NetworkInterfaceType -ne 'Loopback' -and $_.NetworkInterfaceType -ne 'Tunnel' }).Count
} catch { $pre.nic = 0 }
if (-not $pre.net -or $pre.nic -eq 0) { $pre.ok = $false; $problems.Add('prereq: no active network adapter') }

foreach ($t in $Targets) {
  $r = [ordered]@{ t = Short $t 60; dns = $null; ip = $null; tcp = $null; ms = $null }
  $results.Add($r)
  $m = [regex]::Match([string]$t, '^\s*([A-Za-z0-9.\-]+):(\d{1,5})\s*$')
  if (-not $m.Success) { $r.dns = 'bad'; $problems.Add("$($r.t): bad target"); continue }
  $hostName = $m.Groups[1].Value; $port = [int]$m.Groups[2].Value
  if ((Get-Left) -lt 500) { $r.dns = 'skip'; $problems.Add("$($r.t): skipped, overall timeout"); continue }
  # DNS with its own timeout (Resolve-DnsName has none).
  $dnsWatch = [System.Diagnostics.Stopwatch]::StartNew()
  $addr = $null
  try {
    $ar = [System.Net.Dns]::BeginGetHostAddresses($hostName, $null, $null)
    if ($ar.AsyncWaitHandle.WaitOne((Limit $DnsTimeoutMs))) {
      $all = [System.Net.Dns]::EndGetHostAddresses($ar)
      $addr = @($all | Where-Object { $_.AddressFamily -eq 'InterNetwork' }) + @($all | Where-Object { $_.AddressFamily -ne 'InterNetwork' }) | Select-Object -First 1
      if ($addr) { $r.dns = 'ok'; $r.ip = $addr.ToString() } else { $r.dns = 'none' }
    } else { $r.dns = 'timeout' }
  } catch { $r.dns = 'fail' }
  $r.dnsMs = [int]$dnsWatch.ElapsedMilliseconds
  if ($r.dns -ne 'ok') { $problems.Add("$($r.t): DNS $($r.dns)"); continue }
  # TCP connect with its own timeout; latency is the connect time.
  $client = New-Object System.Net.Sockets.TcpClient($addr.AddressFamily)
  try {
    $tcpWatch = [System.Diagnostics.Stopwatch]::StartNew()
    $ar = $client.BeginConnect($addr, $port, $null, $null)
    if ($ar.AsyncWaitHandle.WaitOne((Limit $TcpTimeoutMs))) {
      try { $client.EndConnect($ar); $r.ms = [int]$tcpWatch.ElapsedMilliseconds; $r.tcp = 'ok' } catch { $r.tcp = 'refused' }
    } else { $r.tcp = 'timeout' }
  } catch { $r.tcp = 'fail' } finally { $client.Close() }
  if ($r.tcp -ne 'ok') { $problems.Add("$($r.t): TCP $($r.tcp)") }
  elseif ($r.ms -gt $SlowMs) { $problems.Add("$($r.t): slow $($r.ms)ms") }
}

$okMs = @($results | Where-Object { $_.tcp -eq 'ok' } | ForEach-Object { $_.ms })
$healthy = ($problems.Count -eq 0)
$lat = $null
if ($okMs.Count -gt 0) { $lat = [ordered]@{ min = [int]($okMs | Measure-Object -Minimum).Minimum; max = [int]($okMs | Measure-Object -Maximum).Maximum; avg = [int](($okMs | Measure-Object -Average).Average) } }
$issues = @()
foreach ($p in ($problems | Select-Object -First 10)) { $issues += (Short $p 90) }
$passCount = @($results | Where-Object { $_.tcp -eq 'ok' }).Count
$out = [ordered]@{
  v = 1; kind = 'e360-net'; ok = $healthy; host = Short $env:COMPUTERNAME 32
  at = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); dur = [int]$clock.ElapsedMilliseconds
  pre = $pre
  lat = $lat
  pass = $passCount; total = $results.Count
  issues = $issues
  r = $results.ToArray()
}
# Safe truncation: drop healthy rows, then trim rows and issues, so the JSON always stays valid and under MaxChars.
$json = $out | ConvertTo-Json -Compress -Depth 4
if ($json.Length -gt $MaxChars) { $out.r = @($results | Where-Object { $_.tcp -ne 'ok' }); $out.trunc = 'healthy rows dropped'; $json = $out | ConvertTo-Json -Compress -Depth 4 }
while ($json.Length -gt $MaxChars -and ($out.r.Count -gt 0 -or $out.issues.Count -gt 1)) {
  if ($out.r.Count -gt 0) { $out.r = @($out.r | Select-Object -First ($out.r.Count - 1)) } else { $out.issues = @($out.issues | Select-Object -First ($out.issues.Count - 1)) }
  $out.trunc = 'rows and issues trimmed'
  $json = $out | ConvertTo-Json -Compress -Depth 4
}
if ($json.Length -gt $MaxChars) { $json = ([ordered]@{ v = 1; kind = 'e360-net'; ok = $healthy; pass = $out.pass; total = $out.total; trunc = 'summary only' } | ConvertTo-Json -Compress) }
[Console]::Out.WriteLine($json)
if ($healthy) { exit 0 } else { exit 1 }
