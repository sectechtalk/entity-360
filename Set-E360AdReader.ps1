<#
.SYNOPSIS
  Connects Entity 360 to on-premises Active Directory so INVESTIGATE > Access > AD groups lists every security group
  in the forest a user is in, not only the groups that sync to Entra.

.DESCRIPTION
  Run it on the computer that runs Entity 360, as the Windows user that runs Entity 360.
    1. Checks that the domain controller answers on LDAP (389) and the global catalog (3268) from this computer.
    2. Asks for the password of a plain domain user (no admin rights needed; any domain user can read group
       membership). Make one with New-E360AdReaderAccount.ps1 on a domain controller.
    3. Tests an LDAP bind with that account.
    4. Saves the credential with Export-Clixml. Windows DPAPI encrypts it so only this Windows user on this computer
       can open it. The password never goes into .env, logs or git.
    5. Writes E360_AD_SERVER and E360_AD_CREDENTIAL to the Entity 360 .env file.
    6. Runs the real AD query for the reader account itself and prints the groups it found.
  On a domain-joined Entity 360 host you can skip the credential: the app then uses its own Windows identity.

  Default is a dry run: it only does step 1 and says what -Apply would do. Undo: -Remove -Apply.

.EXAMPLE
  .\Set-E360AdReader.ps1 -Server dc01.contoso.com -UserName 'CONTOSO\svc-e360-reader'          # checks only
  .\Set-E360AdReader.ps1 -Server dc01.contoso.com -UserName 'CONTOSO\svc-e360-reader' -Apply   # save and test
  .\Set-E360AdReader.ps1 -Remove -Apply                                                        # undo
#>
[CmdletBinding()]
param(
  [string]$Server = '',
  [string]$UserName = '',
  [string]$EnvFile = (Join-Path $PSScriptRoot '.env'),
  [string]$CredentialPath = (Join-Path $env:LOCALAPPDATA 'Entity360\ad-reader.xml'),
  [switch]$Apply,
  [switch]$Remove
)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.DirectoryServices
function Step($t) { Write-Host "`n== $t" -ForegroundColor Cyan }
function Ok($t) { Write-Host "  OK   $t" -ForegroundColor Green }
function Bad($t) { Write-Host "  FAIL $t" -ForegroundColor Red }
function Set-EnvLine([string]$file, [string]$name, [string]$value) {
  $lines = @(); if (Test-Path -LiteralPath $file) { $lines = @(Get-Content -LiteralPath $file | Where-Object { $_ -notmatch "^\s*$name\s*=" }) }
  $lines += "$name=$value"; Set-Content -LiteralPath $file -Value $lines -Encoding ASCII
}
function Remove-EnvLine([string]$file, [string]$name) {
  if (Test-Path -LiteralPath $file) { Set-Content -LiteralPath $file -Value @(Get-Content -LiteralPath $file | Where-Object { $_ -notmatch "^\s*$name\s*=" }) -Encoding ASCII }
}
# Runs a script block in its own runspace and gives up after $Seconds, so a stuck LDAP or Kerberos call can never hang this script.
function Invoke-WithTimeout([scriptblock]$Block, [object[]]$ArgList, [int]$Seconds) {
  $ps = [powershell]::Create().AddScript($Block.ToString())
  foreach ($a in $ArgList) { [void]$ps.AddArgument($a) }
  $h = $ps.BeginInvoke()
  try {
    if (-not $h.AsyncWaitHandle.WaitOne($Seconds * 1000)) { return [pscustomobject]@{ ok = $false; timedOut = $true; error = "no answer after $Seconds seconds" } }
    $r = $ps.EndInvoke($h)
    if ($ps.HadErrors -and -not $r) { return [pscustomobject]@{ ok = $false; timedOut = $false; error = ($ps.Streams.Error | Select-Object -First 1 | ForEach-Object { $_.Exception.Message }) } }
    return $r | Select-Object -Last 1
  } catch { return [pscustomobject]@{ ok = $false; timedOut = $false; error = $_.Exception.InnerException.Message + $_.Exception.Message } }
  finally { if ($h.IsCompleted) { $ps.Dispose() } else { [void]$ps.BeginStop($null, $null) } }
}
# LDAP bind plus a RootDSE read with System.DirectoryServices.Protocols (has real timeouts). $auth: Negotiate or Ntlm.
$BindTest = {
  param($srv, $user, $domain, $password, $auth)
  try {
    Add-Type -AssemblyName System.DirectoryServices.Protocols
    $id = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($srv, 389, $false, $false)
    $nc = if ($user) { New-Object System.Net.NetworkCredential($user, $password, $domain) } else { $null }
    $c = New-Object System.DirectoryServices.Protocols.LdapConnection($id, $nc, [System.DirectoryServices.Protocols.AuthType]$auth)
    $c.Timeout = [TimeSpan]::FromSeconds(15)
    $c.SessionOptions.ProtocolVersion = 3
    $c.SessionOptions.Signing = $true; $c.SessionOptions.Sealing = $true
    $c.Bind()
    $req = New-Object System.DirectoryServices.Protocols.SearchRequest('', '(objectClass=*)', [System.DirectoryServices.Protocols.SearchScope]::Base, [string[]]@('defaultNamingContext', 'dnsHostName'))
    $e = $c.SendRequest($req, [TimeSpan]::FromSeconds(15)).Entries[0]
    $c.Dispose()
    [pscustomobject]@{ ok = $true; timedOut = $false; dnc = [string]$e.Attributes['defaultNamingContext'][0]; dc = [string]$e.Attributes['dnsHostName'][0]; error = '' }
  } catch { [pscustomobject]@{ ok = $false; timedOut = $false; error = $_.Exception.Message } }
}
function Test-Port([string]$h, [int]$port) {
  $c = New-Object System.Net.Sockets.TcpClient
  try { return $c.ConnectAsync($h, $port).Wait(3000) -and $c.Connected } catch { return $false } finally { $c.Close() }
}

if ($Remove) {
  Step 'Remove the Entity 360 AD reader connection'
  Write-Host "  Credential file: $CredentialPath"; Write-Host "  .env lines E360_AD_SERVER, E360_AD_CREDENTIAL in $EnvFile"
  if (-not $Apply) { Write-Host "`nDry run. Add -Apply to remove." -ForegroundColor Yellow; return }
  if (Test-Path -LiteralPath $CredentialPath) { Remove-Item -LiteralPath $CredentialPath -Force }
  Remove-EnvLine $EnvFile 'E360_AD_SERVER'; Remove-EnvLine $EnvFile 'E360_AD_CREDENTIAL'
  Ok 'Removed. Restart Entity 360 to pick it up.'; return
}

$ProgressPreference = 'SilentlyContinue'
Write-Progress -Activity 'Entity 360' -Completed   # clears a progress bar left on screen by an earlier command
$joined = (Get-CimInstance Win32_ComputerSystem).PartOfDomain
if (-not $Server) {
  if (-not $joined) { throw 'This computer is not joined to a domain. Pass -Server with a domain controller name or IP address.' }
  $Server = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain().Name
}

Step "1. Can this computer reach $Server?"
try { $ips = @(Resolve-DnsName -Name $Server -ErrorAction Stop | Where-Object { $_.IPAddress } | ForEach-Object { $_.IPAddress }); Ok "DNS: $Server = $($ips -join ', ')" }
catch { if ($Server -match '^\d+\.\d+\.\d+\.\d+$') { Ok "Using IP address $Server" } else { Bad "DNS cannot resolve $Server from this computer. Point this computer's DNS at the domain controller, or pass -Server with the DC's IP address."; return } }
$ldap = Test-Port $Server 389; $gc = Test-Port $Server 3268
if ($ldap) { Ok 'LDAP 389 answers' } else { Bad 'LDAP 389 does not answer (firewall, VPN or wrong address)'; return }
if (Test-Port $Server 88) { Ok 'Kerberos 88 answers' } else { Bad 'Kerberos 88 does not answer. The bind will fall back to NTLM.' }
if ($gc) { Ok 'Global catalog 3268 answers' } else { Bad 'Global catalog 3268 does not answer. Users in other domains of the forest will not be found; one domain still works.' }

if (-not $UserName -and -not $joined) { throw 'Pass -UserName with the reader account, for example DOMAIN\svc-e360-reader.' }
if (-not $Apply) {
  Step 'Dry run'
  Write-Host "  Would ask for the password of $(if ($UserName) { $UserName } else { 'nobody (uses this computer''s Windows identity)' }), test the bind,"
  Write-Host "  save it to $CredentialPath and write E360_AD_SERVER=$Server to $EnvFile."
  Write-Host "`nAdd -Apply to do it." -ForegroundColor Yellow; return
}

$cred = $null
if ($UserName) {
  Step "2. Password for $UserName"
  $sec = Read-Host -AsSecureString "Type the password for $UserName and press Enter"
  if (-not $sec -or $sec.Length -eq 0) { throw 'No password entered.' }
  $cred = New-Object System.Management.Automation.PSCredential($UserName, $sec)
  Ok 'Password received'
}

Step "3. Test the LDAP bind to $Server (15 second limit per try)"
$nc = if ($cred) { $cred.GetNetworkCredential() } else { $null }
$bindArgs = @($Server, $(if ($nc) { $nc.UserName } else { '' }), $(if ($nc) { $nc.Domain } else { '' }), $(if ($nc) { $nc.Password } else { '' }))
Write-Host '  Trying Kerberos (Negotiate)...'
$bind = Invoke-WithTimeout $BindTest ($bindArgs + 'Negotiate') 20
if (-not $bind.ok -and $cred) {
  Bad "Kerberos/Negotiate: $($bind.error)"
  Write-Host '  Trying NTLM...'
  $bind = Invoke-WithTimeout $BindTest ($bindArgs + 'Ntlm') 20
  if ($bind.ok) {
    # Windows only uses NTLM when it cannot get a Kerberos ticket, and it never gets one for an IP address. Saving the DC's
    # IP makes Entity 360's own queries use NTLM too instead of waiting on Kerberos.
    $ip = [System.Net.Dns]::GetHostAddresses($Server) | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1
    if ($ip) { Ok "NTLM works, Kerberos does not from this computer. Saving the DC as $ip so Entity 360 uses NTLM."; $Server = $ip.ToString(); $bindArgs[0] = $Server }
  }
}
if (-not $bind.ok) {
  Bad "Bind failed: $($bind.error)"
  if ($bind.error -match 'credential|password|logon') { Write-Host '  The user name or password is wrong, or the account is disabled or locked. Nothing was saved.' -ForegroundColor Yellow }
  else { Write-Host '  Nothing was saved. Send this output to whoever set up Entity 360.' -ForegroundColor Yellow }
  return
}
$dnc = $bind.dnc
Ok "Bound to $($bind.dc) ($dnc)"

Step '4 and 5. Save the credential and point Entity 360 at AD'
if ($cred) {
  New-Item -ItemType Directory -Force -Path (Split-Path -Parent $CredentialPath) | Out-Null
  $cred | Export-Clixml -LiteralPath $CredentialPath
  Ok "Saved (DPAPI, this Windows user only): $CredentialPath"
  Set-EnvLine $EnvFile 'E360_AD_CREDENTIAL' $CredentialPath
} else { Remove-EnvLine $EnvFile 'E360_AD_CREDENTIAL' }
Set-EnvLine $EnvFile 'E360_AD_SERVER' $Server
Ok "Wrote E360_AD_SERVER$(if ($cred) { ' and E360_AD_CREDENTIAL' }) to $EnvFile"

Step '6. Real query: the groups of the reader account itself'
$sam = if ($cred) { ($cred.UserName -split '\\')[-1] -replace '@.*$', '' } else { $env:USERNAME }
$lookup = {
  param($srv, $user, $domain, $password, $dnc, $sam)
  try {
    Add-Type -AssemblyName System.DirectoryServices.Protocols
    $id = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($srv, 389, $false, $false)
    $nc = if ($user) { New-Object System.Net.NetworkCredential($user, $password, $domain) } else { $null }
    $c = New-Object System.DirectoryServices.Protocols.LdapConnection($id, $nc, [System.DirectoryServices.Protocols.AuthType]::Negotiate)
    $c.Timeout = [TimeSpan]::FromSeconds(15); $c.SessionOptions.ProtocolVersion = 3; $c.SessionOptions.Signing = $true; $c.SessionOptions.Sealing = $true
    $req = New-Object System.DirectoryServices.Protocols.SearchRequest($dnc, "(sAMAccountName=$sam)", [System.DirectoryServices.Protocols.SearchScope]::Subtree, [string[]]@('objectSid'))
    $r = $c.SendRequest($req, [TimeSpan]::FromSeconds(15))
    if (-not $r.Entries.Count) { return [pscustomobject]@{ ok = $false; error = "$sam not found" } }
    [pscustomobject]@{ ok = $true; sid = (New-Object System.Security.Principal.SecurityIdentifier($r.Entries[0].Attributes['objectSid'].GetValues([byte[]])[0], 0)).Value }
  } catch { [pscustomobject]@{ ok = $false; error = $_.Exception.Message } }
}
$found = Invoke-WithTimeout $lookup ($bindArgs + @($dnc, $sam)) 20
if (-not $found.ok) { Bad "Could not look up $sam ($($found.error)). The connection is saved; open AD groups for a synced user in Entity 360."; return }
$sid = $found.sid
$argList = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', ('"' + (Join-Path $PSScriptRoot 'server\ad\Get-E360AdGroups.ps1') + '"'), '-UserSid', $sid, '-Server', $Server)
if ($cred) { $argList += @('-CredentialPath', ('"' + $CredentialPath + '"')) }
$psi = New-Object System.Diagnostics.ProcessStartInfo("$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe", ($argList -join ' '))
$psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true; $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
Write-Host '  Running the same query Entity 360 runs (60 second limit)...'
$p = [System.Diagnostics.Process]::Start($psi)
$stdout = $p.StandardOutput.ReadToEndAsync(); $stderr = $p.StandardError.ReadToEndAsync()
if (-not $p.WaitForExit(60000)) { $p.Kill(); Bad 'The AD query did not finish in 60 seconds. The connection is saved; send this output to whoever set up Entity 360.'; return }
if (-not $stdout.Result.Trim()) { Bad "The AD query returned nothing. $($stderr.Result.Trim())"; return }
$out = $stdout.Result | ConvertFrom-Json
if ($out.status -ne 'live') { Bad "$($out.status): $($out.message)"; return }
Ok "Forest $($out.forest), DC $($out.server). $sam is in $(@($out.groups).Count) security group(s):"
$out.groups | ForEach-Object { Write-Host ("        {0,-8} {1,-14} {2}" -f $_.membership, $_.scope, $_.name) }
Write-Host "`nDone. Restart Entity 360 so it reads the new .env." -ForegroundColor Green
