<#
.SYNOPSIS
  Read-only. Collects the Active Directory and AD CS hardening posture of every domain in the forest for the
  Entity 360 Findings page (AD posture group).

.DESCRIPTION
  Entity 360 runs this on its own host when the AD posture section of Findings opens. It uses the same connection as
  the AD groups tab (Get-E360AdGroups.ps1): the DC in E360_AD_SERVER and the reader credential saved by
  Set-E360AdReader.ps1. Nothing is installed on a DC and nothing is written anywhere. Output is one line of JSON.

  What it reads, and over which path:
    LDAP (389) as the reader account, which needs Domain Users only:
      - Domains in the forest (crossRef objects), domain SID and functional level.
      - Domain controllers (computer accounts with SERVER_TRUST_ACCOUNT) and their operating system.
      - Trusts (trustedDomain objects in CN=System): partner, direction, type and attribute flags.
      - User accounts with a servicePrincipalName (Kerberoastable), accounts without Kerberos pre-authentication
        (AS-REP roastable), the krbtgt password age, gMSA count, computers trusted for unconstrained delegation.
      - LAPS: which LAPS schema attributes exist and which enabled computers have a LAPS password expiry time.
      - AD CS: certificate templates (flags, EKUs, schema version, the DACL via SecurityMasks Dacl/Owner, which any
        authenticated user may read) and the enterprise CAs with the templates each one publishes.
    LDAP bind test (389): one SASL bind per DC with signing and sealing turned off. A DC that requires LDAP signing
      refuses it with "strongerAuthRequired"; a DC that accepts it does not require signing. Nothing is changed.
    SYSVOL (SMB 445), read-only: GptTmpl.inf of the GPOs linked to the domain and to OU=Domain Controllers, for the
      configured LDAP signing, LDAP channel binding, SMB server signing and LAN Manager authentication level.
      This is what Group Policy sets, not the DC's effective registry; a value set locally on a DC is not visible.
    HTTP (80): one unauthenticated request to http://<CA host>/certsrv/ to see whether web enrollment answers over
      plain HTTP (an NTLM relay target, ESC8).

  Not readable over these paths (reported as such, never guessed): CA registry flags (ESC6 EDITF_ATTRIBUTESUBJECTALTNAME2,
  ESC11 RPC encryption), CA officer and manager permissions (ESC7), and the effective DC registry values.

  Connection:
    -Server          A domain controller or domain DNS name. Default: the domain this host is joined to.
    -CredentialPath  A PSCredential saved with Export-Clixml (Windows DPAPI). Default: the current Windows identity.
#>
[CmdletBinding()]
param(
  [string]$Server = '',
  [string]$CredentialPath = '',
  [int]$MaxRows = 2000,
  [int]$StaleDays = 90
)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.DirectoryServices
Add-Type -AssemblyName System.DirectoryServices.Protocols

function Out-Result($obj) { [Console]::Out.Write(($obj | ConvertTo-Json -Depth 8 -Compress)); exit 0 }

$cred = $null
if ($CredentialPath) {
  if (-not (Test-Path -LiteralPath $CredentialPath)) { Out-Result @{ status = 'notConfigured'; message = 'The saved AD reader credential was not found. Run Set-E360AdReader.ps1 again.' } }
  try { $cred = Import-Clixml -LiteralPath $CredentialPath } catch { Out-Result @{ status = 'notConfigured'; message = 'The saved AD reader credential could not be opened. It only works for the Windows user who saved it, on the same computer. Run Set-E360AdReader.ps1 again as the account that runs Entity 360.' } }
}
if (-not $Server) {
  try { $Server = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain().Name }
  catch { Out-Result @{ status = 'notConfigured'; message = 'This computer is not joined to an AD domain and no domain controller is set. Run Set-E360AdReader.ps1 to connect Entity 360 to on-premises AD.' } }
}

$auth = [System.DirectoryServices.AuthenticationTypes]::Secure -bor [System.DirectoryServices.AuthenticationTypes]::Signing -bor [System.DirectoryServices.AuthenticationTypes]::Sealing -bor [System.DirectoryServices.AuthenticationTypes]::ServerBind
function New-Entry([string]$path) {
  if ($cred) { return New-Object System.DirectoryServices.DirectoryEntry($path, $cred.UserName, $cred.GetNetworkCredential().Password, $auth) }
  return New-Object System.DirectoryServices.DirectoryEntry($path, $null, $null, $auth)
}
function Find-All([string]$path, [string]$filter, [string[]]$props, [int]$scope = 2, [switch]$Dacl) {
  $s = New-Object System.DirectoryServices.DirectorySearcher((New-Entry $path), $filter, $props, $scope)
  $s.PageSize = 500
  $s.SizeLimit = $MaxRows
  if ($Dacl) { $s.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl -bor [System.DirectoryServices.SecurityMasks]::Owner }
  $r = $s.FindAll()
  try { return @($r | ForEach-Object { $_ }) } finally { $r.Dispose() }
}
function First($res, [string]$name) { $v = $res.Properties[$name.ToLower()]; if ($v -and $v.Count) { return $v[0] } return $null }
function All($res, [string]$name) { return @($res.Properties[$name.ToLower()] | ForEach-Object { [string]$_ }) }
function Sid-String($bytes) { (New-Object System.Security.Principal.SecurityIdentifier([byte[]]$bytes, 0)).Value }
function FileTime($v) { if ($null -eq $v) { return $null }; $n = [int64]$v; if ($n -le 0 -or $n -ge [DateTime]::MaxValue.ToFileTimeUtc()) { return $null }; return [DateTime]::FromFileTimeUtc($n).ToString('o') }
# .NET method errors reach PowerShell wrapped in MethodInvocationException; find the real one by type.
function Find-Ex($e, [type]$t) { while ($e) { if ($e -is $t) { return $e }; $e = $e.InnerException }; return $null }
function Err([string]$m) { if ($m.Length -gt 300) { return $m.Substring(0, 300) } return $m }

$notes = New-Object System.Collections.Generic.List[string]

# Forest layout.
try {
  $rootDse = New-Entry "LDAP://$Server/RootDSE"
  $configNc = [string]$rootDse.Properties['configurationNamingContext'][0]
  $schemaNc = [string]$rootDse.Properties['schemaNamingContext'][0]
  $rootNc = [string]$rootDse.Properties['rootDomainNamingContext'][0]
  $serverNc = [string]$rootDse.Properties['defaultNamingContext'][0]
  $dcName = [string]$rootDse.Properties['dnsHostName'][0]
  $forestLevel = [string]$rootDse.Properties['forestFunctionality'][0]
} catch {
  $m = $_.Exception.Message
  $status = if ($m -match 'password|credential|logon failure|user name') { 'denied' } else { 'unreachable' }
  Out-Result @{ status = $status; server = $Server; message = "Could not connect to $Server over LDAP: $m" }
}
$crossRefs = Find-All "LDAP://$Server/CN=Partitions,$configNc" '(&(objectClass=crossRef)(systemFlags:1.2.840.113556.1.4.803:=3))' @('nCName', 'dnsRoot', 'nETBIOSName') 1
if (-not $crossRefs.Count) { Out-Result @{ status = 'error'; server = $Server; message = 'No domains were returned from the forest configuration.' } }

# Schema: which LAPS attributes exist (legacy Microsoft LAPS and Windows LAPS).
$schemaHas = @{}
foreach ($a in 'ms-Mcs-AdmPwdExpirationTime', 'msLAPS-PasswordExpirationTime') {
  try { $schemaHas[$a] = [bool](Find-All "LDAP://$Server/$schemaNc" "(lDAPDisplayName=$a)" @('cn') 1).Count } catch { $schemaHas[$a] = $false; $notes.Add("Schema check for $a failed: $(Err $_.Exception.Message)") }
}
$lapsProps = @('name', 'dNSHostName', 'operatingSystem', 'lastLogonTimestamp', 'whenCreated')
if ($schemaHas['ms-Mcs-AdmPwdExpirationTime']) { $lapsProps += 'ms-Mcs-AdmPwdExpirationTime' }
if ($schemaHas['msLAPS-PasswordExpirationTime']) { $lapsProps += 'msLAPS-PasswordExpirationTime' }

# LDAP signing test: SASL bind with signing and sealing off. strongerAuthRequired (8) = the DC requires signing.
function Test-LdapSigning([string]$dcHost) {
  try {
    $id = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($dcHost, 389, $true, $false)
    $c = if ($cred) { New-Object System.DirectoryServices.Protocols.LdapConnection($id, $cred.GetNetworkCredential(), [System.DirectoryServices.Protocols.AuthType]::Negotiate) } else { New-Object System.DirectoryServices.Protocols.LdapConnection($id, $null, [System.DirectoryServices.Protocols.AuthType]::Negotiate) }
    $c.Timeout = [TimeSpan]::FromSeconds(15)
    $c.SessionOptions.ProtocolVersion = 3
    $c.SessionOptions.Signing = $false
    $c.SessionOptions.Sealing = $false
    try { $c.Bind(); return @{ result = 'notRequired'; detail = 'An unsigned bind was accepted.' } } finally { $c.Dispose() }
  } catch {
    $le = Find-Ex $_.Exception ([System.DirectoryServices.Protocols.LdapException])
    if ($le -and $le.ErrorCode -eq 8) { return @{ result = 'required'; detail = 'An unsigned bind was refused (strongerAuthRequired).' } }
    $m = if ($le) { "LDAP error $($le.ErrorCode): $($le.Message)" } else { $_.Exception.Message }
    return @{ result = 'unknown'; detail = Err "Bind test failed: $m" }
  }
}

# SYSVOL: GptTmpl.inf of the GPOs linked to the domain root and OU=Domain Controllers, in precedence order.
$watch = @{
  'MACHINE\System\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity' = 'ldapServerIntegrity'
  'MACHINE\System\CurrentControlSet\Services\NTDS\Parameters\LdapEnforceChannelBinding' = 'ldapChannelBinding'
  'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature' = 'smbServerSigning'
  'MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel' = 'lmCompatibilityLevel'
}
function Read-GpoSettings($d, [string]$dcHost) {
  $out = @{ status = 'read'; values = @{}; gpos = @(); message = '' }
  $links = @()
  foreach ($target in @($d.nc, "OU=Domain Controllers,$($d.nc)")) {
    try {
      $o = Find-All "LDAP://$dcHost/$target" '(objectClass=*)' @('gPLink') 0 | Select-Object -First 1
      $gl = [string](First $o 'gPLink')
      foreach ($m in [regex]::Matches($gl, '\[LDAP://([^;\]]+);(\d)\]', 'IgnoreCase')) {
        $flags = [int]$m.Groups[2].Value
        if ($flags -band 1) { continue }   # link disabled
        $links += [pscustomobject]@{ dn = $m.Groups[1].Value; enforced = [bool]($flags -band 2); level = $(if ($target -eq $d.nc) { 0 } else { 1 }); index = $links.Count }
      }
    } catch { $out.status = 'partial'; $out.message = Err "gPLink on $target could not be read: $($_.Exception.Message)" }
  }
  # gPLink lists the lowest precedence link first. Domain links apply before OU links; enforced links apply last.
  # Windows PowerShell's Sort-Object is not stable, so the original position is a second sort key.
  $ordered = @($links | Where-Object { -not $_.enforced } | Sort-Object level, index) + @($links | Where-Object { $_.enforced } | Sort-Object @{ Expression = 'level'; Descending = $true }, index)
  $drive = $null
  try {
    $root = "\\$dcHost\SYSVOL"
    if ($cred) { $drive = New-PSDrive -Name ("E360SV" + [guid]::NewGuid().ToString('N').Substring(0, 6)) -PSProvider FileSystem -Root $root -Credential $cred -ErrorAction Stop; $base = "$($drive.Name):\" } else { $base = "$root\" }
    foreach ($l in $ordered) {
      if ($l.dn -notmatch 'CN=(\{[0-9A-Fa-f-]{36}\})') { continue }
      $guid = $Matches[1]
      $name = $guid
      try { $g = Find-All "LDAP://$dcHost/$($l.dn)" '(objectClass=groupPolicyContainer)' @('displayName', 'flags') 0 | Select-Object -First 1; if ($g) { $name = [string](First $g 'displayName'); if (([int](First $g 'flags')) -band 2) { continue } } } catch { }
      $inf = Join-Path $base "$($d.dns)\Policies\$guid\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
      $set = @()
      if (Test-Path -LiteralPath $inf) {
        $section = ''
        foreach ($line in (Get-Content -LiteralPath $inf -Encoding Unicode -ErrorAction Stop)) {
          $t = $line.Trim()
          if ($t -match '^\[(.+)\]$') { $section = $Matches[1]; continue }
          if ($section -ne 'Registry Values') { continue }
          if ($t -match '^(.+?)=\d+,(.*)$' -and $watch.ContainsKey($Matches[1])) {
            $key = $watch[$Matches[1]]
            $out.values[$key] = @{ value = $Matches[2].Trim('"'); gpo = $name; level = $(if ($l.level) { 'Domain Controllers OU' } else { 'Domain' }) }
            $set += $key
          }
        }
      }
      $out.gpos += [ordered]@{ name = $name; linkedTo = $(if ($l.level) { 'Domain Controllers OU' } else { 'Domain' }); enforced = $l.enforced; sets = $set }
    }
  } catch { $out.status = 'unavailable'; $out.message = Err "SYSVOL on $dcHost could not be read over SMB: $($_.Exception.Message)" }
  finally { if ($drive) { Remove-PSDrive -Name $drive.Name -ErrorAction SilentlyContinue } }
  return $out
}

$domains = @()
$domainSids = @{}
foreach ($x in $crossRefs) {
  $nc = [string](First $x 'nCName'); $dns = [string](First $x 'dnsRoot'); $nb = [string](First $x 'nETBIOSName')
  $h = if ($nc -eq $serverNc) { $Server } else { $dns }
  $d = [ordered]@{ name = $dns; netbios = $nb; nc = $nc; root = ($nc -eq $rootNc); reachable = $true; message = ''; sid = ''; functionalLevel = ''
    dcs = @(); trusts = @(); spnAccounts = @(); asrepAccounts = @(); delegation = @(); krbtgt = $null; gmsaCount = $null
    laps = [ordered]@{ legacySchema = $schemaHas['ms-Mcs-AdmPwdExpirationTime']; windowsSchema = $schemaHas['msLAPS-PasswordExpirationTime']; computers = @(); total = 0 }
    gpo = $null; errors = @() }
  try {
    $head = Find-All "LDAP://$h/$nc" '(objectClass=domainDNS)' @('objectSid', 'msDS-Behavior-Version') 0 | Select-Object -First 1
    $d.sid = Sid-String (First $head 'objectSid'); $d.functionalLevel = [string](First $head 'msDS-Behavior-Version')
    $domainSids[$d.sid] = $nb
  } catch { $d.reachable = $false; $d.message = Err "Domain $dns could not be read from this host: $($_.Exception.Message)"; $domains += $d; continue }

  $try = { param($label, $block) try { & $block } catch { $d.errors += [ordered]@{ check = $label; message = (Err $_.Exception.Message) } } }

  & $try 'dcs' {
    foreach ($r in (Find-All "LDAP://$h/$nc" '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))' @('name', 'dNSHostName', 'operatingSystem', 'operatingSystemVersion', 'userAccountControl'))) {
      $dcHost = [string](First $r 'dNSHostName'); if (-not $dcHost) { $dcHost = [string](First $r 'name') }
      $sign = Test-LdapSigning $dcHost
      $d.dcs += [ordered]@{ name = [string](First $r 'name'); host = $dcHost; os = [string](First $r 'operatingSystem'); osVersion = [string](First $r 'operatingSystemVersion'); ldapSigning = $sign.result; ldapSigningDetail = $sign.detail }
    }
  }
  & $try 'trusts' {
    foreach ($r in (Find-All "LDAP://$h/CN=System,$nc" '(objectClass=trustedDomain)' @('trustPartner', 'flatName', 'trustDirection', 'trustType', 'trustAttributes', 'whenCreated', 'whenChanged') 1)) {
      $d.trusts += [ordered]@{ partner = [string](First $r 'trustPartner'); flatName = [string](First $r 'flatName'); direction = [int](First $r 'trustDirection'); type = [int](First $r 'trustType'); attributes = [int64](First $r 'trustAttributes')
        created = ([datetime](First $r 'whenCreated')).ToUniversalTime().ToString('o'); changed = ([datetime](First $r 'whenChanged')).ToUniversalTime().ToString('o') }
    }
  }
  & $try 'spn' {
    foreach ($r in (Find-All "LDAP://$h/$nc" '(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(sAMAccountName=krbtgt)))' @('sAMAccountName', 'distinguishedName', 'servicePrincipalName', 'pwdLastSet', 'lastLogonTimestamp', 'adminCount', 'msDS-SupportedEncryptionTypes', 'description'))) {
      $d.spnAccounts += [ordered]@{ sam = [string](First $r 'sAMAccountName'); dn = [string](First $r 'distinguishedName'); spns = @(All $r 'servicePrincipalName' | Select-Object -First 5); spnCount = (All $r 'servicePrincipalName').Count
        pwdLastSet = (FileTime (First $r 'pwdLastSet')); lastLogon = (FileTime (First $r 'lastLogonTimestamp')); adminCount = [int](First $r 'adminCount'); encTypes = $(if ($null -ne (First $r 'msDS-SupportedEncryptionTypes')) { [int](First $r 'msDS-SupportedEncryptionTypes') } else { $null }); description = [string](First $r 'description') }
    }
  }
  & $try 'asrep' {
    foreach ($r in (Find-All "LDAP://$h/$nc" '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' @('sAMAccountName', 'distinguishedName', 'pwdLastSet', 'adminCount'))) {
      $d.asrepAccounts += [ordered]@{ sam = [string](First $r 'sAMAccountName'); dn = [string](First $r 'distinguishedName'); pwdLastSet = (FileTime (First $r 'pwdLastSet')); adminCount = [int](First $r 'adminCount') }
    }
  }
  & $try 'delegation' {
    foreach ($r in (Find-All "LDAP://$h/$nc" '(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(userAccountControl:1.2.840.113556.1.4.803:=8192))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' @('sAMAccountName', 'distinguishedName', 'objectClass', 'operatingSystem'))) {
      $d.delegation += [ordered]@{ sam = [string](First $r 'sAMAccountName'); dn = [string](First $r 'distinguishedName'); kind = $(if ((All $r 'objectClass') -contains 'computer') { 'Computer' } else { 'User' }); os = [string](First $r 'operatingSystem') }
    }
  }
  & $try 'krbtgt' {
    $k = Find-All "LDAP://$h/$nc" '(&(objectClass=user)(sAMAccountName=krbtgt))' @('pwdLastSet') | Select-Object -First 1
    if ($k) { $d.krbtgt = [ordered]@{ pwdLastSet = (FileTime (First $k 'pwdLastSet')) } }
  }
  & $try 'gmsa' { $d.gmsaCount = (Find-All "LDAP://$h/$nc" '(objectClass=msDS-GroupManagedServiceAccount)' @('cn')).Count }
  & $try 'laps' {
    $rows = Find-All "LDAP://$h/$nc" '(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(userAccountControl:1.2.840.113556.1.4.803:=8192))(!(userAccountControl:1.2.840.113556.1.4.803:=67108864)))' $lapsProps
    $d.laps.total = $rows.Count
    if ($rows.Count -ge $MaxRows) { $d.errors += [ordered]@{ check = 'lapsLimit'; message = "Only the first $MaxRows computers were read." } }
    foreach ($r in $rows) {
      $legacy = FileTime (First $r 'ms-Mcs-AdmPwdExpirationTime'); $win = FileTime (First $r 'msLAPS-PasswordExpirationTime')
      $d.laps.computers += [ordered]@{ name = [string](First $r 'name'); os = [string](First $r 'operatingSystem'); lastLogon = (FileTime (First $r 'lastLogonTimestamp')); legacyExpiry = $legacy; windowsExpiry = $win }
    }
  }
  $gpoHost = if ($d.dcs.Count) { $d.dcs[0].host } else { $h }
  $d.gpo = Read-GpoSettings $d $gpoHost
  $domains += $d
}

# AD CS: enterprise CAs and certificate templates (forest-wide, configuration partition).
$pki = [ordered]@{ status = 'read'; message = ''; cas = @(); templates = @(); names = @{} }
$pkiBase = "CN=Public Key Services,CN=Services,$configNc"
try {
  foreach ($r in (Find-All "LDAP://$Server/CN=Enrollment Services,$pkiBase" '(objectClass=pKIEnrollmentService)' @('cn', 'dNSHostName', 'certificateTemplates') 1)) {
    $caHost = [string](First $r 'dNSHostName')
    $web = 'unknown'; $webDetail = ''
    try {
      $req = [System.Net.HttpWebRequest]::Create("http://$caHost/certsrv/"); $req.Method = 'GET'; $req.Timeout = 6000; $req.AllowAutoRedirect = $false
      try { $resp = $req.GetResponse(); $web = 'http'; $webDetail = "HTTP $([int]$resp.StatusCode)"; $resp.Close() }
      catch {
        $we = Find-Ex $_.Exception ([System.Net.WebException])
        if ($we -and $we.Response) { $code = [int]$we.Response.StatusCode; $schemes = [string]$we.Response.Headers['WWW-Authenticate']; $we.Response.Close()
          if ($code -eq 401) { $web = 'http'; $webDetail = "HTTP 401, offers $schemes" } elseif ($code -eq 404) { $web = 'none'; $webDetail = 'HTTP 404' } else { $web = 'unknown'; $webDetail = "HTTP $code" } }
        elseif ($we) { $web = 'none'; $webDetail = Err $we.Message }
        else { $webDetail = Err $_.Exception.Message }
      }
    } catch { $webDetail = Err $_.Exception.Message }
    $pki.cas += [ordered]@{ name = [string](First $r 'cn'); host = $caHost; templates = @(All $r 'certificateTemplates'); webEnrollment = $web; webDetail = $webDetail }
  }
  $sids = @{}
  foreach ($r in (Find-All "LDAP://$Server/CN=Certificate Templates,$pkiBase" '(objectClass=pKICertificateTemplate)' @('cn', 'displayName', 'msPKI-Certificate-Name-Flag', 'msPKI-Enrollment-Flag', 'msPKI-RA-Signature', 'pKIExtendedKeyUsage', 'msPKI-Certificate-Application-Policy', 'msPKI-Template-Schema-Version', 'nTSecurityDescriptor', 'whenChanged') 1 -Dacl)) {
    $aces = @()
    $raw = First $r 'nTSecurityDescriptor'
    if ($raw) {
      $sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
      $sd.SetSecurityDescriptorBinaryForm([byte[]]$raw)
      foreach ($a in $sd.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
        $sid = $a.IdentityReference.Value; $sids[$sid] = $true
        $aces += [ordered]@{ sid = $sid; type = [string]$a.AccessControlType; rights = [string]$a.ActiveDirectoryRights; objectType = $a.ObjectType.ToString() }
      }
      $owner = $sd.GetOwner([System.Security.Principal.SecurityIdentifier]).Value; $sids[$owner] = $true
    } else { $owner = '' }
    $pki.templates += [ordered]@{ name = [string](First $r 'cn'); displayName = [string](First $r 'displayName'); nameFlag = [int64](First $r 'msPKI-Certificate-Name-Flag'); enrollFlag = [int64](First $r 'msPKI-Enrollment-Flag')
      raSignatures = [int](First $r 'msPKI-RA-Signature'); ekus = @(All $r 'pKIExtendedKeyUsage'); appPolicies = @(All $r 'msPKI-Certificate-Application-Policy'); schemaVersion = [int](First $r 'msPKI-Template-Schema-Version')
      owner = $owner; aces = $aces; daclRead = [bool]$raw; changed = ([datetime](First $r 'whenChanged')).ToUniversalTime().ToString('o') }
  }
  # Names for the principals in template ACLs (well-known SIDs are named by Entity 360 itself).
  $lookup = @($sids.Keys | Where-Object { $_ -match '^S-1-5-21-' })
  for ($i = 0; $i -lt $lookup.Count; $i += 40) {
    $chunk = $lookup[$i..([Math]::Min($i + 39, $lookup.Count - 1))]
    $f = '(|' + (($chunk | ForEach-Object { "(objectSid=$_)" }) -join '') + ')'
    try { foreach ($r in (Find-All "GC://$Server/$rootNc" $f @('objectSid', 'sAMAccountName'))) { $s = Sid-String (First $r 'objectSid'); $dom = $domainSids[($s -replace '-\d+$', '')]; $pki.names[$s] = $(if ($dom) { "$dom\$(First $r 'sAMAccountName')" } else { [string](First $r 'sAMAccountName') }) } } catch { $notes.Add("Naming template principals: $(Err $_.Exception.Message)") }
  }
} catch { $pki.status = 'unavailable'; $pki.message = Err "AD CS objects could not be read: $($_.Exception.Message)" }

Out-Result ([ordered]@{
  status = 'live'; server = $dcName; forest = (($crossRefs | Where-Object { [string](First $_ 'nCName') -eq $rootNc } | Select-Object -First 1) | ForEach-Object { [string](First $_ 'dnsRoot') }); forestLevel = $forestLevel
  domains = $domains; domainSids = $domainSids; pki = $pki; notes = @($notes)
})
