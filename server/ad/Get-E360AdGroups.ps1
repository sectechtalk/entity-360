<#
.SYNOPSIS
  Read-only. Lists every security group in the on-premises Active Directory forest that one user is a member of,
  directly or through nesting, including groups that never sync to Entra (Domain Users, Domain Admins, BUILTIN groups,
  groups outside the sync scope, domain local groups in other domains of the forest).

.DESCRIPTION
  Entity 360 runs this on its own host when the AD groups tab opens. It only reads (LDAP searches and attribute reads).
  Output is one line of JSON on stdout. Nothing is written anywhere.

  How the list is built:
    1. Finds the user by objectSid in the global catalog (falls back to the domain partition).
    2. Reads tokenGroups on the user: every security group in the user's own domain, universal groups from the whole
       forest and the primary group, exactly as a Kerberos logon would compute them.
    3. In every other domain of the forest, searches domain local groups that contain the user or one of the user's
       groups, nested to any depth (LDAP_MATCHING_RULE_IN_CHAIN).
    4. Walks memberOf upward from the user to show how each nested group is reached.

  Connection:
    -Server          A domain controller or domain DNS name. Default: the domain this host is joined to.
    -CredentialPath  A PSCredential saved with Export-Clixml (Windows DPAPI, readable only by the same Windows user
                     on the same computer). Default: the current Windows identity (Kerberos on a domain-joined host).
  Any domain user can read group membership by default, so the account needs no extra rights.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$UserSid,
  [string]$Server = '',
  [string]$CredentialPath = '',
  [int]$MaxGroups = 500
)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.DirectoryServices

function Out-Result($obj) { [Console]::Out.Write(($obj | ConvertTo-Json -Depth 6 -Compress)); exit 0 }

if ($UserSid -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$') { Out-Result @{ status = 'error'; message = 'The user has no on-premises security identifier.' } }

$cred = $null
if ($CredentialPath) {
  if (-not (Test-Path -LiteralPath $CredentialPath)) { Out-Result @{ status = 'notConfigured'; message = 'The saved AD reader credential was not found. Run Set-E360AdReader.ps1 again.' } }
  try { $cred = Import-Clixml -LiteralPath $CredentialPath } catch { Out-Result @{ status = 'notConfigured'; message = 'The saved AD reader credential could not be opened. It only works for the Windows user who saved it, on the same computer. Run Set-E360AdReader.ps1 again as the account that runs Entity 360.' } }
}
if (-not $Server) {
  try { $Server = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain().Name }
  catch { Out-Result @{ status = 'notConfigured'; message = 'This computer is not joined to an AD domain and no domain controller is set. Run Set-E360AdReader.ps1 to connect Entity 360 to on-premises AD.' } }
}

# ServerBind: treat -Server as a host name and skip the DC locator, which can stall on a computer that is not joined to the domain.
$auth = [System.DirectoryServices.AuthenticationTypes]::Secure -bor [System.DirectoryServices.AuthenticationTypes]::Signing -bor [System.DirectoryServices.AuthenticationTypes]::Sealing -bor [System.DirectoryServices.AuthenticationTypes]::ServerBind
function New-Entry([string]$path) {
  if ($cred) { return New-Object System.DirectoryServices.DirectoryEntry($path, $cred.UserName, $cred.GetNetworkCredential().Password, $auth) }
  return New-Object System.DirectoryServices.DirectoryEntry($path, $null, $null, $auth)
}
function Find-All([string]$path, [string]$filter, [string[]]$props, [int]$scope = 2) {
  $s = New-Object System.DirectoryServices.DirectorySearcher((New-Entry $path), $filter, $props, $scope)
  $s.PageSize = 500
  $r = $s.FindAll()
  try { return @($r | ForEach-Object { $_ }) } finally { $r.Dispose() }
}
function First($res, [string]$name) { $v = $res.Properties[$name.ToLower()]; if ($v -and $v.Count) { return $v[0] } return $null }
function Esc([string]$v) { $v.Replace('\', '\5c').Replace('*', '\2a').Replace('(', '\28').Replace(')', '\29').Replace([string][char]0, '\00') }
function Sid-String($bytes) { (New-Object System.Security.Principal.SecurityIdentifier([byte[]]$bytes, 0)).Value }
function Nc-Of([string]$dn) { (($dn -split '(?<!\\),') | Where-Object { $_ -match '^DC=' }) -join ',' }

$notes = New-Object System.Collections.Generic.List[string]

# 1. Forest layout: root DSE and the domains (crossRef objects) in the configuration partition.
try {
  $rootDse = New-Entry "LDAP://$Server/RootDSE"
  $configNc = [string]$rootDse.Properties['configurationNamingContext'][0]
  $rootNc = [string]$rootDse.Properties['rootDomainNamingContext'][0]
  $dcName = [string]$rootDse.Properties['dnsHostName'][0]
} catch {
  $m = $_.Exception.Message
  $status = if ($m -match 'password|credential|logon failure|user name') { 'denied' } else { 'unreachable' }
  Out-Result @{ status = $status; server = $Server; message = "Could not connect to $Server over LDAP: $m" }
}
$domains = @()
foreach ($x in (Find-All "LDAP://$Server/CN=Partitions,$configNc" '(&(objectClass=crossRef)(systemFlags:1.2.840.113556.1.4.803:=3))' @('nCName', 'dnsRoot', 'nETBIOSName') 1)) {
  $domains += [pscustomobject]@{ nc = [string](First $x 'nCName'); dns = [string](First $x 'dnsRoot'); netbios = [string](First $x 'nETBIOSName'); reachable = $true; sid = '' }
}
if (-not $domains.Count) { Out-Result @{ status = 'error'; server = $Server; message = 'No domains were returned from the forest configuration.' } }
function Domain-Of([string]$dn) { $nc = Nc-Of $dn; $domains | Where-Object { $_.nc -eq $nc } | Select-Object -First 1 }
# The configured server answers for its own domain; other domains are reached by their DNS name.
$serverNc = Nc-Of ([string]$rootDse.Properties['defaultNamingContext'][0])
function Host-For($d) { if ($d.nc -eq $serverNc) { return $Server } return $d.dns }

# 2. The user, by objectSid. Global catalog first so a user in any domain is found.
$userProps = @('distinguishedName', 'sAMAccountName', 'primaryGroupID', 'userPrincipalName')
$u = $null
try { $u = Find-All "GC://$Server/$rootNc" "(objectSid=$UserSid)" $userProps | Select-Object -First 1 } catch { $notes.Add("Global catalog search failed on ${Server}: $($_.Exception.Message). Searched the domain directly.") }
if (-not $u) { foreach ($d in $domains) { try { $u = Find-All "LDAP://$(Host-For $d)/$($d.nc)" "(objectSid=$UserSid)" $userProps | Select-Object -First 1 } catch { $d.reachable = $false }; if ($u) { break } } }
if (-not $u) { Out-Result @{ status = 'notFound'; server = $dcName; message = "No AD account with SID $UserSid was found in the forest. The account may have been deleted or moved to another forest." } }
$userDn = [string](First $u 'distinguishedName')
$userDomain = Domain-Of $userDn
$userHost = Host-For $userDomain

# 3. tokenGroups: transitive security groups (own domain + universal forest-wide + primary group).
$tokenSids = @()
try {
  $ue = New-Entry "LDAP://$userHost/$userDn"
  $ue.RefreshCache([string[]]@('tokenGroups'))
  foreach ($b in $ue.Properties['tokenGroups']) { $tokenSids += (Sid-String $b) }
} catch { $notes.Add("tokenGroups could not be read: $($_.Exception.Message)") }
$userDomain.sid = ($UserSid -replace '-\d+$', '')
$primarySid = "$($userDomain.sid)-$(First $u 'primaryGroupID')"

# Group records keyed by SID.
$groups = @{}
$groupProps = @('objectSid', 'distinguishedName', 'name', 'sAMAccountName', 'groupType', 'description', 'memberOf')
function Add-Group($res, [string]$via) {
  $sid = Sid-String (First $res 'objectSid')
  if ($groups.ContainsKey($sid)) { return $groups[$sid] }
  $dn = [string](First $res 'distinguishedName')
  $gt = [int64](First $res 'groupType')
  $d = Domain-Of $dn
  $scope = if ($gt -band 1) { 'Builtin' } elseif ($gt -band 2) { 'Global' } elseif ($gt -band 4) { 'Domain local' } elseif ($gt -band 8) { 'Universal' } else { 'Unknown' }
  $g = [pscustomobject]@{ sid = $sid; dn = $dn; name = [string](First $res 'name'); sam = [string](First $res 'sAMAccountName'); domain = $(if ($d) { $d.dns } else { '' }); netbios = $(if ($d) { $d.netbios } else { '' })
    scope = $scope; security = [bool]($gt -band 0x80000000); description = [string](First $res 'description'); memberOf = @($res.Properties['memberof'] | ForEach-Object { [string]$_ }); found = $via }
  $groups[$sid] = $g
  return $g
}
# Resolve SIDs: user's own domain first (covers BUILTIN and domain local groups there), then the global catalog.
function Resolve-Sids([string[]]$sids) {
  $left = @($sids | Where-Object { -not $groups.ContainsKey($_) })
  for ($i = 0; $i -lt $left.Count; $i += 40) {
    $chunk = $left[$i..([Math]::Min($i + 39, $left.Count - 1))]
    $f = '(|' + (($chunk | ForEach-Object { "(objectSid=$_)" }) -join '') + ')'
    try { foreach ($r in (Find-All "LDAP://$userHost/$($userDomain.nc)" "(&(objectClass=group)$f)" $groupProps)) { [void](Add-Group $r 'token') } } catch { $notes.Add("Resolving groups in $($userDomain.dns): $($_.Exception.Message)") }
  }
  $left = @($left | Where-Object { -not $groups.ContainsKey($_) })
  for ($i = 0; $i -lt $left.Count; $i += 40) {
    $chunk = $left[$i..([Math]::Min($i + 39, $left.Count - 1))]
    $f = '(|' + (($chunk | ForEach-Object { "(objectSid=$_)" }) -join '') + ')'
    try { foreach ($r in (Find-All "GC://$Server/$rootNc" "(&(objectClass=group)$f)" $groupProps)) { [void](Add-Group $r 'token') } } catch { $notes.Add("Resolving groups in the global catalog: $($_.Exception.Message)") }
  }
}
Resolve-Sids (@($tokenSids) + @($primarySid))
# BUILTIN groups have the same SID in every domain; keep the user's own domain copy only (done by resolving there first).

# 4. Domain local groups in the other domains of the forest, nested to any depth.
$known = @($userDn) + @($groups.Values | Where-Object { $_.scope -in 'Global', 'Universal' } | ForEach-Object { $_.dn })
foreach ($d in ($domains | Where-Object { $_.nc -ne $userDomain.nc })) {
  for ($i = 0; $i -lt $known.Count; $i += 25) {
    $chunk = $known[$i..([Math]::Min($i + 24, $known.Count - 1))]
    $f = '(|' + (($chunk | ForEach-Object { "(member:1.2.840.113556.1.4.1941:=$(Esc $_))" }) -join '') + ')'
    try { foreach ($r in (Find-All "LDAP://$($d.dns)/$($d.nc)" "(&(objectClass=group)$f)" ($groupProps + 'member'))) { $g = Add-Group $r 'otherDomain'; $g | Add-Member -NotePropertyName members -NotePropertyValue @($r.Properties['member'] | ForEach-Object { [string]$_ }) -Force } }
    catch { $d.reachable = $false; $notes.Add("Domain $($d.dns) could not be searched from this host: $($_.Exception.Message)"); break }
  }
}

# 5. How each group is reached: walk memberOf upward from the user (breadth first, shortest path wins).
$byDn = @{}; foreach ($g in $groups.Values) { $byDn[$g.dn.ToLower()] = $g }
$userMemberOf = @()
try { $ue2 = New-Entry "LDAP://$userHost/$userDn"; $ue2.RefreshCache([string[]]@('memberOf')); $userMemberOf = @($ue2.Properties['memberOf'] | ForEach-Object { [string]$_ }) } catch { }
try { $gcu = Find-All "GC://$Server/$rootNc" "(distinguishedName=$(Esc $userDn))" @('memberOf') | Select-Object -First 1; if ($gcu) { $userMemberOf += @($gcu.Properties['memberof'] | ForEach-Object { [string]$_ }) } } catch { }
foreach ($g in ($groups.Values | Where-Object { $_.found -eq 'otherDomain' -and ($_.members -contains $userDn) })) { $userMemberOf += $g.dn }
$parentsOf = @{}
foreach ($g in $groups.Values) { foreach ($p in $g.memberOf) { $k = $p.ToLower(); if (-not $parentsOf.ContainsKey($g.dn.ToLower())) { $parentsOf[$g.dn.ToLower()] = @() }; $parentsOf[$g.dn.ToLower()] += $k } }
foreach ($g in ($groups.Values | Where-Object { $_.found -eq 'otherDomain' })) { foreach ($m in $g.members) { $mk = $m.ToLower(); if ($byDn.ContainsKey($mk)) { if (-not $parentsOf.ContainsKey($mk)) { $parentsOf[$mk] = @() }; $parentsOf[$mk] += $g.dn.ToLower() } } }
$path = @{}; $queue = New-Object System.Collections.Queue
foreach ($p in ($userMemberOf | ForEach-Object { $_.ToLower() } | Select-Object -Unique)) { if ($byDn.ContainsKey($p) -and -not $path.ContainsKey($p)) { $path[$p] = @(); $queue.Enqueue($p) } }
while ($queue.Count) {
  $c = $queue.Dequeue()
  foreach ($p in ($parentsOf[$c] | Select-Object -Unique)) { if ($p -and $byDn.ContainsKey($p) -and -not $path.ContainsKey($p)) { $path[$p] = @($path[$c]) + @($byDn[$c].name); $queue.Enqueue($p) } }
}
$direct = @{}; foreach ($p in $userMemberOf) { $direct[$p.ToLower()] = $true }

$all = @($groups.Values | Where-Object { $_.security } | Sort-Object name)
$distribution = @($groups.Values | Where-Object { -not $_.security }).Count
$rows = @()
foreach ($g in ($all | Select-Object -First $MaxGroups)) {
  $k = $g.dn.ToLower()
  $membership = if ($g.sid -eq $primarySid) { 'Primary' } elseif ($direct.ContainsKey($k)) { 'Direct' } else { 'Nested' }
  $via = @(); if ($membership -eq 'Nested' -and $path.ContainsKey($k)) { $via = @($path[$k]) }   # plain assignment keeps a one-item array an array
  $rows += [ordered]@{ sid = $g.sid; dn = $g.dn; name = $g.name; sam = $g.sam; domain = $g.domain; netbios = $g.netbios; scope = $g.scope; description = $g.description; membership = $membership; via = $via; pathKnown = ($membership -ne 'Nested' -or $path.ContainsKey($k)) }
}
if ($all.Count -gt $MaxGroups) { $notes.Add("Showing the first $MaxGroups of $($all.Count) security groups.") }
if ($distribution) { $notes.Add("$distribution distribution group(s) left out: they grant no access.") }
Out-Result ([ordered]@{
  status = 'live'; server = $dcName; forest = ($domains | Where-Object { $_.nc -eq $rootNc } | Select-Object -First 1).dns
  user = [ordered]@{ dn = $userDn; sam = "$($userDomain.netbios)\$(First $u 'sAMAccountName')"; domain = $userDomain.dns }
  domains = @($domains | ForEach-Object { [ordered]@{ name = $_.dns; netbios = $_.netbios; reachable = $_.reachable } })
  groups = $rows; notes = @($notes)
})
