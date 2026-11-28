<#
.SYNOPSIS
  Creates the plain domain user Entity 360 uses to read AD group membership. No admin rights, no group added.

.DESCRIPTION
  Run on a domain controller or any server with the ActiveDirectory PowerShell module, as a Domain Admin
  (or an account delegated to create users in the target container).
    - Enabled user, password you type twice (never shown, never saved), password never expires, cannot change it.
    - Member of Domain Users only. Any domain user can read group membership by default, which is all Entity 360 needs.
    - Not added to any privileged or synced group.
  If your Entra sync scope covers the target container, the account also syncs to Entra as a normal user with no roles
  or licenses. Put it in a container outside the sync scope with -Path to avoid that.

  Default is a dry run. Add -Apply to create it. Undo: Remove-ADUser -Identity <name>.

.EXAMPLE
  .\New-E360AdReaderAccount.ps1                       # dry run, CN=Users of this domain
  .\New-E360AdReaderAccount.ps1 -Apply
#>
[CmdletBinding()]
param(
  [string]$SamAccountName = 'svc-e360-reader',
  [string]$Path = '',
  [switch]$Apply
)
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
$domain = Get-ADDomain
if (-not $Path) { $Path = $domain.UsersContainer }
$upn = "$SamAccountName@$($domain.DNSRoot)"
$existing = Get-ADUser -Filter "sAMAccountName -eq '$SamAccountName'" -ErrorAction SilentlyContinue
Write-Host "Domain:  $($domain.DNSRoot) ($($domain.NetBIOSName))"
Write-Host "Account: $($domain.NetBIOSName)\$SamAccountName  ($upn)"
Write-Host "Where:   $Path"
if ($existing) { Write-Host "`nAlready exists: $($existing.DistinguishedName). Nothing to do. To reset its password: Set-ADAccountPassword -Identity $SamAccountName -Reset" -ForegroundColor Yellow; return }
if (-not $Apply) { Write-Host "`nDry run. Add -Apply to create it." -ForegroundColor Yellow; return }
$p1 = Read-Host -AsSecureString "Password for $SamAccountName"
$p2 = Read-Host -AsSecureString 'Same password again'
$plain = { param($s) [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($s)) }
if ((& $plain $p1) -ne (& $plain $p2)) { throw 'The two passwords do not match. Nothing was created.' }
New-ADUser -Name 'Entity 360 AD reader' -SamAccountName $SamAccountName -UserPrincipalName $upn -Path $Path -AccountPassword $p1 -Enabled $true `
  -PasswordNeverExpires $true -CannotChangePassword $true -Description 'Entity 360: read-only AD group membership lookups. No rights beyond Domain Users.'
$u = Get-ADUser $SamAccountName -Properties MemberOf
Write-Host "`nCreated $($u.DistinguishedName). Extra groups: $(@($u.MemberOf).Count) (Domain Users is its primary group)." -ForegroundColor Green
Write-Host "Use it with: .\Set-E360AdReader.ps1 -Server <a domain controller> -UserName '$($domain.NetBIOSName)\$SamAccountName' -Apply"
