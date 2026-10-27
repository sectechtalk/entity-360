<# Read-only local snapshot. Run on the computer being investigated, as its signed-in Windows user.
 No sign-in, no remote queries, no tokens or credential keys collected. Upload the resulting JSON to Entity 360.
#>
[CmdletBinding()]
param([string]$OutputPath=(Join-Path ([Environment]::GetFolderPath('Desktop')) ('Entity360-'+$env:COMPUTERNAME+'-'+(Get-Date -Format 'yyyyMMdd-HHmmss')+'.json')))
$ErrorActionPreference='Stop'
$facts=[System.Collections.Generic.List[object]]::new()
function Add-Fact($area,$key,$value,$source,$status='reported') {
  if($null -eq $value){$value='Not returned';$status='unavailable'}
  $facts.Add(@{area=$area;key=$key;value=$value;source=$source;status=$status})
}
$identity=[System.Security.Principal.WindowsIdentity]::GetCurrent()
$snapshot=[ordered]@{schemaVersion=1;kind='entity360-device-snapshot';host=$env:COMPUTERNAME;collectedAt=(Get-Date).ToUniversalTime().ToString('o');windowsAccount=$identity.Name;sid=$identity.User.Value;facts=$facts;deviceIds=@()}
Add-Fact 'Identity' 'Windows sign-in identity' $identity.Name 'WindowsIdentity.GetCurrent'
Add-Fact 'Identity' 'Collector scope' 'Current Windows user; not proof of browser Microsoft identity' 'Collector'
try { $local=Get-LocalUser -SID $identity.User.Value;Add-Fact 'Identity' 'Windows account source' $local.PrincipalSource.ToString() 'Get-LocalUser' } catch {Add-Fact 'Identity' 'Windows account source' $null 'Get-LocalUser'}
try {
  $logon=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI'
  if($logon.LastLoggedOnUserSID -eq $identity.User.Value){Add-Fact 'Identity' 'Last Windows logon identifier (SID matched)' $logon.LastLoggedOnUser 'LogonUI cache; corroborating evidence, not a live account verification'}
}catch{}
try {$os=Get-CimInstance Win32_OperatingSystem;Add-Fact 'Windows' 'OS' ($os.Caption+' '+$os.Version) 'Win32_OperatingSystem';Add-Fact 'Windows' 'Last boot' $os.LastBootUpTime.ToUniversalTime().ToString('o') 'Win32_OperatingSystem';$pc=Get-CimInstance Win32_ComputerSystem;Add-Fact 'Windows' 'AD domain joined' ([bool]$pc.PartOfDomain) 'Win32_ComputerSystem';Add-Fact 'Windows' 'Domain or workgroup' $pc.Domain 'Win32_ComputerSystem'}catch{Add-Fact 'Windows' 'OS query' $null 'CIM'}
try {
  $dsreg=@("$env:WINDIR\Sysnative\dsregcmd.exe","$env:WINDIR\System32\dsregcmd.exe")|Where-Object {Test-Path -LiteralPath $_}|Select-Object -First 1
  $lines=& $dsreg /status
  foreach($key in @('AzureAdJoined','DomainJoined','WorkplaceJoined','NgcSet','AzureAdPrt','WamDefaultAuthority','WorkAccountCount','IsDeviceJoined','IsUserAzureAD','PolicyEnabled','DeviceEligible','PreReqResult','DeviceAuthStatus','TenantName','MdmUrl','MdmComplianceUrl')){
    $matches=@($lines|Select-String -Pattern ('^\s*'+$key+'\s*:\s*(.+)$'));if($matches.Count){Add-Fact 'Entra' $key $matches[0].Matches[0].Groups[1].Value 'dsregcmd /status (current user)'}
  }
  $device='';$tenant=''
  foreach($line in $lines){if($line -match '^\s*(?:Workplace)?DeviceId\s*:\s*([0-9a-f-]{36})'){$device=$Matches[1]};if($line -match '^\s*(?:Workplace)?TenantId\s*:\s*([0-9a-f-]{36})'){$tenant=$Matches[1];if($device){$snapshot.deviceIds+=@{deviceId=$device;tenantId=$tenant};$device='';$tenant=''}};if($line -match '^\s*WorkplaceTenantName\s*:\s*(.+)$'){Add-Fact 'Entra' 'Registered organization' $Matches[1] 'dsregcmd /status'}}
}catch{Add-Fact 'Entra' 'Device registration query' $null 'dsregcmd'}
try {$gpo=& "$env:WINDIR\System32\gpresult.exe" /r /scope user 2>&1;$code=$LASTEXITCODE;Add-Fact 'Group Policy' 'User Group Policy summary' (($gpo|Out-String).Substring(0,[Math]::Min(6000,($gpo|Out-String).Length))) 'gpresult /r /scope user' $(if($code -eq 0){'reported'}else{'unavailable'})}catch{Add-Fact 'Group Policy' 'User Group Policy summary' $null 'gpresult'}
Add-Fact 'Group Policy' 'Computer policy scope' 'Not collected. Effective computer policy may need an elevated gpresult collection.' 'Collector' 'unavailable'
try {$mp=Get-MpComputerStatus;foreach($key in @('AMServiceEnabled','AntivirusEnabled','RealTimeProtectionEnabled','AntivirusSignatureLastUpdated','IsTamperProtected')){$v=$mp.$key;if($v -is [datetime]){$v=$v.ToUniversalTime().ToString('o')};Add-Fact 'Defender' $key $v 'Get-MpComputerStatus'}}catch{Add-Fact 'Defender' 'Antivirus status' $null 'Get-MpComputerStatus'}
try {$sense=Get-Service Sense;Add-Fact 'Defender' 'Endpoint sensor service' $sense.Status.ToString() 'Get-Service Sense; running alone does not prove cloud onboarding'}catch{Add-Fact 'Defender' 'Endpoint sensor service' $null 'Get-Service Sense'}
try {$mde=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status';Add-Fact 'Defender' 'Endpoint onboarding state' $mde.OnboardingState 'MDE local status; correlate with cloud inventory'}catch{Add-Fact 'Defender' 'Endpoint onboarding state' $null 'MDE local status'}
try {$enrollments=@(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Enrollments'|Where-Object {$_.PSChildName -match '^[0-9a-f-]{36}$'}|ForEach-Object {Get-ItemProperty $_.PSPath}|Where-Object {$_.ProviderID -eq 'MS DM Server'});Add-Fact 'Intune' 'Microsoft MDM enrollment records' $enrollments.Count 'Windows enrollment registry; records can be stale, not proof of current Intune management'}catch{Add-Fact 'Intune' 'Local enrollment records' $null 'Windows enrollment registry'}
# Intune client configuration: registry values, scheduled-task metadata and an event count only. No sign-in, no network calls.
try {
  $edition=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').EditionID
  Add-Fact 'Windows' 'Windows edition' $edition 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion EditionID'
}catch{Add-Fact 'Windows' 'Windows edition' $null 'EditionID'}
try {
  $builtin=@('Deploy Authority','Cloud Authority','Local Authority')
  $n=0
  foreach($k in @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Enrollments' -ErrorAction Stop|Where-Object {$_.PSChildName -match '^[0-9a-f-]{36}$'})){
    $p=Get-ItemProperty $k.PSPath
    if($p.UPN -or $p.DiscoveryServiceFullURL -or ($p.ProviderID -and $builtin -notcontains $p.ProviderID)){
      $n++; if($n -gt 8){break}
      Add-Fact 'Intune' ('MDM enrollment '+$n) ('Provider='+$p.ProviderID+'; UPN='+$p.UPN+'; Discovery='+$p.DiscoveryServiceFullURL+'; State='+$p.EnrollmentState+'; Type='+$p.EnrollmentType) 'HKLM\SOFTWARE\Microsoft\Enrollments (one key per enrollment)'
    }
  }
  if($n -eq 0){Add-Fact 'Intune' 'MDM enrollment keys with a UPN or discovery URL' 0 'HKLM\SOFTWARE\Microsoft\Enrollments'}
}catch{Add-Fact 'Intune' 'MDM enrollment details' $null 'HKLM\SOFTWARE\Microsoft\Enrollments'}
try {
  $tasks=@(Get-ScheduledTask -TaskPath '\Microsoft\Windows\EnterpriseMgmt\*' -ErrorAction Stop)
  foreach($t in ($tasks|Select-Object -First 10)){
    $i=Get-ScheduledTaskInfo -InputObject $t
    $run=if($i.LastRunTime -and $i.LastRunTime.Year -gt 2000){$i.LastRunTime.ToUniversalTime().ToString('o')}else{'never'}
    Add-Fact 'Intune' ('EnterpriseMgmt task '+$t.TaskName) ('State='+$t.State+'; LastRun='+$run+'; LastResult='+$i.LastTaskResult) 'Get-ScheduledTask \Microsoft\Windows\EnterpriseMgmt'
  }
}catch{Add-Fact 'Intune' 'EnterpriseMgmt scheduled tasks' $null 'Get-ScheduledTask'}
try {
  $m=Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\MDM' -ErrorAction Stop
  Add-Fact 'Intune' 'Automatic MDM enrollment policy (AutoEnrollMDM)' $(if($null -ne $m.AutoEnrollMDM){[string]$m.AutoEnrollMDM}else{'Not configured'}) 'HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\MDM'
}catch{Add-Fact 'Intune' 'Automatic MDM enrollment policy (AutoEnrollMDM)' 'Not configured' 'HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\MDM (key absent)'}
try {
  $ev=@(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin';StartTime=(Get-Date).AddHours(-24)} -ErrorAction Stop|Where-Object {$_.Level -le 3})
  $text=if($ev.Count -eq 0){'0'}else{([string]$ev.Count)+' events: '+((($ev|Group-Object Id|Sort-Object Count -Descending|Select-Object -First 6)|ForEach-Object {'ID '+$_.Name+' x'+$_.Count}) -join ', ')}
  Add-Fact 'Intune' 'MDM log errors and warnings (24 hours)' $text 'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin'
}catch{
  if($_.FullyQualifiedErrorId -like '*NoMatchingEventsFound*'){Add-Fact 'Intune' 'MDM log errors and warnings (24 hours)' '0' 'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin'}
  else{Add-Fact 'Intune' 'MDM log errors and warnings (24 hours)' $null 'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin; may need an administrator window'}
}
$office=@("$env:ProgramFiles\Microsoft Office\root\Office16\WINWORD.EXE","${env:ProgramFiles(x86)}\Microsoft Office\root\Office16\WINWORD.EXE")|Where-Object {Test-Path -LiteralPath $_}
Add-Fact 'Office' 'Word installation detected' ([bool]$office) 'Selected Office16 executable paths; absence does not exclude other Office installations'
try {$ids=@(Get-ChildItem 'HKCU:\Software\Microsoft\Office\16.0\Common\Identity\Identities'|ForEach-Object {Get-ItemProperty $_.PSPath}|ForEach-Object {$_.EmailAddress;$_.UserName}|Where-Object {$_ -match '@'}|Select-Object -Unique);Add-Fact 'Office' 'Cached Office identities' ($ids -join ', ') 'Office identity registry; cached identities do not prove license ownership'}catch{Add-Fact 'Office' 'Cached Office identities' $null 'Office identity registry'}
try {foreach($n in @(Get-NetConnectionProfile)){Add-Fact 'Network' 'Network profile' ($n.InterfaceAlias+': '+$n.Name+' ('+$n.NetworkCategory+')') 'Get-NetConnectionProfile'}}catch{Add-Fact 'Network' 'Network profiles' $null 'Get-NetConnectionProfile'}
$snapshot|ConvertTo-Json -Depth 10|Set-Content -LiteralPath $OutputPath -Encoding utf8
Write-Host "Saved read-only device snapshot: $OutputPath"
Write-Host 'Import this JSON in Entity 360 > My account & device. Do not post it publicly; it contains account/device metadata.'
