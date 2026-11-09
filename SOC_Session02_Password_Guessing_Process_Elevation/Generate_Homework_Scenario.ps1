# SOC Session 02 - synthetic password-guessing + process-elevation lab
# Run only in a disposable, isolated Windows 10/11 VM, from 64-bit PowerShell as Administrator.
$ErrorActionPreference = 'Stop'
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { throw 'Open 64-bit Windows PowerShell using Run as Administrator.' }
if (-not [Environment]::Is64BitProcess) { throw 'Use 64-bit Windows PowerShell.' }

$account = 'SOC_Homework_Temp'
if (Get-LocalUser -Name $account -ErrorAction SilentlyContinue) { throw "The account $account already exists. Remove it or use a fresh disposable VM." }
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$marker = "SOC_SESSION02_$stamp"
$out = Join-Path $PSScriptRoot "Homework_Output_$stamp"
New-Item -ItemType Directory -Path $out -Force | Out-Null
$evtx = Join-Path $out 'SOC_Session02_Investigation.evtx'
$auditBackup = Join-Path $out 'audit-policy-backup.csv'
$accountCreated = $false
$taskName = "SOCSession02Limited_$stamp"
$taskCreated = $false
$regPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
$regName = 'ProcessCreationIncludeCmdLine_Enabled'
$regExisted = Test-Path $regPath
$regValueExisted = $false
$regValue = $null
$regKind = $null
if ($regExisted) {
    $k = Get-Item $regPath
    if ($k.GetValueNames() -contains $regName) { $regValueExisted=$true; $regValue=$k.GetValue($regName); $regKind=$k.GetValueKind($regName) }
}
$auditBackedUp = $false
$start = Get-Date
try {
    & auditpol.exe /backup "/file:$auditBackup" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Failed to back up audit policy.' }
    $auditBackedUp = $true
    # Audit Logon success/failure and Process Creation success.
    & auditpol.exe /set /subcategory:'Logon' /success:enable /failure:enable | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not enable Logon auditing.' }
    & auditpol.exe /set /subcategory:'Process Creation' /success:enable | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not enable Process Creation auditing.' }
    New-Item -Path $regPath -Force | Out-Null
    New-ItemProperty -Path $regPath -Name $regName -PropertyType DWord -Value 1 -Force | Out-Null

    $pw = Read-Host "Set a temporary password for $account (do not reuse a real password)" -AsSecureString
    New-LocalUser -Name $account -Password $pw -Description 'SOC homework temporary user' -AccountNeverExpires -PasswordNeverExpires | Out-Null
    $accountCreated = $true
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($pw)
    try { $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }

    Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class LabLogon {
 [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
 public static extern bool LogonUser(string u,string d,string p,int type,int provider,out IntPtr token);
 [DllImport("kernel32.dll", SetLastError=true)] public static extern bool CloseHandle(IntPtr h);
}
'@
    # Four deliberately incorrect network logons, then one successful network logon.
    1..4 | ForEach-Object {
        $t=[IntPtr]::Zero
        $ok=[LabLogon]::LogonUser($account,$env:COMPUTERNAME,'Incorrect-Lab-Password-Only!',3,0,[ref]$t)
        if ($ok) { [LabLogon]::CloseHandle($t) | Out-Null; throw 'Unexpectedly authenticated with the wrong password.' }
        Start-Sleep -Seconds 2
    }
    $t=[IntPtr]::Zero
    $ok=[LabLogon]::LogonUser($account,$env:COMPUTERNAME,$plain,3,0,[ref]$t)
    if (-not $ok) { throw "Successful test logon failed. Win32 error: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())" }
    [LabLogon]::CloseHandle($t) | Out-Null
    $plain=$null

    # Standard-user process creation; harmless PowerShell commands with unique markers.
    $cred = [pscredential]::new("$env:COMPUTERNAME\$account",$pw)
    $stdCmd = "Write-Output '$marker STANDARD_USER'; Get-Date | Out-Null"
    Start-Process "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Credential $cred -ArgumentList "-NoProfile -Command `"$stdCmd`"" -Wait -WindowStyle Hidden

    # Elevated process creation (this script itself must be run elevated).
    $adminCmd = "Write-Output '$marker ELEVATED_ADMIN'; Get-Date | Out-Null"
    Start-Process "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList "-NoProfile -Command `"$adminCmd`"" -Wait -WindowStyle Hidden

    # Best-effort Limited-token launch. Availability depends on UAC / Task Scheduler policy.
    try {
        $who = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        $limitedFile = Join-Path $out 'limited-token-task-marker.txt'
        $action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -Command `"Set-Content -Path '$limitedFile' -Value '$marker LIMITED_TOKEN'`""
        $principal = New-ScheduledTaskPrincipal -UserId $who -LogonType Interactive -RunLevel Limited
        Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Force | Out-Null
        $taskCreated = $true
        Start-ScheduledTask -TaskName $taskName
        Start-Sleep -Seconds 4
    } catch {
        "Limited-token attempt unavailable on this VM: $($_.Exception.Message)" | Set-Content (Join-Path $out 'LIMITED_TOKEN_NOTE.txt')
    }
    Start-Sleep -Seconds 3

    # Export only events from the controlled run window. Filter 4624/4625 by target account;
    # include 4688 events in the same short window so the file stays manageable.
    $from = $start.AddMinutes(-1)
    $to = (Get-Date).AddMinutes(1)
    $all = Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=$from; EndTime=$to; Id=4624,4625,4688} -ErrorAction SilentlyContinue
    $selected = foreach ($e in $all) {
        $xml = [xml]$e.ToXml()
        $data = @{}
        foreach ($d in $xml.Event.EventData.Data) { $data[[string]$d.Name] = [string]$d.'#text' }
        if ($e.Id -eq 4688) {
            if ($data.SubjectUserName -in @($account,$env:USERNAME)) { $e }
        } elseif ($data.TargetUserName -eq $account) { $e }
    }
    if (-not $selected) { throw 'No matching Security events were found. Check audit policy and rerun in a fresh VM.' }
    # Export native EVTX by exporting the Security log with a bounded XPath query, then filter via event time/account.
    # wevtutil supports time-bounded XPath; the resulting EVTX may include other events in this narrow time window.
    $startUtc = $from.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    $endUtc = $to.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    $xpath = "*[System[(EventID=4624 or EventID=4625 or EventID=4688) and TimeCreated[@SystemTime>='$startUtc' and @SystemTime<='$endUtc']]]"
    & wevtutil.exe epl Security $evtx "/q:$xpath" /ow:true
    if ($LASTEXITCODE -ne 0) { throw 'EVTX export failed.' }

    # Instructor-only QA index, generated alongside EVTX (do not distribute this CSV).
    $selected | Sort-Object TimeCreated | Select-Object TimeCreated,Id,RecordId,Message | Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $out 'INSTRUCTOR_Event_Index.csv')
    $selected | Group-Object Id | Select-Object @{n='EventID';e={$_.Name}},Count | Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $out 'INSTRUCTOR_Event_Counts.csv')
    @("Marker: $marker",'Expected logons: four 4625 failures then one 4624 success (verify actual records).','Expected process telemetry: Event 4688 for harmless PowerShell process launches.','TokenElevationType is in the 4688 event XML/message: %%1936 Default, %%1937 Full, %%1938 Limited. Limited is best-effort and is not guaranteed by Windows policy.','Review the EVTX and instructor CSV before giving the EVTX to students.') | Set-Content -Encoding UTF8 (Join-Path $out 'INSTRUCTOR_NOTES.txt')
    Write-Host "`nDone. EVTX created: $evtx" -ForegroundColor Green
    Write-Host 'Open it using Event Viewer > Action > Open Saved Log. Review instructor CSVs and verify actual TokenElevationType values before distribution.' -ForegroundColor Yellow
}
finally {
    if ($taskCreated) { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue }
    if ($accountCreated) { Remove-LocalUser -Name $account -ErrorAction SilentlyContinue }
    if ($auditBackedUp -and (Test-Path $auditBackup)) { & auditpol.exe /restore "/file:$auditBackup" | Out-Null }
    if ($regValueExisted) { New-Item -Path $regPath -Force | Out-Null; New-ItemProperty -Path $regPath -Name $regName -PropertyType $regKind -Value $regValue -Force | Out-Null }
    else {
        if (Test-Path $regPath) { Remove-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue; if (-not $regExisted -and (Get-Item $regPath).GetValueNames().Count -eq 0) { Remove-Item $regPath -Force -ErrorAction SilentlyContinue } }
    }
}
