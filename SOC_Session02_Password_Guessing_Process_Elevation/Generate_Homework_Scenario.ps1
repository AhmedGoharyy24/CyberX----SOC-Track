
# SOC Session 02 - synthetic password-guessing + process-elevation lab
# Run only in a disposable, isolated Windows 10/11 VM,
# from 64-bit PowerShell as Administrator.

$ErrorActionPreference = 'Stop'

# ============================================================
# 1. ENVIRONMENT VALIDATION
# ============================================================

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)

if (-not $admin) {
    throw 'Open 64-bit Windows PowerShell using Run as Administrator.'
}

if (-not [Environment]::Is64BitProcess) {
    throw 'Use 64-bit Windows PowerShell.'
}

# FIX: Resolve PowerShell executable and a valid working directory.
$psExe = Join-Path $PSHOME 'powershell.exe'
$safeWorkingDirectory = Join-Path $env:SystemRoot 'System32'

if (-not (Test-Path -LiteralPath $psExe -PathType Leaf)) {
    throw "PowerShell executable not found: $psExe"
}

if (-not (Test-Path -LiteralPath $safeWorkingDirectory -PathType Container)) {
    throw "Working directory not found: $safeWorkingDirectory"
}

# ============================================================
# 2. INITIALIZATION
# ============================================================

$account = 'SOC_Homework_Temp'

if (Get-LocalUser -Name $account -ErrorAction SilentlyContinue) {
    throw "The account $account already exists. Remove it or use a fresh disposable VM."
}

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

    if ($k.GetValueNames() -contains $regName) {
        $regValueExisted = $true
        $regValue = $k.GetValue($regName)
        $regKind = $k.GetValueKind($regName)
    }
}

$auditBackedUp = $false
$start = Get-Date

# ============================================================
# 3. MAIN EXECUTION
# ============================================================

try {

    Write-Host "`n[1/7] Backing up audit policy..." -ForegroundColor Cyan

    & auditpol.exe /backup "/file:$auditBackup" | Out-Null

    if ($LASTEXITCODE -ne 0) {
        throw 'Failed to back up audit policy.'
    }

    $auditBackedUp = $true

    Write-Host "[2/7] Enabling Windows auditing..." -ForegroundColor Cyan

    & auditpol.exe /set /subcategory:'Logon' /success:enable /failure:enable | Out-Null

    if ($LASTEXITCODE -ne 0) {
        throw 'Could not enable Logon auditing.'
    }

    & auditpol.exe /set /subcategory:'Process Creation' /success:enable | Out-Null

    if ($LASTEXITCODE -ne 0) {
        throw 'Could not enable Process Creation auditing.'
    }

    New-Item -Path $regPath -Force | Out-Null

    New-ItemProperty -Path $regPath `
        -Name $regName `
        -PropertyType DWord `
        -Value 1 `
        -Force | Out-Null

    # ========================================================
    # 4. CREATE TEMPORARY ACCOUNT
    # ========================================================

    Write-Host "[3/7] Creating temporary lab account..." -ForegroundColor Cyan

    $pw = Read-Host "Set a temporary password for $account (do not reuse a real password)" -AsSecureString

    New-LocalUser -Name $account `
        -Password $pw `
        -Description 'SOC homework temporary user' `
        -AccountNeverExpires `
        -PasswordNeverExpires | Out-Null

    $accountCreated = $true

    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($pw)

    try {
        $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
    }

    # ========================================================
    # 5. GENERATE AUTHENTICATION EVENTS
    # ========================================================

    Write-Host "[4/7] Generating authentication events..." -ForegroundColor Cyan

    Add-Type @'
using System;
using System.Runtime.InteropServices;

public static class LabLogon {

    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern bool LogonUser(
        string u,
        string d,
        string p,
        int type,
        int provider,
        out IntPtr token
    );

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr h);
}
'@

    # Four deliberately incorrect network logons.
    1..4 | ForEach-Object {

        $t = [IntPtr]::Zero

        $ok = [LabLogon]::LogonUser(
            $account,
            $env:COMPUTERNAME,
            'Incorrect-Lab-Password-Only!',
            3,
            0,
            [ref]$t
        )

        if ($ok) {
            [LabLogon]::CloseHandle($t) | Out-Null
            throw 'Unexpectedly authenticated with the wrong password.'
        }

        Start-Sleep -Seconds 2
    }

    # One successful network logon.
    $t = [IntPtr]::Zero

    $ok = [LabLogon]::LogonUser(
        $account,
        $env:COMPUTERNAME,
        $plain,
        3,
        0,
        [ref]$t
    )

    if (-not $ok) {
        throw "Successful test logon failed. Win32 error: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }

    [LabLogon]::CloseHandle($t) | Out-Null

    $plain = $null

    # ========================================================
    # 6. PROCESS CREATION EVENTS
    # ========================================================

    Write-Host "[5/7] Generating process creation events..." -ForegroundColor Cyan

    # FIX: Encode PowerShell commands to avoid nested quotation issues.
    # FIX: Explicit WorkingDirectory prevents invalid directory errors.

    # STANDARD USER PROCESS
    $cred = [pscredential]::new(
        "$env:COMPUTERNAME\$account",
        $pw
    )

    $stdCmd = "Write-Output '$marker STANDARD_USER'; Get-Date | Out-Null"

    $stdEncoded = [Convert]::ToBase64String(
        [Text.Encoding]::Unicode.GetBytes($stdCmd)
    )

    $stdProcess = Start-Process `
        -FilePath $psExe `
        -Credential $cred `
        -ArgumentList "-NoProfile -NonInteractive -EncodedCommand $stdEncoded" `
        -WorkingDirectory $safeWorkingDirectory `
        -Wait `
        -WindowStyle Hidden `
        -PassThru

    if ($stdProcess.ExitCode -ne 0) {
        throw "Standard-user process failed. Exit code: $($stdProcess.ExitCode)"
    }

    # ELEVATED ADMIN PROCESS
    $adminCmd = "Write-Output '$marker ELEVATED_ADMIN'; Get-Date | Out-Null"

    $adminEncoded = [Convert]::ToBase64String(
        [Text.Encoding]::Unicode.GetBytes($adminCmd)
    )

    $adminProcess = Start-Process `
        -FilePath $psExe `
        -ArgumentList "-NoProfile -NonInteractive -EncodedCommand $adminEncoded" `
        -WorkingDirectory $safeWorkingDirectory `
        -Wait `
        -WindowStyle Hidden `
        -PassThru

    if ($adminProcess.ExitCode -ne 0) {
        throw "Elevated-admin process failed. Exit code: $($adminProcess.ExitCode)"
    }

    # ========================================================
    # 7. LIMITED TOKEN PROCESS (BEST EFFORT)
    # ========================================================

    Write-Host "[6/7] Attempting limited-token process..." -ForegroundColor Cyan

    try {

        $who = [Security.Principal.WindowsIdentity]::GetCurrent().Name

        $limitedFile = Join-Path $out 'limited-token-task-marker.txt'

        $limitedCmd = "Set-Content -LiteralPath '$limitedFile' -Value '$marker LIMITED_TOKEN'"

        $limitedEncoded = [Convert]::ToBase64String(
            [Text.Encoding]::Unicode.GetBytes($limitedCmd)
        )

        $action = New-ScheduledTaskAction `
            -Execute $psExe `
            -Argument "-NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand $limitedEncoded" `
            -WorkingDirectory $safeWorkingDirectory

        $principal = New-ScheduledTaskPrincipal `
            -UserId $who `
            -LogonType Interactive `
            -RunLevel Limited

        Register-ScheduledTask `
            -TaskName $taskName `
            -Action $action `
            -Principal $principal `
            -Force | Out-Null

        $taskCreated = $true

        Start-ScheduledTask -TaskName $taskName

        Start-Sleep -Seconds 4

    }
    catch {

        "Limited-token attempt unavailable on this VM: $($_.Exception.Message)" |
            Set-Content (Join-Path $out 'LIMITED_TOKEN_NOTE.txt')
    }

    Start-Sleep -Seconds 3

    # ========================================================
    # 8. COLLECT SECURITY EVENTS
    # ========================================================

    Write-Host "[7/7] Collecting and exporting Security events..." -ForegroundColor Cyan

    $from = $start.AddMinutes(-1)
    $to = (Get-Date).AddMinutes(1)

    $all = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        StartTime = $from
        EndTime = $to
        Id = 4624,4625,4688
    } -ErrorAction SilentlyContinue

    $selected = foreach ($e in $all) {

        $xml = [xml]$e.ToXml()

        $data = @{}

        foreach ($d in $xml.Event.EventData.Data) {
            $data[[string]$d.Name] = [string]$d.'#text'
        }

        if ($e.Id -eq 4688) {

            if ($data.SubjectUserName -in @($account,$env:USERNAME)) {
                $e
            }

        }
        elseif ($data.TargetUserName -eq $account) {
            $e
        }
    }

    if (-not $selected) {
        throw 'No matching Security events were found. Check audit policy and rerun in a fresh VM.'
    }

    # ========================================================
    # 9. EXPORT EVTX
    # ========================================================

    $startUtc = $from.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    $endUtc = $to.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')

    $xpath = "*[System[(EventID=4624 or EventID=4625 or EventID=4688) and TimeCreated[@SystemTime>='$startUtc' and @SystemTime<='$endUtc']]]"

    & wevtutil.exe epl Security $evtx "/q:$xpath" /ow:true

    if ($LASTEXITCODE -ne 0) {
        throw 'EVTX export failed.'
    }

    # ========================================================
    # 10. INSTRUCTOR QA FILES
    # ========================================================

    $selected |
        Sort-Object TimeCreated |
        Select-Object TimeCreated,Id,RecordId,Message |
        Export-Csv -NoTypeInformation -Encoding UTF8 `
        (Join-Path $out 'INSTRUCTOR_Event_Index.csv')

    $selected |
        Group-Object Id |
        Select-Object @{n='EventID';e={$_.Name}},Count |
        Export-Csv -NoTypeInformation -Encoding UTF8 `
        (Join-Path $out 'INSTRUCTOR_Event_Counts.csv')

    @(
        "Marker: $marker"
        'Expected logons: four 4625 failures followed by one 4624 success. Verify actual records.'
        'Expected process telemetry: Event 4688 for harmless PowerShell process launches.'
        'TokenElevationType: %%1936 Default, %%1937 Full, %%1938 Limited.'
        'Limited-token execution is best-effort and is not guaranteed by Windows policy.'
        'Review the EVTX and instructor CSV files before distributing the student package.'
    ) | Set-Content -Encoding UTF8 (Join-Path $out 'INSTRUCTOR_NOTES.txt')

    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "HOMEWORK SCENARIO GENERATED SUCCESSFULLY" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green

    Write-Host "`nOutput folder: $out" -ForegroundColor Cyan
    Write-Host "EVTX file: $evtx" -ForegroundColor Cyan

    Write-Host "`nReview instructor CSVs and verify actual TokenElevationType values before distribution." -ForegroundColor Yellow

}
finally {

    # ========================================================
    # 11. CLEANUP AND RESTORE CONFIGURATION
    # ========================================================

    if ($taskCreated) {
        Unregister-ScheduledTask `
            -TaskName $taskName `
            -Confirm:$false `
            -ErrorAction SilentlyContinue
    }

    if ($accountCreated) {
        Remove-LocalUser -Name $account -ErrorAction SilentlyContinue
    }

    if ($auditBackedUp -and (Test-Path $auditBackup)) {
        & auditpol.exe /restore "/file:$auditBackup" | Out-Null
    }

    if ($regValueExisted) {

        New-Item -Path $regPath -Force | Out-Null

        New-ItemProperty `
            -Path $regPath `
            -Name $regName `
            -PropertyType $regKind `
            -Value $regValue `
            -Force | Out-Null

    }
    else {

        if (Test-Path $regPath) {

            Remove-ItemProperty `
                -Path $regPath `
                -Name $regName `
                -ErrorAction SilentlyContinue

            if (-not $regExisted -and (Get-Item $regPath).GetValueNames().Count -eq 0) {
                Remove-Item $regPath -Force -ErrorAction SilentlyContinue
            }
        }
    }

    Write-Host "`nCleanup completed. Temporary account and scheduled task were removed." -ForegroundColor Yellow
}
