# verify-block.ps1 - checks that wu-blocker's Disable took hold on every layer.
# Run elevated:  powershell -ExecutionPolicy Bypass -File .\verify-block.ps1

$ErrorActionPreference = 'SilentlyContinue'
$script:pass = 0
$script:fail = 0

function Ok($m)   { Write-Host "  [OK]   $m"   -ForegroundColor Green;  $script:pass++ }
function Bad($m)  { Write-Host "  [FAIL] $m"   -ForegroundColor Red;    $script:fail++ }
function Skip($m) { Write-Host "  [skip] $m"   -ForegroundColor DarkGray }
function Head($m) { Write-Host ""; Write-Host $m -ForegroundColor Cyan }

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Host "WARNING: run this as Administrator for accurate results." -ForegroundColor Yellow }

$services = @('wuauserv','UsoSvc','BITS','WaaSMedicSvc','DoSvc','uhssvc')

Head "=== 1. Services: disabled, DACL-denied, cannot start ==="
foreach ($s in $services) {
    $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$s"
    if (-not (Test-Path $key)) { Skip "$s (not installed)"; continue }

    $start = (Get-ItemProperty $key).Start
    if ($start -eq 4) { Ok "$s Start=4 (disabled)" } else { Bad "$s Start=$start (expected 4)" }

    $sd = (& sc.exe sdshow $s) -join ''
    if ($sd -match '\(D;[^)]*;;;SY\)') { Ok "$s SCM DACL denies SYSTEM" } else { Bad "$s no SYSTEM deny in SCM DACL" }

    & sc.exe start $s 2>&1 | Out-Null
    $code = $LASTEXITCODE
    if ($code -ne 0) {
        Ok "$s refuses to start (exit $code)"
    } else {
        Bad "$s STARTED despite the block (exit 0)"
        & sc.exe stop $s 2>&1 | Out-Null
    }
}

Head "=== 2. Start=4 across all ControlSets ==="
$csList = @()
Get-ChildItem 'HKLM:\SYSTEM' | ForEach-Object {
    if ($_.PSChildName -match '^ControlSet\d+$') { $csList += $_.PSChildName }
}
$csList += 'CurrentControlSet'
foreach ($s in @('wuauserv','WaaSMedicSvc')) {
    foreach ($cs in ($csList | Select-Object -Unique)) {
        $k = "HKLM:\SYSTEM\$cs\Services\$s"
        if (-not (Test-Path $k)) { continue }
        $v = (Get-ItemProperty $k).Start
        if ($v -eq 4) { Ok "$cs\$s Start=4" } else { Bad "$cs\$s Start=$v (expected 4)" }
    }
}

Head "=== 3. Windows Update policies ==="
$policyChecks = @(
    @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU','NoAutoUpdate','1'),
    @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU','UseWUServer','1'),
    @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate','DisableWindowsUpdateAccess','1'),
    @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate','WUServer','http://localhost'),
    @('HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore','AutoDownload','2')
)
foreach ($c in $policyChecks) {
    $val = (Get-ItemProperty $c[0] -Name $c[1]).$($c[1])
    if ("$val" -eq $c[2]) { Ok "$($c[1]) = $val" } else { Bad "$($c[1]) = '$val' (expected '$($c[2])')" }
}

Head "=== 4. Scheduled tasks disabled or file-denied ==="
$tasks = @(
    '\Microsoft\Windows\WindowsUpdate\Scheduled Start',
    '\Microsoft\Windows\UpdateOrchestrator\Schedule Scan',
    '\Microsoft\Windows\UpdateOrchestrator\USO_UxBroker',
    '\Microsoft\Windows\InstallService\ScanForUpdates',
    '\Microsoft\Windows\WaaSMedic\PerformRemediation'
)
foreach ($t in $tasks) {
    $i = $t.LastIndexOf('\')
    $folder = $t.Substring(0, $i + 1)
    $name   = $t.Substring($i + 1)
    $obj    = Get-ScheduledTask -TaskPath $folder -TaskName $name
    $file   = Join-Path "$env:SystemRoot\System32\Tasks" $t.TrimStart('\')
    $fileDenied = $false
    if (Test-Path $file) { $fileDenied = ((& icacls.exe $file) -join '') -match 'SYSTEM:\(DENY' }

    if (-not $obj -and -not (Test-Path $file)) { Skip "$name (not present)"; continue }
    if (($obj -and $obj.State -eq 'Disabled') -or $fileDenied) {
        Ok "$name (disabled/denied)"
    } else {
        $st = 'none'; if ($obj) { $st = $obj.State }
        Bad "$name state=$st fileDeny=$fileDenied"
    }
}

Head "=== 5. WaaSMedic neutralized ==="
$dll = "$env:SystemRoot\System32\WaaSMedicSvc.dll"
if (Test-Path ($dll + '.wublocker.bak')) { Ok "WaaSMedicSvc.dll renamed to .wublocker.bak" }
elseif (-not (Test-Path $dll))            { Ok "WaaSMedicSvc.dll not present (removed/renamed)" }
else                                       { Bad "WaaSMedicSvc.dll still in place" }

$img = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc").ImagePath
if ("$img" -match 'WUBlockerNullified') { Ok "WaaSMedicSvc ImagePath nullified" } else { Bad "WaaSMedicSvc ImagePath = '$img'" }

Head "=== 6. Behavioural: Windows Update scan should fail ==="
$searchOk = $false
try {
    $session  = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    $null     = $searcher.Search("IsInstalled=0")
    $searchOk = $true
} catch {
    Ok ("Update search failed as expected: " + $_.Exception.Message.Split("`n")[0])
}
if ($searchOk) { Bad "Update search SUCCEEDED - Windows Update is still reachable" }

Write-Host ""
$color = 'Green'
if ($script:fail -gt 0) { $color = 'Yellow' }
Write-Host ("===== RESULT: {0} OK / {1} FAIL =====" -f $script:pass, $script:fail) -ForegroundColor $color
if ($script:fail -eq 0) {
    Write-Host "Windows Update is fully blocked on every checked layer." -ForegroundColor Green
} else {
    Write-Host "$($script:fail) check(s) did not hold - see the red [FAIL] lines above." -ForegroundColor Yellow
}
Write-Host "Tip: reboot and run again to confirm the block survives restart + self-healing." -ForegroundColor DarkGray
