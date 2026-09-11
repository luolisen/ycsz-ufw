param([switch]$DisposableVm)
$ErrorActionPreference = 'Stop'
if (!$DisposableVm -and !($env:GITHUB_ACTIONS -eq 'true' -and $env:RUNNER_ENVIRONMENT -eq 'github-hosted')) { throw 'Run only on an explicitly disposable Windows VM or GitHub-hosted runner.' }
$repo = Split-Path $PSScriptRoot -Parent
$data = Join-Path $env:ProgramData 'YcszFirewall'
if ((Get-Service YcszFirewall -ErrorAction SilentlyContinue) -or (Test-Path $data)) { throw 'Refusing existing service or configuration.' }
if (Get-NetTCPConnection -State Listen -LocalPort 17443 -ErrorAction SilentlyContinue) { throw 'Port 17443 already used.' }
$suffix = [guid]::NewGuid().ToString('N').Substring(0,10)
$fixture = Join-Path $env:ProgramFiles ('Ycsz-Test-' + $suffix)
$user = 'YcszTest' + $suffix
$madeUser = $false
$ownsData = $false
$madeService = $false
function NativeCheck([string]$operation) { if ($LASTEXITCODE) { throw "$operation failed: $LASTEXITCODE" } }
function Remove-FixturePath([string]$Path) {
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    while (Test-Path -LiteralPath $Path) {
        try {
            Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
            return
        } catch {
            if ([DateTime]::UtcNow -ge $deadline) { throw }
            Start-Sleep -Seconds 1
        }
    }
}
function Stop-FixtureProcesses([string]$Path) {
    for ($attempt = 0; $attempt -lt 3; $attempt++) {
        $processes = @(Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -and $_.ExecutablePath -like ($Path + '\*') })
        if ($processes.Count -eq 0) { return }
        foreach ($process in $processes) { Stop-Process -Id ([int]$process.ProcessId) -Force -ErrorAction SilentlyContinue }
        Start-Sleep -Seconds 1
    }
}
try {
    New-Item -ItemType Directory $fixture | Out-Null
    Copy-Item "$repo\artifacts\app\Ycsz.exe","$repo\artifacts\app\Ycsz.Core.dll","$repo\artifacts\app\Ycsz.exe.config","$repo\artifacts\app\System.ps1","$repo\artifacts\app\SecurityProbe.exe","$repo\artifacts\Ycsz-Client-Setup.exe","$repo\artifacts\Ycsz-Client-Setup-NoRuntime.exe" $fixture
    & icacls.exe $fixture /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
    NativeCheck 'Fixture ACL'
    $env:YCSZ_DISPOSABLE_TEST = '1'
    $ownsData = $true
    & "$fixture\SecurityProbe.exe" --initialize
    NativeCheck 'Manager initialization'
    # Compile and execute the actual service creation/configuration lines from NSIS.
    # This tests embedded executable-path quoting, not an independently rewritten command.
    $source = Get-Content "$repo\installer\Ycsz.nsi"
    $commands = @($source | Where-Object { $_.Contains('sc.exe') -and $_ -match ' (create|description|failure|failureflag|sdset) ' })
    if ($commands.Count -ne 5) { throw 'Unexpected service command set; review fixture.' }
    $header = @'
Unicode true
!include "LogicLib.nsh"
Name "Ycsz disposable service fixture"
OutFile "__FIXTURE__\InstallProbe.exe"
InstallDir "__FIXTURE__"
RequestExecutionLevel admin
SilentInstall silent
Section
'@
    $check = @'
Pop $0
${If} $0 != 0
  SetErrorLevel 1
  Quit
${EndIf}
'@
    $script = $header.Replace('__FIXTURE__',$fixture) + "`r`n" + (($commands | ForEach-Object { $_ + "`r`n" + $check }) -join "`r`n") + "`r`nSectionEnd`r`n"
    $script | Set-Content "$fixture\fixture.nsi" -Encoding UTF8
    $nsis = (Get-Command makensis.exe -ErrorAction SilentlyContinue).Source
    if (!$nsis) { $nsis = "${env:ProgramFiles(x86)}\NSIS\makensis.exe" }
    & $nsis /INPUTCHARSET UTF8 /V2 "$fixture\fixture.nsi"
    NativeCheck 'Fixture NSIS compilation'
    $madeService = $true
    $install = Start-Process "$fixture\InstallProbe.exe" -Wait -PassThru
    if ($install.ExitCode -ne 0) { throw 'Production NSIS service commands failed.' }
    Write-Output 'PASS production NSIS service creation and configuration'
    Start-Service YcszFirewall
    (Get-Service YcszFirewall).WaitForStatus('Running',[TimeSpan]::FromSeconds(20))
    Start-Sleep -Seconds 2
    $service = Get-CimInstance Win32_Service -Filter "Name='YcszFirewall'"
    if ($service.StartName -ne 'LocalSystem' -or $service.StartMode -ne 'Auto' -or $service.PathName -ne ('"' + $fixture + '\Ycsz.exe" --service')) { throw 'Unexpected service identity/path/start mode.' }
    Write-Output 'PASS LocalSystem auto-start and quoted executable path'
    $env:YCSZ_TEST_SERVICE_PID = [string]$service.ProcessId
    $env:YCSZ_TEST_USER = $user
    $env:YCSZ_TEST_PASSWORD = [guid]::NewGuid().ToString('N') + '!aA9'
    New-LocalUser -Name $user -Password (ConvertTo-SecureString $env:YCSZ_TEST_PASSWORD -AsPlainText -Force) -AccountNeverExpires | Out-Null
    $madeUser = $true
    $users = Get-LocalGroup -SID 'S-1-5-32-545'
    Add-LocalGroupMember -Group $users -Member $user
    & "$fixture\SecurityProbe.exe" --checks
    NativeCheck 'Windows standard-user and TLS registration checks'
    # Only this newly-created, known-path manager fixture is terminated.
    $before = $service.ProcessId
    Stop-Process -Id $before -Force
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    do {
        Start-Sleep -Seconds 1
        $service = Get-CimInstance Win32_Service -Filter "Name='YcszFirewall'"
    } while (($service.State -ne 'Running' -or $service.ProcessId -eq $before) -and [DateTime]::UtcNow -lt $deadline)
    if ($service.State -ne 'Running' -or !$service.ProcessId -or $service.ProcessId -eq $before) { throw 'SCM did not recover fixture after process termination.' }
    Write-Output 'PASS SCM restarts terminated service with new PID'
    Start-Sleep -Seconds 2
    & "$fixture\SecurityProbe.exe" --persistence
    NativeCheck 'Post-recovery persistence checks'
    Write-Output 'RESULT disposable Windows manager security checks passed; client WFP/network enforcement not exercised'
} finally {
    foreach ($name in @('YCSZ_TEST_USER','YCSZ_TEST_PASSWORD','YCSZ_TEST_SERVICE_PID','YCSZ_DISPOSABLE_TEST')) { [Environment]::SetEnvironmentVariable($name,$null,'Process') }
    if ($madeService) {
        $service = Get-CimInstance Win32_Service -Filter "Name='YcszFirewall'" -ErrorAction SilentlyContinue
        $servicePid = if ($service) { [int]$service.ProcessId } else { 0 }
        Stop-Service YcszFirewall -ErrorAction SilentlyContinue
        if ($servicePid -gt 0) { Wait-Process -Id $servicePid -Timeout 30 -ErrorAction SilentlyContinue }
        & sc.exe delete YcszFirewall | Out-Null
    }
    if ($madeUser) { Remove-LocalUser -Name $user }
    Stop-FixtureProcesses $fixture
    if ($ownsData -and (Test-Path $data)) { Remove-FixturePath $data }
    if (Test-Path $fixture) { Remove-FixturePath $fixture }
}
