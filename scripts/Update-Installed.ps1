# Apply a verified v1.0.1 payload without reinitializing device identity or baseline.
param([string]$Payload = (Join-Path $PSScriptRoot 'payload'))
$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (!(New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run in administrator PowerShell' }
$bin = Join-Path $env:ProgramFiles 'YcszFirewall'
$reg = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\YcszFirewall'
$installed = Get-ItemProperty $reg
if ($installed.DisplayVersion -notin @('1.0.0','1.0.1')) { throw 'Only installed v1.0.0 / v1.0.1 is supported' }
if ($installed.YcszRole -notin @('manager','client')) { throw 'Unknown installed role' }
$files = @('Ycsz.exe','Ycsz.Core.dll','Ycsz.exe.config','System.ps1')
if ($installed.YcszRole -eq 'manager') { $files += @('Ycsz-Client-Setup.exe','Ycsz-Client-Setup-NoRuntime.exe') }
$sc = Join-Path $env:WINDIR 'System32\sc.exe'
function Invoke-Sc([string[]]$Arguments,[string]$Operation) {
    & $sc @Arguments | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "$Operation failed: $LASTEXITCODE" }
}
function Stop-InstalledServiceAndCloseUi {
    $current = Get-Service YcszFirewall
    if ($current.Status -ne 'Stopped') {
        try { Stop-Service YcszFirewall -ErrorAction Stop }
        catch { throw "服务未能停止。若内核自保护已启用，请先在管理页进入已认证的自保护维护窗口，点击“维护停止本机服务”，确认服务已停止后再重试更新。原始错误：$($_.Exception.Message)" }
    }
    $current = Get-Service YcszFirewall
    $current.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(120))
    if ((Get-Service YcszFirewall).Status -ne 'Stopped') { throw 'Service did not stop before replacing files' }
    $close = Start-Process (Join-Path $bin 'Ycsz.exe') -ArgumentList @('--close-ui') -Wait -PassThru
    if ($close.ExitCode -ne 0) { throw "Cannot close interactive Ycsz UI: $($close.ExitCode)" }
}
$manifest = Get-Content (Join-Path $Payload 'hashes.json') -Raw | ConvertFrom-Json
foreach ($name in $files) {
    $expected = $manifest.$name
    if ($expected -notmatch '^[0-9a-fA-F]{64}$' -or (Get-FileHash (Join-Path $Payload $name)).Hash -ne $expected) { throw "Payload hash mismatch: $name" }
}
if ((Get-Item (Join-Path $Payload 'Ycsz.exe')).VersionInfo.FileVersion -ne '1.0.1.0') { throw 'Wrong update version' }
$backup = Join-Path $env:ProgramData ('YcszUpdateBackup-' + (Get-Date -Format yyyyMMdd-HHmmss))
New-Item $backup -ItemType Directory | Out-Null
& icacls.exe $backup /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)(F)' '*S-1-5-32-544:(OI)(CI)(F)' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Cannot secure backup' }
foreach ($name in $files) { if (Test-Path (Join-Path $bin $name)) { Copy-Item (Join-Path $bin $name) $backup } }
$settingsPath = Join-Path $env:ProgramData 'YcszFirewall\settings.bin'
$settingsHash = (Get-FileHash $settingsPath).Hash
Stop-InstalledServiceAndCloseUi
try {
    foreach ($name in $files) { Copy-Item (Join-Path $Payload $name) (Join-Path $bin $name) -Force }
    Invoke-Sc @('config','YcszFirewall','start=','auto') 'SCM startup mode'
    Invoke-Sc @('failure','YcszFirewall','reset=','86400','actions=','restart/5000/restart/10000/restart/30000') 'SCM failure actions'
    Invoke-Sc @('failureflag','YcszFirewall','1') 'SCM failure flag'
    Start-Service YcszFirewall
    (Get-Service YcszFirewall).WaitForStatus('Running',[TimeSpan]::FromSeconds(30))
    Start-Sleep -Seconds 8
    if ((Get-Service YcszFirewall).Status -ne 'Running') { throw 'Updated service did not remain running' }
    Set-ItemProperty $reg DisplayVersion '1.0.1'
    Set-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' YcszFirewallTray ('"' + (Join-Path $bin 'Ycsz.exe') + '" --tray')
    if ($installed.YcszRole -eq 'manager') {
        $shell = New-Object -ComObject WScript.Shell
        $link = $shell.CreateShortcut((Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) 'YCSZ Manager.lnk'))
        $link.TargetPath = Join-Path $bin 'Ycsz.exe'
        $link.WorkingDirectory = $bin
        $link.Save()
    }
    if ($installed.YcszRole -eq 'client') {
        $directory = Get-Item -LiteralPath $bin -Force
        $directory.Attributes = $directory.Attributes -bor [IO.FileAttributes]::Hidden
    }
    foreach ($name in $files) {
        if ((Get-FileHash (Join-Path $bin $name)).Hash -ne $manifest.$name) { throw "Installed hash mismatch: $name" }
    }
    if ((Get-FileHash $settingsPath).Hash -ne $settingsHash) { throw 'Settings identity changed unexpectedly' }
} catch {
    $updateFailure = $_
    try { Stop-InstalledServiceAndCloseUi } catch {
        throw "Rollback stopped before file replacement because service/UI shutdown failed. Backup: $backup. Update error: $updateFailure. Shutdown error: $_"
    }
    foreach ($name in $files) { if (Test-Path (Join-Path $backup $name)) { Copy-Item (Join-Path $backup $name) (Join-Path $bin $name) -Force } }
    Invoke-Sc @('config','YcszFirewall','start=','auto') 'SCM rollback startup mode'
    Invoke-Sc @('failure','YcszFirewall','reset=','86400','actions=','restart/5000/restart/10000/restart/30000') 'SCM rollback failure actions'
    Invoke-Sc @('failureflag','YcszFirewall','1') 'SCM rollback failure flag'
    Set-ItemProperty $reg DisplayVersion $installed.DisplayVersion
    Start-Service YcszFirewall
    (Get-Service YcszFirewall).WaitForStatus('Running',[TimeSpan]::FromSeconds(30))
    throw
}
Write-Output "PASS updated $env:COMPUTERNAME / $($installed.YcszRole) to 1.0.1; service running; payload hashes match; identity and baseline preserved; tray delegated to service supervisor."
Write-Output "Backup: $backup"
