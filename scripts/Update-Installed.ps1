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
$service = Get-Service YcszFirewall
Stop-Service YcszFirewall
$service.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(120))
& (Join-Path $bin 'Ycsz.exe') --close-ui
try {
    foreach ($name in $files) { Copy-Item (Join-Path $Payload $name) (Join-Path $bin $name) -Force }
    Start-Service YcszFirewall
    (Get-Service YcszFirewall).WaitForStatus('Running',[TimeSpan]::FromSeconds(30))
    Start-Sleep -Seconds 8
    if ((Get-Service YcszFirewall).Status -ne 'Running') { throw 'Updated service did not remain running' }
    Set-ItemProperty $reg DisplayVersion '1.0.1'
} catch {
    Stop-Service YcszFirewall -ErrorAction SilentlyContinue
    foreach ($name in $files) { if (Test-Path (Join-Path $backup $name)) { Copy-Item (Join-Path $backup $name) (Join-Path $bin $name) -Force } }
    Start-Service YcszFirewall
    throw
}
Set-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' YcszFirewallTray ('"' + (Join-Path $bin 'Ycsz.exe') + '" --tray')
if ($installed.YcszRole -eq 'manager') {
    $shell = New-Object -ComObject WScript.Shell
    $link = $shell.CreateShortcut((Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) 'YCSZ Manager.lnk'))
    $link.TargetPath = Join-Path $bin 'Ycsz.exe'
    $link.WorkingDirectory = $bin
    $link.Save()
}
Start-Process (Join-Path $bin 'Ycsz.exe') -ArgumentList '--tray'
foreach ($name in $files) {
    if ((Get-FileHash (Join-Path $bin $name)).Hash -ne $manifest.$name) { throw "Installed hash mismatch: $name" }
}
if ((Get-FileHash $settingsPath).Hash -ne $settingsHash) { throw 'Settings identity changed unexpectedly' }
Write-Output "PASS updated $env:COMPUTERNAME / $($installed.YcszRole) to 1.0.1; service running; payload hashes match; identity and baseline preserved; tray launched."
Write-Output "Backup: $backup"
