[CmdletBinding()]
param(
    [string]$PublishedName
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Protection-Validation.ps1')

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Remove-Protection.ps1 must run from an elevated PowerShell.'
}

# Resolve and validate the exact product package before any unload or deletion.
if ($PublishedName) {
    if ($PublishedName -notmatch '^oem[0-9]+\.inf$') { throw 'PublishedName must be an OEM INF name, not a path or command option.' }
    $package = Get-WindowsDriver -Online -Driver $PublishedName -ErrorAction Stop
    Assert-ProtectionPackage $PublishedName $package
}

$app = Get-Service -Name YcszFirewall -ErrorAction SilentlyContinue
if ($null -ne $app -and $app.Status -ne 'Stopped') {
    throw 'YcszFirewall is still running. Authenticate maintenance, call PREPARE_UNLOAD, stop the service, then run this script within the lease.'
}

$driver = Get-Service -Name YcszProtection -ErrorAction SilentlyContinue
if ($null -eq $driver) {
    Write-Output 'PASS YcszProtection is not registered.'
    return
}

$filters = (& (Join-Path $env:WINDIR 'System32\fltmc.exe') filters 2>&1 | Out-String)
if ($LASTEXITCODE -ne 0) { throw 'Cannot confirm loaded filter state. No service or driver package was deleted.' }
if ($filters -match '(?im)^\s*YcszProtection\s') {
    & (Join-Path $env:WINDIR 'System32\fltmc.exe') unload YcszProtection | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "Filter Manager refused YcszProtection unload ($LASTEXITCODE). The maintenance lease may be expired or a control connection is still open. No service was deleted."
    }
}

if ((Get-Service -Name YcszProtection -ErrorAction Stop).Status -ne 'Stopped') {
    throw 'YcszProtection is not stopped after the unload request. Nothing will be deleted.'
}

& (Join-Path $env:WINDIR 'System32\sc.exe') delete YcszProtection | Out-Host
if ($LASTEXITCODE -ne 0) { throw "YcszProtection service deletion failed: $LASTEXITCODE" }

if ($PublishedName) {
    & (Join-Path $env:WINDIR 'System32\pnputil.exe') /delete-driver $PublishedName /uninstall | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "Driver-store removal failed: $LASTEXITCODE" }
}

Write-Output 'PASS YcszProtection unloaded and service registration removed.'
