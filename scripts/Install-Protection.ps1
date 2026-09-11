[CmdletBinding()]
param(
    [string]$DriverPackage = (Join-Path $PSScriptRoot '..\artifacts\driver\Release'),
    [string]$InstallDir = (Join-Path $env:ProgramFiles 'YcszFirewall')
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Protection-Validation.ps1')

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Install-Protection.ps1 must run from an elevated PowerShell.'
    }
}

function Invoke-Sc([string[]]$Arguments,[string]$Operation) {
    & (Join-Path $env:WINDIR 'System32\sc.exe') @Arguments | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "$Operation failed: $LASTEXITCODE" }
}

function Get-ServiceOrNull([string]$Name) {
    try { Get-Service -Name $Name -ErrorAction Stop }
    catch {
        if ($_.FullyQualifiedErrorId -like 'NoServiceFoundForGivenName*') { return $null }
        throw
    }
}

function Wait-Stopped([string]$Name) {
    $service = Get-ServiceOrNull $Name
    if ($null -eq $service) { return }
    $service.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(120))
    if ((Get-Service $Name).Status -ne 'Stopped') { throw "$Name did not stop" }
}

if (-not ('YcszProtectionNative' -as [type])) {
    Add-Type @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class YcszProtectionNative {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern uint QueryDosDevice(string device, StringBuilder target, uint max);
}
'@
}

function ConvertTo-NtPath([string]$Path) {
    $full = [IO.Path]::GetFullPath($Path)
    if ($full -notmatch '^[A-Za-z]:\\') { throw "The protected image must use a local drive path: $full" }
    $drive = $full.Substring(0,2)
    $buffer = New-Object Text.StringBuilder 1024
    $length = [YcszProtectionNative]::QueryDosDevice($drive,$buffer,[uint32]$buffer.Capacity)
    if ($length -eq 0) { throw "QueryDosDevice failed for ${drive}: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())" }
    $device = $buffer.ToString()
    return $device + $full.Substring(2)
}

function Assert-ValidSignature([string]$Path) {
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne 'Valid') { throw "The production protection package must be signed: $Path ($($signature.Status))" }
}

Assert-Administrator
$package = [IO.Path]::GetFullPath($DriverPackage)
$install = [IO.Path]::GetFullPath($InstallDir)
$inf = Join-Path $package 'YcszProtection.inf'
$sys = Join-Path $package 'YcszProtection.sys'
$cat = Join-Path $package 'YcszProtection.cat'
foreach ($path in @($inf,$sys,$cat)) { if (!(Test-Path -LiteralPath $path)) { throw "Missing signed protection package file: $path" } }
Assert-ValidSignature $sys
Assert-ValidSignature $cat
Assert-ProtectionCatalogMembers $package | Out-Null

$image = Join-Path $install 'Ycsz.exe'
if (!(Test-Path -LiteralPath $image)) { throw "Installed Ycsz.exe was not found: $image" }
$ntImage = ConvertTo-NtPath $image
$dataRoot = Get-ProtectionDataRoot
if (!(Test-Path -LiteralPath $dataRoot -PathType Container)) { throw 'The installed product data directory is missing; repair the application first.' }
$dataRootItem = Get-Item -LiteralPath $dataRoot -Force
if (($dataRootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'The ProgramData protection root must not be a reparse point.' }
$ntDataRoot = ConvertTo-NtPath $dataRoot
$service = Get-ServiceOrNull 'YcszFirewall'
if ($null -eq $service) { throw 'YcszFirewall must be installed before the protection driver.' }
$serviceInfo = Get-CimInstance Win32_Service -Filter "Name='YcszFirewall'"
if ($serviceInfo.StartName -ne 'LocalSystem') { throw 'YcszFirewall must run as LocalSystem.' }
Assert-ProtectionServiceCommand $serviceInfo.PathName $image
$existingDriver = Get-ServiceOrNull 'YcszProtection'
if ($null -ne $existingDriver -and $existingDriver.Status -ne 'Stopped') {
    throw 'An existing protection driver is running. Complete authenticated maintenance and unload it before changing its cached trust configuration.'
}

$trustedKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\YcszProtection\Parameters'
$hadTrusted = Test-Path -LiteralPath $trustedKey
$oldTrusted = if ($hadTrusted) { (Get-ItemProperty -LiteralPath $trustedKey -Name TrustedImagePath -ErrorAction SilentlyContinue).TrustedImagePath } else { $null }
$oldDataRoot = if ($hadTrusted) { (Get-ItemProperty -LiteralPath $trustedKey -Name TrustedDataRoot -ErrorAction SilentlyContinue).TrustedDataRoot } else { $null }
$driverWasRegistered = $null -ne (Get-ServiceOrNull 'YcszProtection')
$appWasRunning = $service.Status -ne 'Stopped'
$protectionWasRunning = $false
$appStoppedByScript = $false
$publishedAdded = $null
$appKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\YcszFirewall'
$oldSidType = (Get-ItemProperty -LiteralPath $appKey -ErrorAction Stop).ServiceSidType
$oldSidName = switch ([int]$oldSidType) { 0 { 'none' }; 1 { 'unrestricted' }; 3 { 'restricted' }; default { throw 'Unknown original service SID type; installation cannot safely roll back.' } }
$packagesBefore = @(Get-WindowsDriver -Online -ErrorAction Stop | ForEach-Object { $_.Driver })
$configurationTouched = $false

try {
    if ($appWasRunning) {
        try {
            Stop-Service -Name YcszFirewall -ErrorAction Stop
            Wait-Stopped 'YcszFirewall'
            $appStoppedByScript = $true
        } catch {
            throw "The application service could not be stopped. If kernel self-protection is already active, use the authenticated maintenance stop first. Original error: $($_.Exception.Message)"
        }
    }

    $configurationTouched = $true
    Invoke-Sc @('sidtype','YcszFirewall','unrestricted') 'YcszFirewall service SID configuration'
    $sidOutput = (& (Join-Path $env:WINDIR 'System32\sc.exe') qsidtype YcszFirewall 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0 -or $sidOutput -notmatch 'UNRESTRICTED') { throw 'YcszFirewall service SID was not confirmed as UNRESTRICTED.' }

    $pnputilOutput = & (Join-Path $env:WINDIR 'System32\pnputil.exe') /add-driver $inf /install 2>&1 | Out-String
    $pnputilOutput | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "pnputil driver installation failed: $LASTEXITCODE" }
    $publishedMatch = [regex]::Match($pnputilOutput,'(?im)Published Name\s*:\s*(oem[0-9]+\.inf)')
    if ($publishedMatch.Success -and $packagesBefore -notcontains $publishedMatch.Groups[1].Value) {
        $candidate = $publishedMatch.Groups[1].Value
        Assert-ProtectionPackage $candidate (Get-WindowsDriver -Online -Driver $candidate -ErrorAction Stop)
        $publishedAdded = $candidate
    }

    New-Item -Path $trustedKey -Force | Out-Null
    New-ItemProperty -LiteralPath $trustedKey -Name TrustedImagePath -PropertyType String -Value $ntImage -Force | Out-Null
    New-ItemProperty -LiteralPath $trustedKey -Name TrustedDataRoot -PropertyType String -Value $ntDataRoot -Force | Out-Null
    $configured = (Get-ItemProperty -LiteralPath $trustedKey -Name TrustedImagePath).TrustedImagePath
    if ($configured -cne $ntImage) { throw 'TrustedImagePath verification failed.' }
    $configuredDataRoot = (Get-ItemProperty -LiteralPath $trustedKey -Name TrustedDataRoot).TrustedDataRoot
    if ($configuredDataRoot -cne $ntDataRoot) { throw 'TrustedDataRoot verification failed.' }

    $protection = Get-ServiceOrNull 'YcszProtection'
    if ($null -eq $protection) { throw 'The INF did not register YcszProtection.' }
    if ($protection.Status -ne 'Stopped') { $protectionWasRunning = $true } else { Start-Service -Name YcszProtection; $protectionWasRunning = $true }
    (Get-Service YcszProtection).WaitForStatus('Running',[TimeSpan]::FromSeconds(30))
    if ((Get-Service YcszProtection).Status -ne 'Running') { throw 'YcszProtection did not reach Running.' }

    Start-Service -Name YcszFirewall
    (Get-Service YcszFirewall).WaitForStatus('Running',[TimeSpan]::FromSeconds(30))
    if ((Get-Service YcszFirewall).Status -ne 'Running') { throw 'YcszFirewall did not restart after protection activation.' }
    $activation = & $image --protection-status 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { throw "YcszFirewall is Running but v2 self-protection activation was not confirmed: $activation" }
    Write-Output "PASS protection installed, CAT members verified, and v2 activation confirmed: $ntImage / $ntDataRoot"
} catch {
    $failure = $_
    if (!$configurationTouched) { throw "Protection preflight/stop failed before configuration changes: $failure" }
    # Stop failure is not permission to rewrite a live driver's cached trust or
    # delete its registration. Preserve the recoverable state and report it.
    $rollbackErrors = New-Object 'System.Collections.Generic.List[string]'
    try {
        $currentApp = Get-ServiceOrNull 'YcszFirewall'
        if ($currentApp -and $currentApp.Status -ne 'Stopped') {
            Stop-Service YcszFirewall -ErrorAction Stop
            Wait-Stopped 'YcszFirewall'
        }
        $currentDriver = Get-ServiceOrNull 'YcszProtection'
        if ($currentDriver -and $currentDriver.Status -ne 'Stopped') {
            & (Join-Path $env:WINDIR 'System32\fltmc.exe') unload YcszProtection | Out-Host
            if ($LASTEXITCODE -ne 0) { throw "Authenticated driver unload was not available: $LASTEXITCODE" }
        }
        $currentApp = Get-ServiceOrNull 'YcszFirewall'
        $currentDriver = Get-ServiceOrNull 'YcszProtection'
        Assert-ProtectionRollbackStopped $currentApp $currentDriver
    } catch {
        throw "Installation failed: $failure. Rollback could not establish stopped services: $_. Trust values, registration and driver-store files were preserved; authenticated maintenance is required."
    }
    try {
        if ($null -ne $oldTrusted) { Set-ItemProperty -LiteralPath $trustedKey -Name TrustedImagePath -Value $oldTrusted }
        else { Remove-ItemProperty -LiteralPath $trustedKey -Name TrustedImagePath -ErrorAction SilentlyContinue }
        if ($null -ne $oldDataRoot) { Set-ItemProperty -LiteralPath $trustedKey -Name TrustedDataRoot -Value $oldDataRoot }
        else { Remove-ItemProperty -LiteralPath $trustedKey -Name TrustedDataRoot -ErrorAction SilentlyContinue }
        Invoke-Sc @('sidtype','YcszFirewall',$oldSidName) 'Original service SID restore'
        if ($null -ne $oldSidType) { Set-ItemProperty -LiteralPath $appKey -Name ServiceSidType -Value $oldSidType }
        else { Remove-ItemProperty -LiteralPath $appKey -Name ServiceSidType -ErrorAction SilentlyContinue }
    } catch { $rollbackErrors.Add("Configuration restore failed: $_") }
    if (!$driverWasRegistered -and $rollbackErrors.Count -eq 0) {
        try {
            if (Get-ServiceOrNull 'YcszProtection') { Invoke-Sc @('delete','YcszProtection') 'Protection registration rollback' }
            if ($publishedAdded) {
                Assert-ProtectionPackage $publishedAdded (Get-WindowsDriver -Online -Driver $publishedAdded -ErrorAction Stop)
                & (Join-Path $env:WINDIR 'System32\pnputil.exe') /delete-driver $publishedAdded /uninstall | Out-Host
                if ($LASTEXITCODE -ne 0) { throw "Driver-store rollback failed: $LASTEXITCODE" }
            }
        } catch { $rollbackErrors.Add("Package restore failed: $_") }
    }
    if ($appWasRunning -and $appStoppedByScript -and $rollbackErrors.Count -eq 0) {
        try { Start-Service YcszFirewall -ErrorAction Stop }
        catch { $rollbackErrors.Add("Application restart failed: $_") }
    }
    if ($rollbackErrors.Count) { throw "Installation failed: $failure. Rollback incomplete: $($rollbackErrors -join '; ')" }
    throw "Installation failed; stopped-state configuration rollback completed: $failure"
}
