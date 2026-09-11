[CmdletBinding()]
param(
    [ValidateSet('Static','Dynamic')]
    [string]$Mode = 'Static',
    [string]$FixtureRoot,
    [string]$ProtectedRoot,
    [string]$ProtectedDataRoot,
    [string]$ServiceImagePath,
    [string]$ResultPath,
    [switch]$AllowFixtureMutation
)

$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$results = New-Object 'System.Collections.Generic.List[object]'

function Add-Result([string]$Name,[string]$Status,[string]$Detail) {
    [void]$results.Add([pscustomobject]@{ Name=$Name; Status=$Status; Detail=$Detail })
}

function Write-Results {
    $snapshot = $results.ToArray()
    $summary = [pscustomobject]@{
        Mode=$Mode
        GeneratedUtc=(Get-Date).ToUniversalTime().ToString('o')
        Results=$snapshot
        Uncovered=@($snapshot | Where-Object { $_.Status -eq 'BLOCKED' } | ForEach-Object { $_.Name + ': ' + $_.Detail })
    }
    $json = $summary | ConvertTo-Json -Depth 6
    if ($ResultPath) { Set-Content -LiteralPath $ResultPath -Value $json -Encoding UTF8 }
    Write-Output $json
}

function Test-Contains([string]$Path,[string]$Needle) {
    return (Get-Content -LiteralPath $Path -Raw) -match [regex]::Escape($Needle)
}

function Invoke-StaticChecks {
    $driver = Join-Path $repo 'drivers\YcszProtection'
    $protocol = Join-Path $driver 'ycsz_protection_protocol.h'
    $kernel = Join-Path $driver 'ycsz_protection.c'
    $filter = Join-Path $driver 'ycsz_minifilter.c'
    $transport = Join-Path $repo 'src\Ycsz.Core\SelfProtectionDeviceTransport.cs'
    $core = Join-Path $repo 'src\Ycsz.Core\SelfProtection.cs'
    $preflight = Join-Path $repo 'src\Ycsz.Core\SelfProtectionFilePreflight.cs'
    $app = Join-Path $repo 'src\Ycsz.App\Program.cs'
    $install = Join-Path $repo 'scripts\Install-Protection.ps1'
    $validation = Join-Path $repo 'scripts\Protection-Validation.ps1'
    foreach ($path in @($protocol,$kernel,$filter,$transport,$core,$preflight,$app,$install,$validation)) {
        if (!(Test-Path -LiteralPath $path -PathType Leaf)) { Add-Result 'static source inventory' 'FAIL' "missing $path"; return }
    }
    $checks = @(
        @('protocol version 2', $protocol, 'YCP_PROTOCOL_VERSION              2u'),
        @('tray register IOCTL', $protocol, 'IOCTL_YCP_REGISTER_TRAY'),
        @('dual protected roots', $protocol, 'ProtectedDataRoot'),
        @('tray identity in status', $protocol, 'TrayIdentity'),
        @('exact input lengths', $kernel, 'inputLength != sizeof'),
        @('trusted data root registry', $kernel, 'TrustedDataRoot'),
        @('real tray process validation', $kernel, 'PsLookupProcessByProcessId'),
        @('trusted writer gate', $kernel, 'YcpIsTrustedWriter'),
        @('stream identity context', $filter, 'YCP_STREAM_CONTEXT'),
        @('stream identity query', $filter, 'FileInternalInformation'),
        @('stream context lookup', $filter, 'FltGetStreamContext'),
        @('stream context registration', $filter, 'FltSetStreamContext'),
        @('paging write compatibility', $filter, 'IRP_PAGING_IO'),
        @('reparse gate', $filter, 'FSCTL_SET_REPARSE_POINT'),
        @('v2 user ABI', $transport, 'StateDataRoot'),
        @('activation identity preflight', $preflight, 'GetFileInformationByHandle'),
        @('mapped-write status is explicit', $core, 'MappingWritebackConditionMet'),
        @('actual activation probe', $app, '--protection-status'),
        @('CAT member validation', $install, 'Assert-ProtectionCatalogMembers'),
        @('rollback data root', $install, 'oldDataRoot'),
        @('package delta rollback', $validation, 'New-ProtectionRollbackPlan'),
        @('package snapshot rollback', $install, 'Get-ProtectionPackageSnapshot')
    )
    foreach ($check in $checks) {
        if (Test-Contains $check[1] $check[2]) { Add-Result $check[0] 'PASS' $check[2] }
        else { Add-Result $check[0] 'FAIL' "missing $($check[2])" }
    }
    Add-Result 'preexisting writable mappings' 'BLOCKED' 'Identity is tracked for existing handles, but arbitrary Cache Manager mapped-write denial is intentionally not claimed.'
    Add-Result 'dynamic driver load' 'BLOCKED' 'Static mode does not load the unsigned driver.'
    Add-Result 'signed CAT and unique altitude' 'BLOCKED' 'Requires an isolated Windows target with production signing and an assigned altitude.'
    Add-Result 'termination/mapping/link runtime evidence' 'BLOCKED' 'Static mode records the dynamic matrix; mapped-write compatibility remains an explicit unproven condition.'
}

function Add-NativeDynamicType {
    if ('YcszDynamicNative' -as [type]) { return }
    Add-Type @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class YcszDynamicNative {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr CreateFileMapping(SafeFileHandle file, IntPtr attributes, uint protection, uint high, uint low, string name);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr MapViewOfFile(IntPtr mapping, uint access, uint high, uint low, UIntPtr bytes);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool FlushViewOfFile(IntPtr address, UIntPtr bytes);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool UnmapViewOfFile(IntPtr address);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool DeviceIoControl(SafeFileHandle device, uint code, IntPtr input, uint inputLength, IntPtr output, uint outputLength, out uint returned, IntPtr overlapped);
}
'@
}

function Require-DynamicPreconditions {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Dynamic mode requires an elevated Windows PowerShell.' }
    if (!$AllowFixtureMutation) { throw 'Dynamic mode requires -AllowFixtureMutation because it exercises a disposable fixture.' }
    if ([string]::IsNullOrWhiteSpace($FixtureRoot) -or [string]::IsNullOrWhiteSpace($ProtectedRoot) -or [string]::IsNullOrWhiteSpace($ProtectedDataRoot) -or [string]::IsNullOrWhiteSpace($ServiceImagePath)) {
        throw 'Dynamic mode requires FixtureRoot, ProtectedRoot, ProtectedDataRoot and ServiceImagePath.'
    }
    $fixture = [IO.Path]::GetFullPath($FixtureRoot)
    foreach ($root in @($fixture,[IO.Path]::GetFullPath($ProtectedRoot),[IO.Path]::GetFullPath($ProtectedDataRoot))) {
        if ($root -notlike ($fixture.TrimEnd('\') + '\*') -and $root -ne $fixture) { throw "Dynamic root is outside the disposable fixture: $root" }
    }
    $marker = Join-Path $fixture '.ycsz-dynamic-fixture'
    if (!(Test-Path -LiteralPath $marker -PathType Leaf)) { throw "Missing disposable fixture marker: $marker" }
    $driver = Get-Service -Name YcszProtection -ErrorAction SilentlyContinue
    if (!$driver -or $driver.Status -ne 'Running') { throw 'YcszProtection must already be running in the disposable harness.' }
    $app = Get-Service -Name YcszFirewall -ErrorAction SilentlyContinue
    if (!$app -or $app.Status -ne 'Running') { throw 'YcszFirewall must already be running in the disposable harness.' }
    if (!(Test-Path -LiteralPath $ServiceImagePath -PathType Leaf)) { throw "ServiceImagePath does not exist: $ServiceImagePath" }
    $image = [IO.Path]::GetFullPath($ServiceImagePath)
    if ($image -notlike ($fixture.TrimEnd('\') + '\*')) { throw 'ServiceImagePath is outside the disposable fixture.' }
    $probe = & $image --protection-status 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { throw "The harness is Running but v2 activation was not confirmed: $probe" }
}

function Invoke-DynamicChecks {
    try { Require-DynamicPreconditions } catch { Add-Result 'dynamic preflight' 'BLOCKED' $_.Exception.Message; return }
    Add-NativeDynamicType
    $file = Join-Path ([IO.Path]::GetFullPath($ProtectedRoot)) 'existing-handle.bin'
    $dataFile = Join-Path ([IO.Path]::GetFullPath($ProtectedDataRoot)) 'existing-handle.bin'
    foreach ($candidate in @($file,$dataFile)) {
        if (!(Test-Path -LiteralPath $candidate -PathType Leaf)) { Add-Result 'fixture files' 'BLOCKED' "Pre-create before activation: $candidate"; return }
    }

    $ordinary = Join-Path ([IO.Path]::GetFullPath($FixtureRoot)) 'ordinary-unprotected.bin'
    try {
        [IO.File]::WriteAllText($ordinary,'ordinary fixture write')
        Add-Result 'ordinary non-product write' 'PASS' 'An unrelated fixture path remains writable; no global unknown-path denial observed.'
    } catch { Add-Result 'ordinary non-product write' 'FAIL' $_.Exception.Message }
    finally { if (Test-Path -LiteralPath $ordinary) { Remove-Item -LiteralPath $ordinary -Force -ErrorAction SilentlyContinue } }

    foreach ($candidate in @($file,$dataFile)) {
        $stream = $null
        try {
            $stream = New-Object IO.FileStream($candidate,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
            try { $stream.WriteByte(65); $stream.Flush(); Add-Result "existing handle write $candidate" 'FAIL' 'A non-service write succeeded.' }
            catch { Add-Result "existing handle write $candidate" 'PASS' $_.Exception.Message }
        } catch { Add-Result "existing handle open $candidate" 'PASS' ('open denied before write: ' + $_.Exception.Message) }
        finally { if ($stream) { $stream.Dispose() } }
    }

    $link = Join-Path ([IO.Path]::GetFullPath($ProtectedRoot)) 'dynamic-hardlink.bin'
    try { New-Item -ItemType HardLink -Path $link -Target $file -Force | Out-Null; Add-Result 'hard link mutation' 'FAIL' 'Hard link creation succeeded.' }
    catch { Add-Result 'hard link mutation' 'PASS' $_.Exception.Message }
    finally { if (Test-Path -LiteralPath $link) { Remove-Item -LiteralPath $link -Force -ErrorAction SilentlyContinue } }

    $junction = Join-Path ([IO.Path]::GetFullPath($ProtectedRoot)) 'dynamic-junction'
    try { New-Item -ItemType Junction -Path $junction -Target ([IO.Path]::GetFullPath($ProtectedDataRoot)) | Out-Null; Add-Result 'reparse-point mutation' 'FAIL' 'Junction creation succeeded.' }
    catch { Add-Result 'reparse-point mutation' 'PASS' $_.Exception.Message }
    finally { if (Test-Path -LiteralPath $junction) { Remove-Item -LiteralPath $junction -Force -ErrorAction SilentlyContinue } }

    $mapStream = $null; $mapping = [IntPtr]::Zero; $view = [IntPtr]::Zero
    try {
        $mapStream = New-Object IO.FileStream($file,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
        $addedRef = $false
        $mapStream.SafeFileHandle.DangerousAddRef([ref]$addedRef)
        $mapping = [YcszDynamicNative]::CreateFileMapping($mapStream.SafeFileHandle,[IntPtr]::Zero,0x04,0,4096,$null)
        if ($mapping -eq [IntPtr]::Zero) { Add-Result 'writable mapping' 'PASS' ('CreateFileMapping denied: ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error()) }
        else {
            $view = [YcszDynamicNative]::MapViewOfFile($mapping,0x0002 -bor 0x0020,0,0,[UIntPtr]4096)
            if ($view -eq [IntPtr]::Zero) { Add-Result 'writable mapping' 'PASS' ('MapViewOfFile denied: ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error()) }
            else { [Runtime.InteropServices.Marshal]::WriteByte($view,0,66); if ([YcszDynamicNative]::FlushViewOfFile($view,[UIntPtr]1)) { Add-Result 'writable mapping' 'BLOCKED' 'Mapped writeback reached FlushViewOfFile; compatibility path is intentionally not denied and therefore is not claimed as protected.' } else { Add-Result 'writable mapping' 'PASS' ('FlushViewOfFile denied: ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error()) } }
        }
    } catch { Add-Result 'writable mapping' 'PASS' $_.Exception.Message }
    finally {
        if ($view -ne [IntPtr]::Zero) { [YcszDynamicNative]::UnmapViewOfFile($view) | Out-Null }
        if ($mapping -ne [IntPtr]::Zero) { [YcszDynamicNative]::CloseHandle($mapping) | Out-Null }
        if ($mapStream) { if ($addedRef) { try { $mapStream.SafeFileHandle.DangerousRelease() } catch {} }; $mapStream.Dispose() }
    }

    Add-Result 'normal trusted service writeback' 'BLOCKED' 'This runner does not impersonate the already authenticated service writer; use the isolated service harness to prove an in-root content update and cache writeback.'
    Add-Result 'ordinary SYSTEM writer' 'BLOCKED' 'This run does not manufacture a second SYSTEM token; use the isolated service harness for that identity.'
    Add-Result 'PID/session restart' 'BLOCKED' 'Requires a real user session transition and a service-controlled tray restart; no logout or reboot is performed by this tool.'

    $device = [YcszDynamicNative]::CreateFile('\\.\YcszProtection',0xC0000000,3,[IntPtr]::Zero,3,0,[IntPtr]::Zero)
    if ($device -eq $null -or $device.IsInvalid) {
        Add-Result 'unload concurrency control handle' 'BLOCKED' 'The dynamic runner could not open the protected control device.'
    } else {
        try {
            $unload = & (Join-Path $env:WINDIR 'System32\fltmc.exe') unload YcszProtection 2>&1 | Out-String
            if ($LASTEXITCODE -eq 0) { Add-Result 'unload concurrency control handle' 'FAIL' 'Filter unload succeeded while a control handle was open.' }
            else { Add-Result 'unload concurrency control handle' 'PASS' $unload.Trim() }
        } finally { $device.Dispose() }
    }
    if ($AllowFixtureMutation) {
        try { Remove-Item -LiteralPath ([IO.Path]::GetFullPath($ProtectedRoot)) -Recurse -Force -ErrorAction Stop; Add-Result 'protected directory itself' 'FAIL' 'Protected directory removal succeeded.' }
        catch { Add-Result 'protected directory itself' 'PASS' $_.Exception.Message }
    }
}

if ($Mode -eq 'Static') { Invoke-StaticChecks } else { Invoke-DynamicChecks }
Write-Results
$failed = @($results | Where-Object { $_.Status -eq 'FAIL' }).Count
$blocked = @($results | Where-Object { $_.Status -eq 'BLOCKED' }).Count
if ($failed -gt 0) { exit 1 }
if ($Mode -eq 'Dynamic' -and $blocked -gt 0) { exit 2 }
exit 0
