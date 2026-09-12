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
. (Join-Path $PSScriptRoot 'Protection-Validation.ps1')
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
        Errors=@($snapshot | Where-Object { $_.Status -eq 'ERROR' } | ForEach-Object { $_.Name + ': ' + $_.Detail })
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
    $coverage = Join-Path $driver 'ycsz_initialization_coverage.c'
    $coverageHeader = Join-Path $driver 'ycsz_initialization_coverage.h'
    $transport = Join-Path $repo 'src\Ycsz.Core\SelfProtectionDeviceTransport.cs'
    $core = Join-Path $repo 'src\Ycsz.Core\SelfProtection.cs'
    $preflight = Join-Path $repo 'src\Ycsz.Core\SelfProtectionFilePreflight.cs'
    $app = Join-Path $repo 'src\Ycsz.App\Program.cs'
    $install = Join-Path $repo 'scripts\Install-Protection.ps1'
    $validation = Join-Path $repo 'scripts\Protection-Validation.ps1'
    foreach ($path in @($protocol,$kernel,$filter,$coverage,$coverageHeader,$transport,$core,$preflight,$app,$install,$validation)) {
        if (!(Test-Path -LiteralPath $path -PathType Leaf)) { Add-Result 'static source inventory' 'FAIL' "missing $path"; return }
    }
    $checks = @(
        @('protocol version 4', $protocol, 'YCP_PROTOCOL_VERSION              4u'),
        @('initialization entry limit', $protocol, 'YCP_MAX_INITIALIZATION_ENTRIES'),
        @('initialization timeout', $protocol, 'YCP_INITIALIZATION_TIMEOUT_SECONDS'),
        @('begin initialization IOCTL', $protocol, 'IOCTL_YCP_BEGIN_INITIALIZE'),
        @('declare initialization entry IOCTL', $protocol, 'IOCTL_YCP_DECLARE_INITIALIZATION_ENTRY'),
        @('commit initialization IOCTL', $protocol, 'IOCTL_YCP_COMMIT_INITIALIZE'),
        @('abort initialization IOCTL', $protocol, 'IOCTL_YCP_ABORT_INITIALIZE'),
        @('initialization commit request', $protocol, 'YCP_INITIALIZE_COMMIT_REQUEST'),
        @('initializing state bit', $protocol, 'YCP_STATE_INITIALIZING'),
        @('tray register IOCTL', $protocol, 'IOCTL_YCP_REGISTER_TRAY'),
        @('dual protected roots', $protocol, 'ProtectedDataRoot'),
        @('tray identity in status', $protocol, 'TrayIdentity'),
        @('exact input lengths', $kernel, 'inputLength != sizeof'),
        @('trusted data root registry', $kernel, 'TrustedDataRoot'),
        @('real tray process validation', $kernel, 'PsLookupProcessByProcessId'),
        @('trusted writer gate', $kernel, 'YcpIsTrustedWriter'),
        @('initialization state query', $kernel, 'YcpProtectionIsInitializing'),
        @('initialization stream accounting', $kernel, 'YcpRecordInitializationStream'),
        @('initialization round snapshot', $kernel, 'YcpCaptureInitializationSnapshot'),
        @('initialization round cleanup', $kernel, 'YcpReleaseInitializationSnapshot'),
        @('initialization generation barrier', $kernel, 'InitializationGeneration'),
        @('initialization commit handler', $kernel, 'YcpCommitInitialization'),
        @('initialization abort handler', $kernel, 'YcpAbortInitialization'),
        @('initialization failure accounting', $kernel, 'InitializationFailures'),
        @('initialization coverage declaration', $kernel, 'YcpInitializationCoverageDeclare'),
        @('initialization coverage observation', $kernel, 'YcpInitializationCoverageObserve'),
        @('initialization coverage commit predicate', $coverage, 'YcpInitializationCoverageCanCommit'),
        @('instance volume identity setup', $filter, 'YcpInstanceSetup'),
        @('instance volume serial cache', $filter, 'FltQueryVolumeInformation'),
        @('stream identity context', $filter, 'YCP_STREAM_CONTEXT'),
        @('stream identity query', $filter, 'FileInternalInformation'),
        @('stream context lookup', $filter, 'FltGetStreamContext'),
        @('stream context registration', $filter, 'FltSetStreamContext'),
        @('stream context helper', $filter, 'YcpAttachProtectedStreamContext'),
        @('filter reference release', $filter, 'FltObjectDereference'),
        @('paging write compatibility', $filter, 'IRP_PAGING_IO'),
        @('reparse gate', $filter, 'FSCTL_SET_REPARSE_POINT'),
        @('v4 user ABI', $transport, 'StateDataRoot'),
        @('begin initialize user transport', $transport, 'BeginInitialize'),
        @('declare initialize user transport', $transport, 'DeclareInitializationEntry'),
        @('commit initialize user transport', $transport, 'CommitInitialize'),
        @('abort initialize user transport', $transport, 'AbortInitialize'),
        @('activation identity preflight', $preflight, 'GetFileInformationByHandle'),
        @('handle attributes authority', $preflight, 'FileAttributes'),
        @('path-handle consistency gate', $preflight, 'AttributesConsistent'),
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

function Add-DynamicExceptionResult([string]$Name,[string]$ExpectedStage,[string]$ActualStage,$ErrorRecord,[bool]$ControlSucceeded) {
    $decision = Resolve-ProtectionDynamicException $ErrorRecord $ExpectedStage $ActualStage $ControlSucceeded
    Add-Result $Name $decision.Status $decision.Detail
}

function Add-DynamicNativeFailureResult([string]$Name,[string]$ExpectedStage,[string]$ActualStage,[int]$Code,[bool]$ControlSucceeded) {
    $decision = Resolve-ProtectionDynamicNativeFailure $Code $ExpectedStage $ActualStage $ControlSucceeded
    Add-Result $Name $decision.Status $decision.Detail
}

function Add-DynamicCleanupError([string]$Name,[string]$Path,[string]$Detail,[object]$ErrorRecord,[object]$NativeCode) {
    $suffix = ''
    if ($null -ne $NativeCode) { $suffix = ' Native error: ' + (Get-ProtectionWin32ErrorLabel ([int]$NativeCode)) }
    if ($null -ne $ErrorRecord) {
        $message = if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) { $ErrorRecord.Exception.Message } else { [string]$ErrorRecord }
        $suffix += ' ' + $message
    }
    $cleanup = Resolve-ProtectionCleanupFailure $Path ($Detail + $suffix)
    Add-Result $Name $cleanup.Status $cleanup.Detail
}

function Invoke-DynamicPathCleanup([string]$Name,[string]$Path,[scriptblock]$Action) {
    try { & $Action | Out-Null }
    catch { Add-DynamicCleanupError $Name $Path 'PowerShell cleanup exception.' $_ $null }
}

function Invoke-DynamicWritableMapping([string]$Name,[string]$Path,[bool]$IsControl,[bool]$ControlSucceeded) {
    $stream = $null
    $mapping = [IntPtr]::Zero
    $view = [IntPtr]::Zero
    $addedRef = $false
    try {
        try {
            $stream = New-Object IO.FileStream($Path,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
        } catch {
            Add-DynamicExceptionResult $Name 'mapping-open' 'mapping-open' $_ $ControlSucceeded
            return $false
        }
        try {
            $stream.SafeFileHandle.DangerousAddRef([ref]$addedRef)
        } catch {
            Add-DynamicExceptionResult $Name 'mapping-open' 'mapping-open' $_ $ControlSucceeded
            return $false
        }

        $mapping = [YcszDynamicNative]::CreateFileMapping($stream.SafeFileHandle,[IntPtr]::Zero,0x04,0,4096,$null)
        $mappingError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        if ($mapping -eq [IntPtr]::Zero) {
            Add-DynamicNativeFailureResult $Name 'mapping-create' 'mapping-create' $mappingError $ControlSucceeded
            return $false
        }
        $view = [YcszDynamicNative]::MapViewOfFile($mapping,0x0002,0,0,[UIntPtr]4096)
        $viewError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        if ($view -eq [IntPtr]::Zero) {
            Add-DynamicNativeFailureResult $Name 'mapping-view' 'mapping-view' $viewError $ControlSucceeded
            return $false
        }
        try {
            [Runtime.InteropServices.Marshal]::WriteByte($view,0,66)
        } catch {
            Add-DynamicExceptionResult $Name 'mapping-write' 'mapping-write' $_ $ControlSucceeded
            return $false
        }
        $flushed = [YcszDynamicNative]::FlushViewOfFile($view,[UIntPtr]1)
        $flushError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        if (!$flushed) {
            Add-DynamicNativeFailureResult $Name 'mapping-flush' 'mapping-flush' $flushError $ControlSucceeded
            return $false
        }
        if ($IsControl) { Add-Result $Name 'PASS' 'Ordinary fixture mapping created, writable view updated and FlushViewOfFile succeeded.' }
        else { Add-Result $Name 'BLOCKED' 'Protected target mapping was writable after Active; no mapping-denial evidence is claimed.' }
        return $true
    } finally {
        if ($view -ne [IntPtr]::Zero) {
            $unmapped = [YcszDynamicNative]::UnmapViewOfFile($view)
            $unmapError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if (!$unmapped) { Add-DynamicCleanupError ($Name + ' cleanup') $Path 'UnmapViewOfFile returned false.' $null $unmapError }
        }
        if ($mapping -ne [IntPtr]::Zero) {
            $closed = [YcszDynamicNative]::CloseHandle($mapping)
            $closeError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if (!$closed) { Add-DynamicCleanupError ($Name + ' cleanup') $Path 'CloseHandle returned false.' $null $closeError }
        }
        if ($null -ne $stream) {
            if ($addedRef) {
                try { $stream.SafeFileHandle.DangerousRelease() }
                catch { Add-DynamicCleanupError ($Name + ' cleanup') $Path 'DangerousRelease raised an exception.' $_ $null }
            }
            try { $stream.Dispose() }
            catch { Add-DynamicCleanupError ($Name + ' cleanup') $Path 'FileStream.Dispose raised an exception.' $_ $null }
        }
    }
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
    if ($LASTEXITCODE -ne 0) { throw "The harness is Running but v4 activation was not confirmed: $probe" }
}

function Invoke-DynamicChecks {
    try { Require-DynamicPreconditions } catch { Add-Result 'dynamic preflight' 'BLOCKED' $_.Exception.Message; return }
    try { Add-NativeDynamicType }
    catch { Add-Result 'dynamic native bindings' 'ERROR' $_.Exception.Message; return }
    $file = Join-Path ([IO.Path]::GetFullPath($ProtectedRoot)) 'existing-handle.bin'
    $dataFile = Join-Path ([IO.Path]::GetFullPath($ProtectedDataRoot)) 'existing-handle.bin'
    foreach ($candidate in @($file,$dataFile)) {
        Add-Result ('pre-active existing handle ' + $candidate) 'BLOCKED' 'No safe two-phase fixture holds this handle before activation; a pre-existing file is not evidence of a pre-existing handle.'
        Add-Result ('pre-active writable mapping ' + $candidate) 'BLOCKED' 'No safe two-phase fixture holds this mapping before activation; a post-Active mapping cannot prove this condition.'
    }
    foreach ($candidate in @($file,$dataFile)) {
        if (!(Test-Path -LiteralPath $candidate -PathType Leaf)) { Add-Result 'protected fixture files' 'BLOCKED' "The protected fixture file is missing: $candidate"; return }
    }

    $ordinary = Join-Path ([IO.Path]::GetFullPath($FixtureRoot)) 'ordinary-unprotected.bin'
    $ordinaryRoot = Join-Path ([IO.Path]::GetFullPath($FixtureRoot)) 'ordinary-controls'
    $ordinaryHardlinkTarget = Join-Path $ordinaryRoot 'hardlink-target.bin'
    $ordinaryHardlink = Join-Path $ordinaryRoot 'hardlink.bin'
    $ordinaryJunctionTarget = Join-Path $ordinaryRoot 'junction-target'
    $ordinaryJunction = Join-Path $ordinaryRoot 'junction'
    $ordinaryControlSucceeded = $false
    try {
        [IO.File]::WriteAllText($ordinary,'ordinary fixture write')
        $ordinaryControlSucceeded = $true
        Add-Result 'ordinary non-product write' 'PASS' 'An unrelated fixture path remains writable; no global unknown-path denial observed.'
    } catch { Add-DynamicExceptionResult 'ordinary non-product write' 'ordinary-write' 'ordinary-write' $_ $false }

    foreach ($candidate in @($file,$dataFile)) {
        $stream = $null
        try {
            $stream = New-Object IO.FileStream($candidate,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
            try {
                $stream.WriteByte(65)
                $stream.Flush()
                Add-Result ('post-active new handle write ' + $candidate) 'FAIL' 'A new non-service handle opened after Active and wrote successfully.'
            } catch { Add-DynamicExceptionResult ('post-active new handle write ' + $candidate) 'file-write' 'file-write' $_ $ordinaryControlSucceeded }
        } catch { Add-DynamicExceptionResult ('post-active new handle open ' + $candidate) 'file-open' 'file-open' $_ $ordinaryControlSucceeded }
        finally {
            if ($null -ne $stream) {
                try { $stream.Dispose() }
                catch { Add-DynamicCleanupError ('post-active new handle cleanup ' + $candidate) $candidate 'FileStream.Dispose raised an exception.' $_ $null }
            }
        }
    }

    $hardlinkControlSucceeded = $false
    $link = Join-Path ([IO.Path]::GetFullPath($ProtectedRoot)) 'dynamic-hardlink.bin'
    try {
        New-Item -ItemType Directory -Path $ordinaryRoot -Force -ErrorAction Stop | Out-Null
        [IO.File]::WriteAllText($ordinaryHardlinkTarget,'ordinary hardlink target')
        New-Item -ItemType HardLink -Path $ordinaryHardlink -Target $ordinaryHardlinkTarget -ErrorAction Stop | Out-Null
        $hardlinkControlSucceeded = $true
        Add-Result 'ordinary hard link control' 'PASS' 'An ordinary fixture hard link was created successfully.'
    } catch { Add-DynamicExceptionResult 'ordinary hard link control' 'hardlink-create' 'hardlink-create' $_ $false }
    finally {
        if (Test-Path -LiteralPath $ordinaryHardlink) { Invoke-DynamicPathCleanup 'ordinary hard link control cleanup' $ordinaryHardlink { Remove-Item -LiteralPath $ordinaryHardlink -Force -ErrorAction Stop } }
    }
    if (!$hardlinkControlSucceeded) {
        Add-Result 'hard link mutation' 'BLOCKED' 'The ordinary hard-link control could not be established; target failure is not attributable to protection.'
    } elseif (Test-Path -LiteralPath $link) {
        Add-Result 'hard link mutation' 'ERROR' "The target hard-link evidence path already exists: $link"
    } else {
        try {
            New-Item -ItemType HardLink -Path $link -Target $file -ErrorAction Stop | Out-Null
            Add-Result 'hard link mutation' 'FAIL' 'Hard link creation succeeded after Active.'
        } catch { Add-DynamicExceptionResult 'hard link mutation' 'hardlink-create' 'hardlink-create' $_ $true }
        finally {
            if (Test-Path -LiteralPath $link) { Invoke-DynamicPathCleanup 'hard link mutation cleanup' $link { Remove-Item -LiteralPath $link -Force -ErrorAction Stop } }
        }
    }

    $junctionControlSucceeded = $false
    $junction = Join-Path ([IO.Path]::GetFullPath($ProtectedRoot)) 'dynamic-junction'
    try {
        New-Item -ItemType Directory -Path $ordinaryJunctionTarget -Force -ErrorAction Stop | Out-Null
        New-Item -ItemType Junction -Path $ordinaryJunction -Target $ordinaryJunctionTarget -ErrorAction Stop | Out-Null
        $junctionControlSucceeded = $true
        Add-Result 'ordinary reparse-point control' 'PASS' 'An ordinary fixture junction was created successfully.'
    } catch { Add-DynamicExceptionResult 'ordinary reparse-point control' 'junction-create' 'junction-create' $_ $false }
    finally {
        if (Test-Path -LiteralPath $ordinaryJunction) { Invoke-DynamicPathCleanup 'ordinary reparse-point control cleanup' $ordinaryJunction { Remove-Item -LiteralPath $ordinaryJunction -Force -ErrorAction Stop } }
    }
    if (!$junctionControlSucceeded) {
        Add-Result 'reparse-point mutation' 'BLOCKED' 'The ordinary junction control could not be established; target failure is not attributable to protection.'
    } elseif (Test-Path -LiteralPath $junction) {
        Add-Result 'reparse-point mutation' 'ERROR' "The target junction evidence path already exists: $junction"
    } else {
        try {
            New-Item -ItemType Junction -Path $junction -Target ([IO.Path]::GetFullPath($ProtectedDataRoot)) -ErrorAction Stop | Out-Null
            Add-Result 'reparse-point mutation' 'FAIL' 'Junction creation succeeded after Active.'
        } catch { Add-DynamicExceptionResult 'reparse-point mutation' 'junction-create' 'junction-create' $_ $true }
        finally {
            if (Test-Path -LiteralPath $junction) { Invoke-DynamicPathCleanup 'reparse-point mutation cleanup' $junction { Remove-Item -LiteralPath $junction -Force -ErrorAction Stop } }
        }
    }

    $mappingControlSucceeded = $false
    if (!$ordinaryControlSucceeded) {
        Add-Result 'ordinary writable mapping' 'BLOCKED' 'The ordinary writable-file control failed; target mapping denial is not attributable to protection.'
    } else {
        $mappingControlSucceeded = Invoke-DynamicWritableMapping 'ordinary writable mapping' $ordinary $true $false
    }
    if (!$mappingControlSucceeded) {
        Add-Result 'writable mapping' 'BLOCKED' 'The ordinary mapping control did not complete; target mapping evidence is unavailable.'
    } else {
        [void](Invoke-DynamicWritableMapping 'writable mapping' $file $false $true)
    }

    Add-Result 'normal trusted service writeback' 'BLOCKED' 'This runner does not impersonate the already authenticated service writer; use the isolated service harness to prove an in-root content update and cache writeback.'
    Add-Result 'ordinary SYSTEM writer' 'BLOCKED' 'This run does not manufacture a second SYSTEM token; use the isolated service harness for that identity.'
    Add-Result 'PID/session restart' 'BLOCKED' 'Requires a real user session transition and a service-controlled tray restart; no logout or reboot is performed by this tool.'

    $device = [YcszDynamicNative]::CreateFile('\\.\YcszProtection',0xC0000000,3,[IntPtr]::Zero,3,0,[IntPtr]::Zero)
    $deviceError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    if ($device -eq $null -or $device.IsInvalid) {
        $deviceDetail = if ($null -ne $deviceError -and $deviceError -ne 0) { 'The dynamic runner could not open the protected control device: ' + (Get-ProtectionWin32ErrorLabel $deviceError) } else { 'The dynamic runner could not open the protected control device; no reliable native error was returned.' }
        Add-Result 'unload concurrency control handle' 'BLOCKED' $deviceDetail
        if ($null -ne $device) {
            try { $device.Dispose() }
            catch { Add-DynamicCleanupError 'unload concurrency control handle cleanup' '\\.\YcszProtection' 'Invalid control device Dispose raised an exception.' $_ $null }
        }
    } else {
        try {
            $fltmc = Join-Path $env:WINDIR 'System32\fltmc.exe'
            if (!(Test-Path -LiteralPath $fltmc -PathType Leaf)) {
                Add-Result 'unload concurrency control handle' 'ERROR' "fltmc.exe was not found: $fltmc"
            } else {
                $unload = & $fltmc unload YcszProtection 2>&1 | Out-String
                $unloadExit = $LASTEXITCODE
                $filters = & $fltmc filters 2>&1 | Out-String
                $filtersExit = $LASTEXITCODE
                $filterPresent = $filtersExit -eq 0 -and $filters -match '(?i)YcszProtection'
                $decision = Test-ProtectionExpectedUnloadRejection $unloadExit $unload $filterPresent
                Add-Result 'unload concurrency control handle' $decision.Status ($decision.Detail + (' fltmc exit={0}; filter-query exit={1}.' -f $unloadExit,$filtersExit))
            }
        } catch { Add-Result 'unload concurrency control handle' 'ERROR' ('fltmc invocation failed: ' + $_.Exception.Message) }
        finally {
            try { $device.Dispose() }
            catch { Add-DynamicCleanupError 'unload concurrency control handle cleanup' '\\.\YcszProtection' 'Control device Dispose raised an exception.' $_ $null }
        }
    }

    $ordinaryDelete = Join-Path ([IO.Path]::GetFullPath($FixtureRoot)) 'ordinary-delete-control'
    try {
        New-Item -ItemType Directory -Path $ordinaryDelete -Force -ErrorAction Stop | Out-Null
        [IO.File]::WriteAllText((Join-Path $ordinaryDelete 'file.bin'),'ordinary delete control')
        Remove-Item -LiteralPath $ordinaryDelete -Recurse -Force -ErrorAction Stop
        Add-Result 'ordinary directory deletion control' 'PASS' 'An ordinary fixture directory was deleted successfully.'
    } catch { Add-DynamicExceptionResult 'ordinary directory deletion control' 'directory-delete' 'directory-delete' $_ $false }
    if (!(Test-Path -LiteralPath ([IO.Path]::GetFullPath($ProtectedRoot)))) {
        Add-Result 'protected directory itself' 'BLOCKED' 'The protected root disappeared before the destructive directory check.'
    } else {
        try {
            Remove-Item -LiteralPath ([IO.Path]::GetFullPath($ProtectedRoot)) -Recurse -Force -ErrorAction Stop
            Add-Result 'protected directory itself' 'FAIL' 'Protected directory removal succeeded.'
        } catch { Add-DynamicExceptionResult 'protected directory itself' 'directory-delete' 'directory-delete' $_ $true }
    }

    foreach ($path in @($ordinary,$ordinaryHardlinkTarget,$ordinaryJunctionTarget,$ordinaryRoot)) {
        if (Test-Path -LiteralPath $path) {
            Invoke-DynamicPathCleanup 'ordinary fixture cleanup' $path { Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop }
        }
    }
}

if ($Mode -eq 'Static') { Invoke-StaticChecks } else { Invoke-DynamicChecks }
Write-Results
$failed = @($results | Where-Object { $_.Status -eq 'FAIL' }).Count
$errors = @($results | Where-Object { $_.Status -eq 'ERROR' }).Count
$blocked = @($results | Where-Object { $_.Status -eq 'BLOCKED' }).Count
if ($failed -gt 0 -or $errors -gt 0) { exit 1 }
if ($Mode -eq 'Dynamic' -and $blocked -gt 0) { exit 2 }
exit 0
