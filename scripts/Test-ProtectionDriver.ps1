[CmdletBinding()]
param(
    [ValidateSet('Static','Dynamic','TwoPhase')]
    [string]$Mode = 'Static',
    [string]$FixtureRoot,
    [string]$ProtectedRoot,
    [string]$ProtectedDataRoot,
    [string]$ServiceImagePath,
    [string]$FixtureManifestPath,
    [string]$TwoPhaseStatePath,
    [string]$ActivationSignalPath,
    [ValidateRange(1,3600)]
    [int]$WaitTimeoutSeconds = 120,
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
    Add-Result 'two-phase dynamic harness' 'BLOCKED' 'The two-phase harness is prepared in source, but static mode does not hold objects or activate a service.'
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

function Add-DynamicOwned([object]$Owned,[object]$Context) {
    if ($null -ne $Owned) { [void]$Context.Owned.Add($Owned) }
    return $Owned
}

function Invoke-DynamicOwnedCleanup([object]$Context) {
    if ($null -eq $Context -or $null -eq $Context.Owned) { return }
    foreach ($owned in @($Context.Owned | Sort-Object { $_.Path.Length } -Descending)) {
        $decision=Remove-ProtectionFixtureOwnedPath $owned
        if ($decision.Status -eq 'ERROR') { Add-Result ('owned fixture cleanup ' + $owned.Path) 'ERROR' $decision.Detail }
    }
}

function New-DynamicJunctionOwned([string]$Path,[string]$Target) {
    $full=[IO.Path]::GetFullPath($Path)
    New-Item -ItemType Junction -Path $full -Target ([IO.Path]::GetFullPath($Target)) -ErrorAction Stop | Out-Null
    $entity=$null
    try {
        $entity=Get-ProtectionFixtureEntity $full
        if (($entity.Attributes -band 0x400) -eq 0 -or !$entity.IsDirectory) { throw "Junction identity was not confirmed: $full" }
        return New-ProtectionFixtureOwnedRecord $full 'Junction' $entity
    } catch {
        if ($null -ne $entity -and $entity.IsDirectory -and (($entity.Attributes -band 0x400) -ne 0)) {
            $owned=New-ProtectionFixtureOwnedRecord $full 'Junction' $entity
            Close-ProtectionFixtureEntity $entity; $entity=$null
            $decision=Remove-ProtectionFixtureOwnedPath $owned
            if ($decision.Status -ne 'PASS') { throw ("Junction validation failed and safe handle cleanup was not confirmed: " + $decision.Detail) }
        }
        throw
    } finally { if ($null -ne $entity) { Close-ProtectionFixtureEntity $entity } }
}

function Invoke-DynamicWritableMapping([string]$Name,[string]$Path,[bool]$IsControl,[bool]$ControlSucceeded,$ExpectedIdentity) {
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
        if ($null -ne $ExpectedIdentity) {
            try {
                $opened = Get-ProtectionFixtureHandleEntity $stream.SafeFileHandle $Path
                if ($opened.VolumeSerial -ne [uint64]$ExpectedIdentity.VolumeSerial -or $opened.FileIndex -ne [uint64]$ExpectedIdentity.FileIndex -or $opened.Length -ne [uint64]$ExpectedIdentity.Length -or $opened.NumberOfLinks -ne [uint64]$ExpectedIdentity.NumberOfLinks -or ($opened.Attributes -band 0x400) -ne 0) {
                    Add-Result $Name 'ERROR' 'The opened handle identity did not match the manifest; no write or mapping operation was attempted.'
                    return $false
                }
            } catch { Add-DynamicExceptionResult $Name 'mapping-open' 'mapping-open' $_ $ControlSucceeded; return $false }
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

function Require-TwoPhaseFixturePreconditions {
    $scope=$null
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Two-phase mode requires an elevated Windows PowerShell.' }
        if (!$AllowFixtureMutation) { throw 'Two-phase mode requires -AllowFixtureMutation because it exercises a disposable fixture.' }
        if ([string]::IsNullOrWhiteSpace($FixtureRoot) -or [string]::IsNullOrWhiteSpace($ProtectedRoot) -or [string]::IsNullOrWhiteSpace($ProtectedDataRoot) -or [string]::IsNullOrWhiteSpace($ServiceImagePath)) {
            throw 'Two-phase mode requires FixtureRoot, ProtectedRoot, ProtectedDataRoot and ServiceImagePath.'
        }
        $fixture=[IO.Path]::GetFullPath($FixtureRoot)
        $protected=[IO.Path]::GetFullPath($ProtectedRoot)
        $dataRoot=[IO.Path]::GetFullPath($ProtectedDataRoot)
        $image=[IO.Path]::GetFullPath($ServiceImagePath)
        Assert-ProtectionFixtureChild $fixture $protected
        Assert-ProtectionFixtureChild $fixture $dataRoot
        Assert-ProtectionFixtureChild $fixture $image
        if (!Test-ProtectionFixturePathEquals ([IO.Path]::GetDirectoryName($image)) $protected) { throw 'ProtectedRoot must be exactly the ServiceImagePath directory.' }
        $marker=Join-Path $fixture '.ycsz-dynamic-fixture'
        if (!(Test-Path -LiteralPath $marker -PathType Leaf)) { throw "Missing disposable fixture marker: $marker" }
        $manifestPath=if ([string]::IsNullOrWhiteSpace($FixtureManifestPath)) { Join-Path $fixture '.ycsz-dynamic-fixture.json' } else { [IO.Path]::GetFullPath($FixtureManifestPath) }
        Assert-ProtectionFixtureChild $fixture $manifestPath
        if (!(Test-Path -LiteralPath $manifestPath -PathType Leaf)) { throw "Missing fixture manifest: $manifestPath" }
        $scope=New-ProtectionFixtureScope $fixture @($protected,$dataRoot,$marker,$manifestPath) @() @($manifestPath,$marker)
        $manifestText=Get-Content -LiteralPath $manifestPath -Raw
        $manifest=$manifestText | ConvertFrom-Json
        $manifestFiles=@(Assert-ProtectionFixtureManifest $manifest $fixture $protected $dataRoot $image)
        $protectedPrefix=$protected.TrimEnd('\')+'\'; $dataPrefix=$dataRoot.TrimEnd('\')+'\'
        foreach ($entry in $manifestFiles) {
            $samplePath=[IO.Path]::GetFullPath([string]$entry.Path)
            if (!$samplePath.StartsWith($protectedPrefix,[StringComparison]::OrdinalIgnoreCase) -and !$samplePath.StartsWith($dataPrefix,[StringComparison]::OrdinalIgnoreCase)) {
                throw "Protected sample is outside the requested protected roots: $samplePath"
            }
            $entity=$null
            try {
                $entity=Get-ProtectionFixtureEntity $samplePath 3
                Assert-ProtectionFixtureEntity $entity | Out-Null
                if ($entity.Length -ne [uint64]$entry.Length -or $entity.VolumeSerial -ne [uint64]$entry.VolumeSerial -or $entity.FileIndex -ne [uint64]$entry.FileIndex -or $entity.NumberOfLinks -ne [uint64]$entry.NumberOfLinks) {
                    throw "Protected sample identity or length does not match the manifest: $samplePath"
                }
            } finally { if ($null -ne $entity) { Close-ProtectionFixtureEntity $entity } }
        }
        if ((Get-Content -LiteralPath $manifestPath -Raw) -cne $manifestText) { throw 'Fixture manifest changed while the two-phase scope was being established.' }

        $service=Get-Service -Name YcszFirewall -ErrorAction Stop
        $serviceInfo=Get-CimInstance Win32_Service -Filter "Name='YcszFirewall'" -ErrorAction Stop
        if ($null -eq $serviceInfo -or $serviceInfo.StartName -ne 'LocalSystem') { throw 'The isolated fixture service is not bound to LocalSystem.' }
        Assert-ProtectionServiceCommand ([string]$serviceInfo.PathName) $image
        if ($service.Status -ne 'Stopped') { throw 'The fixture service must be Stopped before pre-active handles and mappings are prepared.' }
        return [pscustomobject]@{
            FixtureRoot=$fixture; ProtectedRoot=$protected; ProtectedDataRoot=$dataRoot; ServiceImagePath=$image
            Manifest=$manifest; ProtectedFiles=$manifestFiles; Scope=$scope; Owned=(New-Object 'System.Collections.Generic.List[object]')
            Held=(New-Object 'System.Collections.Generic.List[object]'); RunId=([guid]::NewGuid().ToString('N'))
            ServiceName='YcszFirewall'; ServicePath=[string]$serviceInfo.PathName
        }
    } catch {
        if ($null -ne $scope) { Close-ProtectionFixtureScope $scope }
        throw
    }
}

function New-TwoPhaseHeldMapping([string]$Path,$ExpectedIdentity) {
    Add-NativeDynamicType
    $full=[IO.Path]::GetFullPath($Path)
    $stream=$null; $mapping=[IntPtr]::Zero; $view=[IntPtr]::Zero; $addedRef=$false; $originalByte=$null
    try {
        $stream=New-Object IO.FileStream($full,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
        $opened=Get-ProtectionFixtureHandleEntity $stream.SafeFileHandle $full
        if ($opened.VolumeSerial -ne [uint64]$ExpectedIdentity.VolumeSerial -or $opened.FileIndex -ne [uint64]$ExpectedIdentity.FileIndex -or $opened.Length -ne [uint64]$ExpectedIdentity.Length -or $opened.NumberOfLinks -ne [uint64]$ExpectedIdentity.NumberOfLinks -or ($opened.Attributes -band 0x400) -ne 0) {
            throw "Pre-active handle identity did not match the manifest: $full"
        }
        $stream.SafeFileHandle.DangerousAddRef([ref]$addedRef)
        $mapping=[YcszDynamicNative]::CreateFileMapping($stream.SafeFileHandle,[IntPtr]::Zero,0x04,0,4096,$null)
        $mappingError=[Runtime.InteropServices.Marshal]::GetLastWin32Error()
        if ($mapping -eq [IntPtr]::Zero) { throw (Get-ProtectionFixtureWin32Exception $mappingError ('Pre-active mapping creation failed: ' + $full)) }
        $view=[YcszDynamicNative]::MapViewOfFile($mapping,0x0002,0,0,[UIntPtr]4096)
        $viewError=[Runtime.InteropServices.Marshal]::GetLastWin32Error()
        if ($view -eq [IntPtr]::Zero) { throw (Get-ProtectionFixtureWin32Exception $viewError ('Pre-active mapping view failed: ' + $full)) }
        $originalByte=[Runtime.InteropServices.Marshal]::ReadByte($view,0)
        [Runtime.InteropServices.Marshal]::WriteByte($view,0,[byte]66)
        $flushed=[YcszDynamicNative]::FlushViewOfFile($view,[UIntPtr]1)
        $flushError=[Runtime.InteropServices.Marshal]::GetLastWin32Error()
        if (!$flushed) { throw (Get-ProtectionFixtureWin32Exception $flushError ('Pre-active writable mapping flush failed: ' + $full)) }
        [Runtime.InteropServices.Marshal]::WriteByte($view,0,$originalByte)
        $restored=[YcszDynamicNative]::FlushViewOfFile($view,[UIntPtr]1)
        $restoreError=[Runtime.InteropServices.Marshal]::GetLastWin32Error()
        if (!$restored) { throw (Get-ProtectionFixtureWin32Exception $restoreError ('Pre-active mapping restore failed: ' + $full)) }
        return [pscustomobject]@{ Path=$full; Stream=$stream; Mapping=$mapping; View=$view; AddedRef=$addedRef; OriginalByte=$originalByte; Expected=$ExpectedIdentity }
    } catch {
        if ($view -ne [IntPtr]::Zero -and $null -ne $originalByte) {
            try { [Runtime.InteropServices.Marshal]::WriteByte($view,0,$originalByte); [void]([YcszDynamicNative]::FlushViewOfFile($view,[UIntPtr]1)) } catch { }
        }
        if ($view -ne [IntPtr]::Zero) { try { [void]([YcszDynamicNative]::UnmapViewOfFile($view)) } catch { } }
        if ($mapping -ne [IntPtr]::Zero) { try { [void]([YcszDynamicNative]::CloseHandle($mapping)) } catch { } }
        if ($null -ne $stream) {
            if ($addedRef) { try { $stream.SafeFileHandle.DangerousRelease() } catch { } }
            try { $stream.Dispose() } catch { }
        }
        throw
    }
}

function Close-TwoPhaseHeldMapping($Held) {
    if ($null -eq $Held) { return @() }
    $errors=New-Object 'System.Collections.Generic.List[string]'
    if ($Held.View -ne [IntPtr]::Zero) {
        try {
            [Runtime.InteropServices.Marshal]::WriteByte($Held.View,0,[byte]$Held.OriginalByte)
            $restored=[YcszDynamicNative]::FlushViewOfFile($Held.View,[UIntPtr]1)
            $restoreError=[Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if (!$restored) { [void]$errors.Add((Get-ProtectionWin32ErrorLabel $restoreError)) }
        } catch { [void]$errors.Add(('mapping restore exception: ' + $_.Exception.Message)) }
        try {
            $unmapped=[YcszDynamicNative]::UnmapViewOfFile($Held.View)
            $unmapError=[Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if (!$unmapped) { [void]$errors.Add(('UnmapViewOfFile: ' + (Get-ProtectionWin32ErrorLabel $unmapError))) }
        } catch { [void]$errors.Add(('UnmapViewOfFile exception: ' + $_.Exception.Message)) }
    }
    if ($Held.Mapping -ne [IntPtr]::Zero) {
        try {
            $closed=[YcszDynamicNative]::CloseHandle($Held.Mapping)
            $closeError=[Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if (!$closed) { [void]$errors.Add(('mapping CloseHandle: ' + (Get-ProtectionWin32ErrorLabel $closeError))) }
        } catch { [void]$errors.Add(('mapping CloseHandle exception: ' + $_.Exception.Message)) }
    }
    if ($null -ne $Held.Stream) {
        if ($Held.AddedRef) { try { $Held.Stream.SafeFileHandle.DangerousRelease() } catch { [void]$errors.Add(('DangerousRelease: ' + $_.Exception.Message)) } }
        try { $Held.Stream.Dispose() } catch { [void]$errors.Add(('FileStream.Dispose: ' + $_.Exception.Message)) }
    }
    return $errors.ToArray()
}

function Set-TwoPhaseState($Context,[string]$Phase,[string]$Detail) {
    if ($null -eq $Context.StateOwned) { throw 'Two-phase state file was not initialized.' }
    $stateIdentity=Test-ProtectionFixtureOwnedIdentity $Context.StateOwned
    if ($stateIdentity.Status -ne 'PASS') { throw ('Two-phase state identity was not stable: ' + $stateIdentity.Detail) }
    $held=@($Context.Held | ForEach-Object {
        [pscustomobject]@{ Path=$_.Path; VolumeSerial=[uint64]$_.Expected.VolumeSerial; FileIndex=[uint64]$_.Expected.FileIndex; Length=[uint64]$_.Expected.Length; HandleHeld=$true; MappingHeld=$true }
    })
    $state=[ordered]@{
        Phase=$Phase; Detail=$Detail; GeneratedUtc=(Get-Date).ToUniversalTime().ToString('o'); ProcessId=$PID
        FixtureRoot=$Context.FixtureRoot; ProtectedRoot=$Context.ProtectedRoot; ProtectedDataRoot=$Context.ProtectedDataRoot
        ServiceImagePath=$Context.ServiceImagePath; ServiceName=$Context.ServiceName; ActivationSignalPath=$Context.SignalPath
        ExpectedSignal='ACTIVATED'; Held=$held
    }
    $json=$state | ConvertTo-Json -Depth 6
    Set-Content -LiteralPath $Context.StateOwned.Path -Value $json -Encoding UTF8
}

function Invoke-TwoPhaseChecks {
    $context=$null; $activeContext=$null; $retainSession=$true
    try {
        try { $context=Require-TwoPhaseFixturePreconditions }
        catch { Add-Result 'two-phase pre-active fixture preconditions' 'BLOCKED' $_.Exception.Message; return }
        try {
            $signalPath=if ([string]::IsNullOrWhiteSpace($ActivationSignalPath)) { Join-Path $context.FixtureRoot ('.ycsz-two-phase-' + $context.RunId + '.signal') } else { [IO.Path]::GetFullPath($ActivationSignalPath) }
            $statePath=if ([string]::IsNullOrWhiteSpace($TwoPhaseStatePath)) { Join-Path $context.FixtureRoot ('.ycsz-two-phase-' + $context.RunId + '.json') } else { [IO.Path]::GetFullPath($TwoPhaseStatePath) }
            foreach ($path in @($signalPath,$statePath)) {
                Assert-ProtectionFixtureChild $context.FixtureRoot $path
                if (Test-ProtectionFixturePathEquals $path $context.FixtureRoot -or Test-ProtectionFixturePathEquals $path $context.ProtectedRoot -or Test-ProtectionFixturePathEquals $path $context.ProtectedDataRoot -or Test-ProtectionFixturePathEquals $path $context.ServiceImagePath) { throw "Two-phase state path is not a leaf inside the fixture: $path" }
            }
            $context.SignalPath=$signalPath; $context.StatePath=$statePath
            $context.SignalOwned=New-ProtectionFixtureFile $signalPath ([Text.Encoding]::UTF8.GetBytes('PENDING'))
            [void]$context.Owned.Add($context.SignalOwned)
            $context.StateOwned=New-ProtectionFixtureFile $statePath ([Text.Encoding]::UTF8.GetBytes('{}'))
            [void]$context.Owned.Add($context.StateOwned)
            Set-TwoPhaseState $context 'Preparing' 'Preparing pre-active handles and writable mappings; no service operation was issued.'

            foreach ($entry in @($context.ProtectedFiles)) {
                try {
                    $held=New-TwoPhaseHeldMapping ([IO.Path]::GetFullPath([string]$entry.Path)) $entry
                    [void]$context.Held.Add($held)
                    Add-Result ('pre-active handle held ' + $held.Path) 'PASS' 'A manifest-matched handle remains open before activation.'
                    Add-Result ('pre-active writable mapping held ' + $held.Path) 'PASS' 'A writable, non-executable mapping view was created before activation and remains held.'
                } catch {
                    Add-Result ('pre-active handle/mapping setup ' + $entry.Path) 'ERROR' $_.Exception.Message
                }
            }
            if ($context.Held.Count -ne @($context.ProtectedFiles).Count) {
                Set-TwoPhaseState $context 'PrepareFailed' 'At least one pre-active handle or mapping could not be established; activation was not attempted.'
                Add-Result 'two-phase pre-active fixture' 'ERROR' 'Not every manifest sample received a verified held handle and writable mapping.'
                return
            }
            Set-TwoPhaseState $context 'Prepared' 'Pre-active handles and writable mappings are held. External isolated harness may activate the exact stopped service and write ACTIVATED to the signal file.'
            Add-Result 'two-phase pre-active fixture' 'PASS' ('Prepared ' + $context.Held.Count + ' manifest-matched held handles and writable mappings; service remains untouched.')
        } catch {
            Add-Result 'two-phase preparation' 'ERROR' $_.Exception.Message
            return
        }

        $activated=$false; $deadline=(Get-Date).ToUniversalTime().AddSeconds($WaitTimeoutSeconds)
        while ((Get-Date).ToUniversalTime() -lt $deadline) {
            $signalIdentity=Test-ProtectionFixtureOwnedIdentity $context.SignalOwned
            if ($signalIdentity.Status -ne 'PASS') { Add-Result 'two-phase activation signal' 'ERROR' $signalIdentity.Detail; break }
            $signalText=Get-Content -LiteralPath $context.SignalPath -Raw
            if ($signalText.Trim() -ceq 'ACTIVATED') { $activated=$true; break }
            Start-Sleep -Milliseconds 250
        }
        if (!$activated) {
            Set-TwoPhaseState $context 'ActivationTimeout' ('No exact ACTIVATED signal arrived within ' + $WaitTimeoutSeconds + ' seconds; held objects were not treated as post-active evidence.')
            Add-Result 'real service activation' 'BLOCKED' ('Timed out waiting for the external isolated harness signal after ' + $WaitTimeoutSeconds + ' seconds; this runner did not start, stop or restart a service.')
            Add-Result 'post-active operations' 'BLOCKED' 'Post-active checks were not run because the real activation signal was absent or invalid.'
            return
        }
        try { $activeContext=Require-DynamicPreconditions }
        catch {
            Set-TwoPhaseState $context 'ActivationRejected' ('ACTIVATED signal was received, but real SCM/service/protocol activation could not be confirmed: ' + $_.Exception.Message)
            Add-Result 'real service activation' 'BLOCKED' $_.Exception.Message
            Add-Result 'post-active operations' 'BLOCKED' 'Post-active checks were not run because the current protocol/status probe did not confirm Active.'
            return
        }
        Set-TwoPhaseState $context 'ActiveVerified' 'The external signal was followed by real SCM identity, session-0 process and current --protection-status verification.'
        Add-Result 'real service activation' 'PASS' 'The exact isolated SCM service, LocalSystem session-0 process, trusted roots and current protection-status protocol were verified without service mutation by this runner.'
        $script:TwoPhaseHeldObjects=$context.Held.ToArray()
        Invoke-DynamicChecks
        $script:TwoPhaseHeldObjects=$null
        Set-TwoPhaseState $context 'Verified' 'Post-active operation matrix completed; see the result entries for each operation and independent control.'
        $retainSession=$false
    } catch { Add-Result 'two-phase runner integrity' 'ERROR' $_.Exception.Message }
    finally {
        $script:TwoPhaseHeldObjects=$null
        if ($null -ne $context -and $null -ne $context.Held) {
            foreach ($held in @($context.Held | Sort-Object { $_.Path.Length } -Descending) ) {
                $closeErrors=@(Close-TwoPhaseHeldMapping $held)
                foreach ($closeError in $closeErrors) { Add-Result ('pre-active held object cleanup ' + $held.Path) 'ERROR' $closeError }
            }
        }
        if ($null -ne $activeContext -and $null -ne $activeContext.Scope) { Close-ProtectionFixtureScope $activeContext.Scope }
        if ($null -ne $context) {
            if (!$retainSession -and $null -ne $context.Owned) { Invoke-DynamicOwnedCleanup $context }
            elseif ($null -ne $context.StatePath) { Add-Result 'two-phase session evidence' 'BLOCKED' ('Session state and activation signal were retained for external cleanup: ' + $context.StatePath) }
            if ($null -ne $context.Scope) { Close-ProtectionFixtureScope $context.Scope }
        }
    }
}

function Require-DynamicPreconditions {
    $scope=$null
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Dynamic mode requires an elevated Windows PowerShell.' }
        if (!$AllowFixtureMutation) { throw 'Dynamic mode requires -AllowFixtureMutation because it exercises a disposable fixture.' }
        if ([string]::IsNullOrWhiteSpace($FixtureRoot) -or [string]::IsNullOrWhiteSpace($ProtectedRoot) -or [string]::IsNullOrWhiteSpace($ProtectedDataRoot) -or [string]::IsNullOrWhiteSpace($ServiceImagePath)) {
            throw 'Dynamic mode requires FixtureRoot, ProtectedRoot, ProtectedDataRoot and ServiceImagePath.'
        }
        $fixture = [IO.Path]::GetFullPath($FixtureRoot)
        $protected = [IO.Path]::GetFullPath($ProtectedRoot)
        $dataRoot = [IO.Path]::GetFullPath($ProtectedDataRoot)
        $image = [IO.Path]::GetFullPath($ServiceImagePath)
        Assert-ProtectionFixtureChild $fixture $protected
        Assert-ProtectionFixtureChild $fixture $dataRoot
        Assert-ProtectionFixtureChild $fixture $image
        if (!Test-ProtectionFixturePathEquals ([IO.Path]::GetDirectoryName($image)) $protected) { throw 'ProtectedRoot must be exactly the ServiceImagePath directory.' }
        $marker = Join-Path $fixture '.ycsz-dynamic-fixture'
        if (!(Test-Path -LiteralPath $marker -PathType Leaf)) { throw "Missing disposable fixture marker: $marker" }
        $manifestPath = if ([string]::IsNullOrWhiteSpace($FixtureManifestPath)) { Join-Path $fixture '.ycsz-dynamic-fixture.json' } else { [IO.Path]::GetFullPath($FixtureManifestPath) }
        Assert-ProtectionFixtureChild $fixture $manifestPath
        if (!(Test-Path -LiteralPath $manifestPath -PathType Leaf)) { throw "Missing fixture manifest: $manifestPath" }
        $scope = New-ProtectionFixtureScope $fixture @($protected,$dataRoot,$marker,$manifestPath) @() @($manifestPath,$marker)
        $manifestText = Get-Content -LiteralPath $manifestPath -Raw
        $manifest = $manifestText | ConvertFrom-Json
        $manifestFiles = @(Assert-ProtectionFixtureManifest $manifest $fixture $protected $dataRoot $image)
        $protectedPrefix=$protected.TrimEnd('\')+'\'
        $dataPrefix=$dataRoot.TrimEnd('\')+'\'
        foreach ($entry in $manifestFiles) {
            $samplePath=[IO.Path]::GetFullPath([string]$entry.Path)
            if (!$samplePath.StartsWith($protectedPrefix,[StringComparison]::OrdinalIgnoreCase) -and !$samplePath.StartsWith($dataPrefix,[StringComparison]::OrdinalIgnoreCase)) {
                throw "Protected sample is outside the requested protected roots: $samplePath"
            }
        }
        if ((Get-Content -LiteralPath $manifestPath -Raw) -cne $manifestText) { throw 'Fixture manifest changed while the stable scope was being established.' }
        foreach ($path in @($marker,$manifestPath,$image)) {
            $entity=$null
            $share=if ([string]::Equals($path,$manifestPath,[StringComparison]::OrdinalIgnoreCase) -or [string]::Equals($path,$marker,[StringComparison]::OrdinalIgnoreCase)) { [uint32]1 } else { [uint32]3 }
            try { $entity=Get-ProtectionFixtureEntity $path $share; Assert-ProtectionFixtureEntity $entity | Out-Null }
            finally { if ($null -ne $entity) { Close-ProtectionFixtureEntity $entity } }
        }
        foreach ($entry in $manifestFiles) {
            $entity=$null
            try {
                $entity=Get-ProtectionFixtureEntity ([string]$entry.Path) 3
                Assert-ProtectionFixtureEntity $entity | Out-Null
                if ($entity.Length -ne [uint64]$entry.Length -or $entity.VolumeSerial -ne [uint64]$entry.VolumeSerial -or $entity.FileIndex -ne [uint64]$entry.FileIndex -or $entity.NumberOfLinks -ne [uint64]$entry.NumberOfLinks) {
                    throw "Protected sample identity or length does not match the manifest: $($entry.Path)"
                }
            } finally { if ($null -ne $entity) { Close-ProtectionFixtureEntity $entity } }
        }

        $driver = Get-Service -Name YcszProtection -ErrorAction Stop
        if ($driver.Status -ne 'Running') { throw 'YcszProtection must already be running in the disposable harness.' }
        $service = Get-Service -Name YcszFirewall -ErrorAction Stop
        if ($service.Status -ne 'Running') { throw 'YcszFirewall must already be running in the disposable harness.' }
        $serviceInfo = Get-CimInstance Win32_Service -Filter "Name='YcszFirewall'" -ErrorAction Stop
        if ($null -eq $serviceInfo -or $serviceInfo.StartName -ne 'LocalSystem' -or [int]$serviceInfo.ProcessId -le 0) { throw 'SCM service identity or PID was not available.' }
        Assert-ProtectionServiceCommand ([string]$serviceInfo.PathName) $image
        $serviceProcess = Get-Process -Id ([int]$serviceInfo.ProcessId) -ErrorAction Stop
        if ($serviceProcess.HasExited -or $serviceProcess.SessionId -ne 0 -or ![string]::Equals([IO.Path]::GetFullPath($serviceProcess.MainModule.FileName),$image,[StringComparison]::OrdinalIgnoreCase)) { throw 'SCM PID does not resolve to the requested session-0 fixture image.' }

        $trustedKey='HKLM:\SYSTEM\CurrentControlSet\Services\YcszProtection\Parameters'
        $trusted=Get-ItemProperty -LiteralPath $trustedKey -ErrorAction Stop
        $expectedNtImage=ConvertTo-ProtectionFixtureNtPath $image
        $expectedNtData=ConvertTo-ProtectionFixtureNtPath $dataRoot
        if ([string]::IsNullOrWhiteSpace([string]$trusted.TrustedImagePath) -or ![string]::Equals([string]$trusted.TrustedImagePath,$expectedNtImage,[StringComparison]::OrdinalIgnoreCase)) { throw 'YcszProtection TrustedImagePath does not match the SCM fixture image.' }
        if ([string]::IsNullOrWhiteSpace([string]$trusted.TrustedDataRoot) -or ![string]::Equals([string]$trusted.TrustedDataRoot,$expectedNtData,[StringComparison]::OrdinalIgnoreCase)) { throw 'YcszProtection TrustedDataRoot does not match the requested fixture data root.' }

        $probe = & $image --protection-status 2>&1 | Out-String
        $probeExit=$LASTEXITCODE
        if ($probeExit -ne 0) { throw "The bound fixture service did not confirm v4 activation: $probe" }
        return [pscustomobject]@{ FixtureRoot=$fixture; ProtectedRoot=$protected; ProtectedDataRoot=$dataRoot; ServiceImagePath=$image; Manifest=$manifest; ProtectedFiles=$manifestFiles; Scope=$scope; Owned=(New-Object 'System.Collections.Generic.List[object]'); RunId=([guid]::NewGuid().ToString('N')); ServicePid=[int]$serviceInfo.ProcessId }
    } catch {
        if ($null -ne $scope) { Close-ProtectionFixtureScope $scope }
        throw
    }
}

function Invoke-DynamicChecks {
    $context=$null
    try { $context=Require-DynamicPreconditions } catch { Add-Result 'dynamic preflight' 'BLOCKED' $_.Exception.Message; return }
    try {
        try { Add-NativeDynamicType }
        catch { Add-Result 'dynamic native bindings' 'ERROR' $_.Exception.Message; return }
        $fileEntries=@($context.ProtectedFiles)
        $filePaths=@($fileEntries | ForEach-Object { [IO.Path]::GetFullPath([string]$_.Path) })
        foreach ($candidate in $filePaths) {
            $held=$null
            if ($null -ne $script:TwoPhaseHeldObjects) { $held=@($script:TwoPhaseHeldObjects | Where-Object { Test-ProtectionFixturePathEquals $_.Path $candidate } | Select-Object -First 1) }
            if ($null -eq $held -or @($held).Count -eq 0) {
                Add-Result ('pre-active existing handle ' + $candidate) 'BLOCKED' 'No safe two-phase fixture holds this handle before activation; a pre-existing file is not evidence of a pre-existing handle.'
                Add-Result ('pre-active writable mapping ' + $candidate) 'BLOCKED' 'No safe two-phase fixture holds this mapping before activation; a post-Active mapping cannot prove this condition.'
            } else {
                $heldItem=@($held)[0]
                try {
                    $heldEntity=Get-ProtectionFixtureHandleEntity $heldItem.Stream.SafeFileHandle $candidate
                    $heldMatch=Test-ProtectionFixtureOwnedEntity ([pscustomobject]@{ Path=$candidate; Kind='File'; VolumeSerial=$heldItem.Expected.VolumeSerial; FileIndex=$heldItem.Expected.FileIndex; NumberOfLinks=$heldItem.Expected.NumberOfLinks }) $heldEntity
                    if (!$heldMatch.Matches) { throw $heldMatch.Detail }
                    Add-Result ('pre-active existing handle ' + $candidate) 'PASS' 'The same manifest-matched handle remained held across externally verified activation.'
                    Add-Result ('pre-active writable mapping ' + $candidate) 'PASS' 'The same pre-active writable mapping/view remained held across externally verified activation; no post-active object was substituted.'
                } catch { Add-Result ('pre-active object continuity ' + $candidate) 'ERROR' $_.Exception.Message }
            }
        }

        $ordinary=Join-Path $context.FixtureRoot ('ordinary-unprotected-' + $context.RunId + '.bin')
        $ordinaryRoot=Join-Path $context.FixtureRoot ('ordinary-controls-' + $context.RunId)
        $ordinaryHardlinkTarget=Join-Path $ordinaryRoot 'hardlink-target.bin'
        $ordinaryHardlink=Join-Path $ordinaryRoot 'hardlink.bin'
        $ordinaryJunctionTarget=Join-Path $ordinaryRoot 'junction-target'
        $ordinaryJunction=Join-Path $ordinaryRoot 'junction'
        $ordinaryControlSucceeded=$false
        try {
            $owned=New-ProtectionFixtureFile $ordinary ([Text.Encoding]::UTF8.GetBytes('ordinary fixture write'))
            [void](Add-DynamicOwned $owned $context)
            $ordinaryControlSucceeded=$true
            Add-Result 'ordinary non-product write' 'PASS' 'A unique ordinary fixture file was created with CreateNew and remains writable.'
        } catch { Add-DynamicExceptionResult 'ordinary non-product write' 'ordinary-write' 'ordinary-write' $_ $false }

        foreach ($entry in $fileEntries) {
            $candidate=[IO.Path]::GetFullPath([string]$entry.Path)
            $stream=$null
            try {
                $stream=New-Object IO.FileStream($candidate,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
                $opened=Get-ProtectionFixtureHandleEntity $stream.SafeFileHandle $candidate
                if ($opened.VolumeSerial -ne [uint64]$entry.VolumeSerial -or $opened.FileIndex -ne [uint64]$entry.FileIndex -or $opened.Length -ne [uint64]$entry.Length -or $opened.NumberOfLinks -ne [uint64]$entry.NumberOfLinks -or ($opened.Attributes -band 0x400) -ne 0) {
                    Add-Result ('post-active new handle open ' + $candidate) 'ERROR' 'The opened handle identity did not match the protected-file manifest; no write was attempted.'
                    continue
                }
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

        $hardlinkControlSucceeded=$false
        $link=Join-Path $context.ProtectedRoot ('dynamic-hardlink-' + $context.RunId + '.bin')
        try {
            $owned=New-ProtectionFixtureDirectory $ordinaryRoot; [void](Add-DynamicOwned $owned $context)
            $owned=New-ProtectionFixtureFile $ordinaryHardlinkTarget ([Text.Encoding]::UTF8.GetBytes('ordinary hardlink target')); [void](Add-DynamicOwned $owned $context)
            $owned=New-ProtectionFixtureHardLink $ordinaryHardlink $ordinaryHardlinkTarget; [void](Add-DynamicOwned $owned $context)
            $hardlinkControlSucceeded=$true
            Add-Result 'ordinary hard link control' 'PASS' 'An ordinary unique fixture hard link was created with the native CreateHardLink API.'
        } catch { Add-DynamicExceptionResult 'ordinary hard link control' 'hardlink-create' 'hardlink-create' $_ $false }
        if (!$hardlinkControlSucceeded) {
            Add-Result 'hard link mutation' 'BLOCKED' 'The ordinary hard-link control could not be established; target failure is not attributable to protection.'
        } else {
            try {
                $owned=New-ProtectionFixtureHardLink $link $filePaths[0]; [void](Add-DynamicOwned $owned $context)
                Add-Result 'hard link mutation' 'FAIL' 'Hard link creation succeeded after Active.'
            } catch { Add-DynamicExceptionResult 'hard link mutation' 'hardlink-create' 'hardlink-create' $_ $true }
        }

        $junctionControlSucceeded=$false
        $junction=Join-Path $context.ProtectedRoot ('dynamic-junction-' + $context.RunId)
        try {
            $owned=New-ProtectionFixtureDirectory $ordinaryJunctionTarget; [void](Add-DynamicOwned $owned $context)
            $owned=New-DynamicJunctionOwned $ordinaryJunction $ordinaryJunctionTarget; [void](Add-DynamicOwned $owned $context)
            $junctionControlSucceeded=$true
            Add-Result 'ordinary reparse-point control' 'PASS' 'An ordinary unique fixture junction was created and identified as a reparse point.'
        } catch { Add-DynamicExceptionResult 'ordinary reparse-point control' 'junction-create' 'junction-create' $_ $false }
        if (!$junctionControlSucceeded) {
            Add-Result 'reparse-point mutation' 'BLOCKED' 'The ordinary junction control could not be established; target failure is not attributable to protection.'
        } else {
            try {
                $owned=New-DynamicJunctionOwned $junction $context.ProtectedDataRoot; [void](Add-DynamicOwned $owned $context)
                Add-Result 'reparse-point mutation' 'FAIL' 'Junction creation succeeded after Active.'
            } catch { Add-DynamicExceptionResult 'reparse-point mutation' 'junction-create' 'junction-create' $_ $true }
        }

        $mappingControlSucceeded=$false
        if (!$ordinaryControlSucceeded) {
            Add-Result 'ordinary writable mapping' 'BLOCKED' 'The ordinary writable-file control failed; target mapping denial is not attributable to protection.'
        } else {
            $mappingControlSucceeded=Invoke-DynamicWritableMapping 'ordinary writable mapping' $ordinary $true $false $null
        }
        if (!$mappingControlSucceeded) {
            Add-Result 'writable mapping' 'BLOCKED' 'The ordinary mapping control did not complete; target mapping evidence is unavailable.'
        } else {
            [void](Invoke-DynamicWritableMapping 'writable mapping' $filePaths[0] $false $true $fileEntries[0])
        }

        Add-Result 'normal trusted service writeback' 'BLOCKED' 'This runner does not impersonate the already authenticated service writer; use the isolated service harness to prove an in-root content update and cache writeback.'
        Add-Result 'ordinary SYSTEM writer' 'BLOCKED' 'This run does not manufacture a second SYSTEM token; use the isolated service harness for that identity.'
        Add-Result 'PID/session restart' 'BLOCKED' 'Requires a real user session transition and a service-controlled tray restart; no logout or reboot is performed by this tool.'

        $device=[YcszDynamicNative]::CreateFile('\\.\YcszProtection',0xC0000000,3,[IntPtr]::Zero,3,0,[IntPtr]::Zero)
        $deviceError=[Runtime.InteropServices.Marshal]::GetLastWin32Error()
        if ($device -eq $null -or $device.IsInvalid) {
            $deviceDetail=if ($null -ne $deviceError -and $deviceError -ne 0) { 'The dynamic runner could not open the protected control device: ' + (Get-ProtectionWin32ErrorLabel $deviceError) } else { 'The dynamic runner could not open the protected control device; no reliable native error was returned.' }
            Add-Result 'unload concurrency control handle' 'BLOCKED' $deviceDetail
            if ($null -ne $device) { try { $device.Dispose() } catch { Add-DynamicCleanupError 'unload concurrency control handle cleanup' '\\.\YcszProtection' 'Invalid control device Dispose raised an exception.' $_ $null } }
        } else {
            try {
                $fltmc=Join-Path $env:WINDIR 'System32\fltmc.exe'
                if (!(Test-Path -LiteralPath $fltmc -PathType Leaf)) { Add-Result 'unload concurrency control handle' 'ERROR' "fltmc.exe was not found: $fltmc" }
                else {
                    $unload=& $fltmc unload YcszProtection 2>&1 | Out-String; $unloadExit=$LASTEXITCODE
                    $filters=& $fltmc filters 2>&1 | Out-String; $filtersExit=$LASTEXITCODE
                    $filterPresent=$filtersExit -eq 0 -and $filters -match '(?i)YcszProtection'
                    $decision=Test-ProtectionExpectedUnloadRejection $unloadExit $unload $filterPresent
                    Add-Result 'unload concurrency control handle' $decision.Status ($decision.Detail + (' fltmc exit={0}; filter-query exit={1}.' -f $unloadExit,$filtersExit))
                }
            } catch { Add-Result 'unload concurrency control handle' 'ERROR' ('fltmc invocation failed: ' + $_.Exception.Message) }
            finally { try { $device.Dispose() } catch { Add-DynamicCleanupError 'unload concurrency control handle cleanup' '\\.\YcszProtection' 'Control device Dispose raised an exception.' $_ $null } }
        }

        $ordinaryDelete=Join-Path $context.FixtureRoot ('ordinary-delete-control-' + $context.RunId)
        $deleteFile=Join-Path $ordinaryDelete 'file.bin'
        $deleteControl=$false
        try {
            $deleteOwnedDirectory=New-ProtectionFixtureDirectory $ordinaryDelete; [void](Add-DynamicOwned $deleteOwnedDirectory $context)
            $owned=New-ProtectionFixtureFile $deleteFile ([Text.Encoding]::UTF8.GetBytes('ordinary delete control')); [void](Add-DynamicOwned $owned $context)
            $fileDecision=Remove-ProtectionFixtureOwnedPath $owned
            if ($fileDecision.Status -ne 'PASS') { Add-Result 'ordinary directory deletion control' $fileDecision.Status $fileDecision.Detail }
            else {
                $dirDecision=Remove-ProtectionFixtureOwnedPath $deleteOwnedDirectory
                if ($dirDecision.Status -eq 'PASS') { $deleteControl=$true; Add-Result 'ordinary directory deletion control' 'PASS' 'An ordinary unique fixture directory and its owned file were deleted by identity.' }
                else { Add-Result 'ordinary directory deletion control' $dirDecision.Status $dirDecision.Detail }
            }
        } catch { Add-DynamicExceptionResult 'ordinary directory deletion control' 'directory-delete' 'directory-delete' $_ $false }
        Add-Result 'protected directory itself' 'BLOCKED' 'The protected-root handle is retained to bind entity identity; deleting that root safely would require releasing the guard and cannot be claimed as an anti-race check.'
    } catch { Add-Result 'dynamic runner integrity' 'ERROR' $_.Exception.Message }
    finally {
        Invoke-DynamicOwnedCleanup $context
        Close-ProtectionFixtureScope $context.Scope
    }
}

if ($Mode -eq 'Static') { Invoke-StaticChecks }
elseif ($Mode -eq 'Dynamic') { Invoke-DynamicChecks }
else { Invoke-TwoPhaseChecks }
Write-Results
$failed = @($results | Where-Object { $_.Status -eq 'FAIL' }).Count
$errors = @($results | Where-Object { $_.Status -eq 'ERROR' }).Count
$blocked = @($results | Where-Object { $_.Status -eq 'BLOCKED' }).Count
if ($failed -gt 0 -or $errors -gt 0) { exit 1 }
if (($Mode -eq 'Dynamic' -or $Mode -eq 'TwoPhase') -and $blocked -gt 0) { exit 2 }
exit 0
