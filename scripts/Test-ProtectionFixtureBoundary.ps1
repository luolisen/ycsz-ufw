[CmdletBinding()]
param(
    [string]$RootPath
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Protection-Validation.ps1')

$checks = New-Object 'System.Collections.Generic.List[string]'
$failures = New-Object 'System.Collections.Generic.List[string]'
$fixtureOwned = New-Object 'System.Collections.Generic.List[object]'
$externalOwned = New-Object 'System.Collections.Generic.List[object]'
$runRootOwned = $null
$externalRootOwned = $null
$lock = $null

function Add-Pass([string]$Name) {
    [void]$checks.Add($Name)
}

function Add-Failure([string]$Name,[string]$Detail) {
    [void]$failures.Add(($Name + ': ' + $Detail))
}

function Must-Reject([string]$Name,[scriptblock]$Action) {
    $rejected = $false
    try { & $Action | Out-Null } catch { $rejected = $true }
    if (!$rejected) { throw ($Name + ' accepted an unsafe or mismatched fixture input.') }
    Add-Pass $Name
}

function Get-ByteFingerprint([string]$Path) {
    return [Convert]::ToBase64String([IO.File]::ReadAllBytes($Path))
}

function New-TestJunction([string]$Path,[string]$Target) {
    $full = [IO.Path]::GetFullPath($Path)
    $targetFull = [IO.Path]::GetFullPath($Target)
    New-Item -ItemType Junction -Path $full -Target $targetFull -ErrorAction Stop | Out-Null
    $entity = $null
    try {
        $entity = Get-ProtectionFixtureEntity $full
        if (!$entity.IsDirectory -or ($entity.Attributes -band 0x400) -eq 0) { throw "Junction identity was not confirmed: $full" }
        return [pscustomobject]@{
            Path=$full; Kind='Junction'; VolumeSerial=$entity.VolumeSerial; FileIndex=$entity.FileIndex
            Attributes=$entity.Attributes; NumberOfLinks=$entity.NumberOfLinks
        }
    } catch {
        if ($null -ne $entity) { Close-ProtectionFixtureEntity $entity; $entity=$null }
        try { Remove-Item -LiteralPath $full -Force -ErrorAction Stop } catch { }
        throw
    } finally {
        if ($null -ne $entity) { Close-ProtectionFixtureEntity $entity }
    }
}

function Remove-TestOwned([object[]]$Owned,[string]$Label) {
    foreach ($item in @($Owned | Sort-Object @{Expression={ $_.Path.Length };Descending=$true}, @{Expression={ $_.Path };Descending=$true})) {
        try {
            $decision = Remove-ProtectionFixtureOwnedPath $item
            if ($decision.Status -eq 'ERROR') { Add-Failure ($Label + ' cleanup ' + $item.Path) $decision.Detail }
        } catch { Add-Failure ($Label + ' cleanup ' + $item.Path) $_.Exception.Message }
    }
}

$tempParent = $null
$runRoot = $null
$externalRoot = $null

try {
    $tempParent = if ([string]::IsNullOrWhiteSpace($RootPath)) { [IO.Path]::GetTempPath().TrimEnd('\') } else { [IO.Path]::GetFullPath($RootPath).TrimEnd('\') }
    if (!(Test-Path -LiteralPath $tempParent -PathType Container)) { throw "Temporary parent is not an existing directory: $tempParent" }
    if ($tempParent -notmatch '^[A-Za-z]:\\') { throw "Temporary parent must be on a local Windows drive: $tempParent" }

    $id = ([guid]::NewGuid()).ToString('N')
    $runRoot = Join-Path $tempParent ('ycsz-fixture-boundary-' + $id)
    $externalRoot = Join-Path $tempParent ('ycsz-fixture-boundary-external-' + $id)
    $runRootOwned = New-ProtectionFixtureDirectory $runRoot
    $externalRootOwned = New-ProtectionFixtureDirectory $externalRoot

    $protectedRoot = Join-Path $runRoot 'app'
    $dataRoot = Join-Path $runRoot 'data'
    $imagePath = Join-Path $protectedRoot 'Ycsz.exe'
    $samplePath = Join-Path $protectedRoot 'existing-handle.bin'
    $sameFilePath = Join-Path $runRoot 'existing-name.bin'
    $sameDirectoryPath = Join-Path $runRoot 'existing-directory'
    $sentinelPath = Join-Path $externalRoot 'outside-sentinel.bin'
    $parentJunctionPath = Join-Path $runRoot 'parent-junction'
    $redirectedFixturePath = Join-Path $parentJunctionPath 'fixture'
    $hardLinkPath = Join-Path $runRoot 'outside-sentinel-link.bin'
    $lockedPath = Join-Path $runRoot 'locked-owned.bin'

    foreach ($directory in @($protectedRoot,$dataRoot)) {
        $owned = New-ProtectionFixtureDirectory $directory
        [void]$fixtureOwned.Add($owned)
    }
    foreach ($file in @(
        [pscustomobject]@{ Path=$imagePath; Bytes=[Text.Encoding]::UTF8.GetBytes('fixture image placeholder') },
        [pscustomobject]@{ Path=$samplePath; Bytes=[Text.Encoding]::UTF8.GetBytes('protected sample bytes') },
        [pscustomobject]@{ Path=$sameFilePath; Bytes=[Text.Encoding]::UTF8.GetBytes('do not overwrite') },
        [pscustomobject]@{ Path=$sentinelPath; Bytes=[Text.Encoding]::UTF8.GetBytes('outside sentinel must remain unchanged') }
    )) {
        $owned = New-ProtectionFixtureFile $file.Path $file.Bytes
        if ($file.Path -eq $sentinelPath) { [void]$externalOwned.Add($owned) } else { [void]$fixtureOwned.Add($owned) }
    }
    $existingFileFingerprint = Get-ByteFingerprint $sameFilePath
    $sentinelFingerprint = Get-ByteFingerprint $sentinelPath
    $sameDirectoryOwned = New-ProtectionFixtureDirectory $sameDirectoryPath
    [void]$fixtureOwned.Add($sameDirectoryOwned)

    $parentJunctionOwned = New-TestJunction $parentJunctionPath $externalRoot
    [void]$fixtureOwned.Add($parentJunctionOwned)
    Must-Reject 'parent junction entity scope' { New-ProtectionFixtureScope $runRoot @($redirectedFixturePath) @() @() }
    if ((Get-ByteFingerprint $sentinelPath) -ne $sentinelFingerprint) { throw 'Parent junction scope changed the outside sentinel.' }
    Add-Pass 'parent junction outside sentinel preservation'

    Must-Reject 'existing same-name file CreateNew' { New-ProtectionFixtureFile $sameFilePath ([Text.Encoding]::UTF8.GetBytes('overwrite attempt')) }
    if ((Get-ByteFingerprint $sameFilePath) -ne $existingFileFingerprint) { throw 'CreateNew changed the existing same-name file.' }
    Add-Pass 'existing same-name file preservation'

    Must-Reject 'existing same-name directory CreateDirectory' { New-ProtectionFixtureDirectory $sameDirectoryPath }
    Add-Pass 'existing same-name directory preservation'

    $hardLinkOwned = New-ProtectionFixtureHardLink $hardLinkPath $sentinelPath
    [void]$fixtureOwned.Add($hardLinkOwned)
    $hardLinkEntity = $null
    try {
        $hardLinkEntity = Get-ProtectionFixtureEntity $hardLinkPath
        Must-Reject 'hard-link entity rejection' { Assert-ProtectionFixtureEntity $hardLinkEntity }
    } finally {
        if ($null -ne $hardLinkEntity) { Close-ProtectionFixtureEntity $hardLinkEntity }
    }
    Must-Reject 'hard-link scope rejection' { New-ProtectionFixtureScope $runRoot @($hardLinkPath) @() @() }
    if ((Get-ByteFingerprint $sentinelPath) -ne $sentinelFingerprint) { throw 'Hard-link checks changed the outside sentinel.' }
    Add-Pass 'hard-link outside sentinel preservation'

    $sampleOwned = $fixtureOwned | Where-Object { $_.Path -eq $samplePath } | Select-Object -First 1
    $manifest = [pscustomobject]@{
        FixtureId=([guid]::NewGuid()).ToString()
        FixtureRoot=$runRoot
        ProtectedRoot=$protectedRoot
        ProtectedDataRoot=$dataRoot
        ServiceImagePath=$imagePath
        ServiceName='YcszFirewall'
        ProtectedFiles=@([pscustomobject]@{
            Path=$samplePath; Length=[uint64]$sampleOwned.Length; VolumeSerial=[uint64]$sampleOwned.VolumeSerial
            FileIndex=[uint64]$sampleOwned.FileIndex; NumberOfLinks=[uint64]$sampleOwned.NumberOfLinks
        })
    }
    $manifestMismatches = @{
        FixtureRoot=(Join-Path $tempParent ('not-the-fixture-' + $id))
        ProtectedRoot=(Join-Path $runRoot 'not-the-app')
        ProtectedDataRoot=(Join-Path $runRoot 'not-the-data')
        ServiceImagePath=(Join-Path $protectedRoot 'not-the-image.exe')
    }
    foreach ($field in $manifestMismatches.Keys) {
        $badManifest = $manifest | Select-Object *
        $badManifest.$field = $manifestMismatches[$field]
        Must-Reject ('manifest ' + $field + ' mismatch') { Assert-ProtectionFixtureManifest $badManifest $runRoot $protectedRoot $dataRoot $imagePath }
    }

    $lockedOwned = New-ProtectionFixtureFile $lockedPath ([Text.Encoding]::UTF8.GetBytes('locked cleanup evidence'))
    [void]$fixtureOwned.Add($lockedOwned)
    $lockedFingerprint = Get-ByteFingerprint $lockedPath
    try {
        $lock = New-Object IO.FileStream($lockedPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        $lockedDecision = Remove-ProtectionFixtureOwnedPath $lockedOwned
        if ($lockedDecision.Status -ne 'ERROR' -or !(Test-Path -LiteralPath $lockedPath -PathType Leaf)) { throw 'Cleanup did not retain an owned file held by a conflicting share handle.' }
        if ((Get-ByteFingerprint $lockedPath) -ne $lockedFingerprint) { throw 'Cleanup failure changed the locked owned file.' }
        Add-Pass 'sharing-locked cleanup failure retains evidence'
    } finally {
        if ($null -ne $lock) { $lock.Dispose(); $lock=$null }
    }
    $releasedDecision = Remove-ProtectionFixtureOwnedPath $lockedOwned
    if ($releasedDecision.Status -ne 'PASS' -or (Test-Path -LiteralPath $lockedPath)) { throw 'Released owned file was not cleaned by exact identity.' }
    Add-Pass 'released owned cleanup'
} catch {
    Add-Failure 'fixture-boundary integration' $_.Exception.Message
} finally {
    if ($null -ne $lock) { try { $lock.Dispose() } catch { Add-Failure 'fixture lock cleanup' $_.Exception.Message } }
    Remove-TestOwned $fixtureOwned 'fixture'
    Remove-TestOwned $externalOwned 'external'
    if ($null -ne $externalRootOwned) {
        try {
            $decision = Remove-ProtectionFixtureOwnedPath $externalRootOwned
            if ($decision.Status -eq 'ERROR') { Add-Failure 'external root cleanup' $decision.Detail }
        } catch { Add-Failure 'external root cleanup' $_.Exception.Message }
    }
    if ($null -ne $runRootOwned) {
        try {
            $decision = Remove-ProtectionFixtureOwnedPath $runRootOwned
            if ($decision.Status -eq 'ERROR') { Add-Failure 'fixture root cleanup' $decision.Detail }
        } catch { Add-Failure 'fixture root cleanup' $_.Exception.Message }
    }
}

if ($failures.Count -gt 0) {
    foreach ($failure in $failures) { Write-Output ('ERROR ' + $failure) }
    Write-Output ('FAIL fixture-boundary integration checks: ' + $failures.Count + '; evidence paths were retained where identity or cleanup could not be confirmed.')
    exit 1
}

Write-Output ('PASS ' + $checks.Count + ' fixture-boundary integration checks; no service, driver or system configuration changed.')
exit 0
