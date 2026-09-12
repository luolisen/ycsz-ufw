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
        return New-ProtectionFixtureOwnedRecord $full 'Junction' $entity
    } catch {
        if ($null -ne $entity -and $entity.IsDirectory -and (($entity.Attributes -band 0x400) -ne 0)) {
            $owned=New-ProtectionFixtureOwnedRecord $full 'Junction' $entity
            Close-ProtectionFixtureEntity $entity; $entity=$null
            $decision=Remove-ProtectionFixtureOwnedPath $owned
            if ($decision.Status -ne 'PASS') { throw ("Junction validation failed and safe handle cleanup was not confirmed: " + $decision.Detail) }
        }
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
    $racePath = Join-Path $runRoot 'identity-race.bin'
    $raceBackupPath = Join-Path $runRoot 'identity-race-original-backup.bin'
    $raceReplacementSourcePath = Join-Path $runRoot 'identity-race-replacement-source.bin'
    $nonEmptyDirectoryPath = Join-Path $runRoot 'non-empty-directory'
    $nonEmptyChildPath = Join-Path $nonEmptyDirectoryPath 'child.bin'

    foreach ($directory in @($protectedRoot,$dataRoot)) {
        $owned = New-ProtectionFixtureDirectory $directory
        [void]$fixtureOwned.Add($owned)
    }
    $sameFileOwned = $null
    foreach ($file in @(
        [pscustomobject]@{ Path=$imagePath; Bytes=[Text.Encoding]::UTF8.GetBytes('fixture image placeholder') },
        [pscustomobject]@{ Path=$samplePath; Bytes=[Text.Encoding]::UTF8.GetBytes('protected sample bytes') },
        [pscustomobject]@{ Path=$sameFilePath; Bytes=[Text.Encoding]::UTF8.GetBytes('do not overwrite') },
        [pscustomobject]@{ Path=$sentinelPath; Bytes=[Text.Encoding]::UTF8.GetBytes('outside sentinel must remain unchanged') }
    )) {
        $owned = New-ProtectionFixtureFile $file.Path $file.Bytes
        if ($file.Path -eq $sentinelPath) { [void]$externalOwned.Add($owned) }
        else {
            [void]$fixtureOwned.Add($owned)
            if ($file.Path -eq $sameFilePath) { $sameFileOwned=$owned }
        }
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
    $junctionDecision=Remove-ProtectionFixtureOwnedPath $parentJunctionOwned
    if ($junctionDecision.Status -ne 'PASS' -or (Test-Path -LiteralPath $parentJunctionPath)) { throw ('Owned junction was not removed by its verified handle: ' + $junctionDecision.Detail) }
    [void]$fixtureOwned.Remove($parentJunctionOwned)
    if ((Get-ByteFingerprint $sentinelPath) -ne $sentinelFingerprint) { throw 'Removing the owned junction changed its external target.' }
    Add-Pass 'owned junction handle-bound cleanup preserves target'

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
    $hardLinkDecision=Remove-ProtectionFixtureOwnedPath $hardLinkOwned
    if ($hardLinkDecision.Status -ne 'PASS' -or (Test-Path -LiteralPath $hardLinkPath)) { throw ('Owned hard link was not removed by its verified handle: ' + $hardLinkDecision.Detail) }
    [void]$fixtureOwned.Remove($hardLinkOwned)
    if ((Get-ByteFingerprint $sentinelPath) -ne $sentinelFingerprint) { throw 'Removing the hard link changed the outside sentinel.' }
    Add-Pass 'hard-link handle-bound cleanup preserves sentinel'

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

    $wrongOwned=$sampleOwned | Select-Object *
    $wrongOwned.Path=$sameFilePath
    $wrongDecision=Remove-ProtectionFixtureOwnedPath $wrongOwned
    if ($wrongDecision.Status -ne 'ERROR' -or (Get-ByteFingerprint $sameFilePath) -ne $existingFileFingerprint) { throw 'Owned identity mismatch was not rejected without changing the evidence path.' }
    Add-Pass 'owned identity mismatch retains evidence'

    $nonEmptyDirectoryOwned=New-ProtectionFixtureDirectory $nonEmptyDirectoryPath
    $nonEmptyChildOwned=New-ProtectionFixtureFile $nonEmptyChildPath ([Text.Encoding]::UTF8.GetBytes('non-empty directory child'))
    [void]$fixtureOwned.Add($nonEmptyDirectoryOwned); [void]$fixtureOwned.Add($nonEmptyChildOwned)
    $nonEmptyFingerprint=Get-ByteFingerprint $nonEmptyChildPath
    $nonEmptyDecision=Remove-ProtectionFixtureOwnedPath $nonEmptyDirectoryOwned
    if ($nonEmptyDecision.Status -ne 'ERROR' -or !(Test-Path -LiteralPath $nonEmptyDirectoryPath -PathType Container) -or (Get-ByteFingerprint $nonEmptyChildPath) -ne $nonEmptyFingerprint) { throw 'Non-empty directory cleanup was not rejected with its evidence retained.' }
    Add-Pass 'non-empty directory cleanup retains evidence'
    $nonEmptyChildDecision=Remove-ProtectionFixtureOwnedPath $nonEmptyChildOwned
    $nonEmptyDirectoryDecision=Remove-ProtectionFixtureOwnedPath $nonEmptyDirectoryOwned
    if ($nonEmptyChildDecision.Status -ne 'PASS' -or $nonEmptyDirectoryDecision.Status -ne 'PASS') { throw 'Non-empty directory could not be safely cleaned after its child was removed.' }
    [void]$fixtureOwned.Remove($nonEmptyChildOwned); [void]$fixtureOwned.Remove($nonEmptyDirectoryOwned)
    Add-Pass 'empty directory handle-bound cleanup'

    $raceOwned=New-ProtectionFixtureFile $racePath ([Text.Encoding]::UTF8.GetBytes('original race object'))
    $replacementOwned=New-ProtectionFixtureFile $raceReplacementSourcePath ([Text.Encoding]::UTF8.GetBytes('replacement bytes must remain'))
    $raceBackupOwned=$raceOwned | Select-Object *
    $raceBackupOwned.Path=$raceBackupPath
    $replacementAtPath=$replacementOwned | Select-Object *
    $replacementAtPath.Path=$racePath
    [void]$fixtureOwned.Add($raceOwned); [void]$fixtureOwned.Add($replacementOwned); [void]$fixtureOwned.Add($raceBackupOwned); [void]$fixtureOwned.Add($replacementAtPath)
    $replacementFingerprint=Get-ByteFingerprint $raceReplacementSourcePath
    $raceHook = {
        param($deleteHandle,$originalEntity)
        Add-ProtectionFixtureNativeType
        $renamedError=0
        $renamed=[YcszFixtureBoundaryNative]::RenameFileByHandle($deleteHandle,$raceBackupPath,[ref]$renamedError)
        if (!$renamed) { throw (Get-ProtectionFixtureWin32Exception $renamedError ('Controlled handle-bound rename failed (' + (Get-ProtectionWin32ErrorLabel $renamedError) + '): ' + $raceBackupPath)) }
        $moved=[YcszFixtureBoundaryNative]::MoveFileEx($raceReplacementSourcePath,$racePath,[uint32]0x8)
        $moveError=[Runtime.InteropServices.Marshal]::GetLastWin32Error()
        if (!$moved) { throw (Get-ProtectionFixtureWin32Exception $moveError ('Controlled replacement failed (' + (Get-ProtectionWin32ErrorLabel $moveError) + '): ' + $racePath)) }
        $replacementEntity=$null
        try {
            $replacementEntity=Get-ProtectionFixtureEntity $racePath
            if ($replacementEntity.VolumeSerial -eq $originalEntity.VolumeSerial -and $replacementEntity.FileIndex -eq $originalEntity.FileIndex) { throw 'Controlled replacement did not change the path identity.' }
        } finally { if ($null -ne $replacementEntity) { Close-ProtectionFixtureEntity $replacementEntity } }
        if ((Get-ByteFingerprint $racePath) -ne $replacementFingerprint) { throw 'Controlled replacement bytes changed before the old handle was dispositioned.' }
    }
    $raceDecision=Remove-ProtectionFixtureOwnedPath $raceOwned $raceHook -AllowDeleteShare
    if ($raceDecision.Status -ne 'PASS' -or !$raceDecision.ReplacementDetected -or !(Test-Path -LiteralPath $racePath -PathType Leaf) -or (Test-Path -LiteralPath $raceBackupPath) -or (Get-ByteFingerprint $racePath) -ne $replacementFingerprint) { throw ('Handle-bound replacement regression failed: ' + $raceDecision.Detail) }
    [void]$fixtureOwned.Remove($raceOwned)
    [void]$fixtureOwned.Remove($raceBackupOwned)
    [void]$fixtureOwned.Remove($replacementOwned)
    $replacementCheck=Test-ProtectionFixtureOwnedIdentity $replacementAtPath
    if ($replacementCheck.Status -ne 'PASS' -or !$replacementCheck.Exists) { throw 'The replacement object identity was not preserved after old-handle disposition.' }
    Add-Pass 'controlled replacement retains replacement identity and bytes'
    $replacementDecision=Remove-ProtectionFixtureOwnedPath $replacementAtPath
    if ($replacementDecision.Status -ne 'PASS' -or (Test-Path -LiteralPath $racePath)) { throw ('Replacement object was not cleaned by its own verified handle: ' + $replacementDecision.Detail) }
    [void]$fixtureOwned.Remove($replacementAtPath)
    Add-Pass 'replacement cleanup remains separately owned'

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
