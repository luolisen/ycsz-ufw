# Pure validation shared by the maintenance scripts and isolated tests.
function Assert-ProtectionFixtureChild([string]$Fixture,[string]$Candidate) {
    $root = [IO.Path]::GetFullPath($Fixture).TrimEnd('\')
    $path = [IO.Path]::GetFullPath($Candidate)
    if (!$path.StartsWith($root + '\',[StringComparison]::OrdinalIgnoreCase)) {
        throw "Dynamic path must be strictly inside the disposable fixture: $path"
    }
}

function Assert-ProtectionServiceCommand([string]$Command,[string]$Image) {
    $suffix = '" --service'
    if (!$Command -or !$Image -or !$Command.StartsWith('"') -or !$Command.EndsWith($suffix,[StringComparison]::Ordinal)) {
        throw 'The product service command must quote the image and use only --service.'
    }
    $actual = $Command.Substring(1,$Command.Length - 1 - $suffix.Length)
    if (![string]::Equals($actual,$Image,[StringComparison]::OrdinalIgnoreCase)) {
        throw 'The product service image does not exactly match the fixed installation path.'
    }
}

function Resolve-ProtectionSignTool {
    $command = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    $roots = @(
        (Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'),
        (Join-Path $env:ProgramFiles 'Windows Kits\10\bin')
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }
    $tool = Get-ChildItem -Path $roots -Filter signtool.exe -Recurse -ErrorAction SilentlyContinue |
        Sort-Object FullName -Descending | Select-Object -First 1
    if (!$tool) { throw 'signtool.exe was not found; CAT member binding cannot be verified.' }
    return $tool.FullName
}

function Assert-ProtectionCatalogMembers([string]$PackageDirectory) {
    if ([string]::IsNullOrWhiteSpace($PackageDirectory)) { throw 'PackageDirectory is required.' }
    $package = [IO.Path]::GetFullPath($PackageDirectory)
    $inf = Join-Path $package 'YcszProtection.inf'
    $sys = Join-Path $package 'YcszProtection.sys'
    $cat = Join-Path $package 'YcszProtection.cat'
    foreach ($path in @($inf,$sys,$cat)) { if (!(Test-Path -LiteralPath $path -PathType Leaf)) { throw "Protection package member is missing: $path" } }
    $catalogLine = Get-Content -LiteralPath $inf | Where-Object { $_ -match '^\s*CatalogFile\s*=\s*YcszProtection\.cat\s*$' } | Select-Object -First 1
    if (!$catalogLine) { throw 'YcszProtection.inf does not bind exactly to YcszProtection.cat.' }
    $signTool = Resolve-ProtectionSignTool
    foreach ($member in @($inf,$sys)) {
        & $signTool verify /kp /c $cat $member | Out-Host
        if ($LASTEXITCODE -ne 0) { throw "CAT member binding verification failed for $member ($LASTEXITCODE)." }
    }
    return $true
}

function Get-ProtectionDataRoot {
    $common = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
    if ([string]::IsNullOrWhiteSpace($common)) { throw 'CommonApplicationData is unavailable.' }
    return [IO.Path]::GetFullPath((Join-Path $common 'YcszFirewall'))
}

function Assert-ProtectionPackage([string]$PublishedName,$Package) {
    if ($PublishedName -notmatch '^oem[0-9]+\.inf$') { throw 'Expected an OEM INF name, not a path or command option.' }
    if (@($Package).Count -ne 1 -or !$Package -or
        [IO.Path]::GetFileName($Package.OriginalFileName) -ine 'YcszProtection.inf' -or
        $Package.ProviderName -ine 'YCSZ' -or $Package.ClassName -ine 'ActivityMonitor') {
        throw 'The selected driver-store package is not YCSZ protection.'
    }
    if ($Package.PSObject.Properties.Name -contains 'CatalogFile' -and $Package.CatalogFile -ine 'YcszProtection.cat') {
        throw 'The selected driver-store package is not bound to YcszProtection.cat.'
    }
}

function Test-IsProtectionPackage($Package) {
    if ($null -eq $Package) { return $false }
    return [IO.Path]::GetFileName([string]$Package.OriginalFileName) -ieq 'YcszProtection.inf' -and
        [string]$Package.ProviderName -ieq 'YCSZ' -and
        [string]$Package.ClassName -ieq 'ActivityMonitor'
}

function Get-ProtectionPackageName($Package) {
    if ($null -eq $Package -or [string]::IsNullOrWhiteSpace([string]$Package.Driver)) { return $null }
    $name = [IO.Path]::GetFileName([string]$Package.Driver)
    if ($name -notmatch '^oem[0-9]+\.inf$') { return $null }
    return $name.ToLowerInvariant()
}

function Get-ProtectionPackageSnapshot {
    return @(Get-WindowsDriver -Online -ErrorAction Stop | ForEach-Object { $_ })
}

function Get-ProtectionPackageDelta([object[]]$Before,[object[]]$After) {
    $beforeMap=@{}; $afterMap=@{}
    foreach ($package in @($Before)) {
        $name=Get-ProtectionPackageName $package
        if ($name) { $beforeMap[$name]=$package }
    }
    foreach ($package in @($After)) {
        $name=Get-ProtectionPackageName $package
        if ($name) { $afterMap[$name]=$package }
    }
    $newNames=@($afterMap.Keys | Where-Object { !$beforeMap.ContainsKey($_) } | Sort-Object)
    $removedNames=@($beforeMap.Keys | Where-Object { !$afterMap.ContainsKey($_) } | Sort-Object)
    $newPackages=@($newNames | ForEach-Object { $afterMap[$_] })
    $removedPackages=@($removedNames | ForEach-Object { $beforeMap[$_] })
    $beforeProtection=@($beforeMap.Values | Where-Object { Test-IsProtectionPackage $_ })
    $afterProtection=@($afterMap.Values | Where-Object { Test-IsProtectionPackage $_ })
    $newProtection=@($newPackages | Where-Object { Test-IsProtectionPackage $_ })
    $removedProtection=@($removedPackages | Where-Object { Test-IsProtectionPackage $_ })
    $newOther=@($newPackages | Where-Object { !(Test-IsProtectionPackage $_) })
    return [pscustomobject]@{
        Before=@($Before); After=@($After); NewNames=$newNames; RemovedNames=$removedNames
        NewPackages=$newPackages; RemovedPackages=$removedPackages
        BeforeProtection=$beforeProtection; AfterProtection=$afterProtection
        NewProtection=$newProtection; RemovedProtection=$removedProtection; NewOther=$newOther
    }
}

function Assert-ProtectionPackageDelta($Delta,[switch]$AllowNoop) {
    if ($null -eq $Delta) { throw 'Protection package delta is missing.' }
    if (@($Delta.RemovedProtection).Count -gt 0) { throw 'An existing YCSZ protection package disappeared during installation.' }
    if (@($Delta.NewOther).Count -gt 0) { throw 'An unrelated driver package appeared; no package will be deleted automatically.' }
    if (@($Delta.NewProtection).Count -gt 1) { throw 'More than one new YCSZ protection package appeared; refusing ambiguous rollback.' }
    if (!$AllowNoop -and @($Delta.BeforeProtection).Count -eq 0 -and @($Delta.NewProtection).Count -eq 0) {
        throw 'No new YCSZ protection package was observable after installation.'
    }
    if (@($Delta.AfterProtection).Count -eq 0) { throw 'No YCSZ protection package is present after installation.' }
    return $Delta
}

function New-ProtectionRollbackPlan($Before,$After,[bool]$DriverWasRegistered,[bool]$ApplicationWasRunning) {
    $delta=Get-ProtectionPackageDelta $Before $After
    Assert-ProtectionPackageDelta $delta -AllowNoop:($DriverWasRegistered -and @($delta.NewProtection).Count -eq 0) | Out-Null
    return [pscustomobject]@{
        Delta=$delta
        NewProtectionNames=@($delta.NewProtection | ForEach-Object { Get-ProtectionPackageName $_ })
        ExistingProtectionNames=@($delta.BeforeProtection | ForEach-Object { Get-ProtectionPackageName $_ })
        RestoreOldPackage=(@($delta.BeforeProtection).Count -gt 0)
        RemoveNewRegistration=(-not $DriverWasRegistered)
        RestartApplication=$ApplicationWasRunning
    }
}

function Assert-ProtectionRollbackStopped($ApplicationService,$DriverService) {
    foreach ($service in @($ApplicationService,$DriverService)) {
        if ($null -ne $service -and $service.Status -ne 'Stopped') {
            throw 'Rollback may not alter configuration or remove files while a product service is not stopped.'
        }
    }
}

function Get-ProtectionNativeErrorCode($ErrorRecord) {
    $exception = $null
    if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) {
        $exception = $ErrorRecord.Exception
    } elseif ($ErrorRecord -is [System.Exception]) {
        $exception = $ErrorRecord
    }
    while ($null -ne $exception) {
        if ($exception -is [System.ComponentModel.Win32Exception]) {
            return [int]$exception.NativeErrorCode
        }
        $nativeProperty = $exception.PSObject.Properties['NativeErrorCode']
        if ($null -ne $nativeProperty) {
            try { return [int]$nativeProperty.Value } catch { }
        }
        # HRESULT is signed; casting a negative Int32 to UInt32 throws in
        # PowerShell. Reinterpret its bits instead of converting its value.
        $hresult = [BitConverter]::ToUInt32([BitConverter]::GetBytes([int]$exception.HResult),0)
        if (($hresult -band [uint32]4294901760) -eq [uint32]2147942400) {
            return [int]($hresult -band [uint32]0x0000FFFF)
        }
        $exception = $exception.InnerException
    }
    return $null
}

function Get-ProtectionWin32ErrorLabel([int]$Code) {
    $hex = ('0x{0:X8}' -f ([uint32]$Code))
    switch ($Code) {
        2 { return "ERROR_FILE_NOT_FOUND ($Code/$hex)" }
        5 { return "ERROR_ACCESS_DENIED ($Code/$hex)" }
        32 { return "ERROR_SHARING_VIOLATION ($Code/$hex)" }
        50 { return "ERROR_NOT_SUPPORTED ($Code/$hex)" }
        87 { return "ERROR_INVALID_PARAMETER ($Code/$hex)" }
        120 { return "ERROR_CALL_NOT_IMPLEMENTED ($Code/$hex)" }
        default { return "Win32 error $Code/$hex" }
    }
}

function Resolve-ProtectionDynamicNativeFailure([int]$Code,[string]$ExpectedStage,[string]$ActualStage,[bool]$ControlSucceeded) {
    $label = Get-ProtectionWin32ErrorLabel $Code
    if ($Code -eq 50 -or $Code -eq 120) {
        return [pscustomobject]@{ Status='BLOCKED'; Detail=("The platform or filesystem does not support {0}: {1}" -f $ActualStage,$label) }
    }
    if (!$ControlSucceeded) {
        return [pscustomobject]@{ Status='ERROR'; Detail=("Control precondition failed before {0}: {1}" -f $ActualStage,$label) }
    }
    if ($ExpectedStage -ne $ActualStage) {
        return [pscustomobject]@{ Status='ERROR'; Detail=("Native error was captured at unexpected stage {0}; expected {1}: {2}" -f $ActualStage,$ExpectedStage,$label) }
    }
    switch ($Code) {
        5 { return [pscustomobject]@{ Status='PASS'; Detail=("Expected protection denial at {0}: {1}" -f $ActualStage,$label) } }
        87 { return [pscustomobject]@{ Status='ERROR'; Detail=("The dynamic call supplied an invalid parameter at {0}: {1}" -f $ActualStage,$label) } }
        32 { return [pscustomobject]@{ Status='ERROR'; Detail=("The fixture has a sharing conflict at {0}; this is not protection evidence: {1}" -f $ActualStage,$label) } }
        2 { return [pscustomobject]@{ Status='ERROR'; Detail=("The fixture path is missing at {0}; this is not protection evidence: {1}" -f $ActualStage,$label) } }
        default { return [pscustomobject]@{ Status='ERROR'; Detail=("Unexpected native error at {0}; this is not protection evidence: {1}" -f $ActualStage,$label) } }
    }
}

function Resolve-ProtectionDynamicException($ErrorRecord,[string]$ExpectedStage,[string]$ActualStage,[bool]$ControlSucceeded) {
    $code = Get-ProtectionNativeErrorCode $ErrorRecord
    if ($null -eq $code) {
        $message = if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) { $ErrorRecord.Exception.Message } else { [string]$ErrorRecord }
        return [pscustomobject]@{ Status='ERROR'; Detail=("No reliable Win32 error was captured at {0}: {1}" -f $ActualStage,$message) }
    }
    return Resolve-ProtectionDynamicNativeFailure $code $ExpectedStage $ActualStage $ControlSucceeded
}

function Resolve-ProtectionCleanupFailure([string]$Path,[string]$Detail) {
    return [pscustomobject]@{ Status='ERROR'; Detail=('Cleanup failed for {0}. Evidence path is retained. {1}' -f $Path,$Detail) }
}

function Test-ProtectionExpectedUnloadRejection([int]$ExitCode,[string]$Output,[bool]$FilterStillPresent) {
    if ($ExitCode -eq 0) {
        return [pscustomobject]@{ Status='FAIL'; Detail='fltmc unload succeeded while the control handle was open.' }
    }
    if (!$FilterStillPresent) {
        return [pscustomobject]@{ Status='ERROR'; Detail='The unload command was non-zero, but the target filter could not be confirmed as still present.' }
    }
    if ($Output -match '(?i)STATUS_FLT_DO_NOT_DETACH|ERROR_FLT_DO_NOT_DETACH|0xC01C0010|0x801F0010') {
        return [pscustomobject]@{ Status='PASS'; Detail='fltmc reported STATUS_FLT_DO_NOT_DETACH and the target filter remained present.' }
    }
    return [pscustomobject]@{ Status='ERROR'; Detail=('fltmc returned a non-zero result without the expected STATUS_FLT_DO_NOT_DETACH evidence: ' + $Output.Trim()) }
}
