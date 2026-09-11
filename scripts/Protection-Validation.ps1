# Pure validation shared by the maintenance scripts and isolated tests.
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
