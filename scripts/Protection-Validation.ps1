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
