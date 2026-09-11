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

function Assert-ProtectionPackage([string]$PublishedName,$Package) {
    if ($PublishedName -notmatch '^oem[0-9]+\.inf$') { throw 'Expected an OEM INF name, not a path or command option.' }
    if (@($Package).Count -ne 1 -or !$Package -or
        [IO.Path]::GetFileName($Package.OriginalFileName) -ine 'YcszProtection.inf' -or
        $Package.ProviderName -ine 'YCSZ' -or $Package.ClassName -ine 'ActivityMonitor') {
        throw 'The selected driver-store package is not YCSZ protection.'
    }
}
