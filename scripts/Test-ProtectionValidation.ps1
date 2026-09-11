$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Protection-Validation.ps1')
$count = 0
function Must-Reject([scriptblock]$Action) {
    $rejected = $false
    try { & $Action } catch { $rejected = $true }
    if (!$rejected) { throw 'Unsafe input was accepted.' }
    $script:count++
}
$image = 'C:\Program Files\YcszFirewall\Ycsz.exe'
Assert-ProtectionServiceCommand ('"' + $image + '" --service') $image
Assert-ProtectionServiceCommand ('"' + $image.ToUpperInvariant() + '" --service') $image
$count += 2
foreach ($command in @(
    ('"' + $image + '.other.exe" --service'),
    ('"C:\other\Ycsz.exe" --service --path "' + $image + '"'),
    ($image + ' --service'),
    ('"' + $image + '" --service --extra'),
    ('"' + $image + '" --SERVICE'),
    ''
)) { Must-Reject { Assert-ProtectionServiceCommand $command $image } }
$package = [pscustomobject]@{ OriginalFileName='C:\DriverStore\YcszProtection.inf'; ProviderName='YCSZ'; ClassName='ActivityMonitor' }
Assert-ProtectionPackage 'oem12.inf' $package
$count++
foreach ($name in @('..\oem12.inf','/force','other.inf','oem12.inf.extra')) {
    Must-Reject { Assert-ProtectionPackage $name $package }
}
foreach ($field in @('OriginalFileName','ProviderName','ClassName')) {
    $bad = [pscustomobject]@{ OriginalFileName=$package.OriginalFileName; ProviderName=$package.ProviderName; ClassName=$package.ClassName }
    $bad.$field = 'OtherVendor'
    Must-Reject { Assert-ProtectionPackage 'oem12.inf' $bad }
}
Must-Reject { Assert-ProtectionPackage 'oem12.inf' $null }
Must-Reject { Assert-ProtectionPackage 'oem12.inf' @($package,$package) }
Write-Output "PASS $count pure protection install/remove input checks; no service, driver or system configuration changed."
