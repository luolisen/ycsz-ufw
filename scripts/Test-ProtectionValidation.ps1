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
$badCatalog = [pscustomobject]@{ OriginalFileName=$package.OriginalFileName; ProviderName=$package.ProviderName; ClassName=$package.ClassName; CatalogFile='Other.cat' }
Must-Reject { Assert-ProtectionPackage 'oem12.inf' $badCatalog }
Must-Reject { Assert-ProtectionPackage 'oem12.inf' $null }
Must-Reject { Assert-ProtectionPackage 'oem12.inf' @($package,$package) }
Must-Reject { Assert-ProtectionCatalogMembers (Join-Path $env:TEMP 'missing-ycsz-protection-package') }
$stopped = [pscustomobject]@{ Status='Stopped' }
Assert-ProtectionRollbackStopped $null $null
Assert-ProtectionRollbackStopped $stopped $stopped
$count += 2
foreach ($state in @('Running','StartPending','StopPending','Paused')) {
    $notStopped = [pscustomobject]@{ Status=$state }
    Must-Reject { Assert-ProtectionRollbackStopped $notStopped $stopped }
    Must-Reject { Assert-ProtectionRollbackStopped $stopped $notStopped }
}
Write-Output "PASS $count pure protection install/remove input checks; no service, driver or system configuration changed."
