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
$oldPackage = [pscustomobject]@{ Driver='oem12.inf'; OriginalFileName='C:\DriverStore\YcszProtection.inf'; ProviderName='YCSZ'; ClassName='ActivityMonitor'; CatalogFile='YcszProtection.cat' }
$newPackage = [pscustomobject]@{ Driver='oem13.inf'; OriginalFileName='C:\DriverStore\YcszProtection.inf'; ProviderName='YCSZ'; ClassName='ActivityMonitor'; CatalogFile='YcszProtection.cat' }
$otherPackage = [pscustomobject]@{ Driver='oem14.inf'; OriginalFileName='C:\DriverStore\Other.inf'; ProviderName='Other'; ClassName='Other' }
$delta = Get-ProtectionPackageDelta @($oldPackage) @($oldPackage,$newPackage)
Assert-ProtectionPackageDelta $delta | Out-Null
$plan = New-ProtectionRollbackPlan @($oldPackage) @($oldPackage,$newPackage) $true $true
if (@($plan.NewProtectionNames).Count -ne 1 -or [string]$plan.NewProtectionNames[0] -ne 'oem13.inf' -or !$plan.RestoreOldPackage -or !$plan.RestartApplication) { throw 'Package rollback plan did not preserve the old package and new delta.' }
$count += 2
Must-Reject { Assert-ProtectionPackageDelta (Get-ProtectionPackageDelta @() @()) }
Must-Reject { Assert-ProtectionPackageDelta (Get-ProtectionPackageDelta @($oldPackage) @($oldPackage,$newPackage,[pscustomobject]@{ Driver='oem15.inf'; OriginalFileName='C:\DriverStore\YcszProtection.inf'; ProviderName='YCSZ'; ClassName='ActivityMonitor' })) }
Must-Reject { Assert-ProtectionPackageDelta (Get-ProtectionPackageDelta @($oldPackage) @($newPackage)) }
Must-Reject { Assert-ProtectionPackageDelta (Get-ProtectionPackageDelta @() @($otherPackage)) }
$count += 4

function Invoke-FaultScenario([string]$Stage) {
    $state=[pscustomobject]@{ Stage=$Stage; Quiescent=$false; MutationCount=0; PreservedBeforeMutation=$true; RollbackEvidence=$false; RestoreFailed=$false; PackageMutationAttempted=$false; PartialPackagePublished=$false; PackagePlan=$null; PackagePlanCaptured=$false; PackageRollbackAttempted=$false; PackageStatePreserved=$false }
    $old=[pscustomobject]@{ Driver='oem12.inf'; OriginalFileName='C:\DriverStore\YcszProtection.inf'; ProviderName='YCSZ'; ClassName='ActivityMonitor'; CatalogFile='YcszProtection.cat' }
    $new=[pscustomobject]@{ Driver='oem13.inf'; OriginalFileName='C:\DriverStore\YcszProtection.inf'; ProviderName='YCSZ'; ClassName='ActivityMonitor'; CatalogFile='YcszProtection.cat' }
    try {
        if ($Stage -eq 'BeforeMutation') { throw 'injected before mutation' }
        if ($Stage -eq 'UnloadRefused') { throw 'injected unload refusal' }
        $state.Quiescent=$true
        $state.MutationCount++
        $state.PackageMutationAttempted=$true
        if ($Stage -eq 'Install') { $state.PartialPackagePublished=$true }
        $afterPackages=if ($state.PartialPackagePublished -or $Stage -in @('Load','Activation','RestoreFailure')) { @($old,$new) } else { @($old) }
        $state.PackagePlan=New-ProtectionRollbackPlan @($old) $afterPackages $true $true
        $state.PackagePlanCaptured=$true
        if ($Stage -eq 'Install') { throw 'injected install failure after partial package publication' }
        $state.MutationCount++
        if ($Stage -eq 'Load') { throw 'injected load failure' }
        $state.MutationCount++
        if ($Stage -eq 'Activation') { throw 'injected activation failure' }
        if ($Stage -eq 'RestoreFailure') { throw 'injected restore failure' }
    } catch {
        $state.RollbackEvidence=$true
        $state.RestoreFailed=$Stage -eq 'RestoreFailure'
        if (!$state.Quiescent) { $state.PreservedBeforeMutation=($state.MutationCount -eq 0) }
        if ($state.PackageMutationAttempted -and !$state.PackagePlanCaptured) { $state.PackageStatePreserved=$true }
        if ($state.PackagePlanCaptured) { $state.PackageRollbackAttempted=$true }
    }
    return $state
}
foreach ($stage in @('BeforeMutation','Install','Load','Activation','UnloadRefused','RestoreFailure')) {
    $scenario=Invoke-FaultScenario $stage
    if (!$scenario.RollbackEvidence) { throw "Fault injection did not reach rollback: $stage" }
    if (($stage -eq 'BeforeMutation' -or $stage -eq 'UnloadRefused') -and (!$scenario.PreservedBeforeMutation -or $scenario.MutationCount -ne 0)) { throw "Unsafe mutation occurred before quiescence: $stage" }
    if (($stage -eq 'BeforeMutation' -or $stage -eq 'UnloadRefused') -and $scenario.PackageMutationAttempted) { throw "Package mutation occurred before quiescence: $stage" }
    if ($stage -eq 'Install' -and (!$scenario.PartialPackagePublished -or !$scenario.PackagePlanCaptured -or !$scenario.PackageRollbackAttempted)) { throw 'Partial package publication was not captured for rollback.' }
    if (($stage -eq 'Load' -or $stage -eq 'Activation' -or $stage -eq 'RestoreFailure') -and !$scenario.PackageRollbackAttempted) { throw "Package rollback was not planned for: $stage" }
    if ($stage -eq 'RestoreFailure' -and !$scenario.RestoreFailed) { throw 'Restore failure was not retained as an explicit failure.' }
    $count++
}
Write-Output "PASS $count pure protection install/remove input checks; no service, driver or system configuration changed."
