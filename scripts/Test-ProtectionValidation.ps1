$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Protection-Validation.ps1')
$count = 0
function Must-Reject([scriptblock]$Action) {
    $rejected = $false
    try { & $Action } catch { $rejected = $true }
    if (!$rejected) { throw 'Unsafe input was accepted.' }
    $script:count++
}
Assert-ProtectionFixtureChild 'C:\fixture[1]' 'c:\fixture[1]\app\Ycsz.exe'
Assert-ProtectionFixtureChild 'C:\fixture\' 'C:\fixture\app'
$count += 2
Must-Reject { Assert-ProtectionFixtureChild 'C:\fixture[1]' 'C:\fixture1\app' }
Must-Reject { Assert-ProtectionFixtureChild 'C:\fixture' 'C:\fixture-other\app' }
Must-Reject { Assert-ProtectionFixtureChild 'C:\fixture' 'C:\fixture' }
Must-Reject { Assert-ProtectionFixtureChild 'C:\fixture' 'C:\fixture\..\outside' }
Must-Reject { Assert-ProtectionFixtureChild 'C:\fixture' 'D:\fixture\app' }
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

function Invoke-ActivationBarrierCheck {
    $state=[pscustomobject]@{ Phase='Idle'; Owner=0; Deadline=0; Marked=0; Failures=0 }
    $state.Phase='Initializing'; $state.Owner=10; $state.Deadline=120
    if ($state.Phase -ne 'Initializing') { throw 'Begin published Active before scan.' }
    $product='\Device\Volume\Ycsz'
    if (!('\Device\Volume\Ycsz\data'.StartsWith($product)) -or ('\Device\Volume\other'.StartsWith($product))) { throw 'Initialization namespace guard boundary is wrong.' }
    $state.Marked=1; $state.Failures=1
    if ($state.Failures -ne 0 -or $state.Marked -lt 1) { $commitAllowed=$false } else { $commitAllowed=$true }
    if ($commitAllowed -or $state.Phase -eq 'Active') { throw 'Scan failure still allowed Active.' }
    $state.Phase='Idle'; $state.Owner=0; $state.Marked=0; $state.Failures=0
    $state.Phase='Initializing'; $state.Owner=10; $state.Marked=1
    if ($state.Failures -ne 0 -or $state.Marked -lt 1) { throw 'Complete scan was not commit-ready.' }
    $state.Phase='Active'
    if ($state.Phase -ne 'Active') { throw 'Complete scan did not commit Active.' }
    if ($state.Phase -eq 'Active' -and $state.Owner -ne 10) { throw 'Stable Active owner was changed.' }
    return $true
}
Invoke-ActivationBarrierCheck | Out-Null
$count++

$accessDenied = Resolve-ProtectionDynamicNativeFailure 5 'file-write' 'file-write' $true
if ($accessDenied.Status -ne 'PASS') { throw 'ERROR_ACCESS_DENIED was not accepted only for the matched protected write stage.' }
$missing = Resolve-ProtectionDynamicNativeFailure 2 'file-write' 'file-write' $true
if ($missing.Status -eq 'PASS') { throw 'Missing-file evidence was incorrectly accepted as protection.' }
$sharing = Resolve-ProtectionDynamicNativeFailure 32 'hardlink-create' 'hardlink-create' $true
if ($sharing.Status -eq 'PASS') { throw 'Sharing-conflict evidence was incorrectly accepted as protection.' }
$unsupported = Resolve-ProtectionDynamicNativeFailure 50 'mapping-create' 'mapping-create' $true
if ($unsupported.Status -ne 'BLOCKED') { throw 'Unsupported mapping was not classified as BLOCKED.' }
$invalidParameter = Resolve-ProtectionDynamicNativeFailure 87 'mapping-view' 'mapping-view' $true
if ($invalidParameter.Status -ne 'ERROR') { throw 'Invalid mapping parameters were not classified as ERROR.' }
$unknown = Resolve-ProtectionDynamicNativeFailure 1234 'file-write' 'file-write' $true
if ($unknown.Status -ne 'ERROR') { throw 'Unknown native errors were not classified as ERROR.' }
$wrongStage = Resolve-ProtectionDynamicNativeFailure 5 'file-write' 'file-open' $true
if ($wrongStage.Status -ne 'ERROR') { throw 'An access denial from the wrong stage was incorrectly accepted.' }
$noControl = Resolve-ProtectionDynamicNativeFailure 5 'file-write' 'file-write' $false
if ($noControl.Status -ne 'ERROR') { throw 'An access denial without a successful control precondition was incorrectly accepted.' }
$win32Exception = New-Object System.ComponentModel.Win32Exception(5)
if ((Get-ProtectionNativeErrorCode $win32Exception) -ne 5) { throw 'Win32 exception error-code extraction failed.' }
$accessException = New-Object System.UnauthorizedAccessException 'fixture access denied'
if ((Get-ProtectionNativeErrorCode $accessException) -ne 5) { throw 'Signed HRESULT access-denied extraction failed.' }
$missingException = New-Object System.IO.FileNotFoundException 'fixture missing'
if ((Get-ProtectionNativeErrorCode $missingException) -ne 2) { throw 'Signed HRESULT file-not-found extraction failed.' }
$wrappedException = New-Object System.Exception 'wrapper',$accessException
if ((Get-ProtectionNativeErrorCode $wrappedException) -ne 5) { throw 'Inner signed HRESULT extraction failed.' }
$unloadPass = Test-ProtectionExpectedUnloadRejection 1 'Error: ERROR_FLT_DO_NOT_DETACH (0x801F0010)' $true
if ($unloadPass.Status -ne 'PASS') { throw 'Expected filter unload refusal was not classified as PASS.' }
$unloadUnknown = Test-ProtectionExpectedUnloadRejection 1 'Error: invalid parameter' $true
if ($unloadUnknown.Status -eq 'PASS') { throw 'Unknown fltmc failure was incorrectly classified as PASS.' }
$unloadSuccess = Test-ProtectionExpectedUnloadRejection 0 '' $true
if ($unloadSuccess.Status -ne 'FAIL') { throw 'Successful fltmc unload was not classified as FAIL.' }
$cleanup = Resolve-ProtectionCleanupFailure 'C:\fixture\evidence.bin' 'simulated cleanup failure'
if ($cleanup.Status -ne 'ERROR' -or $cleanup.Detail -notmatch 'evidence\.bin' -or $cleanup.Detail -notmatch 'retained') { throw 'Cleanup failure did not retain the evidence path.' }
$count += 13

$manifestFixture = 'C:\fixture-guid'
$manifestProtected = Join-Path $manifestFixture 'app'
$manifestData = Join-Path $manifestFixture 'data'
$manifestImage = Join-Path $manifestProtected 'Ycsz.exe'
$manifestSample = Join-Path $manifestProtected 'sample.bin'
$manifestSampleEntry = [pscustomobject]@{ Path=$manifestSample; Length=4; VolumeSerial=10; FileIndex=20; NumberOfLinks=1 }
$manifest = [pscustomobject]@{
    FixtureId=([guid]::NewGuid()).ToString(); FixtureRoot=$manifestFixture; ProtectedRoot=$manifestProtected
    ProtectedDataRoot=$manifestData; ServiceImagePath=$manifestImage; ServiceName='YcszFirewall'
    ProtectedFiles=@($manifestSampleEntry)
}
Assert-ProtectionFixtureManifest $manifest $manifestFixture $manifestProtected $manifestData $manifestImage | Out-Null
$count++
foreach ($field in @('FixtureRoot','ProtectedRoot','ProtectedDataRoot','ServiceImagePath')) {
    $badManifest = $manifest | Select-Object *
    $badManifest.$field = 'C:\not-the-requested-path'
    Must-Reject { Assert-ProtectionFixtureManifest $badManifest $manifestFixture $manifestProtected $manifestData $manifestImage }
}

$dynamic = Get-Content (Join-Path $PSScriptRoot 'Test-ProtectionDriver.ps1') -Raw
$shared = Get-Content (Join-Path $PSScriptRoot 'Protection-Validation.ps1') -Raw
foreach ($needle in @(
    'Resolve-ProtectionDynamicException',
    'Test-ProtectionExpectedUnloadRejection',
    'pre-active existing handle',
    'pre-active writable mapping',
    'ordinary writable mapping',
    'Add-DynamicCleanupError',
    'FixtureManifestPath',
    'New-ProtectionFixtureScope',
    'Get-ProtectionFixtureHandleEntity',
    'New-ProtectionFixtureHardLink',
    'New-DynamicJunctionOwned',
    'Invoke-DynamicOwnedCleanup',
    'Win32_Service',
    'TrustedImagePath',
    'TrustedDataRoot'
)) {
    if ($dynamic -notmatch [regex]::Escape($needle)) { throw "Dynamic evidence regression guard missing: $needle" }
}
foreach ($needle in @(
    'GetFileInformationByHandle',
    '0x02000000 -bor 0x00200000',
    'CreateHardLink',
    'CreateNew',
    'Remove-ProtectionFixtureOwnedPath'
)) {
    if ($shared -notmatch [regex]::Escape($needle)) { throw "Fixture boundary helper guard missing: $needle" }
}
if ($dynamic -match 'MapViewOfFile\([^\r\n]*0x0002\s*-bor\s*0x0020') { throw 'Writable mapping still requests execute access.' }
if ($dynamic -match 'catch\s*\{\s*Add-Result[^\r\n]*\x27PASS\x27') { throw 'Dynamic exception catch still unconditionally records PASS.' }
if ($dynamic -match 'WriteAllText') { throw 'Dynamic fixture controls still overwrite files with WriteAllText.' }
if ($dynamic -match 'Remove-Item[^\r\n]*-Recurse') { throw 'Dynamic cleanup still recursively deletes an unknown path.' }
$count += 2
Write-Output "PASS $count pure protection install/remove and dynamic evidence classification checks; no service, driver or system configuration changed."
