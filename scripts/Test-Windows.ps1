param([ValidateSet('Static','Installed')][string]$Mode='Static',[string]$InstallDir="$env:ProgramFiles\YcszFirewall")
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$results = New-Object 'System.Collections.Generic.List[object]'
function Check([string]$name,[scriptblock]$body) {
    try { & $body; $results.Add([pscustomobject]@{ Test=$name; Result='PASS'; Detail='' }) }
    catch { $results.Add([pscustomobject]@{ Test=$name; Result='FAIL'; Detail=[string]$_ }) }
}
if ($Mode -eq 'Static') {
    foreach ($script in @(Get-ChildItem -LiteralPath $PSScriptRoot -Filter '*.ps1')) {
        Check "Parse $($script.Name)" {
            $tokens=$null; $errors=$null
            [System.Management.Automation.Language.Parser]::ParseFile($script.FullName,[ref]$tokens,[ref]$errors) | Out-Null
            if ($errors.Count) { throw ($errors | Out-String) }
        }
    }
    Check 'Tray lifecycle source gates' {
        $program=Get-Content (Join-Path $repo 'src\Ycsz.App\Program.cs') -Raw
        if ($program -notmatch 'process\.SessionId==0') { throw 'close-ui does not exclude session 0' }
        if ($program -notmatch '必须先确认防护服务已停止') { throw 'close-ui service-stop gate missing' }
        if ($program -notmatch 'new WindowsInteractiveSessionSource') { throw 'service tray supervisor missing' }
    }
    Check 'Update replacement gate' {
        $update=Get-Content (Join-Path $repo 'scripts\Update-Installed.ps1') -Raw
        if ($update -notmatch 'Stop-InstalledServiceAndCloseUi') { throw 'update does not stop service and close UI' }
        if ($update -notmatch "failureflag.*YcszFirewall") { throw 'update does not preserve SCM failure flag' }
    }
    Check 'PowerShell scripts parse' {
        $parseErrors = @()
        foreach ($script in Get-ChildItem (Join-Path $repo 'scripts') -Filter '*.ps1') {
            $tokens = $null; $errors = $null
            [System.Management.Automation.Language.Parser]::ParseFile($script.FullName,[ref]$tokens,[ref]$errors) | Out-Null
            if ($errors.Count) { $parseErrors += "$($script.Name): $($errors | Out-String)" }
        }
        if ($parseErrors.Count) { throw ($parseErrors -join "`n") }
    }
    Check 'Self protection driver source gates' {
        $driver=Join-Path $repo 'drivers\YcszProtection'
        foreach ($name in @('ycsz_protection.c','ycsz_minifilter.c','ycsz_protection.h','ycsz_protection_protocol.h','YcszProtection.vcxproj','YcszProtection.inf')) {
            if (!(Test-Path (Join-Path $driver $name))) { throw "Missing driver source: $name" }
        }
        if (!(Test-Path (Join-Path $repo 'scripts\Test-ProtectionDriver.ps1'))) { throw 'Dynamic driver validation tool missing' }
        $source=(Get-Content (Join-Path $driver 'ycsz_protection.c') -Raw) + (Get-Content (Join-Path $driver 'ycsz_minifilter.c') -Raw)
        foreach ($needle in @('OB_OPERATION_HANDLE_CREATE','OB_OPERATION_HANDLE_DUPLICATE','PROCESS_TERMINATE','IRP_MJ_WRITE','FileDispositionInformation','FileRenameInformation','IOCTL_YCP_REGISTER_TRAY','YcpIsTrustedWriter','FSCTL_SET_REPARSE_POINT','ProtectedDataRoot','TrustedDataRoot','FLT_STREAM_CONTEXT','FltGetStreamContext','FltSetStreamContext','FltQueryInformationFile','FileInternalInformation','YcpPostOperationFile')) {
            if ($source -notmatch [regex]::Escape($needle)) { throw "Driver source gate missing: $needle" }
        }
        if ($source -match 'Ioctl.*PID|arbitrary.*PID') { throw 'Driver source appears to expose an arbitrary PID control path' }
        $inf=Get-Content (Join-Path $driver 'YcszProtection.inf') -Raw
        if ($inf -notmatch 'ClassGuid=\{b86dff51-a31e-4bac-b3cf-e8cfe75c9fc2\}') { throw 'ActivityMonitor ClassGuid mismatch' }
        if ($source -notmatch 'OpenFileObjects == 0' -or $source -notmatch 'FsContext = &g_YcpState') { throw 'Control file references do not gate optional unload' }
        if ($source -match 'DriverUnload\s*=') { throw 'Unload must be managed by Filter Manager' }
        $protocol=Get-Content (Join-Path $driver 'ycsz_protection_protocol.h') -Raw
        if ($protocol -notmatch 'YCP_PROTOCOL_VERSION\s+2u' -or $protocol -notmatch 'YCP_MAX_LEASE_SECONDS\s+900') { throw 'Protection protocol v2 or maintenance lease bound missing' }
        if ($protocol -notmatch 'IOCTL_YCP_PREPARE_UNLOAD') { throw 'Authenticated unload protocol missing' }
        $installer=Get-Content (Join-Path $repo 'installer\Ycsz.nsi') -Raw
        if ($installer -match 'YcszProtection') { throw 'Unverified driver must not be in the default installer' }
    }
    Check 'Self protection user-mode gates' {
        $program=Get-Content (Join-Path $repo 'src\Ycsz.App\Program.cs') -Raw
        $transport=Get-Content (Join-Path $repo 'src\Ycsz.Core\SelfProtectionDeviceTransport.cs') -Raw
        $driver=Get-Content (Join-Path $repo 'drivers\YcszProtection\ycsz_protection.c') -Raw
        if ($program -notmatch 'new WindowsSelfProtectionTransport\(Store\.Root\)') { throw 'Service does not bind the fixed ProgramData root to the device transport' }
        if ($program -notmatch 'self-protection-enter' -or $program -notmatch 'self-protection-exit') { throw 'Authenticated maintenance IPC operations missing' }
        if ($program -notmatch 'self-protection-prepare-unload' -or $program -notmatch 'PrepareUnload') { throw 'Authenticated unload preparation path missing' }
        $preflight=Get-Content (Join-Path $repo 'src\Ycsz.Core\SelfProtectionFilePreflight.cs') -Raw
        if ($transport -notmatch 'QueryDosDevice' -or $transport -notmatch 'StateDataRoot' -or $transport -notmatch 'RegisterTray' -or $driver -notmatch 'SeLocateProcessImageName' -or $preflight -notmatch 'GetFileInformationByHandle') { throw 'Fixed image identity, dual-root, file identity or tray contract missing' }
        if ($program -notmatch 'SelfProtectionFilePreflight' -or $preflight -notmatch 'MappingWritebackConditionMet') { throw 'Activation preflight or mapped-write condition missing' }
        if ($program -notmatch '--protection-status' -or $program -notmatch 'RegisterTray') { throw 'Actual activation or tray registration path missing' }
        if ($transport -match 'ServiceStop') { throw 'Transport must not report unimplemented kernel ServiceStop capability' }
        if ($program -notmatch 'CanStop=!protectedService' -or $program -notmatch 'self-protection-stop' -or $program -match 'SetServiceStatus') { throw 'Fixed SCM controls/authenticated internal stop contract missing' }
    }
    Check 'Protection install and removal gates' {
        $install=Get-Content (Join-Path $repo 'scripts\Install-Protection.ps1') -Raw
        $validation=Get-Content (Join-Path $repo 'scripts\Protection-Validation.ps1') -Raw
        $remove=Get-Content (Join-Path $repo 'scripts\Remove-Protection.ps1') -Raw
        foreach ($needle in @('TrustedImagePath','TrustedDataRoot','sidtype','QueryDosDevice','Get-AuthenticodeSignature','Assert-ProtectionCatalogMembers','Protection-Validation.ps1','--protection-status','pnputil','oldDataRoot','Get-ProtectionPackageSnapshot','New-ProtectionRollbackPlan','oldPackageInf','packagePlan')) {
            if ($install -notmatch [regex]::Escape($needle)) { throw "Protection installer gate missing: $needle" }
        }
        if ($install -match 'Published Name') { throw 'Protection installer must not parse localized pnputil Published Name output' }
        foreach ($needle in @('Resolve-ProtectionSignTool','signtool.exe','verify /kp /c','LASTEXITCODE')) {
            if ($validation -notmatch [regex]::Escape($needle)) { throw "Protection validation gate missing: $needle" }
        }
        foreach ($needle in @('PREPARE_UNLOAD','fltmc.exe','unload YcszProtection','No service was deleted')) {
            if ($remove -notmatch [regex]::Escape($needle)) { throw "Protection remover gate missing: $needle" }
        }
        $props=Get-Content (Join-Path $repo 'Directory.Build.props') -Raw
        $packages=Get-Content (Join-Path $repo 'packages.config') -Raw
        if ($props -notmatch '10\.0\.28000\.2526' -or $packages -notmatch 'Microsoft\.Windows\.WDK\.x64') { throw 'Pinned WDK NuGet inputs missing' }
        $workflow=Get-Content (Join-Path $repo '.github\workflows\windows-build.yml') -Raw
        if ($workflow -notmatch 'windows-2025-vs2026' -or $workflow -notmatch 'InfVerif' -or $workflow -notmatch 'Test-ProtectionDriver') { throw 'Windows driver CI gates missing' }
    }
} else {
    # Read-only installed checks. Never alter network, proxy, service or WFP state.
    Check 'Service running' { if ((Get-Service YcszFirewall).Status -ne 'Running') { throw 'Service not running' } }
    Check 'Service identity and path' { $s=Get-CimInstance Win32_Service -Filter "Name='YcszFirewall'"; if ($s.StartName -ne 'LocalSystem' -or $s.PathName -notlike "*$InstallDir*") { throw ($s | Out-String) } }
    Check 'Uninstall entry visible' { $r=Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\YcszFirewall; if (!$r.DisplayName -or $r.SystemComponent -eq 1) { throw 'Missing or hidden entry' } }
    Check 'Protected directory ACL' { $acl=Get-Acl "$env:ProgramData\YcszFirewall"; if (!$acl.AreAccessRulesProtected) { throw 'ACL inherits parent permissions' }; foreach ($r in $acl.Access) { $sid=$r.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value; if ($sid -notin @('S-1-5-18','S-1-5-32-544')) { throw "Unexpected ACL principal $sid" } } }
    Check 'Configuration uses protected binary' { $b=[IO.File]::ReadAllBytes("$env:ProgramData\YcszFirewall\settings.bin"); if ($b.Length -lt 32 -or $b[0] -eq 123) { throw 'Configuration missing or appears plaintext' } }
    Check 'Executable PE signature' { $b=[IO.File]::ReadAllBytes("$InstallDir\Ycsz.exe"); if ($b[0] -ne 77 -or $b[1] -ne 90) { throw 'Not a PE image' } }
    Check 'SCM failure recovery configured' { $r=Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\YcszFirewall; if (!$r.FailureActions) { throw 'Missing failure actions' } }
    Check 'Protection activation when installed' {
        $driver=Get-Service YcszProtection -ErrorAction SilentlyContinue
        if ($driver) {
            if ($driver.Status -ne 'Running') { throw 'YcszProtection is registered but not Running' }
            $probe=Start-Process (Join-Path $InstallDir 'Ycsz.exe') -ArgumentList @('--protection-status') -Wait -PassThru -WindowStyle Hidden
            if ($probe.ExitCode -ne 0) { throw 'YcszProtection is Running but v2 activation was not confirmed' }
        }
    }
}
$results | Format-Table -AutoSize
$results | Where-Object Result -eq 'FAIL' | ForEach-Object {
    Write-Output "FAIL DETAIL: $($_.Test)"
    Write-Output $_.Detail
}
if (@($results | Where-Object Result -eq 'FAIL').Count) { exit 1 }
Write-Output 'Read-only checks complete. Network enforcement, GUI, TLS and rollback still require the manual VM test matrix.'
