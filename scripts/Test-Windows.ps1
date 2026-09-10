param([ValidateSet('Static','Installed')][string]$Mode='Static',[string]$InstallDir="$env:ProgramFiles\YcszFirewall")
$ErrorActionPreference = 'Stop'
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
} else {
    # Read-only installed checks. Never alter network, proxy, service or WFP state.
    Check 'Service running' { if ((Get-Service YcszFirewall).Status -ne 'Running') { throw 'Service not running' } }
    Check 'Service identity and path' { $s=Get-CimInstance Win32_Service -Filter "Name='YcszFirewall'"; if ($s.StartName -ne 'LocalSystem' -or $s.PathName -notlike "*$InstallDir*") { throw ($s | Out-String) } }
    Check 'Uninstall entry visible' { $r=Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\YcszFirewall; if (!$r.DisplayName -or $r.SystemComponent -eq 1) { throw 'Missing or hidden entry' } }
    Check 'Protected directory ACL' { $acl=Get-Acl "$env:ProgramData\YcszFirewall"; if (!$acl.AreAccessRulesProtected) { throw 'ACL inherits parent permissions' }; foreach ($r in $acl.Access) { $sid=$r.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value; if ($sid -notin @('S-1-5-18','S-1-5-32-544')) { throw "Unexpected ACL principal $sid" } } }
    Check 'Configuration uses protected binary' { $b=[IO.File]::ReadAllBytes("$env:ProgramData\YcszFirewall\settings.bin"); if ($b.Length -lt 32 -or $b[0] -eq 123) { throw 'Configuration missing or appears plaintext' } }
    Check 'Executable PE signature' { $b=[IO.File]::ReadAllBytes("$InstallDir\Ycsz.exe"); if ($b[0] -ne 77 -or $b[1] -ne 90) { throw 'Not a PE image' } }
    Check 'SCM failure recovery configured' { $r=Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\YcszFirewall; if (!$r.FailureActions) { throw 'Missing failure actions' } }
}
$results | Format-Table -AutoSize
if (@($results | Where-Object Result -eq 'FAIL').Count) { exit 1 }
Write-Output 'Read-only checks complete. Network enforcement, GUI, TLS and rollback still require the manual VM test matrix.'
