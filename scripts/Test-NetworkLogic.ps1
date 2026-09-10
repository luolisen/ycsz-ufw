# Synthetic cmdlet harness: runs the production Capture/Apply functions with fake
# adapters and a temporary hosts file. Never imports or invokes Windows networking.
$ErrorActionPreference='Stop'
$tokens=$null; $parseErrors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'System.ps1'),[ref]$tokens,[ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors | Out-String) }
foreach ($name in @('Capture-Network','Apply-Network')) {
    $definition=$ast.Find({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name},$false)
    if (!$definition) { throw "Missing function $name" }
    . ([scriptblock]::Create($definition.Extent.Text))
}
$script:mutations=New-Object 'System.Collections.Generic.List[string]'
$script:current=$null
function Get-NetAdapter { param([switch]$IncludeHidden) foreach($a in $script:current.Adapters) { [pscustomobject]@{ InterfaceGuid=[guid]$a.Id; Name=$a.Name; InterfaceDescription='fixture'; ifIndex=$a.Index; AdminStatus=$(if($a.Enabled){'Up'}else{'Down'}) } } }
function Get-NetIPInterface { param($InterfaceIndex,$AddressFamily) $a=$script:current.Adapters | Where-Object Index -eq $InterfaceIndex | Select-Object -First 1; if($a) { [pscustomobject]@{ Dhcp=$(if($AddressFamily -eq 'IPv6'){if($a.DhcpV6){'Enabled'}else{'Disabled'}}else{if($a.Dhcp){'Enabled'}else{'Disabled'}}); RouterDiscovery=$(if($a.RouterDiscovery){'Enabled'}else{'Disabled'}) } } }
function Get-ItemProperty { param($LiteralPath) $a=$script:current.Adapters | Where-Object {$LiteralPath -like "*$($_.Id)*"} | Select-Object -First 1; $dns=@(); if($a) { if($LiteralPath -like '*Tcpip6*'){if(!$a.DnsV6Automatic){$dns=@($a.DnsV6)}}else{if(!$a.DnsAutomatic){$dns=@($a.Dns)}} }; [pscustomobject]@{NameServer=($dns -join ',')} }
function Get-NetIPAddress { param($InterfaceIndex) @() }
function Get-NetRoute { param($InterfaceIndex) @() }
function Get-NetAdapterBinding { param($Name,[switch]$IncludeHidden,[switch]$AllBindings) [pscustomobject]@{ComponentID='ms_tcpip';Enabled=$true} }
function Get-DnsClientServerAddress { param($InterfaceIndex,$AddressFamily) [pscustomobject]@{Index=$InterfaceIndex;Family=$AddressFamily} }
function Set-NetIPInterface { param($InterfaceIndex,$AddressFamily,$Dhcp,$RouterDiscovery) $script:mutations.Add("IP:$InterfaceIndex/$AddressFamily/$Dhcp") }
function Set-DnsClientServerAddress { param([Parameter(ValueFromPipeline=$true)]$InputObject,[switch]$ResetServerAddresses,$ServerAddresses) process {$script:mutations.Add("DNS:$($InputObject.Index)/$($InputObject.Family)")} }
function Disable-NetAdapter { param([Parameter(ValueFromPipeline=$true)]$InputObject,[switch]$Confirm) process {$script:mutations.Add("DISABLE:$($InputObject.ifIndex)")} }
function Enable-NetAdapter { param([Parameter(ValueFromPipeline=$true)]$InputObject,[switch]$Confirm) process {$script:mutations.Add("ENABLE:$($InputObject.ifIndex)")} }
function Clear-DnsClientCache { $script:mutations.Add('CACHE') }
# Unexpected paths fail closed; these mocks must never fall through to system cmdlets.
foreach($cmd in @('New-NetIPAddress','Remove-NetIPAddress','New-NetRoute','Remove-NetRoute','Rename-NetAdapter','Enable-NetAdapterBinding','Disable-NetAdapterBinding')) {
    Set-Item -LiteralPath "Function:$cmd" -Value { throw 'Unexpected network mutation in fixture' }
}
function Snapshot {
    [pscustomobject]@{ HostsExists=$true; HostsBase64=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('baseline')); Adapters=@([pscustomobject]@{Id='7a04db5c-f8d7-45c7-a5d5-f258917218ed';Index=1;Name='fixture1';Enabled=$true;Dhcp=$true;DhcpV6=$true;RouterDiscovery=$true;DnsAutomatic=$true;Dns=@();DnsV6Automatic=$true;DnsV6=@();Addresses=@();Routes=@();Bindings=@('ms_tcpip')}) }
}
function Assert($condition,$message) { if(!$condition){throw $message} }
$fixture=Join-Path ([IO.Path]::GetTempPath()) ('ycsz-network-'+[guid]::NewGuid().ToString('N'))
$hostsPath=Join-Path $fixture 'hosts'
function Get-HostsPath { $script:hostsPath }
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($hostsPath)) | Out-Null
$script:passed=0
function Test($name,[scriptblock]$body) {
    $script:current=Snapshot
    $script:mutations.Clear()
    [IO.File]::WriteAllText($hostsPath,'baseline')
    & $body
    $script:passed++
    Write-Output "PASS $name"
}
try {
    Test 'capture detects deleted hosts' {
        [IO.File]::Delete($hostsPath)
        $observed=Capture-Network | ConvertFrom-Json
        Assert (!$observed.HostsExists -and $observed.HostsBase64 -eq '') 'Missing hosts was not represented'
    }
    Test 'deleted hosts recreated without adapter writes' {
        $desired=Snapshot
        [IO.File]::Delete($hostsPath)
        Apply-Network $desired
        Assert ([IO.File]::ReadAllText($hostsPath) -eq 'baseline') 'Hosts not recreated'
        Assert (($script:mutations -join ',') -eq 'CACHE') 'Unexpected network mutation'
    }
    Test 'hosts-only drift does not rewrite DHCP or DNS' {
        [IO.File]::WriteAllText($hostsPath,'changed')
        Apply-Network (Snapshot)
        Assert ([IO.File]::ReadAllText($hostsPath) -eq 'baseline') 'Hosts not restored'
        Assert (($script:mutations -join ',') -eq 'CACHE') 'Unchanged adapter was modified'
    }
    Test 'unchanged baseline makes no writes' { Apply-Network (Snapshot); Assert ($script:mutations.Count -eq 0) 'No-op performed writes' }
    Test 'absent initial hosts restored as absence' {
        $desired=Snapshot; $desired.HostsExists=$false; $desired.HostsBase64=''
        Apply-Network $desired
        Assert (![IO.File]::Exists($hostsPath)) 'Unwanted hosts still exists'
    }
    Test 'DHCP drift changes only IPv4 mode' {
        $desired=Snapshot; $desired.Adapters[0].Dhcp=$false
        Apply-Network $desired
        Assert (($script:mutations -join ',') -eq 'IP:1/IPv4/Disabled') 'Wrong mutation scope'
    }
    Test 'DNS drift changes only IPv4 DNS' {
        $desired=Snapshot; $desired.Adapters[0].DnsAutomatic=$false; $desired.Adapters[0].Dns=@('192.0.2.53')
        Apply-Network $desired
        Assert (($script:mutations -join ',') -eq 'DNS:1/IPv4') 'Wrong DNS mutation scope'
    }
    Test 'missing adapter still permits hosts recovery and reports error' {
        $desired=Snapshot; $script:current.Adapters=@(); [IO.File]::WriteAllText($hostsPath,'changed')
        $caught=$false
        try { Apply-Network $desired } catch { $caught=$_.ToString().Contains('Adapter missing') }
        Assert $caught 'Missing adapter not reported'
        Assert ([IO.File]::ReadAllText($hostsPath) -eq 'baseline') 'Hosts recovery skipped'
    }
    Test 'new adapter alone is disabled' {
        $desired=Snapshot; $extra=(Snapshot).Adapters[0]; $extra.Id=[guid]::NewGuid().ToString(); $extra.Index=2; $extra.Name='fixture2'; $script:current.Adapters+=@($extra)
        Apply-Network $desired
        Assert (($script:mutations -join ',') -eq 'DISABLE:2') 'Wrong adapter disabled'
    }
    Write-Output "RESULT $script:passed/9 synthetic network tests passed; no Windows cmdlets executed"
} finally {
    if([IO.File]::Exists($hostsPath)){[IO.File]::Delete($hostsPath)}
    if([IO.Directory]::Exists($fixture)){[IO.Directory]::Delete($fixture,$true)}
}
