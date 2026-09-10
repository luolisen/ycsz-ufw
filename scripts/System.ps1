param([Parameter(Mandatory=$true)][ValidateSet('capture','apply','proxy','certificate')][string]$Mode,[string]$InputFile)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
function Read-Input { Get-Content -LiteralPath $InputFile -Raw -Encoding UTF8 | ConvertFrom-Json }
function Get-HostsPath { Join-Path $env:SystemRoot 'System32\drivers\etc\hosts' }
function Capture-Network {
    $items = @()
    foreach ($adapter in @(Get-NetAdapter -IncludeHidden | Sort-Object InterfaceGuid)) {
        # Ignore OS-owned tunnel miniports without configurable IP interfaces.
        $ip = @(Get-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue) | Select-Object -First 1
        if ($null -eq $ip) { continue }
        $ip6 = Get-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily IPv6 -ErrorAction SilentlyContinue | Select-Object -First 1
        $guid = $adapter.InterfaceGuid.ToString().Trim('{}').ToLowerInvariant()
        $key = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{$guid}"
        $reg = Get-ItemProperty -LiteralPath $key -ErrorAction SilentlyContinue
        $reg6 = Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\{$guid}" -ErrorAction SilentlyContinue
        $addresses = @(Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -ErrorAction SilentlyContinue | Where-Object { $_.PrefixOrigin -eq 'Manual' -and $_.IPAddress -ne '::1' -and $_.IPAddress -notlike 'fe80:*' } | Sort-Object IPAddress | ForEach-Object { @{ Address = $_.IPAddress; Prefix = [int]$_.PrefixLength } })
        $routes = @(Get-NetRoute -InterfaceIndex $adapter.ifIndex -ErrorAction SilentlyContinue | Where-Object { $_.Protocol -eq 'NetMgmt' -and $_.NextHop -ne '0.0.0.0' -and $_.NextHop -ne '::' } | Sort-Object DestinationPrefix,NextHop | ForEach-Object { @{ Prefix = $_.DestinationPrefix; NextHop = $_.NextHop; Metric = [int]$_.RouteMetric } })
        $automatic = [string]::IsNullOrWhiteSpace([string]$reg.NameServer)
        $automatic6 = [string]::IsNullOrWhiteSpace([string]$reg6.NameServer)
        $dns6 = @(); if (!$automatic6) { $dns6 = @(([string]$reg6.NameServer -split '[,; ]+') | Where-Object { $_ }) }
        $dns = @(); if (!$automatic) { $dns = @(([string]$reg.NameServer -split '[,; ]+') | Where-Object { $_ }) }
        $bindings = @(Get-NetAdapterBinding -Name ([WildcardPattern]::Escape($adapter.Name)) -IncludeHidden -AllBindings -ErrorAction SilentlyContinue | Where-Object Enabled | Select-Object -ExpandProperty ComponentID | Sort-Object)
        $items += @{ Id = $guid; Name = $adapter.Name; Description = $adapter.InterfaceDescription; Enabled = ($adapter.AdminStatus -eq 'Up'); Dhcp = ($ip.Dhcp -eq 'Enabled'); DnsAutomatic = $automatic; Dns = $dns; DhcpV6 = ($null -eq $ip6 -or $ip6.Dhcp -eq 'Enabled'); RouterDiscovery = ($null -eq $ip6 -or $ip6.RouterDiscovery -eq 'Enabled'); DnsV6Automatic = $automatic6; DnsV6 = $dns6; Addresses = $addresses; Routes = $routes; Bindings = $bindings }
    }
    $hosts = Get-HostsPath
    $exists = [IO.File]::Exists($hosts)
    $content = ''; if ($exists) { $content = [Convert]::ToBase64String([IO.File]::ReadAllBytes($hosts)) }
    @{ Adapters = $items; HostsExists = $exists; HostsBase64 = $content } | ConvertTo-Json -Depth 12 -Compress
}
function Apply-Network($baseline) {
    $errors = New-Object 'System.Collections.Generic.List[string]'
    $observed = Capture-Network | ConvertFrom-Json
    $all = @(Get-NetAdapter -IncludeHidden)
    # Only disable newly added IP-capable adapters. Never remove hardware or drivers.
    $known = @($baseline.Adapters | ForEach-Object { $_.Id.ToLowerInvariant() })
    foreach ($adapter in $all) {
        $guid = $adapter.InterfaceGuid.ToString().Trim('{}').ToLowerInvariant()
        if ($known -notcontains $guid -and $adapter.AdminStatus -eq 'Up' -and @(Get-NetIPInterface -InterfaceIndex $adapter.ifIndex -ErrorAction SilentlyContinue).Count -gt 0) {
            try { $adapter | Disable-NetAdapter -Confirm:$false } catch { $errors.Add("Cannot disable new adapter ${guid}: $_") }
        }
    }
    foreach ($expected in @($baseline.Adapters)) {
        try {
            $a = $all | Where-Object { $_.InterfaceGuid.ToString().Trim('{}') -eq $expected.Id } | Select-Object -First 1
            if (!$a) { throw "Adapter missing; driver/hardware restoration required: $($expected.Id)" }
            if ($a.Name -ne $expected.Name) { $a | Rename-NetAdapter -NewName $expected.Name -Confirm:$false; $a = Get-NetAdapter -IncludeHidden | Where-Object { $_.InterfaceGuid.ToString().Trim('{}') -eq $expected.Id } | Select-Object -First 1 }
            if ($a.AdminStatus -ne 'Up' -and $expected.Enabled) { $a | Enable-NetAdapter -Confirm:$false }
            $previous = $observed.Adapters | Where-Object { $_.Id -eq $expected.Id } | Select-Object -First 1
            $index = $a.ifIndex
            $dhcp = 'Disabled'; if ($expected.Dhcp) { $dhcp = 'Enabled' }
            if ($null -eq $previous -or $previous.Dhcp -ne $expected.Dhcp) { Set-NetIPInterface -InterfaceIndex $index -AddressFamily IPv4 -Dhcp $dhcp }
            $ip6 = Get-NetIPInterface -InterfaceIndex $index -AddressFamily IPv6 -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($null -ne $ip6) {
                $dhcp6 = 'Disabled'; if ($expected.DhcpV6) { $dhcp6 = 'Enabled' }
                $router = 'Disabled'; if ($expected.RouterDiscovery) { $router = 'Enabled' }
                if ($null -eq $previous -or $previous.DhcpV6 -ne $expected.DhcpV6 -or $previous.RouterDiscovery -ne $expected.RouterDiscovery) { Set-NetIPInterface -InterfaceIndex $index -AddressFamily IPv6 -Dhcp $dhcp6 -RouterDiscovery $router }
            }
            $currentAddresses = @(Get-NetIPAddress -InterfaceIndex $index -ErrorAction SilentlyContinue | Where-Object { $_.PrefixOrigin -eq 'Manual' -and $_.IPAddress -ne '::1' -and $_.IPAddress -notlike 'fe80:*' })
            foreach ($current in $currentAddresses) {
                if (!@($expected.Addresses | Where-Object { $_.Address -eq $current.IPAddress -and $_.Prefix -eq $current.PrefixLength }).Count) { $current | Remove-NetIPAddress -Confirm:$false }
            }
            foreach ($addr in @($expected.Addresses)) {
                if (!@($currentAddresses | Where-Object { $_.IPAddress -eq $addr.Address -and $_.PrefixLength -eq $addr.Prefix }).Count) { New-NetIPAddress -InterfaceIndex $index -IPAddress $addr.Address -PrefixLength $addr.Prefix | Out-Null }
            }
            $dns4Object = Get-DnsClientServerAddress -InterfaceIndex $index -AddressFamily IPv4
            if ($null -eq $previous -or $previous.DnsAutomatic -ne $expected.DnsAutomatic -or (!$expected.DnsAutomatic -and [string]::Join('|',@($previous.Dns)) -ne [string]::Join('|',@($expected.Dns)))) {
                if ($expected.DnsAutomatic) { $dns4Object | Set-DnsClientServerAddress -ResetServerAddresses }
                else { $dns4Object | Set-DnsClientServerAddress -ServerAddresses @($expected.Dns) }
            }
            $dns6Object = Get-DnsClientServerAddress -InterfaceIndex $index -AddressFamily IPv6 -ErrorAction SilentlyContinue
            if ($null -ne $dns6Object -and ($null -eq $previous -or $previous.DnsV6Automatic -ne $expected.DnsV6Automatic -or (!$expected.DnsV6Automatic -and [string]::Join('|',@($previous.DnsV6)) -ne [string]::Join('|',@($expected.DnsV6))))) {
                if ($expected.DnsV6Automatic) { $dns6Object | Set-DnsClientServerAddress -ResetServerAddresses }
                else { $dns6Object | Set-DnsClientServerAddress -ServerAddresses @($expected.DnsV6) }
            }
            $routes = @(Get-NetRoute -InterfaceIndex $index -ErrorAction SilentlyContinue | Where-Object { $_.Protocol -eq 'NetMgmt' -and $_.NextHop -ne '0.0.0.0' -and $_.NextHop -ne '::' })
            foreach ($r in $routes) { if (!@($expected.Routes | Where-Object { $_.Prefix -eq $r.DestinationPrefix -and $_.NextHop -eq $r.NextHop -and $_.Metric -eq $r.RouteMetric }).Count) { $r | Remove-NetRoute -Confirm:$false } }
            foreach ($r in @($expected.Routes)) { if (!@($routes | Where-Object { $_.DestinationPrefix -eq $r.Prefix -and $_.NextHop -eq $r.NextHop -and $_.RouteMetric -eq $r.Metric }).Count) { New-NetRoute -InterfaceIndex $index -DestinationPrefix $r.Prefix -NextHop $r.NextHop -RouteMetric $r.Metric | Out-Null } }
            foreach ($binding in @(Get-NetAdapterBinding -Name ([WildcardPattern]::Escape($a.Name)) -IncludeHidden -AllBindings)) {
                $wanted = @($expected.Bindings) -contains $binding.ComponentID
                if ($wanted -and !$binding.Enabled) { $binding | Enable-NetAdapterBinding -Confirm:$false }
                if (!$wanted -and $binding.Enabled) { $binding | Disable-NetAdapterBinding -Confirm:$false }
            }
            if (!$expected.Enabled -and $a.AdminStatus -eq 'Up') { $a | Disable-NetAdapter -Confirm:$false }
        } catch { $errors.Add([string]$_) }
    }
    try {
        $hosts = Get-HostsPath
        $desiredBytes = [Convert]::FromBase64String($baseline.HostsBase64)
        $wantedExists = $true; if ($null -ne $baseline.PSObject.Properties['HostsExists']) { $wantedExists = [bool]$baseline.HostsExists }
        if (!$wantedExists) {
            if ([IO.File]::Exists($hosts)) { [IO.File]::Delete($hosts); Clear-DnsClientCache }
        } elseif (![IO.File]::Exists($hosts) -or [Convert]::ToBase64String([IO.File]::ReadAllBytes($hosts)) -ne $baseline.HostsBase64) {
            [IO.File]::WriteAllBytes($hosts,$desiredBytes); Clear-DnsClientCache
        }
    } catch { $errors.Add("hosts: $_") }
    if ($errors.Count) { throw ($errors -join '; ') }
}
function Reset-Proxies {
    $events = @()
    $paths = @('Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings')
    foreach ($sid in @(Get-ChildItem Registry::HKEY_USERS | Where-Object { $_.PSChildName -match '^S-1-5-21-\d+-\d+-\d+-\d+$' })) { $paths += "Registry::$($sid.Name)\Software\Microsoft\Windows\CurrentVersion\Internet Settings" }
    foreach ($path in $paths) {
        if (!(Test-Path -LiteralPath $path)) { continue }
        $r = Get-ItemProperty -LiteralPath $path
        $changed = ($r.ProxyEnable -eq 1 -or ![string]::IsNullOrWhiteSpace([string]$r.AutoConfigURL) -or $r.AutoDetect -eq 1)
        $connections = "$path\Connections"
        if (Test-Path -LiteralPath $connections) {
            $key = Get-Item -LiteralPath $connections
            foreach ($valueName in $key.GetValueNames()) {
                $bytes = $key.GetValue($valueName)
                if ($bytes -is [byte[]] -and $bytes.Length -ge 12 -and ($bytes[8] -band 14) -ne 0) {
                    $changed = $true; $bytes[8] = [byte](($bytes[8] -band 240) -bor 1)
                    Set-ItemProperty -LiteralPath $connections -Name $valueName -Value $bytes
                }
            }
        }
        if ($changed) {
            New-ItemProperty -LiteralPath $path -Name ProxyEnable -PropertyType DWord -Value 0 -Force | Out-Null
            New-ItemProperty -LiteralPath $path -Name AutoDetect -PropertyType DWord -Value 0 -Force | Out-Null
            Remove-ItemProperty -LiteralPath $path -Name AutoConfigURL -ErrorAction SilentlyContinue
            $events += "Disabled WinINET manual/PAC/autodetect for $path"
        }
    }
    $events | ConvertTo-Json -Compress
}
switch ($Mode) {
    'capture' { Capture-Network }
    'apply' { Apply-Network (Read-Input) }
    'proxy' { Reset-Proxies }
    'certificate' {
        $p = Read-Input
        $cert = New-SelfSignedCertificate -DnsName 'Ycsz-Manager' -CertStoreLocation 'Cert:\LocalMachine\My' -KeyAlgorithm RSA -KeyLength 3072 -HashAlgorithm SHA256 -NotAfter (Get-Date).AddYears(3) -KeyExportPolicy Exportable -Type SSLServerAuthentication
        try { Export-PfxCertificate -Force -Cert $cert -FilePath $p.Path -Password (ConvertTo-SecureString $p.Password -AsPlainText -Force) | Out-Null }
        finally { Remove-Item -LiteralPath "Cert:\LocalMachine\My\$($cert.Thumbprint)" -DeleteKey -ErrorAction SilentlyContinue }
    }
}
