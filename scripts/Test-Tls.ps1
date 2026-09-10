param([string]$Mono,[Parameter(Mandatory=$true)][string]$Probe)
$ErrorActionPreference='Stop'
# Portable TLS harness only. Does not install a certificate into any system store.
$fixture=Join-Path ([IO.Path]::GetTempPath()) ('ycsz-tls-'+[Guid]::NewGuid().ToString('N')+'.pfx')
$rsa=[Security.Cryptography.RSA]::Create(2048)
try {
    $request=[Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=YcszTestOnly',$rsa,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $cert=$request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-5),[DateTimeOffset]::UtcNow.AddDays(1))
    try { [IO.File]::WriteAllBytes($fixture,$cert.Export([Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12,'ycsz-test-only-123')) }
    finally { $cert.Dispose() }
    if ($Mono) { & $Mono $Probe $fixture } else { & $Probe $fixture }
    if($LASTEXITCODE) { throw 'TLS probes failed' }
} finally { $rsa.Dispose(); if(Test-Path -LiteralPath $fixture) { Remove-Item -LiteralPath $fixture -Force } }
