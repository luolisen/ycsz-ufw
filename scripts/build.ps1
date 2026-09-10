param([switch]$SkipInstaller)
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
$csc = "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if (!(Test-Path $csc)) { throw 'Install .NET Framework 4.8 on Windows x64 first.' }
New-Item -ItemType Directory -Force artifacts\app | Out-Null
$core = @(Get-ChildItem src\Ycsz.Core\*.cs | ForEach-Object FullName)
$app = @(Get-ChildItem src\Ycsz.App\*.cs | ForEach-Object FullName)
$tests = @(Get-ChildItem src\Ycsz.Tests\*.cs | ForEach-Object FullName)
& $csc /nologo /target:library /optimize+ /warnaserror /out:artifacts\app\Ycsz.Core.dll /r:System.Web.Extensions.dll /r:System.Core.dll $core
if ($LASTEXITCODE) { throw 'Core compile failed' }
& $csc /nologo /platform:x64 /target:winexe /optimize+ /warnaserror /win32manifest:src\Ycsz.App\app.manifest /out:artifacts\app\Ycsz.exe /r:artifacts\app\Ycsz.Core.dll /r:System.Core.dll /r:System.Security.dll /r:System.ServiceProcess.dll /r:System.Windows.Forms.dll /r:System.Drawing.dll /r:System.Xml.dll /r:System.Xml.Linq.dll $app
if ($LASTEXITCODE) { throw 'Application compile failed' }
Copy-Item src\Ycsz.App\App.config artifacts\app\Ycsz.exe.config -Force
Copy-Item scripts\System.ps1 artifacts\app\System.ps1 -Force
& $csc /nologo /platform:x64 /target:exe /optimize+ /warnaserror /out:artifacts\app\Ycsz.Tests.exe /r:artifacts\app\Ycsz.Core.dll /r:artifacts\app\Ycsz.exe /r:System.Core.dll $tests
if ($LASTEXITCODE) { throw 'Tests compile failed' }
& artifacts\app\Ycsz.Tests.exe | Tee-Object artifacts\test-results-windows.txt
if ($LASTEXITCODE) { throw 'Tests failed' }
& $csc /nologo /target:exe /optimize+ /warnaserror /out:artifacts\app\TlsProbe.exe /r:artifacts\app\Ycsz.Core.dll src\Ycsz.Probes\TlsProbe.cs
if ($LASTEXITCODE) { throw 'TLS probe compile failed' }
& ./scripts/Test-Tls.ps1 -Probe (Resolve-Path artifacts\app\TlsProbe.exe).Path | Tee-Object artifacts\tls-results-windows.txt
& ./scripts/Test-NetworkLogic.ps1 | Tee-Object artifacts\network-logic-results-windows.txt
if (!$SkipInstaller) {
    $nsis = (Get-Command makensis.exe -ErrorAction SilentlyContinue).Source
    if (!$nsis) { $nsis = "${env:ProgramFiles(x86)}\NSIS\makensis.exe" }
    if (!(Test-Path $nsis)) { throw 'Install NSIS 3 using its official installer or choco install nsis.' }
    & $nsis /INPUTCHARSET UTF8 /V3 installer\Ycsz.nsi | Tee-Object artifacts\installer-build-windows.txt
    if ($LASTEXITCODE) { throw 'Installer build failed' }
    Get-FileHash artifacts\Ycsz-Setup-0.1.0-x64.exe,artifacts\app\Ycsz.exe,artifacts\app\Ycsz.Core.dll -Algorithm SHA256 | Format-Table -AutoSize | Out-String | Set-Content artifacts\SHA256SUMS-WINDOWS.txt
}
