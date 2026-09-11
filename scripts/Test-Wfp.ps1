$ErrorActionPreference = 'Stop'
if (Get-Service YcszFirewall -ErrorAction SilentlyContinue) { throw 'Disposable Windows only: existing service' }
$root = Split-Path $PSScriptRoot -Parent
$csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$app = Join-Path $root 'artifacts\app'
& $csc /nologo /platform:x64 /out:$app\WfpProbe.exe /reference:$app\Ycsz.exe /reference:$app\Ycsz.Core.dll $root\src\Ycsz.Probes\WfpProbe.cs
if ($LASTEXITCODE -ne 0) { throw 'WFP probe compilation failed' }
& $app\WfpProbe.exe
if ($LASTEXITCODE -ne 0) { throw 'WFP native transaction validation failed' }
