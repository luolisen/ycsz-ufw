#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p artifacts/app
mcs -sdk:4.5 -target:library -optimize+ -warnaserror -out:artifacts/app/Ycsz.Core.dll \
  -r:System.Web.Extensions -r:System.Core src/Ycsz.Core/*.cs
mcs -sdk:4.5 -platform:x64 -target:winexe -optimize+ -warnaserror \
  -win32manifest:src/Ycsz.App/app.manifest -out:artifacts/app/Ycsz.exe \
  -r:artifacts/app/Ycsz.Core.dll -r:System.Core -r:System.Security -r:System.ServiceProcess -r:System.Management \
  -r:System.IO.Compression -r:System.IO.Compression.FileSystem -r:System.Windows.Forms -r:System.Drawing -r:System.Xml -r:System.Xml.Linq src/Ycsz.App/*.cs
cp src/Ycsz.App/App.config artifacts/app/Ycsz.exe.config
cp scripts/System.ps1 artifacts/app/System.ps1
mcs -sdk:4.5 -platform:x64 -target:exe -optimize+ -warnaserror -out:artifacts/app/Ycsz.Tests.exe \
  -r:artifacts/app/Ycsz.Core.dll -r:artifacts/app/Ycsz.exe -r:System.Core src/Ycsz.Tests/*.cs
mono artifacts/app/Ycsz.Tests.exe | tee artifacts/test-results.txt
mcs -sdk:4.5 -target:exe -optimize+ -warnaserror -out:artifacts/app/TlsProbe.exe -r:artifacts/app/Ycsz.Core.dll src/Ycsz.Probes/TlsProbe.cs
if [[ "${YCSZ_BUILD_DRIVER:-0}" == "1" ]]; then
  : "${YCSZ_DRIVER_MSBUILD:?Set YCSZ_DRIVER_MSBUILD to an official Windows WDK msbuild executable when explicitly building the driver}"
  "$YCSZ_DRIVER_MSBUILD" drivers/YcszProtection/YcszProtection.vcxproj /p:Configuration=Release /p:Platform=x64 /m
fi
if [[ -n "${YCSZ_PWSH:-}" ]]; then
  "$YCSZ_PWSH" -NoLogo -NoProfile -File scripts/Test-Tls.ps1 -Mono "$(command -v mono)" -Probe artifacts/app/TlsProbe.exe | tee artifacts/tls-results.txt
  "$YCSZ_PWSH" -NoLogo -NoProfile -File scripts/Test-NetworkLogic.ps1 | tee artifacts/network-logic-results.txt
  "$YCSZ_PWSH" -NoLogo -NoProfile -File scripts/Test-Windows.ps1 -Mode Static | tee artifacts/powershell-results.txt
fi
python3 scripts/fetch-net48.py
makensis -INPUTCHARSET UTF8 -V3 -DWITHOUT_NET48 -DCLIENT_ONLY -DOUTPUT_FILE=../artifacts/Ycsz-Client-Setup-NoRuntime.exe installer/Ycsz.nsi | tee artifacts/client-noruntime-build.txt
makensis -INPUTCHARSET UTF8 -V3 -DWITHOUT_NET48 -DOUTPUT_FILE=../artifacts/Ycsz-Setup-1.0.1-NoRuntime-x64.exe installer/Ycsz.nsi | tee artifacts/noruntime-build.txt
makensis -INPUTCHARSET UTF8 -V3 -DCLIENT_ONLY -DOUTPUT_FILE=../artifacts/Ycsz-Client-Setup.exe installer/Ycsz.nsi | tee artifacts/client-installer-build.txt
makensis -INPUTCHARSET UTF8 -V3 installer/Ycsz.nsi | tee artifacts/installer-build.txt
shasum -a 256 artifacts/Ycsz-Setup-1.0.1-x64.exe artifacts/app/Ycsz.exe artifacts/app/Ycsz.Core.dll > artifacts/SHA256SUMS
