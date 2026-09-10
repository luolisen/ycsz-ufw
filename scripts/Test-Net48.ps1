$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$nsis = (Get-Command makensis.exe -ErrorAction SilentlyContinue).Source
if (!$nsis) { $nsis = "${env:ProgramFiles(x86)}\NSIS\makensis.exe" }
$folder = Join-Path $env:TEMP ('ycsz-net48-' + [guid]::NewGuid().ToString('N'))
New-Item $folder -ItemType Directory | Out-Null
$cases = @(
    @{Name='already-48'; Before=528040; After=528040; Code=0; Expected=10},
    @{Name='newer-481'; Before=533320; After=533320; Code=0; Expected=10},
    @{Name='missing-install-success'; Before=0; After=528040; Code=0; Expected=11},
    @{Name='older-install-success'; Before=461808; After=528040; Code=0; Expected=11},
    @{Name='reboot-required'; Before=0; After=528040; Code=3010; Expected=3010},
    @{Name='reboot-initiated'; Before=0; After=528040; Code=1641; Expected=3010},
    @{Name='cancelled'; Before=0; After=0; Code=1602; Expected=1602},
    @{Name='install-failed'; Before=0; After=0; Code=1603; Expected=1603},
    @{Name='success-but-registry-missing'; Before=0; After=0; Code=0; Expected=1603}
)
$template = @'
Unicode true
!include "LogicLib.nsh"
Name "Dependency gate fixture"
OutFile "__OUT__"
RequestExecutionLevel user
SilentInstall silent
Var Calls
!macro Net48ReadRelease
  ${If} $Calls == 0
    StrCpy $0 __BEFORE__
  ${Else}
    StrCpy $0 __AFTER__
  ${EndIf}
!macroend
!macro Net48RunInstaller
  IntOp $Calls $Calls + 1
  StrCpy $0 __CODE__
!macroend
!macro Net48StopReboot
  SetErrorLevel 3010
  Quit
!macroend
!macro Net48StopFailure
  SetErrorLevel $0
  Quit
!macroend
!include "__INCLUDE__"
Section
  StrCpy $Calls 0
  Call EnsureNet48
  IntOp $0 $Calls + 10
  SetErrorLevel $0
SectionEnd
'@
try {
    foreach ($case in $cases) {
        $exe = Join-Path $folder ($case.Name + '.exe')
        $text = $template.Replace('__OUT__',$exe).Replace('__INCLUDE__',"$repo\installer\Net48.nsh").Replace('__BEFORE__',[string]$case.Before).Replace('__AFTER__',[string]$case.After).Replace('__CODE__',[string]$case.Code)
        $source = Join-Path $folder 'fixture.nsi'
        $text | Set-Content $source -Encoding UTF8
        & $nsis /V1 $source
        if ($LASTEXITCODE) { throw 'Dependency fixture compilation failed' }
        $p = Start-Process $exe -PassThru
        if (!$p.WaitForExit(30000)) { $p.Kill(); throw 'Fixture timeout' }
        if ($p.ExitCode -ne $case.Expected) { throw "$($case.Name): expected $($case.Expected), got $($p.ExitCode)" }
        Write-Output "PASS .NET dependency gate: $($case.Name)"
    }
} finally { Remove-Item $folder -Recurse -Force }
