Unicode true
!include "MUI2.nsh"
!include "x64.nsh"
!include "WinVer.nsh"
Name "YCSZ 教育机房防火墙"
!ifndef OUTPUT_FILE
!define OUTPUT_FILE "..\artifacts\Ycsz-Setup-1.0.1-x64.exe"
!endif
OutFile "${OUTPUT_FILE}"
InstallDir "$PROGRAMFILES64\YcszFirewall"
RequestExecutionLevel admin
SetCompressor /SOLID lzma
ShowInstDetails show
ShowUninstDetails show
VIProductVersion "1.0.1.0"
VIAddVersionKey /LANG=2052 "ProductName" "YCSZ 教育机房防火墙"
VIAddVersionKey /LANG=2052 "FileDescription" "YCSZ 原生 Windows 客户端与管理端安装程序"
VIAddVersionKey /LANG=2052 "FileVersion" "1.0.1"
VIAddVersionKey /LANG=2052 "LegalCopyright" "YCSZ contributors"
!define MUI_ABORTWARNING
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "SimpChinese"
Function .onInit
  ${IfNot} ${RunningX64}
    MessageBox MB_ICONSTOP "仅支持 Windows x64。"
    Abort
  ${EndIf}
  ${IfNot} ${AtLeastWin10}
    MessageBox MB_ICONSTOP "本版本运行支持范围为 Windows 10/11 x64。"
    Abort
  ${EndIf}
  SetRegView 64
  ReadRegStr $0 HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\YcszFirewall" "InstallLocation"
  ${If} $0 != ""
    MessageBox MB_ICONSTOP "已安装本产品。请先通过管理页卸载，防止覆盖原网络基线。"
    Abort
  ${EndIf}
FunctionEnd
!macro Net48ReadRelease
  StrCpy $0 0
  ClearErrors
  ReadRegDWORD $0 HKLM "SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" "Release"
!macroend
!macro Net48RunInstaller
!ifdef WITHOUT_NET48
  StrCpy $0 1603
  MessageBox MB_ICONSTOP "此安装包不内置运行库。请先安装 .NET Framework 4.8，或使用内置运行库版。" /SD IDOK
  SetErrorLevel 1603
  Quit
!else
  DetailPrint "正在安装内置的 .NET Framework 4.8，请稍候。"
  InitPluginsDir
  SetOutPath "$PLUGINSDIR"
  File /oname=net48-offline.exe "..\artifacts\redist\NDP48-x86-x64-AllOS-ENU.exe"
  ClearErrors
  ExecWait '"$PLUGINSDIR\net48-offline.exe" /passive /norestart /ChainingPackage YcszFirewall' $0
  ${If} ${Errors}
    StrCpy $0 1603
  ${EndIf}
  Delete "$PLUGINSDIR\net48-offline.exe"
!endif
!macroend
!macro Net48StopReboot
  MessageBox MB_ICONINFORMATION ".NET Framework 安装要求重启。请保存工作并重启 Windows，再重新运行本安装包。YCSZ 尚未安装。" /SD IDOK
  SetErrorLevel 3010
  Quit
!macroend
!macro Net48StopFailure
  MessageBox MB_ICONSTOP ".NET Framework 4.8 安装未完成（错误码 $0）。YCSZ 尚未安装，请解决运行库安装问题后重试。" /SD IDOK
  SetErrorLevel $0
  Quit
!macroend
!include "Net48.nsh"
; Repair only known payload paths left by an interrupted installation. The root
; is secured first; resetting a child then inherits that restricted root ACL.
!macro RepairPayloadAcl PATH
  ${If} ${FileExists} "$INSTDIR\${PATH}"
    nsExec::ExecToLog '"$SYSDIR\icacls.exe" "$INSTDIR\${PATH}" /reset /T'
    Pop $0
    ${If} $0 != 0
      MessageBox MB_ICONSTOP "修复安装文件权限失败：${PATH}。安装已停止，文件已保留。"
      Abort
    ${EndIf}
  ${EndIf}
!macroend
Section "YCSZ" SEC_MAIN
  Call EnsureNet48
  SetRegView 64
  SetShellVarContext all
  StrCpy $INSTDIR "$PROGRAMFILES64\YcszFirewall"
  SetOutPath "$INSTDIR"
  ; Do not recursively apply directory inheritance flags to individual files.
  ; On Windows this left payload files with empty DACLs and broke the next
  ; setowner call (invalid handle), then prevented a retry from overwriting them.
  nsExec::ExecToLog '"$SYSDIR\icacls.exe" "$INSTDIR" /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX"'
  Pop $0
  ${If} $0 != 0
    MessageBox MB_ICONSTOP "安装目录权限设置失败，安装已停止。"
    Abort
  ${EndIf}
  !insertmacro RepairPayloadAcl "Ycsz.exe"
  !insertmacro RepairPayloadAcl "Ycsz.Core.dll"
  !insertmacro RepairPayloadAcl "Ycsz.exe.config"
  !insertmacro RepairPayloadAcl "System.ps1"
  !insertmacro RepairPayloadAcl "README.md"
  !insertmacro RepairPayloadAcl "TASK.md"
  !insertmacro RepairPayloadAcl "PLAN.md"
  !insertmacro RepairPayloadAcl "Uninstall.exe"
  !insertmacro RepairPayloadAcl "docs"
  !insertmacro RepairPayloadAcl "Ycsz-Client-Setup.exe"
  !insertmacro RepairPayloadAcl "Ycsz-Client-Setup-NoRuntime.exe"
  !insertmacro RepairPayloadAcl "client.ycsz"
  File "..\artifacts\app\Ycsz.exe"
  File "..\artifacts\app\Ycsz.Core.dll"
  File "..\artifacts\app\Ycsz.exe.config"
  File "..\artifacts\app\System.ps1"
!ifndef CLIENT_ONLY
!ifndef WITHOUT_NET48
  File "..\artifacts\Ycsz-Client-Setup.exe"
!endif
  File "..\artifacts\Ycsz-Client-Setup-NoRuntime.exe"
!else
  ${If} ${FileExists} "$EXEDIR\client.ycsz"
    CopyFiles /SILENT "$EXEDIR\client.ycsz" "$INSTDIR\client.ycsz"
  ${EndIf}
!endif
  File "..\README.md"
  File "..\TASK.md"
  File "..\PLAN.md"
  SetOutPath "$INSTDIR\docs"
  File "..\docs\SECURITY-VALIDATION.md"
  File "..\docs\ARCHITECTURE.md"
  SetOutPath "$INSTDIR"
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  nsExec::ExecToLog '"$SYSDIR\icacls.exe" "$INSTDIR" /setowner *S-1-5-32-544 /T'
  Pop $0
  ${If} $0 != 0
    MessageBox MB_ICONSTOP "安装目录所有者设置失败，安装已停止。"
    Abort
  ${EndIf}
!ifdef CLIENT_ONLY
  ExecWait '"$INSTDIR\Ycsz.exe" --setup-client' $0
!else
  ExecWait '"$INSTDIR\Ycsz.exe" --setup' $0
!endif
  ${If} $0 != 0
    MessageBox MB_ICONSTOP "初始化未完成。未启动服务；请查看错误后重试。安装文件保留在安装目录。"
    Abort
  ${EndIf}
  Delete "$INSTDIR\client.ycsz"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\YcszFirewall" "DisplayName" "YCSZ 教育机房防火墙"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\YcszFirewall" "DisplayVersion" "1.0.1"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\YcszFirewall" "Publisher" "YCSZ"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\YcszFirewall" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\YcszFirewall" "UninstallString" '"$INSTDIR\Uninstall.exe"'
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\YcszFirewall" "NoModify" 1
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\YcszFirewall" "NoRepair" 1
  nsExec::ExecToLog '"$SYSDIR\sc.exe" create YcszFirewall binPath= "\$\"$INSTDIR\Ycsz.exe\$\" --service" start= auto obj= LocalSystem DisplayName= "YCSZ Education Firewall"'
  Pop $0
  ${If} $0 != 0
    MessageBox MB_ICONSTOP "服务创建失败。请以管理员身份检查已有服务和初始化文件。"
    Abort
  ${EndIf}
  nsExec::ExecToLog '"$SYSDIR\sc.exe" description YcszFirewall "Education lab firewall. Administrator-managed, recoverable Windows service."'
  Pop $0
  ${If} $0 != 0
    MessageBox MB_ICONSTOP "服务配置失败；安装信息已登记，可通过卸载入口恢复后重试。"
    Abort
  ${EndIf}
  nsExec::ExecToLog '"$SYSDIR\sc.exe" failure YcszFirewall reset= 86400 actions= restart/5000/restart/10000/restart/30000'
  Pop $0
  ${If} $0 != 0
    MessageBox MB_ICONSTOP "服务配置失败；安装信息已登记，可通过卸载入口恢复后重试。"
    Abort
  ${EndIf}
  nsExec::ExecToLog '"$SYSDIR\sc.exe" failureflag YcszFirewall 1'
  Pop $0
  ${If} $0 != 0
    MessageBox MB_ICONSTOP "服务配置失败；安装信息已登记，可通过卸载入口恢复后重试。"
    Abort
  ${EndIf}
  nsExec::ExecToLog '"$SYSDIR\sc.exe" sdset YcszFirewall "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)"'
  Pop $0
  ${If} $0 != 0
    MessageBox MB_ICONSTOP "服务配置失败；安装信息已登记，可通过卸载入口恢复后重试。"
    Abort
  ${EndIf}
  ExecWait '"$INSTDIR\Ycsz.exe" --installed-role' $0
  ${If} $0 == 10
    CreateShortCut "$DESKTOP\YCSZ 管理端.lnk" "$INSTDIR\Ycsz.exe"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\YcszFirewall" "YcszRole" "manager"
    nsExec::ExecToLog '"$SYSDIR\netsh.exe" advfirewall firewall add rule name="YCSZ Manager TLS" dir=in action=allow program="$INSTDIR\Ycsz.exe" protocol=TCP localport=17443 remoteip=LocalSubnet profile=domain,private'
    Pop $0
    ${If} $0 != 0
      MessageBox MB_ICONSTOP "管理端入站规则配置失败，服务尚未启动。请检查后通过卸载入口恢复。"
      Abort
    ${EndIf}
  ${ElseIf} $0 == 20
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\YcszFirewall" "YcszRole" "client"
  ${Else}
    MessageBox MB_ICONSTOP "无法确认安装角色，服务尚未启动。"
    Abort
  ${EndIf}
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "YcszFirewallTray" '"$INSTDIR\Ycsz.exe" --tray'
  CreateDirectory "$SMPROGRAMS\YCSZ 教育机房防火墙"
  CreateShortCut "$SMPROGRAMS\YCSZ 教育机房防火墙\管理界面.lnk" "$INSTDIR\Ycsz.exe"
  CreateShortCut "$SMPROGRAMS\YCSZ 教育机房防火墙\使用说明.lnk" "$INSTDIR\README.md"
  nsExec::ExecToLog '"$SYSDIR\sc.exe" start YcszFirewall'
  Pop $0
  ${If} $0 != 0
    MessageBox MB_ICONEXCLAMATION "安装已完成，但服务启动失败。请查看 ProgramData\YcszFirewall\service.log，或使用管理员恢复步骤。"
  ${EndIf}
  Exec '"$INSTDIR\Ycsz.exe" --tray'
SectionEnd
Function un.onInit
  SetRegView 64
  ExecWait '"$INSTDIR\Ycsz.exe" --uninstall-authorize' $0
  ${If} $0 != 0
    MessageBox MB_ICONSTOP "密码验证或网络恢复失败，卸载已取消。"
    Abort
  ${EndIf}
FunctionEnd
Section "Uninstall"
  SetShellVarContext all
  ExecWait '"$INSTDIR\Ycsz.exe" --close-ui' $0
  nsExec::ExecToLog '"$SYSDIR\sc.exe" delete YcszFirewall'
  Pop $0
  ${If} $0 != 0
  ${AndIf} $0 != 1060
  ${AndIf} $0 != 1072
    MessageBox MB_ICONSTOP "服务删除失败。安装文件和卸载记录已保留，请管理员检查后重试。"
    Abort
  ${EndIf}
  nsExec::ExecToLog '"$SYSDIR\netsh.exe" advfirewall firewall delete rule name="YCSZ Manager TLS" program="$INSTDIR\Ycsz.exe"'
  Pop $0
  DeleteRegValue HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "YcszFirewallTray"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\YcszFirewall"
  Delete "$DESKTOP\YCSZ 管理端.lnk"
  Delete "$SMPROGRAMS\YCSZ 教育机房防火墙\管理界面.lnk"
  Delete "$SMPROGRAMS\YCSZ 教育机房防火墙\使用说明.lnk"
  RMDir "$SMPROGRAMS\YCSZ 教育机房防火墙"
  Delete /REBOOTOK "$INSTDIR\Ycsz.exe"
  Delete /REBOOTOK "$INSTDIR\Ycsz.Core.dll"
  Delete "$INSTDIR\Ycsz.exe.config"
  Delete "$INSTDIR\System.ps1"
  Delete "$INSTDIR\Ycsz-Client-Setup.exe"
  Delete "$INSTDIR\Ycsz-Client-Setup-NoRuntime.exe"
  Delete "$INSTDIR\client.ycsz"
  Delete "$INSTDIR\README.md"
  Delete "$INSTDIR\TASK.md"
  Delete "$INSTDIR\PLAN.md"
  Delete "$INSTDIR\docs\SECURITY-VALIDATION.md"
  Delete "$INSTDIR\docs\ARCHITECTURE.md"
  RMDir "$INSTDIR\docs"
  Delete /REBOOTOK "$INSTDIR\Uninstall.exe"
  RMDir /REBOOTOK "$INSTDIR"
  MessageBox MB_ICONINFORMATION "卸载完成。原网络基线、加密配置与审计日志保留在 ProgramData\YcszFirewall，供管理员归档；重新安装前请按说明归档该目录。"
SectionEnd
