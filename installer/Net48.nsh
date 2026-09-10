; Shared dependency gate. Test harness supplies side-effect-free implementations
; of the four macros; production definitions remain in Ycsz.nsi.
Function EnsureNet48
  !insertmacro Net48ReadRelease
  ${If} $0 >= 528040
    Return
  ${EndIf}
  !insertmacro Net48RunInstaller
  ${If} $0 == 3010
  ${OrIf} $0 == 1641
    !insertmacro Net48StopReboot
  ${ElseIf} $0 != 0
    !insertmacro Net48StopFailure
  ${EndIf}
  !insertmacro Net48ReadRelease
  ${If} $0 < 528040
    StrCpy $0 1603
    !insertmacro Net48StopFailure
  ${EndIf}
FunctionEnd
