using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
namespace Ycsz {
    internal static class Privileges {
        public static void EnableAudit() {
            IntPtr token;
            if(!OpenProcessToken(Process.GetCurrentProcess().Handle,0x28,out token)) throw new Win32Exception(Marshal.GetLastWin32Error());
            try {
                Luid id; if(!LookupPrivilegeValue(null,"SeSecurityPrivilege",out id)) throw new Win32Exception(Marshal.GetLastWin32Error());
                var privileges=new TokenPrivileges { Count=1,Id=id,Attributes=2 };
                if(!AdjustTokenPrivileges(token,false,ref privileges,0,IntPtr.Zero,IntPtr.Zero)) throw new Win32Exception(Marshal.GetLastWin32Error());
                int error=Marshal.GetLastWin32Error(); if(error!=0) throw new Win32Exception(error);
            } finally { CloseHandle(token); }
        }
        [StructLayout(LayoutKind.Sequential)] struct Luid { public uint Low; public int High; }
        [StructLayout(LayoutKind.Sequential)] struct TokenPrivileges { public uint Count; public Luid Id; public uint Attributes; }
        [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr process,uint access,out IntPtr token);
        [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool LookupPrivilegeValue(string system,string name,out Luid id);
        [DllImport("advapi32.dll",SetLastError=true)] static extern bool AdjustTokenPrivileges(IntPtr token,bool disableAll,ref TokenPrivileges privileges,uint length,IntPtr old,IntPtr returned);
        [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    }
}
