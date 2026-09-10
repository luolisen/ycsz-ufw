using System;
using System.Diagnostics;

namespace Ycsz {
    public static class ProcessScanner {
        // Inspect one known process; the guard owns enumeration and scheduling.
        public static void Inspect(Process process,Action<string,string,bool> report) {
            try {
                string filename=process.ProcessName+".exe",label;
                if(!Defaults.Processes.TryGetValue(filename,out label)) return;
                int id=process.Id;
                try {
                    process.Kill(); bool exited=process.WaitForExit(2000);
                    report("proxy_process",label+" "+filename+" PID="+id+(exited?" 已终止":" 终止等待超时"),exited);
                } catch(Exception e) { report("proxy_process",filename+" PID="+id+" 终止失败："+e.Message,false); }
            } catch(InvalidOperationException) {} catch(System.ComponentModel.Win32Exception) {}
        }
    }
}
