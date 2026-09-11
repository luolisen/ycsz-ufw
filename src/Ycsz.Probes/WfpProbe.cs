using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using Ycsz;
class WfpProbe {
    [DllImport("fwpuclnt.dll")] static extern uint FwpmTransactionBegin0(IntPtr engine,uint flags);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmTransactionAbort0(IntPtr engine);
    static int Main() {
        if(Directory.Exists(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"YcszFirewall"))) throw new InvalidOperationException("Disposable Windows only: existing configuration");
        using(var wfp=new Wfp()) {
            var engine=(IntPtr)typeof(Wfp).GetField("engine",BindingFlags.Instance|BindingFlags.NonPublic).GetValue(wfp);
            var add=typeof(Wfp).GetMethod("Add",BindingFlags.Instance|BindingFlags.NonPublic);
            try {
                if(FwpmTransactionBegin0(engine,0)!=0) throw new Exception("begin failed");
                try {
                    string app=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),"svchost.exe");
                    foreach(var ip in new[]{"192.0.2.53","2001:db8::53"}) foreach(int proto in new[]{6,17}) {
                        add.Invoke(wfp,new object[]{"Probe DNS",ip,53,proto,app,false});
                        Console.WriteLine("PASS native WFP app + address + port + protocol: "+ip+" / "+proto);
                    }
                    add.Invoke(wfp,new object[]{"Probe deny IPv4",null,0,0,null,false});
                    add.Invoke(wfp,new object[]{"Probe deny IPv6",null,0,0,null,true});
                    Console.WriteLine("PASS native WFP default deny IPv4 / IPv6 (transaction not committed)");
                } finally { if(FwpmTransactionAbort0(engine)!=0) throw new Exception("abort failed"); }
            } finally { wfp.RemoveAll(); }
        }
        Console.WriteLine("PASS native WFP validation rolled back; no blocking policy activated"); return 0;
    }
}
