// Disposable Windows CI fixture only. Never ship this probe in the installer.
using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Security.Cryptography.X509Certificates;
using Ycsz;

static class SecurityProbe {
    const string TestPassword="Ycsz-probe-only-123";
    static int passed;
    static void Check(string name,bool ok) { if(!ok) throw new Exception(name); passed++; Console.WriteLine("PASS "+name); }
    static void Denied(string name,Action action) { bool denied=false; try { action(); } catch(UnauthorizedAccessException) { denied=true; } Check(name,denied); }
    static void Rejected(string name,Action action) { bool rejected=false; try { action(); } catch(InvalidOperationException) { rejected=true; } Check(name,rejected); }
    static Packet Call(string op,string token=null) { return Ipc.Call(new Packet { Op=op,Token=token }); }
    static int Main(string[] args) {
        try {
            if(Environment.GetEnvironmentVariable("YCSZ_DISPOSABLE_TEST")!="1") throw new Exception("Requires explicitly enabled disposable Windows fixture");
            if(args[0]=="--idle") { System.Threading.Thread.Sleep(30000); return 0; }
            if(args[0]=="--initialize") {
                if(Directory.Exists(Store.Root)) throw new Exception("Refusing existing configuration");
                Store.Initialize(); var s=new Settings { Role="manager",Password=Crypto.HashPassword(TestPassword),PfxPassword=Crypto.Token() };
                PowerShell.Run("certificate",Json.Encode(new { Path=Store.PathFor("manager.pfx"),Password=s.PfxPassword }));
                var cert=new X509Certificate2(Store.PathFor("manager.pfx"),s.PfxPassword);
                try { s.CertificateHash=Crypto.Sha256(cert.RawData); } finally { cert.Reset(); }
                Store.Save("settings.bin",s); Store.Save("manager.bin",new ManagerState());
                Check("isolated manager configuration initialized",true);
            } else if(args[0]=="--checks") { StandardUser(); Registration(); ProcessDetection(); }
            else if(args[0]=="--persistence") {
                string token=Ipc.Call(new Packet { Op="login",Password=TestPassword }).Token;
                var nodes=Json.Decode<System.Collections.Generic.List<ClientState>>(Call("list",token).Data);
                Check("independent devices persisted across service crash",nodes.Count==2 && nodes.Select(n=>n.Id).Distinct().Count()==2);
                Check("authenticated computer name persisted",nodes.Any(n=>n.Name=="LAB-RENAMED"));
                Check("revocation persisted",nodes.Count(n=>n.Revoked)==1); Call("logout",token);
            } else throw new Exception("Unknown probe mode");
            Console.WriteLine("RESULT "+passed+" Windows checks passed"); return 0;
        } catch(Exception e) { Console.WriteLine("FAIL "+e); return 1; }
    }
    static void StandardUser() {
        IntPtr token;
        if(!LogonUser(Environment.GetEnvironmentVariable("YCSZ_TEST_USER"),".",Environment.GetEnvironmentVariable("YCSZ_TEST_PASSWORD"),2,0,out token)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        try { using(WindowsIdentity.Impersonate(token)) {
            Check("fixture identity is a standard user",!new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator));
            Denied("standard user cannot read protected credentials",()=> { using(File.Open(Store.PathFor("settings.bin"),FileMode.Open,FileAccess.Read)) {} });
            Denied("standard user cannot overwrite installed executable",()=> { using(File.Open(Path.Combine(Store.Bin,"Ycsz.exe"),FileMode.Open,FileAccess.Write)) {} });
            Denied("standard user cannot overwrite PowerShell helper",()=> { using(File.Open(Path.Combine(Store.Bin,"System.ps1"),FileMode.Open,FileAccess.Write)) {} });
            IntPtr scm=OpenSCManager(null,null,1); if(scm==IntPtr.Zero) throw new Exception("SCM query unavailable");
            try { foreach(uint access in new uint[]{0x20,2,0x10000}) {
                IntPtr service=OpenService(scm,"YcszFirewall",access); int error=Marshal.GetLastWin32Error(); if(service!=IntPtr.Zero) CloseServiceHandle(service);
                Check("standard user denied service access "+access,service==IntPtr.Zero && error==5);
            } } finally { CloseServiceHandle(scm); }
            int pid=Int32.Parse(Environment.GetEnvironmentVariable("YCSZ_TEST_SERVICE_PID"));
            IntPtr process=OpenProcess(1,false,pid); int processError=Marshal.GetLastWin32Error(); if(process!=IntPtr.Zero) CloseHandle(process);
            Check("standard user cannot acquire service terminate handle",process==IntPtr.Zero && processError==5);
            Check("standard user can query IPC status",Call("status").Ok);
            Rejected("unauthenticated management command rejected",()=>Call("list"));
            Rejected("forged management session rejected",()=>Call("list",Crypto.Token()));
            string session=Ipc.Call(new Packet { Op="login",Password=TestPassword }).Token;
            Check("password-authorized standard user management works",Call("list",session).Ok);
            Call("logout",session); Rejected("logout invalidates management session",()=>Call("list",session));
        } } finally { CloseHandle(token); }
    }
    static void ProcessDetection() {
        foreach(var name in new[]{"v2ray.exe","safe-fixture.exe"}) {
            string path=Path.Combine(Store.Bin,name); File.Copy(Path.Combine(Store.Bin,"SecurityProbe.exe"),path,true);
            using(var process=Process.Start(new ProcessStartInfo { FileName=path,Arguments="--idle",UseShellExecute=false,CreateNoWindow=true })) {
                try {
                    System.Threading.Thread.Sleep(300); bool reported=false;
                    ProcessScanner.Inspect(process,(kind,detail,success)=> { reported=kind=="proxy_process" && success; });
                    Check(name=="v2ray.exe"?"client scanner terminates harmless proxy-name fixture and reports":"client scanner leaves unrelated process running",name=="v2ray.exe"?process.HasExited&&reported:!process.HasExited&&!reported);
                } finally { if(!process.HasExited) { process.Kill(); process.WaitForExit(5000); } }
            }
        }
    }
    static void Registration() {
        string session=Ipc.Call(new Packet { Op="login",Password=TestPassword }).Token;
        var bundle=Json.Decode<Enrollment>(Ipc.Call(new Packet { Op="create-bundle",Token=session,Data="192.0.2.10" }).Data);
        var a=EnrollmentRegistry.NewIdentity(bundle,"LAB-SAME"); var b=EnrollmentRegistry.NewIdentity(bundle,"LAB-SAME");
        var local=Json.Copy(bundle); local.Host="127.0.0.1";
        foreach(var n in new[]{a,b}) Check("TLS enrollment independent device "+n.Name,Register(local,n).Ok);
        a.Host=b.Host="127.0.0.1";
        var first=Wire.Heartbeat(a,Beat("LAB-RENAMED")); Check("authenticated name heartbeat accepted",first.Ok);
        Check("repeated registration idempotent",Register(local,a).Ok);
        var forged=Json.Copy(a); forged.Token=bundle.Token; Check("bundle cannot authenticate device heartbeat",!Wire.Heartbeat(forged,Beat("FORGED")).Ok);
        var attacker=Json.Copy(a); attacker.Token=Crypto.Token(); Check("shared bundle cannot overwrite device credential",!Register(local,attacker).Ok);
        Check("second device heartbeat accepted",Wire.Heartbeat(b,Beat("LAB-SAME")).Ok);
        var nodes=Json.Decode<System.Collections.Generic.List<ClientState>>(Call("list",session).Data);
        Check("manager exposes two independent named devices",nodes.Count==2 && nodes.Any(n=>n.Name=="LAB-RENAMED"));
        Ipc.Call(new Packet { Op="revoke",Id=b.ClientId,Token=session });
        Check("revoked device heartbeat rejected",!Wire.Heartbeat(b,Beat("LAB-SAME")).Ok);
        Check("revoked device cannot restore itself via universal bundle",!Register(local,b).Ok);
        string export=Path.Combine(Store.Bin,"fixture-client.zip");
        ClientPackage.Export(export,Crypto.Seal(Json.Encode(bundle),TestPassword));
        using(var zip=ZipFile.OpenRead(export)) {
            Check("universal ZIP contains installer and encrypted enrollment",zip.Entries.Count==3 && zip.GetEntry("Ycsz-Client-Setup.exe")!=null && zip.GetEntry("client.ycsz")!=null);
            using(var input=zip.GetEntry("client.ycsz").Open()) using(var bytes=new MemoryStream()) { input.CopyTo(bytes); var exported=Json.Decode<Enrollment>(Crypto.Open(bytes.ToArray(),TestPassword)); Check("export is reusable without device identity",exported.Universal && exported.ClientId==null && exported.BundleId==bundle.BundleId); }
        }
        string small=ClientPackage.ResolveInstaller(false);
        Check("runtime choice selects distinct installers",small!=ClientPackage.ResolveInstaller(true));
        ClientPackage.Export(export,Crypto.Seal(Json.Encode(bundle),TestPassword),small,false);
        using(var zip=ZipFile.OpenRead(export)) {
            using(var input=zip.GetEntry("Ycsz-Client-Setup.exe").Open()) using(var bytes=new MemoryStream()) { input.CopyTo(bytes); Check("runtime-free export uses selected installer bytes",Convert.ToBase64String(bytes.ToArray())==Convert.ToBase64String(File.ReadAllBytes(small))); }
            using(var reader=new StreamReader(zip.GetEntry("安装说明.txt").Open())) Check("runtime-free export explains prerequisite",reader.ReadToEnd().Contains("不内置运行库"));
        }
        Call("disable-bundles",session);
        var third=EnrollmentRegistry.NewIdentity(bundle,"LAB-THIRD"); Check("disabled bundle blocks new devices",!Register(local,third).Ok);
        Check("disabling bundle preserves existing device heartbeat",Wire.Heartbeat(a,Beat("LAB-RENAMED")).Ok);
        Call("logout",session);
    }
    static Packet Register(Enrollment bundle,Enrollment node) { return Wire.Heartbeat(bundle,new Packet { Op="register",Id=node.ClientId,Token=bundle.Token,Data=node.Token,BundleId=bundle.BundleId,Name=node.Name }); }
    static Packet Beat(string name) { return new Packet { Op="heartbeat",Name=name,Status="test fixture",Events=new System.Collections.Generic.List<SecurityEvent>(),Network=new NetworkSnapshot { HostsBase64="" } }; }
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool LogonUser(string user,string domain,string password,int type,int provider,out IntPtr token);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr OpenSCManager(string machine,string database,uint access);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr OpenService(IntPtr scm,string name,uint access);
    [DllImport("advapi32.dll")] static extern bool CloseServiceHandle(IntPtr handle);
    [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint access,bool inherit,int pid);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
}
