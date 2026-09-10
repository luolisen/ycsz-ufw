using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;

namespace Ycsz {
    public sealed class Guard : IDisposable {
        readonly Settings settings; ClientDisk disk; readonly object sync=new object();
        readonly AutoResetEvent wake=new AutoResetEvent(false); readonly Queue<NetworkSnapshot> requested=new Queue<NetworkSnapshot>();
        Thread monitor,network,processes; volatile bool stopping,prepared; Wfp firewall; Audit audit;
        string status="启动中"; DateTime nextNetwork=DateTime.MinValue,nextRules=DateTime.MinValue,nextProxy=DateTime.MinValue;
        bool dirty; readonly Dictionary<string,DateTime> recent=new Dictionary<string,DateTime>();
        public Guard(Settings s) {
            settings=s; disk=Store.Load<ClientDisk>("client.bin");
            if(!disk.CleanStop) Report("service_recovered","上次服务未正常结束，已由服务管理器恢复",true);
            disk.CleanStop=false; Persist();
            monitor=new Thread(Monitor) { IsBackground=true }; network=new Thread(SyncLoop) { IsBackground=true }; processes=new Thread(()=> { while(!stopping) { if(!prepared) Try("process_scan",ScanProcesses); Thread.Sleep(1000); } }) { IsBackground=true }; processes.Start(); monitor.Start(); network.Start();
        }
        void Persist() { lock(sync) { Store.Save("client.bin",disk); dirty=false; } }
        public void Report(string kind,string detail,bool success) { Report(new SecurityEvent { Kind=kind,Detail=detail,Success=success }); }
        void Report(SecurityEvent item) {
            lock(sync) {
                item.Detail=(item.Detail??""); if(item.Detail.Length>1024) item.Detail=item.Detail.Substring(0,1024);
                string key=item.Kind+"|"+item.Detail; DateTime last;
                if(recent.TryGetValue(key,out last) && DateTime.UtcNow-last<TimeSpan.FromSeconds(30)) return;
                if(recent.Count>4096) recent.Clear(); recent[key]=DateTime.UtcNow;
                if(disk.Events.Count>=2000) { disk.Events.RemoveAt(0); disk.DroppedEvents++; Store.Log("Event queue full: oldest event evicted"); }
                disk.Events.Add(item); disk.History.Add(item); if(disk.History.Count>200) disk.History.RemoveAt(0); dirty=true;
            }
            Store.Log(item.Kind+" "+item.Success+" "+item.Detail);
        }
        void Monitor() {
            try {
                firewall=new Wfp();
                // Establish a minimal deny policy before slow DNS / baseline checks.
                firewall.Apply(new Policy { Allow=new List<string>(),Thawed=disk.Policy.Thawed },settings.Enrollment,x=>Report("bootstrap_warning",x,false));
                try { audit=new Audit(settings,firewall,Report); } catch(Exception e) { Report("audit_unavailable",e.Message,false); }
                while(!stopping) {
                    if(prepared) { wake.WaitOne(1000); continue; }
                    Policy policy; long appliedNetwork,attemptedNetwork; lock(sync) { policy=Json.Copy(disk.Policy); appliedNetwork=disk.AppliedNetworkRevision; attemptedNetwork=disk.AttemptedNetworkRevision; }
                    if(DateTime.UtcNow>=nextRules) {
                        try {
                            firewall.Apply(policy,settings.Enrollment,x=>Report("dns_warning",x,false));
                            lock(sync) { disk.AppliedRevision=policy.Revision; dirty=true; status=policy.Thawed?"已解冻出口；进程及配置防护运行中":"已冻结出口；IP 白名单防护运行中"; }
                            lock(sync) nextRules=disk.Policy.Revision==policy.Revision?DateTime.UtcNow.AddMinutes(5):DateTime.MinValue;
                            Report("policy_applied","出口策略版本 "+policy.Revision+"；"+(policy.Thawed?"解冻":"冻结"),true);
                        } catch(Exception e) { Report("firewall_error",e.Message,false); lock(sync) status="出口规则更新失败；请查看事件"; nextRules=DateTime.UtcNow.AddSeconds(30); }
                    }
                    if(DateTime.UtcNow>=nextProxy) { Try("proxy_scan",CheckProxy); nextProxy=DateTime.UtcNow.AddSeconds(5); }
                    NetworkSnapshot change=null; lock(sync) if(requested.Count>0) change=requested.Dequeue();
                    if(change!=null) ApplyNetwork(change,0);
                    if(NetworkCommandGate.ShouldApply(policy,appliedNetwork,attemptedNetwork) && DateTime.UtcNow>=nextNetwork) ApplyNetwork(policy.Network,policy.NetworkRevision);
                    if(DateTime.UtcNow>=nextNetwork) { Try("network_scan",CheckNetwork); nextNetwork=DateTime.UtcNow.AddSeconds(15); }
                    if(dirty) Persist(); wake.WaitOne(1000);
                }
            } catch(Exception e) { Report("guard_fatal",e.ToString(),false); Persist(); Environment.Exit(2); }
        }
        void Try(string kind,Action action) { try { action(); } catch(Exception e) { Report(kind+"_error",e.Message,false); } }
        void ScanProcesses() {
            foreach(var p in Process.GetProcesses()) using(p) {
                ProcessScanner.Inspect(p,(kind,detail,success)=>Report(kind,detail,success));
            }
        }
        void CheckProxy() {
            string result=PowerShell.Run("proxy"); if(!String.IsNullOrWhiteSpace(result) && result!="null") Report("system_proxy",result,true);
            ProxyInfo info;
            if(!WinHttpGetDefaultProxyConfiguration(out info)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            try { if(info.AccessType!=1) { var direct=new ProxyInfo { AccessType=1 }; if(!WinHttpSetDefaultProxyConfiguration(ref direct)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()); Report("winhttp_proxy","已关闭 WinHTTP 系统代理",true); } }
            finally { if(info.Proxy!=IntPtr.Zero) GlobalFree(info.Proxy); if(info.Bypass!=IntPtr.Zero) GlobalFree(info.Bypass); }
        }
        void CheckNetwork() {
            NetworkSnapshot baseline; lock(sync) baseline=Json.Copy(disk.Baseline);
            var current=PowerShell.Capture(); var drift=NetworkCompare.Drift(baseline,current); if(drift.Count==0) return;
            Report("network_changed",String.Join("；",drift),false);
            try { PowerShell.Apply(baseline); var remaining=NetworkCompare.Drift(baseline,PowerShell.Capture()); Report("network_rollback",remaining.Count==0?"已恢复基线":String.Join("；",remaining),remaining.Count==0); }
            catch(Exception e) { Report("network_rollback",e.Message,false); }
        }
        void ApplyNetwork(NetworkSnapshot desired,long revision) {
            NetworkSnapshot old; long oldRevision; lock(sync) { old=Json.Copy(disk.Baseline); oldRevision=disk.AppliedNetworkRevision; }
            // Commit the attempt before touching the network. A crash or failed command
            // must not turn the next service loop into an endless disconnect/retry cycle.
            if(revision>0) {
                lock(sync) { disk.AttemptedNetworkRevision=revision; dirty=true; }
                try { Persist(); } catch(Exception e) { Report("network_attempt_save_failed",e.Message,false); return; }
            }
            try {
                PowerShell.Apply(desired); var current=PowerShell.Capture(); var drift=NetworkCompare.Drift(desired,current);
                if(drift.Count>0) throw new InvalidOperationException(String.Join("；",drift));
                if(revision>0) { var probe=Wire.Heartbeat(settings.Enrollment,new Packet { Op="heartbeat",Status="远程网络配置验证中",Network=current,Events=new List<SecurityEvent>(),Revision=disk.AppliedRevision,NetworkRevision=oldRevision }); if(!probe.Ok) throw new InvalidOperationException("新网络未通过管理端连通验证"); }
                lock(sync) { disk.Baseline=Json.Copy(desired); if(revision>0) disk.AppliedNetworkRevision=revision; dirty=true; }
                Persist(); nextRules=DateTime.MinValue; Report("network_authorized","授权基线已应用并复核，版本 "+revision,true);
            } catch(Exception e) { lock(sync) { disk.Baseline=old; disk.AppliedNetworkRevision=oldRevision; dirty=true; } Report("network_authorized",e.Message,false); Try("network_recovery",()=>PowerShell.Apply(old)); }
            nextNetwork=DateTime.UtcNow.AddSeconds(15);
        }
        void SyncLoop() {
            while(!stopping) {
                if(!prepared) try {
                    Packet outgoing; lock(sync) outgoing=new Packet { Op="heartbeat",Status=CurrentStatus()+"；离线队列丢弃总数="+disk.DroppedEvents,Revision=disk.AppliedRevision,NetworkRevision=disk.AppliedNetworkRevision,Network=Json.Copy(disk.Baseline),Events=disk.Events.Take(64).Select(Json.Copy).ToList() };
                    var response=Wire.Heartbeat(settings.Enrollment,outgoing);
                    if(!response.Ok || response.Policy==null) throw new InvalidOperationException(response.Error??"策略缺失");
                    response.Policy.Allow=Rules.Validate(response.Policy.Allow); if(response.Policy.Network!=null) response.Policy.Network.Validate();
                    lock(sync) {
                        var sent=new HashSet<string>(outgoing.Events.Select(e=>e.Id)); disk.Events.RemoveAll(e=>sent.Contains(e.Id));
                        if(response.Policy.Revision>disk.Policy.Revision) { disk.Policy=Json.Copy(response.Policy); nextRules=DateTime.MinValue; }
                        else if(response.Policy.Revision==disk.Policy.Revision && disk.AppliedRevision==0) disk.Policy=Json.Copy(response.Policy);
                        dirty=true;
                    }
                    Persist();
                } catch(Exception e) { Report("manager_offline",e.Message,false); }
                for(int i=0;i<10&&!stopping;i++) Thread.Sleep(1000);
            }
        }
        string CurrentStatus() {
            if(disk.Policy.NetworkRevision>disk.AppliedNetworkRevision) return status+(disk.AttemptedNetworkRevision>=disk.Policy.NetworkRevision?"；网络配置未成功，需管理员重新下发":"；网络配置待应用");
            return status;
        }
        public Packet Command(Packet p) {
            lock(sync) {
                if(p.Op=="status") return new Packet { Ok=true,Status=CurrentStatus() };
                if(p.Op=="details") return new Packet { Ok=true,Data=Json.Encode(new ClientState { Id=settings.Enrollment.ClientId,Name=Environment.MachineName,Status=CurrentStatus(),Network=disk.Baseline,Policy=disk.Policy,AppliedRevision=disk.AppliedRevision,AppliedNetworkRevision=disk.AppliedNetworkRevision,Events=disk.History.ToList() }) };
                if(p.Op=="set-network") { if(p.Network==null) throw new ArgumentException("缺少基线"); p.Network.Validate(); if(requested.Count>0) throw new InvalidOperationException("上一次配置正在等待应用"); requested.Enqueue(Json.Copy(p.Network)); wake.Set(); return new Packet { Ok=true,Status="已排队，应用结果见事件" }; }
                if(p.Op=="accept-baseline") { if(requested.Count>0) throw new InvalidOperationException("存在待执行配置"); disk.Baseline=PowerShell.Capture(); Persist(); Report("baseline_accepted","本地管理员接纳当前网络状态",true); return new Packet { Ok=true }; }
                throw new ArgumentException("未知客户端操作");
            }
        }
        public void PrepareRemoval() { prepared=true; if(audit!=null) { audit.Dispose(); audit=null; } if(firewall!=null) firewall.RemoveAll(); Audit.Restore(settings); }
        public void Dispose() {
            stopping=true; wake.Set(); if(monitor!=null&&!monitor.Join(95000)) return; if(network!=null) network.Join(15000); if(processes!=null) processes.Join(3000);
            if(audit!=null) audit.Dispose(); if(firewall!=null) firewall.Dispose();
            lock(sync) { disk.CleanStop=true; Persist(); }
        }
        [StructLayout(LayoutKind.Sequential)] struct ProxyInfo { public uint AccessType; public IntPtr Proxy,Bypass; }
        [DllImport("winhttp.dll",SetLastError=true)] static extern bool WinHttpGetDefaultProxyConfiguration(out ProxyInfo info);
        [DllImport("winhttp.dll",SetLastError=true)] static extern bool WinHttpSetDefaultProxyConfiguration(ref ProxyInfo info);
        [DllImport("kernel32.dll")] static extern IntPtr GlobalFree(IntPtr memory);
    }
}
