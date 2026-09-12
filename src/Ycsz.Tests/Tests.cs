using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using Ycsz;
static class Tests {
    static int count,failed;
    static void Test(string name,Action body) { count++; try { body(); Console.WriteLine("PASS "+name); } catch(Exception e) { failed++; Console.WriteLine("FAIL "+name+": "+e.Message); } }
    static void Is(bool value) { if(!value) throw new Exception("assertion failed"); }
    static void Throws(Action body) { bool caught=false; try { body(); } catch { caught=true; } Is(caught); }
    static NetworkSnapshot Snapshot() { return new NetworkSnapshot { HostsBase64=Convert.ToBase64String(new byte[]{35,10}),Adapters=new[]{new AdapterSnapshot { Id="7a04db5c-f8d7-45c7-a5d5-f258917218ed",Name="Ethernet",Enabled=true,Dhcp=true,DnsAutomatic=true,Bindings=new[]{"ms_tcpip","ms_tcpip6"} }} }; }
    static Enrollment Bundle() { return new Enrollment { Universal=true,BundleId=Guid.NewGuid().ToString("N"),Host="192.0.2.10",CertificateHash=new string('a',64),Token=Crypto.Token() }; }
    static ManagerState Registry(Enrollment e) { var s=new ManagerState(); s.Bundles.Add(new EnrollmentBundle { Id=e.BundleId,Token=e.Token }); return s; }
    static Packet Register(Enrollment b,Enrollment n) { return new Packet { Op="register",Id=n.ClientId,BundleId=b.BundleId,Token=b.Token,Data=n.Token,Name=n.Name }; }
    static int Main() {
        Test("all 20 requested executable names covered",()=> { Is(Defaults.Processes.Count==20); foreach(var name in new[]{"V2RAY.EXE","xray.exe","shadowsocks-libev.exe","server-win.exe","trojan.exe","hysteria.exe","hy.exe","tuic-client.exe","tuic-server.exe","sing-box.exe","mihomo.exe","clash.exe","naiveproxy.exe","v2rayN.exe","clash for windows.exe","clash-verge.exe","mihomo-party.exe","netch.exe","furious.exe","hiddify.exe"}) Is(Defaults.Processes.ContainsKey(name)); Is(!Defaults.Processes.ContainsKey("my-v2ray.exe")); });
        Test("password salt and verification",()=> { var a=Crypto.HashPassword("test-only-password-123"); var b=Crypto.HashPassword("test-only-password-123"); Is(a.Salt!=b.Salt && a.Hash!=b.Hash); Is(Crypto.Verify("test-only-password-123",a)); Is(!Crypto.Verify("wrong",a)); Is(!Crypto.Verify(null,a)); });
        Test("password length bounded",()=> { Throws(()=>Crypto.HashPassword("short")); Throws(()=>Crypto.HashPassword(new string('x',257))); });
        Test("constant comparison length differences",()=> { Is(Crypto.Equal(new byte[]{1,2},new byte[]{1,2})); Is(!Crypto.Equal(new byte[]{1},new byte[]{1,0})); Is(!Crypto.EqualText(null,null)); });
        Test("enrollment authenticated encryption",()=> { string password="enrollment-test-123"; var payload=Crypto.Seal("机房 test",password); Is(Crypto.Open(payload,password)=="机房 test"); Throws(()=>Crypto.Open(payload,"different-password")); payload[55]^=1; Throws(()=>Crypto.Open(payload,password)); });
        Test("envelope truncation rejected",()=> { Throws(()=>Crypto.Open(new byte[20],"enrollment-test-123")); });
        Test("allowlist normalizes and deduplicates",()=> { Is(Rules.Normalize(" WWW.GOV.CN ")=="www.gov.cn"); Is(Rules.Normalize("192.168.1.88/24")=="192.168.1.0/24"); Is(Rules.Normalize("2001:db8::1/64")=="2001:db8::/64"); Is(Rules.Validate(new[]{"a.cn","A.CN"," "}).Count==1); });
        Test("injection and broad CIDR rejected",()=> { foreach(var bad in new[]{"https://gov.cn/path","*.gov.cn","a.cn;whoami","0.0.0.0/0","::/0","1.2.3.4/99","a.cn:443","localhost","1.2.3.4\nwhoami","fe80::1%3","a..cn"}) Throws(()=>Rules.Normalize(bad)); });
        Test("wire frame round trip",()=> { using(var ms=new MemoryStream()) { Wire.Send(ms,new Packet { Op="heartbeat",Data="汉字" }); ms.Position=0; Is(Wire.Receive(ms).Data=="汉字"); } });
        Test("wire oversized and negative rejected before allocation",()=> { foreach(var n in new[]{-1,0,Wire.MaxFrame+1}) using(var ms=new MemoryStream(BitConverter.GetBytes(IPAddress.HostToNetworkOrder(n)))) Throws(()=>Wire.Receive(ms)); });
        Test("wire truncated body rejected",()=> { using(var ms=new MemoryStream(new byte[]{0,0,0,10,123})) Throws(()=>Wire.Receive(ms)); });
        Test("network baseline round trip",()=> { var b=Snapshot(); b.Validate(); Is(NetworkCompare.Drift(b,Json.Copy(b)).Count==0); });
        Test("hosts and bindings drift detected",()=> { var b=Snapshot(); var c=Json.Copy(b); c.HostsBase64=Convert.ToBase64String(new byte[]{1}); c.Adapters[0].Bindings=new[]{"ms_tcpip"}; Is(NetworkCompare.Drift(b,c).Count==2); });
        Test("missing and new adapters handled",()=> { var b=Snapshot(); var c=Json.Copy(b); c.Adapters[0].Id=Guid.NewGuid().ToString(); Is(NetworkCompare.Drift(b,c).Count==2); c.Adapters[0].Enabled=false; Is(NetworkCompare.Drift(b,c).Count==1); });
        Test("network arbitrary binding and bad IP rejected",()=> { var b=Snapshot(); b.Adapters[0].Bindings=new[]{"a;whoami"}; Throws(()=>b.Validate()); b=Snapshot(); b.Adapters[0].Dns=new[]{"x;whoami"}; Throws(()=>b.Validate()); });
        Test("WFP GUID constants valid",()=> { Is(Wfp.ProviderKey!=Guid.Empty); Is(Wfp.SublayerKey!=Guid.Empty); });
        Test("WFP x64 ABI sizes",()=> { Is(IntPtr.Size==8); Is(Marshal.SizeOf(typeof(Wfp.Value))==16); Is(Marshal.SizeOf(typeof(Wfp.Condition))==40); Is(Marshal.SizeOf(typeof(Wfp.Filter))==200); Is(Marshal.SizeOf(typeof(Wfp.Sublayer))==72); Is(Marshal.SizeOf(typeof(Wfp.Provider))==64); });
        Test("WFP critical x64 offsets",()=> { Is(Marshal.OffsetOf(typeof(Wfp.Filter),"Action").ToInt32()==128); Is(Marshal.OffsetOf(typeof(Wfp.Filter),"Context").ToInt32()==152); Is(Marshal.OffsetOf(typeof(Wfp.Filter),"Id").ToInt32()==176); });
        Test("self protection IOCTL ABI stays fixed",()=> { Is(SelfProtectionProtocol.Version==4); Is(WindowsSelfProtectionTransport.ControlHeaderSize==16); Is(WindowsSelfProtectionTransport.ProcessIdentitySize==1088); Is(WindowsSelfProtectionTransport.ActivateRequestSize==3160); Is(WindowsSelfProtectionTransport.InitializeCommitRequestSize==40); Is(WindowsSelfProtectionTransport.InitializeAbortRequestSize==32); Is(WindowsSelfProtectionTransport.InitializationEntryRequestSize==56); Is(WindowsSelfProtectionTransport.TrayRequestSize==1104); Is(WindowsSelfProtectionTransport.MaintenanceRequestSize==40); Is(WindowsSelfProtectionTransport.UnloadRequestSize==32); Is(WindowsSelfProtectionTransport.StatusSize==4296); Is(WindowsSelfProtectionTransport.BeginInitializeIoctl==0x8000e000u); Is(WindowsSelfProtectionTransport.CommitInitializeIoctl==0x8000e01cu); Is(WindowsSelfProtectionTransport.AbortInitializeIoctl==0x8000e020u); Is(WindowsSelfProtectionTransport.DeclareInitializationEntryIoctl==0x8000e024u); Is(WindowsSelfProtectionTransport.EnterMaintenanceIoctl==0x8000e004u); Is(WindowsSelfProtectionTransport.ExitMaintenanceIoctl==0x8000e008u); Is(WindowsSelfProtectionTransport.QueryStatusIoctl==0x8000e00cu); Is(WindowsSelfProtectionTransport.PrepareUnloadIoctl==0x8000e010u); Is(WindowsSelfProtectionTransport.RegisterTrayIoctl==0x8000e014u); Is(WindowsSelfProtectionTransport.UnregisterTrayIoctl==0x8000e018u); });
        Test("default IPv4 and IPv6 routes valid",()=> { var b=Snapshot(); b.Adapters[0].Routes=new[]{new RouteSetting { Prefix="0.0.0.0/0",NextHop="192.168.1.1",Metric=5 },new RouteSetting { Prefix="::/0",NextHop="fe80::1",Metric=10 }}; b.Validate(); });
        Test("route family mismatch rejected",()=> { var b=Snapshot(); b.Adapters[0].Routes=new[]{new RouteSetting { Prefix="::/0",NextHop="192.168.1.1",Metric=5 }}; Throws(()=>b.Validate()); });
        Test("IPv6 DNS and router discovery drift",()=> { var b=Snapshot(); var c=Json.Copy(b); c.Adapters[0].RouterDiscovery=false; c.Adapters[0].DnsV6Automatic=false; c.Adapters[0].DnsV6=new[]{"2001:db8::53"}; Is(NetworkCompare.Drift(b,c).Count==1); });
        Test("automatic DNS lease changes ignored",()=> { var b=Snapshot(); var c=Json.Copy(b); c.Adapters[0].Dns=new[]{"192.168.1.1"}; c.Adapters[0].DnsV6=new[]{"2001:db8::53"}; Is(NetworkCompare.Drift(b,c).Count==0); });
        Test("binding and address order ignored",()=> { var b=Snapshot(); var c=Json.Copy(b); c.Adapters[0].Bindings=c.Adapters[0].Bindings.Reverse().ToArray(); Is(NetworkCompare.Drift(b,c).Count==0); });
        Test("duplicate adapters rejected",()=> { var b=Snapshot(); b.Adapters=new[]{b.Adapters[0],Json.Copy(b.Adapters[0])}; Throws(()=>b.Validate()); });
        Test("empty hosts baseline valid",()=> { var b=Snapshot(); b.HostsBase64=""; b.Validate(); });
        Test("huge hosts rejected",()=> { var b=Snapshot(); b.HostsBase64=new string('A',350004); Throws(()=>b.Validate()); });
        Test("bounded whitelist count",()=> { Throws(()=>Rules.Validate(Enumerable.Range(1,513).Select(i=>"host"+i+".cn"))); Is(Rules.Validate(new string[0]).Count==0); });
        Test("null certificate rejected",()=>Is(!Wire.CertificateAccepted(null,"abc")));
        Test("wire JSON null rejected",()=> { using(var ms=new MemoryStream()) { var body=System.Text.Encoding.UTF8.GetBytes("null"); var size=BitConverter.GetBytes(IPAddress.HostToNetworkOrder(body.Length)); ms.Write(size,0,4); ms.Write(body,0,body.Length); ms.Position=0; Throws(()=>Wire.Receive(ms)); } });
        Test("session login backoff",()=> { var record=Crypto.HashPassword("login-gate-test-123"); var gate=new LoginGate(); Is(!gate.Check("incorrect",record)); Is(!gate.Check("login-gate-test-123",record)); });
        Test("deleted empty hosts differs from existing empty hosts",()=> { var b=Snapshot(); b.HostsBase64=""; var c=Json.Copy(b); c.HostsExists=false; c.Validate(); Is(NetworkCompare.Drift(b,c).Count==1); });
        Test("absent hosts cannot carry contradictory content",()=> { var b=Snapshot(); b.HostsExists=false; Throws(()=>b.Validate()); });
        Test("failed network revision does not repeat after restart",()=> {
            var disk=new ClientDisk { Policy=new Policy { Network=Snapshot(),NetworkRevision=1 } };
            Is(NetworkCommandGate.ShouldApply(disk.Policy,disk.AppliedNetworkRevision,disk.AttemptedNetworkRevision));
            disk.AttemptedNetworkRevision=1;
            disk=Json.Copy(disk); // durable attempt marker is retained while applied version remains zero
            Is(!NetworkCommandGate.ShouldApply(disk.Policy,disk.AppliedNetworkRevision,disk.AttemptedNetworkRevision));
            disk.Policy.NetworkRevision=2;
            Is(NetworkCommandGate.ShouldApply(disk.Policy,disk.AppliedNetworkRevision,disk.AttemptedNetworkRevision));
        });
        Test("applied and empty network commands are not repeated",()=> {
            Is(!NetworkCommandGate.ShouldApply(new Policy { Network=Snapshot(),NetworkRevision=3 },3,2));
            Is(!NetworkCommandGate.ShouldApply(new Policy { NetworkRevision=4 },0,0));
        });
        Test("one universal bundle creates independent same-name machines",()=> {
            var bundle=Bundle(); var state=Registry(bundle); var a=EnrollmentRegistry.NewIdentity(bundle,"LAB-PC"); var b=EnrollmentRegistry.NewIdentity(bundle,"LAB-PC");
            EnrollmentRegistry.Register(state,Register(bundle,a)); EnrollmentRegistry.Register(state,Register(bundle,b));
            Is(state.Clients.Count==2 && a.ClientId!=b.ClientId && a.Token!=b.Token && a.Token!=bundle.Token);
            Is(state.Clients.All(c=>c.Name=="LAB-PC"));
        });
        Test("registration retry preserves policy and identity after serialization",()=> {
            var bundle=Bundle(); var state=Registry(bundle); var a=EnrollmentRegistry.NewIdentity(bundle,"LAB-01"); var node=EnrollmentRegistry.Register(state,Register(bundle,a)); node.Policy.Thawed=true; node.Policy.Revision=7;
            state=Json.Copy(state); var retry=EnrollmentRegistry.Register(state,Register(bundle,a)); Is(state.Clients.Count==1 && retry.Policy.Thawed && retry.Policy.Revision==7);
        });
        Test("shared bundle cannot overwrite another machine identity",()=> {
            var bundle=Bundle(); var state=Registry(bundle); var a=EnrollmentRegistry.NewIdentity(bundle,"LAB-01"); EnrollmentRegistry.Register(state,Register(bundle,a));
            var bad=Register(bundle,a); bad.Data=Crypto.Token(); Throws(()=>EnrollmentRegistry.Register(state,bad)); Is(state.Clients[0].Token==a.Token);
        });
        Test("revoked node cannot re-enroll with old identity",()=> {
            var bundle=Bundle(); var state=Registry(bundle); var a=EnrollmentRegistry.NewIdentity(bundle,"LAB-01"); EnrollmentRegistry.Register(state,Register(bundle,a)).Revoked=true;
            Throws(()=>EnrollmentRegistry.Register(state,Register(bundle,a))); Is(state.Clients[0].Revoked);
        });
        Test("disabled and incorrect bundle tokens reject registration",()=> {
            var bundle=Bundle(); var state=Registry(bundle); var a=EnrollmentRegistry.NewIdentity(bundle,"LAB-01"); var request=Register(bundle,a); request.Token=Crypto.Token();
            Throws(()=>EnrollmentRegistry.Register(state,request)); state.Bundles.Clear(); Throws(()=>EnrollmentRegistry.Register(state,Register(bundle,a))); Is(state.Clients.Count==0);
        });
        Test("malformed machine data rejected before state mutation",()=> {
            var bundle=Bundle(); var state=Registry(bundle); var a=EnrollmentRegistry.NewIdentity(bundle,"LAB-01");
            foreach(var name in new[]{"",new string('a',64),"bad\nname"," padded"}) { var p=Register(bundle,a); p.Name=name; Throws(()=>EnrollmentRegistry.Register(state,p)); }
            var bad=Register(bundle,a); bad.Id="../settings"; Throws(()=>EnrollmentRegistry.Register(state,bad)); bad=Register(bundle,a); bad.Data="short"; Throws(()=>EnrollmentRegistry.Register(state,bad)); Is(state.Clients.Count==0);
        });
        Test("device quota enforced but authenticated retries still allowed",()=> {
            var bundle=Bundle(); var state=Registry(bundle); var a=EnrollmentRegistry.NewIdentity(bundle,"LAB-01"); EnrollmentRegistry.Register(state,Register(bundle,a));
            while(state.Clients.Count<64) state.Clients.Add(new ClientState { Id=Guid.NewGuid().ToString("N") });
            Throws(()=>EnrollmentRegistry.Register(state,Register(bundle,EnrollmentRegistry.NewIdentity(bundle,"LAB-65")))); Is(EnrollmentRegistry.Register(state,Register(bundle,a)).Id==a.ClientId);
        });
        Test("pending identity must match bundle endpoint and certificate",()=> {
            var bundle=Bundle(); var a=EnrollmentRegistry.NewIdentity(bundle,"LAB-01"); Is(EnrollmentRegistry.SameBundle(a,bundle)); bundle.CertificateHash=new string('b',64); Is(!EnrollmentRegistry.SameBundle(a,bundle));
        });
        Test("legacy enrollment remains readable",()=> { var legacy=EnrollmentRegistry.NewIdentity(Bundle(),"LAB-01"); legacy.BundleId=null; EnrollmentRegistry.Validate(Json.Copy(legacy)); });
        Test("universal bundle never is a device credential",()=> { var bundle=Bundle(); EnrollmentRegistry.Validate(bundle); Is(bundle.ClientId==null); var node=EnrollmentRegistry.NewIdentity(bundle,"LAB-01"); Is(!node.Universal); });
        Test("tray supervisor recovers an exited tray after backoff",()=> {
            var source=new FakeSessionSource { Current=1 }; var runtime=new FakeTrayRuntime(); var messages=new List<string>();
            var options=new TraySupervisorOptions { PollInterval=TimeSpan.FromSeconds(1),InitialRetryDelay=TimeSpan.FromSeconds(5),MaximumRetryDelay=TimeSpan.FromSeconds(20),LogThrottle=TimeSpan.FromMinutes(1) };
            var supervisor=new TraySupervisor(source,runtime,m=>messages.Add(m),options); var t=DateTime.UtcNow;
            supervisor.Tick(t); Is(runtime.StartCount==1 && supervisor.CurrentSessionId==1); runtime.Started[0].Exited=true;
            supervisor.Tick(t.AddSeconds(1)); Is(runtime.StartCount==1); supervisor.Tick(t.AddSeconds(5)); Is(runtime.StartCount==1); supervisor.Tick(t.AddSeconds(6)); Is(runtime.StartCount==2 && messages.Count==1); supervisor.Dispose();
        });
        Test("tray supervisor adopts an existing real instance without duplicate start",()=> {
            var source=new FakeSessionSource { Current=2 }; var runtime=new FakeTrayRuntime { Existing=new FakeTrayProcess() }; var supervisor=new TraySupervisor(source,runtime, null);
            supervisor.Tick(DateTime.UtcNow); supervisor.Tick(DateTime.UtcNow.AddSeconds(10)); Is(runtime.StartCount==0 && runtime.FindCount==1); supervisor.Dispose(); Is(runtime.Existing.Disposed);
        });
        Test("tray supervisor releases instance when interactive session exits",()=> {
            var source=new FakeSessionSource { Current=3 }; var runtime=new FakeTrayRuntime(); var supervisor=new TraySupervisor(source,runtime,null); supervisor.Tick(DateTime.UtcNow); Is(runtime.StartCount==1);
            source.Current=null; supervisor.Tick(DateTime.UtcNow.AddSeconds(1)); Is(runtime.Started[0].Disposed && supervisor.CurrentSessionId==-1); supervisor.Dispose();
        });
        Test("tray supervisor backs off repeated launch failures",()=> {
            var source=new FakeSessionSource { Current=4 }; var runtime=new FakeTrayRuntime { FailStart=true }; var messages=new List<string>();
            var options=new TraySupervisorOptions { PollInterval=TimeSpan.FromSeconds(1),InitialRetryDelay=TimeSpan.FromSeconds(5),MaximumRetryDelay=TimeSpan.FromSeconds(20),LogThrottle=TimeSpan.FromMinutes(1) };
            var supervisor=new TraySupervisor(source,runtime,m=>messages.Add(m),options); var t=DateTime.UtcNow;
            supervisor.Tick(t); supervisor.Tick(t.AddSeconds(4)); Is(runtime.StartCount==1); supervisor.Tick(t.AddSeconds(5)); Is(runtime.StartCount==2); supervisor.Tick(t.AddSeconds(10)); Is(runtime.StartCount==2 && supervisor.NextAttemptUtc==t.AddSeconds(15)); Is(messages.Count==1); supervisor.Dispose();
        });
        Test("tray rapid crashes retain backoff until stable uptime",()=> {
            var runtime=new FakeTrayRuntime(); var supervisor=new TraySupervisor(new FakeSessionSource { Current=1 },runtime,null); var t=DateTime.UtcNow;
            supervisor.Tick(t); runtime.Started[0].Exited=true; supervisor.Tick(t.AddSeconds(1)); supervisor.Tick(t.AddSeconds(6));
            runtime.Started[1].Exited=true; supervisor.Tick(t.AddSeconds(7)); Is(supervisor.ConsecutiveFailures==2 && supervisor.NextAttemptUtc==t.AddSeconds(17));
            supervisor.Tick(t.AddSeconds(12)); Is(runtime.StartCount==2); supervisor.Tick(t.AddSeconds(17)); Is(runtime.StartCount==3);
            supervisor.Tick(t.AddSeconds(78)); Is(supervisor.ConsecutiveFailures==0); supervisor.Dispose();
        });
        Test("normal maintenance stop prevents tray relaunch",()=> {
            var source=new FakeSessionSource { Current=5 }; var runtime=new FakeTrayRuntime(); var supervisor=new TraySupervisor(source,runtime,null); supervisor.Tick(DateTime.UtcNow); supervisor.Stop(TrayStopReason.Maintenance); runtime.Started[0].Exited=true; supervisor.Tick(DateTime.UtcNow.AddMinutes(1)); Is(runtime.StartCount==1 && supervisor.IsStopping && runtime.Started[0].Disposed); supervisor.Dispose();
        });
        Test("file identity preflight rejects aliases, reparse points and unreadable entries",()=> {
            var result=SelfProtectionFilePreflight.Evaluate(new[] {
                Observation("bin/Ycsz.exe",7,11,false,true,false),
                Observation("data/state.db",7,12,false,true,false),
                Observation("alias/state.db",7,12,false,true,false,2),
                Observation("junction",7,13,true,true,true),
                Observation("locked.dat",7,14,false,false,false)
            });
            Is(!result.Passed && !result.MappingWritebackConditionMet && result.ScannedEntries==5 && result.Issues.Count>=3);
        });
        Test("file identity preflight passes only unique readable identities",()=> {
            var result=SelfProtectionFilePreflight.Evaluate(new[] {
                Observation("bin/Ycsz.exe",7,11,false,true,false),
                Observation("data",7,12,false,true,true),
                Observation("data/state.db",7,13,false,true,false)
            });
            Is(result.Passed && !result.MappingWritebackConditionMet && result.ScannedEntries==3 && result.InitializationEntries.Count==3 && result.Issues.Count==0);
        });
        Test("file identity manifest separates volumes with the same file index",()=> {
            var result=SelfProtectionFilePreflight.Evaluate(new[] {
                Observation("volume-a",1,7,false,true,true),
                Observation("volume-b",2,7,false,true,false)
            });
            Is(result.Passed && result.InitializationEntries.Count==2 && result.InitializationEntries[0].IsDirectory && !result.InitializationEntries[1].IsDirectory);
        });
        Test("file identity preflight requires handle and path attributes to agree",()=> {
            var observation=Observation("state",7,12,false,true,false); observation.AttributesConsistent=false;
            var result=SelfProtectionFilePreflight.Evaluate(new[] { observation });
            Is(!result.Passed && result.Issues.Any(issue=>issue.IndexOf("句柄属性",StringComparison.Ordinal)>=0));
        });
        Test("activation preflight fails before transport and does not claim mapped-write protection",()=> {
            var full=SelfProtectionCapability.ProcessTermination|SelfProtectionCapability.FileMutation;
            var transport=new FakeProtectionTransport(new SelfProtectionReply { Accepted=true,DriverLoaded=true,Capabilities=full });
            var coordinator=new SelfProtectionCoordinator(transport,Identity,(session,op)=>true,TimeSpan.FromMinutes(5),()=>SelfProtectionFilePreflight.Evaluate(new[] { Observation("alias",7,12,false,true,false),Observation("state",7,12,false,true,false) }));
            Is(!coordinator.Activate(DateTime.UtcNow) && transport.Requests.Count==0 && coordinator.Status.State==SelfProtectionState.Failed && !coordinator.Status.MappingWritebackConditionMet);
        });
        Test("successful file preflight does not prove mapped-write protection",()=> {
            var full=SelfProtectionCapability.ProcessTermination|SelfProtectionCapability.FileMutation;
            var transport=new FakeProtectionTransport(new SelfProtectionReply { Accepted=true,DriverLoaded=true,Capabilities=full });
            var coordinator=new SelfProtectionCoordinator(transport,Identity,(session,op)=>true,TimeSpan.FromMinutes(5),()=>SelfProtectionFilePreflight.Evaluate(new[] { Observation("state",7,12,false,true,false) }));
            Is(coordinator.Activate(DateTime.UtcNow) && transport.Requests.Count==3 && transport.Requests[0].Operation==SelfProtectionOperation.BeginInitialize && transport.Requests[1].Operation==SelfProtectionOperation.DeclareInitializationEntry && transport.Requests[2].Operation==SelfProtectionOperation.CommitInitialize && !coordinator.Status.MappingWritebackConditionMet && coordinator.Status.UserText().IndexOf("映射写回条件未满足",StringComparison.Ordinal)>=0);
        });
        Test("activation keeps protection in initializing until the second scan and commit",()=> {
            var full=SelfProtectionCapability.ProcessTermination|SelfProtectionCapability.FileMutation; var transport=new FakeProtectionTransport(new SelfProtectionReply { Accepted=true,DriverLoaded=true,Capabilities=full });
            SelfProtectionCoordinator coordinator=null; int scans=0;
            coordinator=new SelfProtectionCoordinator(transport,Identity,(session,op)=>true,TimeSpan.FromMinutes(5),()=> { scans++; if(scans==2) Is(coordinator.Status.State==SelfProtectionState.Initializing && !coordinator.Status.ProcessProtectionActive); return GoodPreflight(); });
            Is(coordinator.Activate(DateTime.UtcNow)); Is(scans==2 && coordinator.Status.State==SelfProtectionState.Active && transport.Requests.Count==3 && transport.Requests[0].Operation==SelfProtectionOperation.BeginInitialize && transport.Requests[1].Operation==SelfProtectionOperation.DeclareInitializationEntry && transport.Requests[2].Operation==SelfProtectionOperation.CommitInitialize);
        });
        Test("second scan failure aborts initialization and never publishes active",()=> {
            var full=SelfProtectionCapability.ProcessTermination|SelfProtectionCapability.FileMutation; var transport=new FakeProtectionTransport(new SelfProtectionReply { Accepted=true,DriverLoaded=true,Capabilities=full }); int scans=0;
            var coordinator=new SelfProtectionCoordinator(transport,Identity,(session,op)=>true,TimeSpan.FromMinutes(5),()=> ++scans==1?GoodPreflight():SelfProtectionFilePreflight.Evaluate(new[] { Observation("alias",7,12,false,true,false),Observation("state",7,12,false,true,false) }));
            Is(!coordinator.Activate(DateTime.UtcNow) && coordinator.Status.State==SelfProtectionState.Failed && !coordinator.Status.DriverLoaded && transport.Requests.Count==3 && transport.Requests[0].Operation==SelfProtectionOperation.BeginInitialize && transport.Requests[1].Operation==SelfProtectionOperation.DeclareInitializationEntry && transport.Requests[2].Operation==SelfProtectionOperation.AbortInitialize);
        });
        Test("successful second scan with changed identities aborts before commit",()=> {
            var changed=new[] {
                new[] { Observation("state",7,13,false,true,false) },
                new[] { Observation("state",8,12,false,true,false) },
                new[] { Observation("state",7,12,false,true,false),Observation("new",7,13,false,true,false) }
            };
            foreach(var observations in changed) {
                int scans=0;
                var transport=new FakeProtectionTransport(new SelfProtectionReply { Accepted=true,DriverLoaded=true,Capabilities=SelfProtectionCapability.ProcessTermination|SelfProtectionCapability.FileMutation });
                var coordinator=new SelfProtectionCoordinator(transport,Identity,(session,op)=>true,TimeSpan.FromMinutes(5),()=> ++scans==1?GoodPreflight():SelfProtectionFilePreflight.Evaluate(observations));
                Is(!coordinator.Activate(DateTime.UtcNow) && coordinator.Status.State==SelfProtectionState.Failed);
                Is(transport.Requests.Count==3 && transport.Requests[2].Operation==SelfProtectionOperation.AbortInitialize);
            }
        });
        Test("commit failure aborts initialization without changing a stable active target",()=> {
            var full=SelfProtectionCapability.ProcessTermination|SelfProtectionCapability.FileMutation; var transport=new FakeProtectionTransport(new SelfProtectionReply { Accepted=true,DriverLoaded=true,Capabilities=full }); transport.FailCommit=true;
            var coordinator=new SelfProtectionCoordinator(transport,Identity,(session,op)=>true,TimeSpan.FromMinutes(5),()=>GoodPreflight());
            Is(!coordinator.Activate(DateTime.UtcNow) && coordinator.Status.State==SelfProtectionState.Failed && transport.Requests.Count==4 && transport.Requests[2].Operation==SelfProtectionOperation.CommitInitialize && transport.Requests[3].Operation==SelfProtectionOperation.AbortInitialize);
        });
        Test("active on the begin reply is rejected as a race",()=> {
            var full=SelfProtectionCapability.ProcessTermination|SelfProtectionCapability.FileMutation; var transport=new FakeProtectionTransport(new SelfProtectionReply { Accepted=true,DriverLoaded=true,Capabilities=full,Phase=SelfProtectionPhase.Active }); transport.PreserveBeginPhase=true;
            var coordinator=new SelfProtectionCoordinator(transport,Identity,(session,op)=>true,TimeSpan.FromMinutes(5),()=>GoodPreflight());
            Is(!coordinator.Activate(DateTime.UtcNow) && coordinator.Status.State==SelfProtectionState.Failed && transport.Requests.Count==2 && transport.Requests[0].Operation==SelfProtectionOperation.BeginInitialize && transport.Requests[1].Operation==SelfProtectionOperation.AbortInitialize);
        });
        Test("self protection never reports active when driver is unavailable",()=> {
            var transport=new FakeProtectionTransport(new SelfProtectionReply { Accepted=false,DriverLoaded=false,Error="未加载" });
            var coordinator=new SelfProtectionCoordinator(transport,Identity, (session,op)=>true, TimeSpan.FromMinutes(5),()=>GoodPreflight());
            Is(!coordinator.Activate(DateTime.UtcNow) && coordinator.Status.State==SelfProtectionState.Failed && !coordinator.Status.DriverLoaded && coordinator.Status.UserText().Contains("未启用"));
        });
        Test("driverless status is healthy but never claims kernel protection",()=> {
            var status=SelfProtectionStatus.Driverless(false,DateTime.MinValue);
            Is(status.DriverlessMode && !status.DriverLoaded && !status.ProcessProtectionActive && !status.FileProtectionActive && status.UserText().Contains("无驱动模式") && status.UserText().Contains("不承诺抵抗完整管理员"));
            status=SelfProtectionStatus.Driverless(true,DateTime.UtcNow.AddMinutes(5));
            Is(status.DriverlessMaintenanceAuthorized && status.UserText().Contains("管理员维护窗口已授权") && !status.UserText().Contains("内核自保护已启用"));
        });
        Test("self protection requires all capabilities before activation",()=> {
            var transport=new FakeProtectionTransport(new SelfProtectionReply { Accepted=true,DriverLoaded=true,Capabilities=SelfProtectionCapability.ProcessTermination });
            var coordinator=new SelfProtectionCoordinator(transport,Identity, (session,op)=>true, TimeSpan.FromMinutes(5),()=>GoodPreflight());
            Is(!coordinator.Activate(DateTime.UtcNow) && coordinator.Status.State==SelfProtectionState.Degraded && !coordinator.Status.FileProtectionActive && !coordinator.Status.ServiceStopProtectionActive);
        });
        Test("self protection maintenance is authenticated, bounded and reversible",()=> {
            var full=SelfProtectionCapability.ProcessTermination|SelfProtectionCapability.FileMutation;
            var transport=new FakeProtectionTransport(new SelfProtectionReply { Accepted=true,DriverLoaded=true,Capabilities=full },new SelfProtectionReply { Accepted=true,DriverLoaded=true,Capabilities=full },new SelfProtectionReply { Accepted=true,DriverLoaded=true,Capabilities=full });
            var coordinator=new SelfProtectionCoordinator(transport,Identity, (session,op)=>session=="teacher-session", TimeSpan.FromSeconds(5),()=>GoodPreflight()); var t=DateTime.UtcNow;
            Is(coordinator.Activate(t)); Is(!coordinator.Status.ServiceStopProtectionActive); Is(!coordinator.BeginMaintenance("forged-session",t)); Is(coordinator.BeginMaintenance("teacher-session",t)); Is(coordinator.Status.State==SelfProtectionState.Maintenance && coordinator.CanStopService("teacher-session",t.AddSeconds(1))); Is(!coordinator.CanStopService("forged-session",t.AddSeconds(1))); Is(coordinator.EndMaintenance("teacher-session",t.AddSeconds(2)) && coordinator.Status.State==SelfProtectionState.Active);
        });
        Test("expired self protection maintenance closes without user authorization",()=> {
            var full=SelfProtectionCapability.ProcessTermination|SelfProtectionCapability.FileMutation;
            var transport=new FakeProtectionTransport(new SelfProtectionReply { Accepted=true,DriverLoaded=true,Capabilities=full },new SelfProtectionReply { Accepted=true,DriverLoaded=true,Capabilities=full },new SelfProtectionReply { Accepted=true,DriverLoaded=true,Capabilities=full });
            var coordinator=new SelfProtectionCoordinator(transport,Identity, (session,op)=>true, TimeSpan.FromSeconds(5),()=>GoodPreflight()); var t=DateTime.UtcNow; Is(coordinator.Activate(t)); Is(coordinator.BeginMaintenance("session",t)); coordinator.Tick(t.AddSeconds(6)); Is(coordinator.Status.State==SelfProtectionState.Active && transport.Requests.Count==5);
        });
        Test("self protection maintenance failure fails closed",()=> {
            var full=SelfProtectionCapability.ProcessTermination|SelfProtectionCapability.FileMutation;
            var transport=new FakeProtectionTransport(new SelfProtectionReply { Accepted=true,DriverLoaded=true,Capabilities=full },new SelfProtectionReply { Accepted=false,DriverLoaded=false,Error="synthetic maintenance failure" });
            var coordinator=new SelfProtectionCoordinator(transport,Identity, (session,op)=>true, TimeSpan.FromMinutes(5),()=>GoodPreflight()); var t=DateTime.UtcNow; Is(coordinator.Activate(t)); Is(!coordinator.BeginMaintenance("session",t)); Is(coordinator.Status.State==SelfProtectionState.Failed && !coordinator.CanStopService("session",t.AddSeconds(1)));
        });
        Test("self protection prepare unload requires the active maintenance lease",()=> {
            var full=SelfProtectionCapability.ProcessTermination|SelfProtectionCapability.FileMutation;
            var transport=new FakeProtectionTransport(
                new SelfProtectionReply { Accepted=true,DriverLoaded=true,Capabilities=full },
                new SelfProtectionReply { Accepted=true,DriverLoaded=true,Capabilities=full },
                new SelfProtectionReply { Accepted=true,DriverLoaded=true,Capabilities=SelfProtectionCapability.FileMutation },
                new SelfProtectionReply { Accepted=true,DriverLoaded=true,Capabilities=full });
            var coordinator=new SelfProtectionCoordinator(transport,Identity,(session,op)=>session=="teacher",TimeSpan.FromMinutes(5),()=>GoodPreflight());
            var t=DateTime.UtcNow; Is(coordinator.Activate(t)); Is(!coordinator.PrepareUnload("teacher",t)); Is(coordinator.BeginMaintenance("teacher",t)); Is(coordinator.PrepareUnload("teacher",t.AddSeconds(1))); Is(coordinator.Status.State==SelfProtectionState.Maintenance && coordinator.CanStopService("teacher",t.AddSeconds(2))); Is(coordinator.EndMaintenance("teacher",t.AddSeconds(3)));
        });
        Test("failed driver keeps an authenticated recovery stop path",()=> {
            var transport=new FakeProtectionTransport(new SelfProtectionReply { Accepted=false,DriverLoaded=false,Error="device absent" });
            var coordinator=new SelfProtectionCoordinator(transport,Identity,(session,op)=>true,TimeSpan.FromMinutes(5),()=>GoodPreflight()); var t=DateTime.UtcNow;
            Is(!coordinator.Activate(t)); Is(coordinator.CanStopForRecovery("logged-in",t)); Is(!coordinator.CanStopForRecovery(null,t));
        });
        Test("uncertain maintenance exit retains lease and retries at expiry",()=> {
            var full=SelfProtectionCapability.ProcessTermination|SelfProtectionCapability.FileMutation;
            var ok=new SelfProtectionReply { Accepted=true,DriverLoaded=true,Capabilities=full };
            var transport=new FakeProtectionTransport(ok,ok,new SelfProtectionReply { Accepted=false,DriverLoaded=false,Error="lost response" },ok);
            var coordinator=new SelfProtectionCoordinator(transport,Identity,(session,op)=>true,TimeSpan.FromSeconds(5),()=>GoodPreflight());
            var t=DateTime.UtcNow; Is(coordinator.Activate(t)); Is(coordinator.BeginMaintenance("teacher",t));
            var lease=coordinator.Status.MaintenanceLeaseId;
            Is(!coordinator.EndMaintenance("teacher",t.AddSeconds(1)));
            Is(coordinator.Status.MaintenanceLeaseId==lease && !coordinator.CanStopService("teacher",t.AddSeconds(2)));
            coordinator.Tick(t.AddSeconds(6)); Is(coordinator.Status.State==SelfProtectionState.Active && transport.Requests.Count==6);
        });
        Test("driver status rejects truncated, stale and mismatched replies",()=> {
            var request=SelfProtectionRequest.CreateCommit(Identity(),1,DateTime.UtcNow); request.ProtectedDataRoot="kernel-data-root";
            var valid=DriverStatus(request,false);
            Is(WindowsSelfProtectionTransport.DecodeStatus(valid,request,"kernel-image","kernel-root").Capabilities==(SelfProtectionCapability.ProcessTermination|SelfProtectionCapability.FileMutation));
            var begin=SelfProtectionRequest.CreateBegin(Identity(),1,DateTime.UtcNow); begin.ProtectedDataRoot="kernel-data-root";
            var initializing=WindowsSelfProtectionTransport.DecodeStatus(DriverStatus(begin,false,true),begin,"kernel-image","kernel-root");
            Is(initializing.Phase==SelfProtectionPhase.Initializing && initializing.Capabilities==SelfProtectionCapability.None);
            Throws(()=>WindowsSelfProtectionTransport.DecodeStatus(new byte[12],request,"kernel-image","kernel-root"));
            foreach(int offset in new[]{0,4,8,12,16,20,24,32,40,56,88,104,1128}) {
                var bad=(byte[])valid.Clone(); bad[offset]^=128;
                Throws(()=>WindowsSelfProtectionTransport.DecodeStatus(bad,request,"kernel-image","kernel-root"));
            }
            var unterminated=(byte[])valid.Clone(); for(int i=104;i<1128;i++) unterminated[i]=65;
            Throws(()=>WindowsSelfProtectionTransport.DecodeStatus(unterminated,request,"kernel-image","kernel-root"));
        });
        Test("driver maintenance reply binds lease and reports protection suspended",()=> {
            var request=SelfProtectionRequest.Create(SelfProtectionOperation.EnterMaintenance,Identity(),Guid.NewGuid().ToString("N"),DateTime.UtcNow.AddMinutes(1)); request.ProtectedDataRoot="kernel-data-root";
            var wire=DriverStatus(request,true);
            Is(WindowsSelfProtectionTransport.DecodeStatus(wire,request,"kernel-image","kernel-root").Capabilities==SelfProtectionCapability.FileMutation);
            wire[40]^=1; Throws(()=>WindowsSelfProtectionTransport.DecodeStatus(wire,request,"kernel-image","kernel-root"));
        });
        Test("maintenance reuses the registered process instance identity",()=> {
            var ok=new SelfProtectionReply { Accepted=true,DriverLoaded=true,Capabilities=SelfProtectionCapability.ProcessTermination|SelfProtectionCapability.FileMutation };
            var transport=new FakeProtectionTransport(ok,ok,ok); int captures=0;
            var coordinator=new SelfProtectionCoordinator(transport,()=>{ captures++; return Identity(); },(session,op)=>true,TimeSpan.FromMinutes(1),()=>GoodPreflight());
            var t=DateTime.UtcNow; Is(coordinator.Activate(t)); Is(coordinator.BeginMaintenance("teacher",t)); Is(coordinator.EndMaintenance("teacher",t));
            Is(captures==1 && Object.ReferenceEquals(transport.Requests[0].Identity,transport.Requests[3].Identity));
        });
        Test("self protection rejects arbitrary identity and request secrets",()=> {
            var identity=Identity(); identity.ImagePath=Path.Combine(Path.GetTempPath(),"not-ycsz.exe"); Throws(()=>identity.Validate());
            var request=SelfProtectionRequest.CreateBegin(Identity(),1,DateTime.UtcNow); Is(request.MaintenanceLeaseId==null && request.RequestId.Length==32);
        });
        Test("tray registration binds a user session identity and can be revoked",()=> {
            var full=SelfProtectionCapability.ProcessTermination|SelfProtectionCapability.FileMutation;
            var transport=new FakeProtectionTransport(new SelfProtectionReply { Accepted=true,DriverLoaded=true,Capabilities=full },new SelfProtectionReply { Accepted=true,DriverLoaded=true,Capabilities=full },new SelfProtectionReply { Accepted=true,DriverLoaded=true,Capabilities=full });
            var coordinator=new SelfProtectionCoordinator(transport,Identity,(session,op)=>true,TimeSpan.FromMinutes(5),()=>GoodPreflight()); var tray=TrayIdentity(); var t=DateTime.UtcNow;
            Is(coordinator.Activate(t)); Is(coordinator.RegisterTray(tray,t)); Is(transport.Requests[3].Operation==SelfProtectionOperation.RegisterTray && transport.Requests[3].TrayIdentity.SessionId==7); Is(coordinator.UnregisterTray(tray,t)); Is(transport.Requests[4].Operation==SelfProtectionOperation.UnregisterTray);
        });
        Console.WriteLine("RESULT "+(count-failed)+"/"+count+" passed; Windows integration NOT executed"); return failed==0?0:1;
    }

    sealed class FakeSessionSource : IInteractiveSessionSource {
        public int? Current;
        public int? GetActiveSessionId() { return Current; }
    }
    sealed class FakeTrayRuntime : ITrayRuntime {
        public bool FailStart; public FakeTrayProcess Existing; public int StartCount,FindCount; public readonly List<FakeTrayProcess> Started=new List<FakeTrayProcess>();
        public ITrayProcess FindExisting(int sessionId) { FindCount++; return Existing; }
        public ITrayProcess Start(int sessionId) { StartCount++; if(FailStart) throw new InvalidOperationException("synthetic launch failure"); var process=new FakeTrayProcess(); Started.Add(process); return process; }
    }
    sealed class FakeTrayProcess : ITrayProcess {
        public bool Exited; public bool Disposed;
        public int ProcessId { get { return 9000; } }
        public bool HasExited { get { return Exited || Disposed; } }
        public void Dispose() { Disposed=true; }
    }
    sealed class FakeProtectionTransport : ISelfProtectionTransport {
        readonly Queue<SelfProtectionReply> replies; SelfProtectionReply beginReply; public readonly List<SelfProtectionRequest> Requests=new List<SelfProtectionRequest>(); public bool FailCommit; public bool PreserveBeginPhase;
        public FakeProtectionTransport(params SelfProtectionReply[] replies) { this.replies=new Queue<SelfProtectionReply>(replies); }
        public SelfProtectionReply Send(SelfProtectionRequest request) {
            request.Validate(DateTime.UtcNow); Requests.Add(request);
            if(request.Operation==SelfProtectionOperation.AbortInitialize) return new SelfProtectionReply { Accepted=true,DriverLoaded=false,Phase=SelfProtectionPhase.Unavailable };
            if(request.Operation==SelfProtectionOperation.BeginInitialize) {
                beginReply=replies.Count==0?new SelfProtectionReply { Accepted=false,DriverLoaded=false,Error="no synthetic reply" }:replies.Dequeue();
                return PreserveBeginPhase?Clone(beginReply,beginReply.Phase):Clone(beginReply,SelfProtectionPhase.Initializing);
            }
            if(request.Operation==SelfProtectionOperation.DeclareInitializationEntry) {
                return beginReply==null?new SelfProtectionReply { Accepted=false,DriverLoaded=false,Error="no synthetic begin" }:Clone(beginReply,SelfProtectionPhase.Initializing);
            }
            if(request.Operation==SelfProtectionOperation.CommitInitialize) {
                if(FailCommit) return new SelfProtectionReply { Accepted=false,DriverLoaded=false,Error="synthetic commit failure" };
                return beginReply==null?new SelfProtectionReply { Accepted=false,DriverLoaded=false,Error="no synthetic begin" }:Clone(beginReply,SelfProtectionPhase.Active);
            }
            return replies.Count==0?new SelfProtectionReply { Accepted=false,DriverLoaded=false,Error="no synthetic reply" }:replies.Dequeue();
        }
        static SelfProtectionReply Clone(SelfProtectionReply reply,SelfProtectionPhase phase) { return new SelfProtectionReply { Accepted=reply.Accepted,DriverLoaded=reply.DriverLoaded,Capabilities=phase==SelfProtectionPhase.Initializing?SelfProtectionCapability.None:reply.Capabilities,Error=reply.Error,Phase=phase }; }
    }
    static byte[] DriverStatus(SelfProtectionRequest request,bool maintenance) { return DriverStatus(request,maintenance,false); }
    static byte[] DriverStatus(SelfProtectionRequest request,bool maintenance,bool initializing) {
        var bytes=new byte[4296];
        Action<int,byte[]> put=(offset,value)=>Array.Copy(value,0,bytes,offset,value.Length);
        put(0,BitConverter.GetBytes(4296u)); put(4,BitConverter.GetBytes(4u)); put(8,BitConverter.GetBytes(initializing?198u:(maintenance?79u:71u)));
        put(16,BitConverter.GetBytes((uint)request.Identity.ProcessId)); put(24,BitConverter.GetBytes(request.Identity.StartTimeUtcFileTime));
        if(maintenance) { put(32,BitConverter.GetBytes(request.MaintenanceExpiresUtcFileTime)); put(40,HexBytes(request.MaintenanceLeaseId)); }
        put(56,HexBytes(request.Identity.ImageSha256)); put(88,HexBytes(request.Identity.InstanceNonce));
        put(104,System.Text.Encoding.Unicode.GetBytes("kernel-image")); put(1128,System.Text.Encoding.Unicode.GetBytes("kernel-root")); put(2152,System.Text.Encoding.Unicode.GetBytes("kernel-data-root")); if(initializing) { put(3176,BitConverter.GetBytes(1u)); put(3180,BitConverter.GetBytes(1u)); } return bytes;
    }
    static byte[] HexBytes(string value) { var result=new byte[value.Length/2]; for(int i=0;i<result.Length;i++) result[i]=Convert.ToByte(value.Substring(i*2,2),16); return result; }
    static SelfProtectionFileIdentityObservation Observation(string path,ulong volume,ulong fileIndex,bool reparse,bool readable,bool directory) { return Observation(path,volume,fileIndex,reparse,readable,directory,1); }
    static SelfProtectionPreflightResult GoodPreflight() { return SelfProtectionFilePreflight.Evaluate(new[] { Observation("state",7,12,false,true,false) }); }
    static SelfProtectionFileIdentityObservation Observation(string path,ulong volume,ulong fileIndex,bool reparse,bool readable,bool directory,uint linkCount) { return new SelfProtectionFileIdentityObservation { Path=path,VolumeSerial=volume,FileIndex=fileIndex,LinkCount=linkCount,ReparsePoint=reparse,Readable=readable,IsDirectory=directory,AttributesConsistent=true }; }
    static ProtectionIdentity Identity() { return new ProtectionIdentity { ServiceName=ProtectionIdentity.ExpectedServiceName,ProcessId=1234,SessionId=0,StartTimeUtcFileTime=DateTime.UtcNow.ToFileTimeUtc(),ImagePath=Path.Combine(Path.GetTempPath(),"Ycsz.exe"),ImageSha256=new string('a',64),InstanceNonce=new string('b',32) }; }
    static ProtectionIdentity TrayIdentity() { return new ProtectionIdentity { ServiceName=ProtectionIdentity.ExpectedServiceName,ProcessId=5678,SessionId=7,StartTimeUtcFileTime=DateTime.UtcNow.ToFileTimeUtc(),ImagePath=Path.Combine(Path.GetTempPath(),"Ycsz.exe"),ImageSha256=new string('c',64),InstanceNonce=new string('d',32) }; }
}
