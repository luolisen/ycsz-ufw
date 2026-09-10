using System;
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
        Console.WriteLine("RESULT "+(count-failed)+"/"+count+" passed; Windows integration NOT executed"); return failed==0?0:1;
    }
}
