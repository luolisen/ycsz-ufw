using System;
using System.Collections.Generic;
using System.Linq;
namespace Ycsz {
    public static class NetworkCommandGate {
        public static bool ShouldApply(Policy policy, long applied, long attempted) {
            return policy != null && policy.Network != null && policy.NetworkRevision > Math.Max(applied, attempted);
        }
    }
    public static class NetworkCompare {
        public static List<string> Drift(NetworkSnapshot baseline,NetworkSnapshot current) {
            var drift=new List<string>();
            if(baseline.HostsExists!=current.HostsExists || baseline.HostsBase64!=current.HostsBase64) drift.Add("hosts 内容变化");
            foreach(var expected in baseline.Adapters) {
                var found=current.Adapters.FirstOrDefault(a=>String.Equals(a.Id,expected.Id,StringComparison.OrdinalIgnoreCase));
                if(found==null) { drift.Add("缺少网卡 "+expected.Id); continue; }
                if(Signature(expected)!=Signature(found)) drift.Add("网卡配置变化 "+expected.Name+" ("+expected.Id+")");
            }
            foreach(var added in current.Adapters.Where(a=>!baseline.Adapters.Any(b=>String.Equals(a.Id,b.Id,StringComparison.OrdinalIgnoreCase)))) if(added.Enabled) drift.Add("新增启用网卡 "+added.Name+" ("+added.Id+")");
            return drift;
        }
        static string Signature(AdapterSnapshot a) {
            return Json.Encode(new { a.Name,a.Enabled,a.Dhcp,a.DhcpV6,a.RouterDiscovery,a.DnsV6Automatic,DnsV6=a.DnsV6Automatic?new string[0]:a.DnsV6,a.DnsAutomatic,Dns=a.DnsAutomatic?new string[0]:a.Dns,
                Addresses=a.Addresses.Select(x=>x.Address+"/"+x.Prefix).OrderBy(x=>x).ToArray(),
                Routes=a.Routes.Select(x=>x.Prefix+"|"+x.NextHop+"|"+x.Metric).OrderBy(x=>x).ToArray(),Bindings=a.Bindings.OrderBy(x=>x).ToArray() });
        }
    }
}
