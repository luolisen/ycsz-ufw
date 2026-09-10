using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;

namespace Ycsz {
    public static class Json {
        public static string Encode(object value) { return new JavaScriptSerializer { MaxJsonLength = 32 * 1024 * 1024, RecursionLimit = 64 }.Serialize(value); }
        public static T Decode<T>(string text) { return new JavaScriptSerializer { MaxJsonLength = 32 * 1024 * 1024, RecursionLimit = 64 }.Deserialize<T>(text); }
        public static T Copy<T>(T value) { return Decode<T>(Encode(value)); }
    }
    public sealed class PasswordRecord { public string Salt; public string Hash; public int Iterations; }
    public sealed class Enrollment { public string ClientId; public string Name; public string Host; public int Port = 17443; public string CertificateHash; public string Token; }
    public sealed class Settings {
        public string Role; public PasswordRecord Password; public Enrollment Enrollment;
        public string PfxPassword; public int Port = 17443; public string CertificateHash;
        public int PreviousAudit = -1;
    }
    public sealed class Policy {
        public long Revision = 1; public bool Thawed; public List<string> Allow = Defaults.Domains.ToList();
        public NetworkSnapshot Network; public long NetworkRevision;
    }
    public sealed class AdapterSnapshot {
        public string Id; public string Name; public string Description; public bool Enabled; public bool Dhcp;
        public bool DnsAutomatic; public string[] Dns = new string[0];
        public bool DhcpV6 = true; public bool RouterDiscovery = true; public bool DnsV6Automatic = true; public string[] DnsV6 = new string[0];
        public IpSetting[] Addresses = new IpSetting[0]; public RouteSetting[] Routes = new RouteSetting[0];
        public string[] Bindings = new string[0];
    }
    public sealed class IpSetting { public string Address; public int Prefix; }
    public sealed class RouteSetting { public string Prefix; public string NextHop; public int Metric; }
    public sealed class NetworkSnapshot {
        public AdapterSnapshot[] Adapters = new AdapterSnapshot[0]; public string HostsBase64; public bool HostsExists = true;
        public void Validate() {
            if (Adapters == null || Adapters.Length > 64) throw new InvalidDataException("网卡列表无效");
            var ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var a in Adapters) {
                Guid guid;
                if (a == null || !Guid.TryParse(a.Id, out guid) || !ids.Add(a.Id)) throw new InvalidDataException("网卡 GUID 无效或重复");
                if (a.DnsV6 == null || a.DnsV6.Length > 16 || a.Dns == null || a.Addresses == null || a.Routes == null || a.Bindings == null || a.Dns.Length > 16 || a.Addresses.Length > 32 || a.Routes.Length > 128 || a.Bindings.Length > 128) throw new InvalidDataException("网络列表无效");
                foreach (var dns in a.Dns.Concat(a.DnsV6)) ParseIp(dns);
                if (String.IsNullOrEmpty(a.Name) || a.Name.Length > 128 || a.Name.Any(Char.IsControl)) throw new InvalidDataException("网卡名称无效");
                foreach (var ip in a.Addresses) { var p = ParseIp(ip.Address); if (ip.Prefix < 0 || ip.Prefix > (p.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128)) throw new InvalidDataException("地址前缀无效"); }
                foreach (var r in a.Routes) { var next = ParseIp(r.NextHop); var parts = r.Prefix.Split('/'); int bits; if (parts.Length != 2 || !Int32.TryParse(parts[1], out bits)) throw new InvalidDataException("路由前缀无效"); var destination = ParseIp(parts[0]); if (destination.AddressFamily != next.AddressFamily || bits < 0 || bits > (destination.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128) || r.Metric < 0 || r.Metric > 9999) throw new InvalidDataException("路由无效"); }
                foreach (var b in a.Bindings) if (b == null || !Regex.IsMatch(b, "^[a-zA-Z0-9_.-]{1,128}$")) throw new InvalidDataException("网卡绑定无效");
            }
            if (HostsBase64 == null || HostsBase64.Length > 250000) throw new InvalidDataException("hosts 大小无效");
            Convert.FromBase64String(HostsBase64);
            if (!HostsExists && HostsBase64.Length != 0) throw new InvalidDataException("不存在的 hosts 不能包含文件内容");
            if (System.Text.Encoding.UTF8.GetByteCount(Json.Encode(this)) > 300000) throw new InvalidDataException("网络快照超过 300KB");
        }
        static IPAddress ParseIp(string text) { IPAddress ip; if (text == null || text.Contains("%") || !IPAddress.TryParse(text, out ip)) throw new InvalidDataException("IP 地址无效"); return ip; }
    }
    public sealed class SecurityEvent {
        public string Id = Guid.NewGuid().ToString("N"); public string Utc = DateTime.UtcNow.ToString("o");
        public string Kind; public string Detail; public bool Success;
    }
    public sealed class ClientState {
        public string Id; public string Name; public string Token; public Policy Policy = new Policy();
        public string LastSeen; public string Status; public NetworkSnapshot Network;
        public long AppliedRevision; public long AppliedNetworkRevision; public bool Revoked;
        public List<SecurityEvent> Events = new List<SecurityEvent>();
    }
    public sealed class ManagerState { public List<string> Allow = Defaults.Domains.ToList(); public List<ClientState> Clients = new List<ClientState>(); }
    public sealed class ClientDisk { public Policy Policy = new Policy(); public NetworkSnapshot Baseline; public long AppliedNetworkRevision; public long AppliedRevision; public List<SecurityEvent> Events = new List<SecurityEvent>(); public long AttemptedNetworkRevision; public bool CleanStop = true; public long DroppedEvents; public List<SecurityEvent> History = new List<SecurityEvent>(); }
    public sealed class Packet {
        public string Op; public string Password; public string Id; public string Token; public string Name;
        public string Data; public string Error; public string Status; public bool Ok; public bool Thawed;
        public long Revision; public long NetworkRevision; public NetworkSnapshot Network;
        public List<SecurityEvent> Events; public Policy Policy;
    }
    public static class Defaults {
        public static readonly string[] Domains = { "www.gov.cn", "www.moe.gov.cn", "www.smartedu.cn", "www.icourse163.org", "www.xuexi.cn", "www.cnki.net", "www.cctv.com", "www.news.cn", "www.people.com.cn", "www.baidu.com", "baike.baidu.com" };
        public static readonly Dictionary<string,string> Processes = new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase) {
            {"v2ray.exe","V2Ray"}, {"xray.exe","Xray"}, {"shadowsocks-libev.exe","Shadowsocks-libev"},
            {"server-win.exe","ShadowsocksR"}, {"trojan.exe","Trojan"}, {"hysteria.exe","Hysteria"}, {"hy.exe","Hysteria"},
            {"tuic-client.exe","tuic"}, {"tuic-server.exe","tuic"}, {"sing-box.exe","Sing-box"},
            {"mihomo.exe","Mihomo"}, {"clash.exe","Mihomo/Clash"}, {"naiveproxy.exe","NaiveProxy"},
            {"v2rayN.exe","v2rayN"}, {"clash for windows.exe","Clash for Windows"}, {"clash-verge.exe","Clash Verge"},
            {"mihomo-party.exe","Mihomo Party"}, {"netch.exe","Netch"}, {"furious.exe","Furious"}, {"hiddify.exe","Hiddify"}
        };
    }
    public static class Rules {
        public static string Normalize(string input) {
            if (String.IsNullOrWhiteSpace(input)) throw new InvalidDataException("白名单条目不能为空");
            string s = input.Trim().ToLowerInvariant();
            if (s.Length > 253 || s.Contains("%")) throw new InvalidDataException("条目过长或含作用域标识");
            IPAddress ip;
            var parts = s.Split('/'); int bits;
            if (parts.Length == 2 && IPAddress.TryParse(parts[0], out ip) && Int32.TryParse(parts[1], out bits)) {
                int max = ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128;
                if (bits < 1 || bits > max) throw new InvalidDataException("不允许 /0 或无效 CIDR");
                byte[] b = ip.GetAddressBytes(); for (int i = bits; i < max; i++) b[i / 8] &= (byte)~(1 << (7 - i % 8));
                return new IPAddress(b).ToString() + "/" + bits;
            }
            if (IPAddress.TryParse(s, out ip)) return ip.ToString();
            if (!Regex.IsMatch(s, @"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$") || Uri.CheckHostName(s) != UriHostNameType.Dns)
                throw new InvalidDataException("仅接受准确域名、IP 或 CIDR；不接受 URL、通配符和端口：" + input);
            return s;
        }
        public static List<string> Validate(IEnumerable<string> lines) {
            if (lines == null) throw new InvalidDataException("白名单缺失");
            var list = lines.Where(x => !String.IsNullOrWhiteSpace(x)).Select(Normalize).Distinct().ToList();
            if (list.Count > 512) throw new InvalidDataException("最多 512 个白名单条目"); return list;
        }
        public static bool IsIp(string text) { IPAddress ip; return IPAddress.TryParse(text.Split('/')[0], out ip); }
    }
}
