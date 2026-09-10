using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;

namespace Ycsz {
    // Call under the manager state lock; persist before acknowledging registration.
    public static class EnrollmentRegistry {
        public static string ComputerName(string name) {
            if(String.IsNullOrWhiteSpace(name) || name.Length>63 || name.Any(Char.IsControl) || name!=name.Trim()) throw new InvalidDataException("计算机名称无效");
            return name;
        }
        public static bool ValidToken(string value) {
            if(value==null || value.Length!=44) return false;
            try { return Convert.FromBase64String(value).Length==32; } catch(FormatException) { return false; }
        }
        public static void Validate(Enrollment e) {
            IPAddress host; Guid id;
            if(e==null || !IPAddress.TryParse(e.Host,out host) || host.AddressFamily!=AddressFamily.InterNetwork || host.Equals(IPAddress.Any) || IPAddress.IsLoopback(host) || e.Port<1024 || e.Port>65535 || e.CertificateHash==null || !System.Text.RegularExpressions.Regex.IsMatch(e.CertificateHash,"^[0-9a-f]{64}$") || !ValidToken(e.Token)) throw new InvalidDataException("注册包参数无效");
            if(!Guid.TryParseExact(e.Universal?e.BundleId:e.ClientId,"N",out id)) throw new InvalidDataException("注册包标识无效");
        }
        public static Enrollment NewIdentity(Enrollment bundle,string computerName) {
            Validate(bundle);
            if(!bundle.Universal) throw new InvalidDataException("需要通用接入包");
            return new Enrollment { ClientId=Guid.NewGuid().ToString("N"),Name=ComputerName(computerName),Token=Crypto.Token(),Host=bundle.Host,Port=bundle.Port,CertificateHash=bundle.CertificateHash,BundleId=bundle.BundleId };
        }
        public static bool SameBundle(Enrollment identity,Enrollment bundle) {
            return identity!=null && !identity.Universal && identity.BundleId==bundle.BundleId && identity.Host==bundle.Host && identity.Port==bundle.Port && identity.CertificateHash==bundle.CertificateHash;
        }
        public static ClientState Register(ManagerState state,Packet request) {
            Guid id;
            if(request.Op!="register" || !Guid.TryParseExact(request.Id,"N",out id) || !ValidToken(request.Data) || !ValidToken(request.Token)) throw new InvalidDataException("注册请求无效");
            string name=ComputerName(request.Name);
            var bundle=state.Bundles.FirstOrDefault(b=>b.Id==request.BundleId);
            if(bundle==null || !Crypto.EqualText(bundle.Token,request.Token)) throw new UnauthorizedAccessException("接入包无效或已停用");
            var node=state.Clients.FirstOrDefault(c=>c.Id==request.Id);
            if(node!=null) {
                if(node.Revoked || node.BundleId!=bundle.Id || !Crypto.EqualText(node.Token,request.Data)) throw new UnauthorizedAccessException("设备身份冲突或已撤销");
                return node; // Lost response/restart: same identity, no duplicate, no policy reset.
            }
            if(state.Clients.Count>=64) throw new InvalidOperationException("此版本最多 64 台客户端");
            node=new ClientState { Id=request.Id,Name=name,Token=request.Data,BundleId=bundle.Id,Policy=new Policy { Allow=state.Allow.ToList() } };
            state.Clients.Add(node); return node;
        }
    }
}
