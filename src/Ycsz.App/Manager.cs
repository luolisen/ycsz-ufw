using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading;

namespace Ycsz {
    public sealed class Manager : IDisposable {
        readonly Settings settings; readonly object sync=new object(); ManagerState state;
        readonly X509Certificate2 certificate; readonly TcpListener listener; readonly Semaphore slots=new Semaphore(16,16);
        volatile bool stopping; Thread thread;
        public Manager(Settings s) {
            settings=s; state=Store.Load<ManagerState>("manager.bin");
            foreach(var node in state.Clients) if(Store.Exists("node-"+node.Id+".bin")) { var saved=Store.Load<ClientState>("node-"+node.Id+".bin"); node.Network=saved.Network; node.Events=saved.Events; node.LastSeen=saved.LastSeen; node.Status=saved.Status; node.AppliedRevision=saved.AppliedRevision; node.AppliedNetworkRevision=saved.AppliedNetworkRevision; }
            certificate=new X509Certificate2(Store.PathFor("manager.pfx"),s.PfxPassword,X509KeyStorageFlags.MachineKeySet);
            listener=new TcpListener(IPAddress.Any,s.Port); listener.Start(32);
            thread=new Thread(Accept) { IsBackground=true }; thread.Start();
        }
        void Accept() {
            while(!stopping) {
                try { var client=listener.AcceptTcpClient(); if(!slots.WaitOne(0)) { client.Close(); continue; } ThreadPool.QueueUserWorkItem(x=>Serve(client)); }
                catch(Exception e) { if(!stopping) { Store.Log("Listener: "+e.Message); Thread.Sleep(500); } }
            }
        }
        void Serve(TcpClient client) {
            try {
                using(client) using(var deadline=new Timer(x=>{try{client.Close();}catch{}},null,15000,Timeout.Infinite)) {
                    client.ReceiveTimeout=10000; client.SendTimeout=10000;
                    using(var tls=new SslStream(client.GetStream(),false)) {
                        tls.ReadTimeout=10000; tls.WriteTimeout=10000; tls.AuthenticateAsServer(certificate,false,SslProtocols.Tls12,false);
                        var request=Wire.Receive(tls); Wire.Send(tls,Heartbeat(request));
                    }
                }
            } catch(Exception e) { Store.Log("TLS request rejected: "+e.GetType().Name); }
            finally { slots.Release(); }
        }
        Packet Heartbeat(Packet p) {
            lock(sync) {
                var node=state.Clients.FirstOrDefault(c=>c.Id==p.Id);
                if (p.Op!="heartbeat" || node==null || node.Revoked || !Crypto.EqualText(node.Token,p.Token)) return new Packet { Error="认证失败" };
                if (p.Events==null || p.Events.Count>64 || (p.Status!=null && p.Status.Length>2048)) return new Packet { Error="消息无效" };
                if(p.Network!=null) p.Network.Validate();
                foreach(var item in p.Events) if(item==null || item.Id==null || item.Id.Length>64 || item.Kind==null || item.Kind.Length>64 || item.Detail==null || item.Detail.Length>1024 || item.Utc==null || item.Utc.Length>64) return new Packet { Error="事件无效" };
                foreach(var item in p.Events) if(!node.Events.Any(e=>e.Id==item.Id)) node.Events.Add(item);
                if(node.Events.Count>200) node.Events.RemoveRange(0,node.Events.Count-200);
                node.LastSeen=DateTime.UtcNow.ToString("o"); node.Status=p.Status; node.Network=p.Network;
                node.AppliedRevision=p.Revision; node.AppliedNetworkRevision=p.NetworkRevision;
                Store.Save("node-"+node.Id+".bin",node);
                return new Packet { Ok=true,Policy=Json.Copy(node.Policy) };
            }
        }
        void SaveIndex() {
            var index=new ManagerState { Allow=state.Allow.ToList(),Clients=state.Clients.Select(c=>new ClientState { Id=c.Id,Name=c.Name,Token=c.Token,Revoked=c.Revoked,Policy=Json.Copy(c.Policy) }).ToList() };
            Store.Save("manager.bin",index);
        }
        ClientState Find(string id) { var node=state.Clients.FirstOrDefault(c=>c.Id==id); if(node==null) throw new ArgumentException("客户端不存在"); return node; }
        public Packet Command(Packet p) {
            lock(sync) {
                if(p.Op=="status") return new Packet { Ok=true,Status="管理服务运行中；TLS :"+settings.Port };
                if(p.Op=="list") {
                    var nodes=state.Clients.Select(c=>new ClientState { Id=c.Id,Name=c.Name,LastSeen=c.LastSeen,Status=c.Status,Revoked=c.Revoked,AppliedRevision=c.AppliedRevision,AppliedNetworkRevision=c.AppliedNetworkRevision,Policy=new Policy { Revision=c.Policy.Revision,Thawed=c.Policy.Thawed,Allow=null } }).ToList();
                    return new Packet { Ok=true,Data=Json.Encode(nodes) };
                }
                if(p.Op=="details") { var copy=Json.Copy(Find(p.Id)); copy.Token=null; return new Packet { Ok=true,Data=Json.Encode(copy) }; }
                if(p.Op=="allow") return new Packet { Ok=true,Data=Json.Encode(state.Allow) };
                var before=Json.Copy(state);
                try {
                if(p.Op=="set-allow") {
                    state.Allow=Rules.Validate(Json.Decode<List<string>>(p.Data)); foreach(var c in state.Clients) { c.Policy.Allow=state.Allow.ToList(); c.Policy.Revision++; }
                } else if(p.Op=="thaw") { var node=Find(p.Id); node.Policy.Thawed=p.Thawed; node.Policy.Revision++; }
                else if(p.Op=="set-network") {
                    if(p.Network==null) throw new ArgumentException("缺少网络配置"); p.Network.Validate(); var node=Find(p.Id);
                    if(node.Network==null) throw new InvalidOperationException("客户端尚未报告网络基线");
                    var expected=new HashSet<string>(node.Network.Adapters.Select(a=>a.Id),StringComparer.OrdinalIgnoreCase);
                    if(!expected.SetEquals(p.Network.Adapters.Select(a=>a.Id))) throw new InvalidOperationException("不允许远程增加/删除网卡身份；请在本机核验后接纳基线");
                    node.Policy.Network=Json.Copy(p.Network); node.Policy.NetworkRevision++; node.Policy.Revision++;
                } else if(p.Op=="enroll") {
                    if(state.Clients.Count>=64) throw new InvalidOperationException("此版本最多 64 台客户端");
                    if(String.IsNullOrWhiteSpace(p.Name) || p.Name.Length>64) throw new ArgumentException("客户端名称须为 1–64 字符");
                    IPAddress host; if(!IPAddress.TryParse(p.Data,out host) || host.AddressFamily!=AddressFamily.InterNetwork || IPAddress.IsLoopback(host) || host.Equals(IPAddress.Any)) throw new ArgumentException("请输入管理端固定 IPv4 地址");
                    var node=new ClientState { Id=Guid.NewGuid().ToString("N"),Name=p.Name,Token=Crypto.Token(),Policy=new Policy { Allow=state.Allow.ToList() } }; state.Clients.Add(node); SaveIndex();
                    return new Packet { Ok=true,Data=Json.Encode(new Enrollment { ClientId=node.Id,Name=node.Name,Token=node.Token,Host=host.ToString(),Port=settings.Port,CertificateHash=settings.CertificateHash }) };
                } else if(p.Op=="revoke") Find(p.Id).Revoked=true;
                else throw new ArgumentException("未知管理操作");
                SaveIndex(); return new Packet { Ok=true,Status="已保存，等待客户端拉取并回报应用结果" };
                } catch { state=before; throw; }
            }
        }
        public void Dispose() { stopping=true; listener.Stop(); if(thread!=null) thread.Join(2000); /* Active connections time out before process exit. */ }
    }
}
