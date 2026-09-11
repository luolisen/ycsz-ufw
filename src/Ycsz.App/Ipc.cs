using System;
using System.Collections.Generic;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Ycsz {
    public sealed class IpcServer : IDisposable {
        public const string Name = "YcszFirewall.Control.v1";
        volatile bool stopping; readonly Func<Packet,Packet> handler; readonly Settings settings;
        readonly LoginGate gate = new LoginGate(); readonly Dictionary<string,DateTime> sessions = new Dictionary<string,DateTime>();
        readonly Action<Packet,Packet> afterReply;
        Thread thread; NamedPipeServerStream waiting;
        public IpcServer(Settings s,Func<Packet,Packet> callback,Action<Packet,Packet> completed=null) { afterReply=completed; settings=s; handler=callback; thread=new Thread(Loop) { IsBackground=true }; thread.Start(); }
        void Loop() {
            while (!stopping) {
                try {
                    Packet completedRequest=null,completedReply=null;
                    var acl = new PipeSecurity(); acl.SetAccessRuleProtection(true,false);
                    acl.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid,null),PipeAccessRights.FullControl,AccessControlType.Deny));
                    acl.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null),PipeAccessRights.FullControl,AccessControlType.Allow));
                    acl.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid,null),PipeAccessRights.FullControl,AccessControlType.Allow));
                    acl.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid,null),PipeAccessRights.ReadWrite,AccessControlType.Allow));
                    using (var pipe = new NamedPipeServerStream(Name,PipeDirection.InOut,1,PipeTransmissionMode.Byte,PipeOptions.Asynchronous,4096,4096,acl)) {
                        waiting=pipe; pipe.WaitForConnection(); if (stopping) break;
                        using (var deadline = new Timer(x=> { try { pipe.Dispose(); } catch { } },null,15000,Timeout.Infinite)) {
                            Packet reply; Packet request=null;
                            try {
                                request = Wire.Receive(pipe);
                                if (request.Op == "status") reply = new Packet { Ok=true,Data=settings.Role,Status=handler(request).Status };
                                else if (request.Op == "login") {
                                    if (!gate.Check(request.Password,settings.Password)) reply = new Packet { Error="密码错误或尝试过于频繁，请稍后重试" };
                                    else { if (sessions.Count > 64) sessions.Clear(); string token=Crypto.Token(); sessions[token]=DateTime.UtcNow.AddMinutes(15); reply=new Packet { Ok=true,Token=token,Data=settings.Role }; }
                                    request.Password=null;
                                } else {
                                    DateTime expiry;
                                    if (request.Token == null || !sessions.TryGetValue(request.Token,out expiry) || DateTime.UtcNow > expiry) reply=new Packet { Error="会话已失效，请关闭窗口后重新验证密码" };
                                    else if (request.Op == "logout") { sessions.Remove(request.Token); reply=new Packet { Ok=true }; }
                                    else reply=handler(request);
                                }
                            } catch (Exception e) { reply=new Packet { Error=e.Message }; }
                            Wire.Send(pipe,reply);
                            completedRequest=request; completedReply=reply;
                        }
                    }
                    if(afterReply!=null) afterReply(completedRequest,completedReply);
                } catch (Exception e) { if (!stopping) { Store.Log("IPC: "+e.Message); Thread.Sleep(500); } }
            }
        }
        public void Dispose() { stopping=true; try { if(waiting!=null) waiting.Dispose(); } catch {} if (thread!=null) thread.Join(2000); }
    }
    public static class Ipc {
        // A standard user can squat on a pipe name while the service is down.
        // Validate the peer PID against SCM before transmitting any password/token.
        static void VerifyServiceEndpoint(SafePipeHandle pipe) {
            uint peer; if(!GetNamedPipeServerProcessId(pipe,out peer)) throw new UnauthorizedAccessException("无法验证本地服务身份");
            IntPtr scm=OpenSCManager(null,null,1); if(scm==IntPtr.Zero) throw new UnauthorizedAccessException("无法查询服务管理器");
            try {
                IntPtr service=OpenService(scm,Program.ServiceName,4); if(service==IntPtr.Zero) throw new UnauthorizedAccessException("防护服务未安装");
                try { ServiceStatus data; uint needed; if(!QueryServiceStatusEx(service,0,out data,(uint)Marshal.SizeOf(typeof(ServiceStatus)),out needed) || data.Pid==0 || data.Pid!=peer) throw new UnauthorizedAccessException("管道端点不是已注册防护服务；已拒绝发送凭据"); }
                finally { CloseServiceHandle(service); }
            } finally { CloseServiceHandle(scm); }
        }
        [StructLayout(LayoutKind.Sequential)] struct ServiceStatus { public uint Type,State,Accepted,Win32Exit,ServiceExit,Checkpoint,WaitHint,Pid,Flags; }
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe,out uint pid);
        [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr OpenSCManager(string machine,string database,uint access);
        [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr OpenService(IntPtr manager,string name,uint access);
        [DllImport("advapi32.dll",SetLastError=true)] static extern bool QueryServiceStatusEx(IntPtr service,int level,out ServiceStatus status,uint size,out uint needed);
        [DllImport("advapi32.dll")] static extern bool CloseServiceHandle(IntPtr handle);
        public static Packet Call(Packet request) {
            using (var pipe = new NamedPipeClientStream(".",IpcServer.Name,PipeDirection.InOut,PipeOptions.Asynchronous)) {
                try { pipe.Connect(4000); } catch (TimeoutException) { throw new TimeoutException("无法连接本机防护服务：服务可能正在启动或反复重启，请查看 service.log；这不是密码验证失败。"); }
                VerifyServiceEndpoint(pipe.SafePipeHandle);
                using (var deadline = new Timer(x=> { try { pipe.Dispose(); } catch {} },null,15000,Timeout.Infinite)) { Wire.Send(pipe,request); var reply=Wire.Receive(pipe); if (!reply.Ok) throw new InvalidOperationException(reply.Error ?? "操作失败"); return reply; }
            }
        }
    }
}
