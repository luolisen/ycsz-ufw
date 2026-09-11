using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Principal;
using System.ServiceProcess;
using System.Runtime.InteropServices;
using System.Threading;
using System.Windows.Forms;

namespace Ycsz {
    static class Program {
        public const string ServiceName="YcszFirewall";
        [STAThread] static int Main(string[] args) {
            if(args.Length>0 && args[0]=="--service") { ServiceBase.Run(new HostService()); return 0; }
            if(args.Length>0 && args[0]=="--protection-status") return QueryProtectionStatus();
            Application.EnableVisualStyles(); Application.SetCompatibleTextRenderingDefault(false);
            try {
                if(args.Length>0 && args[0]=="--installed-role") { RequireAdmin(); string role=Store.Load<Settings>("settings.bin").Role; return role=="manager"?10:role=="client"?20:1; }
                if(args.Length>0 && (args[0]=="--setup" || args[0]=="--setup-client")) { RequireAdmin(); using(var setup=new SetupForm(args[0]=="--setup-client")) return setup.ShowDialog()==DialogResult.OK?0:1; }
                if(args.Length>0 && args[0]=="--close-ui") { RequireAdmin(); CloseInteractiveUi(); return 0; }
                if(args.Length>0 && args[0]=="--recover") { RequireAdmin(); Recovery(); MessageBox.Show("本产品的出口规则已移除，审计设置已恢复。服务保持停止。","管理员恢复"); return 0; }
                if(args.Length>0 && args[0]=="--uninstall-authorize") {
                    RequireAdmin(); var settings=Store.Load<Settings>("settings.bin");
                    using(var prompt=new PasswordDialog("验证管理密码后卸载",null,settings.Password)) {
                        if(prompt.ShowDialog()!=DialogResult.OK) return 1;
                        try { AuthorizedUninstall(prompt.AuthenticatedPassword); }
                        finally { prompt.ClearAuthenticatedPassword(); }
                    }
                    return 0;
                }
                if(args.Length>0 && args[0]=="--tray") {
                    bool acquired;
                    using(var mutex=TrayInstanceLock.Acquire(Process.GetCurrentProcess().SessionId,out acquired)) {
                        if(!acquired) return 0;
                        try { Application.Run(new TrayContext()); } finally { mutex.ReleaseMutex(); }
                    }
                    return 0;
                }
                OpenConsole(); return 0;
            } catch(Exception e) { MessageBox.Show(e.Message,"YCSZ 教育机房防火墙",MessageBoxButtons.OK,MessageBoxIcon.Error); return 1; }
        }
        public static void OpenConsole() {
            using(var login=new PasswordDialog("管理验证",null,null)) if(login.ShowDialog()==DialogResult.OK) using(var form=new ConsoleForm(login.Session,login.Role)) form.ShowDialog();
        }
        static int QueryProtectionStatus() {
            try {
                var reply=Ipc.Call(new Packet { Op="self-protection-status" });
                Console.WriteLine(reply.Status??"");
                return reply.Ok?0:1;
            } catch(Exception e) { Console.Error.WriteLine(e.Message); return 1; }
        }
        static void CloseInteractiveUi() {
            using(var service=new ServiceController(ServiceName)) {
                try {
                    if(service.Status!=ServiceControllerStatus.Stopped) throw new InvalidOperationException("维护关闭界面前必须先确认防护服务已停止");
                } catch(InvalidOperationException e) {
                    var native=e.InnerException as System.ComponentModel.Win32Exception;
                    if(native==null || native.NativeErrorCode!=1060) throw;
                }
            }
            string executable=Path.GetFullPath(Path.Combine(Store.Bin,"Ycsz.exe"));
            int current=Process.GetCurrentProcess().Id;
            foreach(var process in Process.GetProcessesByName("Ycsz")) using(process) {
                if(process.Id==current) continue;
                try {
                    if(process.SessionId==0) continue;
                    if(!String.Equals(Path.GetFullPath(process.MainModule.FileName),executable,StringComparison.OrdinalIgnoreCase)) continue;
                    process.Kill();
                    if(!process.WaitForExit(5000)) throw new System.TimeoutException("界面进程未在维护期限内退出："+process.Id);
                } catch(InvalidOperationException) { if(!process.HasExited) throw; }
            }
        }
        static bool IsServiceInstalled(string name) {
            using(var service=new ServiceController(name)) {
                try { var ignored=service.Status; return true; }
                catch(InvalidOperationException e) { var native=e.InnerException as System.ComponentModel.Win32Exception; if(native!=null && native.NativeErrorCode==1060) return false; throw; }
            }
        }
        static void AuthorizedUninstall(string password) {
            bool appInstalled=IsServiceInstalled(ServiceName);
            bool protectionInstalled=IsServiceInstalled("YcszProtection");
            if(!appInstalled) { Recovery(); return; }
            using(var service=new ServiceController(ServiceName)) {
                ServiceControllerStatus state;
                try { state=service.Status; } catch(InvalidOperationException e) { throw new InvalidOperationException("无法读取 YCSZ 服务状态",e); }
                if(state==ServiceControllerStatus.Stopped) {
                    if(protectionInstalled) throw new InvalidOperationException("自保护驱动仍已注册；请在服务运行时通过认证维护准备卸载，或按 Remove-Protection.ps1 流程处理");
                    Recovery(); return;
                }
            }
            Packet login=Ipc.Call(new Packet { Op="login",Password=password });
            bool maintenance=false;
            try {
                try {
                    Ipc.Call(new Packet { Op="self-protection-enter",Token=login.Token });
                    maintenance=true;
                    Ipc.Call(new Packet { Op="self-protection-prepare-unload",Token=login.Token });
                } catch {
                    if(maintenance) throw;
                    // A registered but unavailable driver must not make the
                    // authenticated uninstall path impossible.  The service
                    // only grants this recovery stop when its protection state
                    // is Failed/Unavailable; it never opens SCM Stop globally.
                }
                Ipc.Call(new Packet { Op="self-protection-stop",Token=login.Token });
                using(var service=new ServiceController(ServiceName)) service.WaitForStatus(ServiceControllerStatus.Stopped,TimeSpan.FromSeconds(120));
            } catch {
                if(maintenance) { try { Ipc.Call(new Packet { Op="self-protection-exit",Token=login.Token }); } catch {} }
                throw;
            }
            Recovery();
        }
        static void RequireAdmin() { using(var identity=WindowsIdentity.GetCurrent()) if(!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator)) throw new UnauthorizedAccessException("此操作需要通过 UAC 以管理员身份运行"); }
        static void Recovery() {
            using(var service=new ServiceController(ServiceName)) {
                try { if(service.Status!=ServiceControllerStatus.Stopped) { service.Stop(); service.WaitForStatus(ServiceControllerStatus.Stopped,TimeSpan.FromSeconds(120)); } }
                catch(InvalidOperationException e) { var native=e.InnerException as System.ComponentModel.Win32Exception; if(native==null || native.NativeErrorCode!=1060) throw; }
            }
            var settings=Store.Load<Settings>("settings.bin");
            if(settings.Role=="client") { using(var firewall=new Wfp()) firewall.RemoveAll(); Audit.Restore(settings); }
        }
    }
    sealed class HostService : ServiceBase {
        Guard guard; Manager manager; IpcServer ipc; TraySupervisor tray; Settings settings; System.Threading.Timer selfProtectionTimer;
        SelfProtectionCoordinator selfProtection;
        readonly object trayIdentityLock=new object();
        readonly Dictionary<int,ProtectionIdentity> registeredTrays=new Dictionary<int,ProtectionIdentity>();
        readonly bool protectedService;
        readonly object lifecycleLock=new object();
        string pendingStopSession;
        bool stopping;
        bool cleanupStarted;
        public HostService() {
            ServiceName=Program.ServiceName;
            // Freeze accepted controls before ServiceBase.Run. Once the product
            // driver is installed, SCM Stop is never opened as a maintenance bypass.
            using(var key=Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\YcszProtection")) protectedService=key!=null;
            CanStop=!protectedService; CanShutdown=true; AutoLog=true;
        }
        protected override void OnStart(string[] args) {
            Store.Initialize(); settings=Store.Load<Settings>("settings.bin");
            if(settings.Role=="client") guard=new Guard(settings); else if(settings.Role=="manager") manager=new Manager(settings); else throw new InvalidDataException("角色无效");
            selfProtection=new SelfProtectionCoordinator(
                new WindowsSelfProtectionTransport(Store.Root),
                ()=>ProtectionIdentity.CaptureCurrent(Path.Combine(Store.Bin,"Ycsz.exe")),
                (session,operation)=>!String.IsNullOrWhiteSpace(session),
                TimeSpan.FromMinutes(5));
            bool protectionReady=!protectedService || selfProtection.Activate(DateTime.UtcNow);
            Store.Log("Self protection: "+selfProtection.Status.UserText());
            selfProtectionTimer=new System.Threading.Timer(x=>RefreshSelfProtection(),null,1000,1000);
            ipc=new IpcServer(settings,Handle,AfterReply);
            if(protectedService && !protectionReady) Store.Log("Tray supervisor withheld because kernel self-protection activation was not confirmed");
            try {
                if(!protectedService || protectionReady) {
                    Action<ITrayProcess,int> register=protectedService?new Action<ITrayProcess,int>(RegisterTray):null;
                    Action<ITrayProcess,int> unregister=protectedService?new Action<ITrayProcess,int>(UnregisterTray):null;
                    tray=new TraySupervisor(new WindowsInteractiveSessionSource(),new WindowsTrayRuntime(),m=>Store.Log("Tray: "+m),null,register,unregister); tray.Start();
                }
            }
            catch(Exception e) { Store.Log("Tray supervisor unavailable: "+e); if(tray!=null) { tray.Dispose(); tray=null; } }
            Store.Log("Service started: "+settings.Role);
        }

        void RegisterTray(ITrayProcess process,int sessionId) {
            if(process==null || process.ProcessId<=0) throw new InvalidOperationException("托盘进程句柄无效");
            var identity=ProtectionIdentity.CaptureProcess(process.ProcessId,Path.Combine(Store.Bin,"Ycsz.exe"),sessionId);
            if(selfProtection==null || !selfProtection.RegisterTray(identity,DateTime.UtcNow)) throw new InvalidOperationException("驱动未确认当前用户会话托盘登记");
            lock(trayIdentityLock) registeredTrays[identity.ProcessId]=identity;
            Store.Log("Tray protection registered: pid="+identity.ProcessId+" session="+identity.SessionId);
        }

        void UnregisterTray(ITrayProcess process,int sessionId) {
            if(process==null) return;
            ProtectionIdentity identity=null;
            lock(trayIdentityLock) registeredTrays.TryGetValue(process.ProcessId,out identity);
            if(identity==null) return;
            if(selfProtection!=null && !selfProtection.UnregisterTray(identity,DateTime.UtcNow)) {
                Store.Log("Tray protection unregister failed: pid="+identity.ProcessId+" session="+sessionId);
                return;
            }
            lock(trayIdentityLock) registeredTrays.Remove(identity.ProcessId);
            Store.Log("Tray protection unregistered: pid="+identity.ProcessId+" session="+identity.SessionId);
        }
        Packet Handle(Packet request) {
            if(request!=null && request.Op=="self-protection-status") {
                var state=selfProtection==null?SelfProtectionStatus.Unavailable("驱动未构建或未加载"):selfProtection.Status;
                return new Packet { Ok=state.State==SelfProtectionState.Active && state.DriverLoaded && state.ProcessProtectionActive && state.FileProtectionActive,Status=state.UserText() };
            }
            if(request!=null && request.Op=="self-protection-enter") return ChangeSelfProtection(request,true);
            if(request!=null && request.Op=="self-protection-exit") return ChangeSelfProtection(request,false);
            if(request!=null && request.Op=="self-protection-prepare-unload") return PrepareSelfProtectionUnload(request);
            if(request!=null && request.Op=="self-protection-stop") {
                lock(lifecycleLock) {
                    if(stopping || !protectedService || selfProtection==null || !CanStopForRequest(request.Token,DateTime.UtcNow))
                        return new Packet { Error="停服需要当前登录会话的有效自保护维护授权" };
                    pendingStopSession=request.Token;
                    return new Packet { Ok=true,Status="维护停服请求已接受" };
                }
            }
            var reply=guard!=null?guard.Command(request):manager.Command(request);
            if(reply==null) return null;
            var protection=selfProtection==null?SelfProtectionStatus.Unavailable("驱动未构建或未加载"):selfProtection.Status;
            if(request.Op=="status") reply.Status=SelfProtectionStatus.Append(reply.Status,protection);
            else if(request.Op=="details" && settings.Role=="client" && !String.IsNullOrWhiteSpace(reply.Data)) {
                var state=Json.Decode<ClientState>(reply.Data); state.Status=SelfProtectionStatus.Append(state.Status,protection); reply.Data=Json.Encode(state);
            }
            return reply;
        }
        Packet ChangeSelfProtection(Packet request,bool enter) {
            lock(lifecycleLock) {
            if(stopping) return new Packet { Error="服务正在维护停止" };
            bool accepted=false;
            if(selfProtection!=null) {
                accepted=enter?selfProtection.BeginMaintenance(request.Token,DateTime.UtcNow):selfProtection.EndMaintenance(request.Token,DateTime.UtcNow);

            }
            var status=selfProtection==null?SelfProtectionStatus.Unavailable("驱动未构建或未加载"):selfProtection.Status;
            Store.Log("Self protection maintenance "+(enter?"enter":"exit")+": "+(accepted?"accepted":"rejected"));
            return new Packet { Ok=accepted,Status=status.UserText(),Error=accepted?null:(status.Failure??(enter?"无法进入自保护维护窗口":"无法结束自保护维护窗口")) };
        }
        }
        Packet PrepareSelfProtectionUnload(Packet request) {
            lock(lifecycleLock) {
                if(stopping || selfProtection==null) return new Packet { Error="服务正在停止或自保护未初始化" };
                bool accepted=selfProtection.PrepareUnload(request.Token,DateTime.UtcNow);
                var status=selfProtection.Status;
                Store.Log("Self protection prepare unload: "+(accepted?"accepted":"rejected"));
                return new Packet { Ok=accepted,Status=status.UserText(),Error=accepted?null:(status.Failure??"无法准备驱动卸载") };
            }
        }
        bool CanStopForRequest(string session,DateTime utcNow) {
            return selfProtection.CanStopService(session,utcNow) || selfProtection.CanStopForRecovery(session,utcNow);
        }
        void AfterReply(Packet request,Packet reply) {
            if(request==null || request.Op!="self-protection-stop" || reply==null || !reply.Ok) return;
            ThreadPool.QueueUserWorkItem(x=> {
                lock(lifecycleLock) {
                    if(stopping || !String.Equals(pendingStopSession,request.Token,StringComparison.Ordinal)) return;
                    pendingStopSession=null;
                    // Revalidate after the response is delivered. Expiry or a
                    // cancelled lease must not leave a queued stop permission.
                    if(!CanStopForRequest(request.Token,DateTime.UtcNow)) { Store.Log("Maintenance stop expired before dispatch"); return; }
                    stopping=true;
                }
                try { Stop(); }
                catch(Exception e) { Store.Log("Maintenance stop failed: "+e); }
            });
        }
        protected override void OnStop() { StopComponents(TrayStopReason.ServiceStopping); }
        protected override void OnShutdown() { StopComponents(TrayStopReason.SystemShutdown); }
        void StopComponents(TrayStopReason reason) {
            lock(lifecycleLock) {
                if(cleanupStarted) return;
                cleanupStarted=true; stopping=true; pendingStopSession=null;
            }
            if(reason==TrayStopReason.ServiceStopping) RequestAdditionalTime(120000);
            if(selfProtectionTimer!=null) { selfProtectionTimer.Dispose(); selfProtectionTimer=null; }
            if(tray!=null) { tray.Stop(reason); tray.Dispose(); tray=null; }
            if(ipc!=null) { ipc.Dispose(); ipc=null; }
            if(guard!=null) { guard.Dispose(); guard=null; }
            if(manager!=null) { manager.Dispose(); manager=null; }
            if(reason==TrayStopReason.ServiceStopping) Store.Log("Service stopped normally");
        }

        void RefreshSelfProtection() {
            lock(lifecycleLock) {
                if(stopping || selfProtection==null) return;
                selfProtection.Tick(DateTime.UtcNow);
            }
        }
    }
}
