using System;
using System.Diagnostics;
using System.IO;
using System.Security.Principal;
using System.ServiceProcess;
using System.Windows.Forms;

namespace Ycsz {
    static class Program {
        public const string ServiceName="YcszFirewall";
        [STAThread] static int Main(string[] args) {
            if(args.Length>0 && args[0]=="--service") { ServiceBase.Run(new HostService()); return 0; }
            Application.EnableVisualStyles(); Application.SetCompatibleTextRenderingDefault(false);
            try {
                if(args.Length>0 && args[0]=="--installed-role") { RequireAdmin(); string role=Store.Load<Settings>("settings.bin").Role; return role=="manager"?10:role=="client"?20:1; }
                if(args.Length>0 && args[0]=="--setup") { RequireAdmin(); using(var setup=new SetupForm()) return setup.ShowDialog()==DialogResult.OK?0:1; }
                if(args.Length>0 && args[0]=="--close-ui") { RequireAdmin(); foreach(var process in Process.GetProcessesByName("Ycsz")) using(process) { if(process.Id==Process.GetCurrentProcess().Id) continue; try { if(String.Equals(process.MainModule.FileName,Path.Combine(Store.Bin,"Ycsz.exe"),StringComparison.OrdinalIgnoreCase)) process.Kill(); } catch(InvalidOperationException) {} } return 0; }
                if(args.Length>0 && args[0]=="--recover") { RequireAdmin(); Recovery(); MessageBox.Show("本产品的出口规则已移除，审计设置已恢复。服务保持停止。","管理员恢复"); return 0; }
                if(args.Length>0 && args[0]=="--uninstall-authorize") {
                    RequireAdmin(); var settings=Store.Load<Settings>("settings.bin");
                    using(var prompt=new PasswordDialog("验证管理密码后卸载",null,settings.Password)) if(prompt.ShowDialog()!=DialogResult.OK) return 1;
                    Recovery(); return 0;
                }
                if(args.Length>0 && args[0]=="--tray") { Application.Run(new TrayContext()); return 0; }
                OpenConsole(); return 0;
            } catch(Exception e) { MessageBox.Show(e.Message,"YCSZ 教育机房防火墙",MessageBoxButtons.OK,MessageBoxIcon.Error); return 1; }
        }
        public static void OpenConsole() {
            using(var login=new PasswordDialog("管理验证",null,null)) if(login.ShowDialog()==DialogResult.OK) using(var form=new ConsoleForm(login.Session,login.Role)) form.ShowDialog();
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
        Guard guard; Manager manager; IpcServer ipc;
        public HostService() { ServiceName=Program.ServiceName; CanStop=true; CanShutdown=true; AutoLog=true; }
        protected override void OnStart(string[] args) {
            Store.Initialize(); var settings=Store.Load<Settings>("settings.bin");
            if(settings.Role=="client") guard=new Guard(settings); else if(settings.Role=="manager") manager=new Manager(settings); else throw new InvalidDataException("角色无效");
            ipc=new IpcServer(settings,p=>guard!=null?guard.Command(p):manager.Command(p)); Store.Log("Service started: "+settings.Role);
        }
        protected override void OnStop() { RequestAdditionalTime(120000); if(ipc!=null) ipc.Dispose(); if(guard!=null) guard.Dispose(); if(manager!=null) manager.Dispose(); Store.Log("Service stopped normally"); }
        protected override void OnShutdown() { if(ipc!=null) ipc.Dispose(); if(guard!=null) guard.Dispose(); if(manager!=null) manager.Dispose(); }
    }
}
