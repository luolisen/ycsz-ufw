using System;
using System.Diagnostics;
using System.IO;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;

namespace Ycsz {
    public static class Store {
        public static readonly string Root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"YcszFirewall");
        public static readonly string Bin = AppDomain.CurrentDomain.BaseDirectory;
        static readonly byte[] Entropy = Encoding.UTF8.GetBytes("YcszFirewall.Settings.v1");
        public static string PathFor(string name) { if (Path.GetFileName(name) != name) throw new ArgumentException("无效文件名"); return Path.Combine(Root,name); }
        public static bool Exists(string name) { return File.Exists(PathFor(name)); }
        public static void Initialize() {
            bool existed=Directory.Exists(Root);
            if(existed) {
                if((File.GetAttributes(Root)&FileAttributes.ReparsePoint)!=0) throw new IOException("配置目录不得是重解析链接");
                var owner=(SecurityIdentifier)Directory.GetAccessControl(Root).GetOwner(typeof(SecurityIdentifier));
                if(!owner.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid) && !owner.IsWellKnown(WellKnownSidType.LocalSystemSid)) throw new IOException("已有配置目录所有者不可信，请管理员归档后重试");
            }
            var security = new DirectorySecurity(); security.SetAccessRuleProtection(true,false); security.SetOwner(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid,null));
            foreach (var sid in new[]{WellKnownSidType.LocalSystemSid,WellKnownSidType.BuiltinAdministratorsSid}) security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid,null),FileSystemRights.FullControl,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));
            if(!existed) Directory.CreateDirectory(Root,security); else Directory.SetAccessControl(Root,security);
            // Secure pre-existing files too; ProgramData allows standard users to pre-create directories.
            foreach(var file in Directory.GetFiles(Root)) {
                if((File.GetAttributes(file)&FileAttributes.ReparsePoint)!=0) throw new IOException("配置文件不得是重解析链接");
                var acl=new FileSecurity(); acl.SetAccessRuleProtection(true,false); acl.SetOwner(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid,null));
                foreach(var sid in new[]{WellKnownSidType.LocalSystemSid,WellKnownSidType.BuiltinAdministratorsSid}) acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid,null),FileSystemRights.FullControl,AccessControlType.Allow));
                File.SetAccessControl(file,acl);
            }
        }
        public static void Save<T>(string name,T value) {
            byte[] bytes = Encoding.UTF8.GetBytes(Json.Encode(value));
            byte[] protectedBytes = ProtectedData.Protect(bytes,Entropy,DataProtectionScope.LocalMachine); Array.Clear(bytes,0,bytes.Length); Write(name,protectedBytes);
        }
        public static T Load<T>(string name) {
            var bytes = ProtectedData.Unprotect(File.ReadAllBytes(PathFor(name)),Entropy,DataProtectionScope.LocalMachine);
            try { return Json.Decode<T>(Encoding.UTF8.GetString(bytes)); } finally { Array.Clear(bytes,0,bytes.Length); }
        }
        public static void Write(string name,byte[] bytes) {
            string target = PathFor(name), temp = target + "." + Guid.NewGuid().ToString("N") + ".tmp";
            try { using (var stream = new FileStream(temp,FileMode.CreateNew,FileAccess.Write,FileShare.None)) { stream.Write(bytes,0,bytes.Length); stream.Flush(true); }
                if (File.Exists(target)) File.Replace(temp,target,null); else File.Move(temp,target);
            } finally { if (File.Exists(temp)) File.Delete(temp); }
        }
        public static void Log(string text) {
            lock (typeof(Store)) {
                try { string file = PathFor("service.log"); if (File.Exists(file) && new FileInfo(file).Length > 2*1024*1024) { string old = PathFor("service.previous.log"); if (File.Exists(old)) File.Delete(old); File.Move(file,old); }
                    File.AppendAllText(file,DateTime.UtcNow.ToString("o") + " " + text + Environment.NewLine,Encoding.UTF8);
                } catch { }
            }
        }
    }
    public static class PowerShell {
        public static string Run(string mode,string input = null,int timeout = 60000) {
            if (!System.Text.RegularExpressions.Regex.IsMatch(mode,"^[a-z-]+$")) throw new ArgumentException("mode");
            string path = null;
            try {
                if (input != null) { path = Store.PathFor("input-"+Guid.NewGuid().ToString("N")+".json"); File.WriteAllText(path,input,new UTF8Encoding(true)); }
                string script = Path.Combine(Store.Bin,"System.ps1");
                var psi = new ProcessStartInfo { FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),@"WindowsPowerShell\v1.0\powershell.exe"), Arguments = "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \""+script+"\" -Mode "+mode+(path == null ? "" : " -InputFile \""+path+"\""), UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true, StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8 };
                using (var process = new Process { StartInfo = psi }) {
                    var output = new StringBuilder(); var error = new StringBuilder();
                    process.OutputDataReceived += (s,e) => { if (e.Data != null) lock (output) { if (output.Length < 2*1024*1024) output.AppendLine(e.Data); } };
                    process.ErrorDataReceived += (s,e) => { if (e.Data != null) lock (error) { if (error.Length < 16384) error.AppendLine(e.Data); } };
                    process.Start(); process.BeginOutputReadLine(); process.BeginErrorReadLine();
                    if (!process.WaitForExit(timeout)) { try { process.Kill(); } catch { } throw new TimeoutException("系统操作超时："+mode); }
                    process.WaitForExit(); if (process.ExitCode != 0) throw new InvalidOperationException(mode+"："+error.ToString().Trim()); return output.ToString().Trim();
                }
            } finally { if (path != null && File.Exists(path)) File.Delete(path); }
        }
        public static NetworkSnapshot Capture() { var snapshot = Json.Decode<NetworkSnapshot>(Run("capture")); snapshot.Validate(); return snapshot; }
        public static void Apply(NetworkSnapshot snapshot) { snapshot.Validate(); Run("apply",Json.Encode(snapshot),90000); }
    }
}
