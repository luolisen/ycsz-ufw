using System;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Net;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace Ycsz {
    public static class ClientPackage {
        public static string Installer { get { return Path.Combine(Store.Bin,"Ycsz-Client-Setup.exe"); } }
        public static void CheckInstaller() { if(!File.Exists(Installer)) throw new FileNotFoundException("未找到客户端安装程序，请使用完整的管理端安装包"); }
        public static string ResolveInstaller(bool includeRuntime) {
            string name=includeRuntime?"Ycsz-Client-Setup.exe":"Ycsz-Client-Setup-NoRuntime.exe";
            string local=Path.Combine(Store.Bin,name);
            if(File.Exists(local)) return local;
            if(!includeRuntime) throw new FileNotFoundException("客户端安装器缺失，请修复管理端安装",local);
            const string release="https://github.com/luolisen/ycsz-ufw/releases/download/v1.0.0/";
            string cache=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"YcszFirewall","Installers","1.0.0");
            Directory.CreateDirectory(cache); string target=Path.Combine(cache,name),temp=target+"."+Guid.NewGuid().ToString("N")+".tmp";
            ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;
            try {
                using(var web=new InstallerDownload()) {
                    string manifest=web.DownloadString(release+"DELIVERY-SHA256SUMS");
                    var match=Regex.Match(manifest,@"(?m)^([a-fA-F0-9]{64})[ \t]+Ycsz-Client-Setup\.exe\r?$");
                    if(!match.Success) throw new InvalidDataException("发布页缺少客户端安装器校验值");
                    string expected=match.Groups[1].Value;
                    if(File.Exists(target) && Hash(target).Equals(expected,StringComparison.OrdinalIgnoreCase)) return target;
                    web.DownloadFile(release+name,temp);
                    if(!Hash(temp).Equals(expected,StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("下载的客户端安装器校验失败");
                    if(File.Exists(target)) File.Replace(temp,target,null); else File.Move(temp,target);
                    return target;
                }
            } catch(WebException e) { throw new IOException("需要联网获取内置运行库版客户端安装器。请检查网络后重试，或取消内置运行库。",e); }
            finally { if(File.Exists(temp)) File.Delete(temp); }
        }
        static string Hash(string path) { using(var sha=SHA256.Create()) using(var file=File.OpenRead(path)) return BitConverter.ToString(sha.ComputeHash(file)).Replace("-",""); }
        sealed class InstallerDownload : WebClient {
            protected override WebRequest GetWebRequest(Uri address) { var request=base.GetWebRequest(address); request.Timeout=120000; return request; }
        }
        public static void Export(string destination,byte[] enrollment) { CheckInstaller(); Export(destination,enrollment,Installer,true); }
        public static void Export(string destination,byte[] enrollment,string installer,bool includeRuntime) {
            if(!File.Exists(installer)) throw new FileNotFoundException("客户端安装器缺失",installer);
            string temp=destination+"."+Guid.NewGuid().ToString("N")+".tmp";
            try {
                using(var file=new FileStream(temp,FileMode.CreateNew,FileAccess.Write,FileShare.None))
                using(var zip=new ZipArchive(file,ZipArchiveMode.Create)) {
                    zip.CreateEntryFromFile(installer,"Ycsz-Client-Setup.exe");
                    using(var stream=zip.CreateEntry("client.ycsz").Open()) stream.Write(enrollment,0,enrollment.Length);
                    using(var writer=new StreamWriter(zip.CreateEntry("安装说明.txt").Open(),new UTF8Encoding(true))) writer.Write((includeRuntime?"本包内置 .NET Framework 4.8，缺少时自动安装。\r\n":"本包不内置运行库，安装前请准备 .NET Framework 4.8。\r\n")+"请先解压全部文件，再运行 Ycsz-Client-Setup.exe。\r\n同一份包可部署多台电脑，每台安装后使用独立身份和本机计算机名称。\r\n安装需管理员权限，输入本机管理密码及管理员另行提供的注册包密码。\r\n先安装管理端 v0.2.0 或更新版本，保持管理端固定 IPv4 可达。\r\n请勿克隆已初始化的 ProgramData 配置；应在每台电脑分别运行安装。\r\n");
                }
                if(File.Exists(destination)) File.Replace(temp,destination,null); else File.Move(temp,destination);
            } finally { if(File.Exists(temp)) File.Delete(temp); }
        }
    }
}
