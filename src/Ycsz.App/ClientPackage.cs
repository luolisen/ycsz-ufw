using System;
using System.IO;
using System.IO.Compression;
using System.Text;

namespace Ycsz {
    public static class ClientPackage {
        public static string Installer { get { return Path.Combine(Store.Bin,"Ycsz-Client-Setup.exe"); } }
        public static void CheckInstaller() { if(!File.Exists(Installer)) throw new FileNotFoundException("未找到客户端安装程序，请使用完整的管理端安装包"); }
        public static void Export(string destination,byte[] enrollment) {
            CheckInstaller();
            string temp=destination+"."+Guid.NewGuid().ToString("N")+".tmp";
            try {
                using(var file=new FileStream(temp,FileMode.CreateNew,FileAccess.Write,FileShare.None))
                using(var zip=new ZipArchive(file,ZipArchiveMode.Create)) {
                    zip.CreateEntryFromFile(Installer,"Ycsz-Client-Setup.exe");
                    using(var stream=zip.CreateEntry("client.ycsz").Open()) stream.Write(enrollment,0,enrollment.Length);
                    using(var writer=new StreamWriter(zip.CreateEntry("安装说明.txt").Open(),new UTF8Encoding(true))) writer.Write("请先解压全部文件，再运行 Ycsz-Client-Setup.exe。\r\n同一份包可部署多台电脑，每台安装后使用独立身份和本机计算机名称。\r\n安装需管理员权限，输入本机管理密码及管理员另行提供的注册包密码。\r\n先安装管理端 v0.2.0 或更新版本，保持管理端固定 IPv4 可达。\r\n请勿克隆已初始化的 ProgramData 配置；应在每台电脑分别运行安装。\r\n");
                }
                if(File.Exists(destination)) File.Replace(temp,destination,null); else File.Move(temp,destination);
            } finally { if(File.Exists(temp)) File.Delete(temp); }
        }
    }
}
