using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Ycsz {
    public sealed class SelfProtectionFileIdentityObservation {
        public string Path;
        public ulong VolumeSerial;
        public ulong FileIndex;
        public uint LinkCount;
        public bool ReparsePoint;
        public bool Readable;
        public bool IsDirectory;
    }

    public sealed class SelfProtectionPreflightResult {
        public bool Passed { get; private set; }
        public bool MappingWritebackConditionMet { get; private set; }
        public int ScannedEntries { get; private set; }
        public IList<string> Issues { get; private set; }

        internal SelfProtectionPreflightResult(bool passed,int scannedEntries,IList<string> issues) {
            Passed=passed;
            // Directory/link inspection does not detect existing writable
            // sections or prove cache writeback ownership. Do not claim it does.
            MappingWritebackConditionMet=false;
            ScannedEntries=scannedEntries;
            Issues=issues??new List<string>();
        }

        public string Summary {
            get {
                if(Passed) return "文件身份 preflight 通过：扫描 "+ScannedEntries+" 项";
                return "文件身份 preflight 未通过："+String.Join("；",new List<string>(Issues).ToArray());
            }
        }
    }

    // This is a read-only activation gate.  It deliberately refuses aliases
    // before activation instead of trying to deny unknown filesystem traffic.
    public static class SelfProtectionFilePreflight {
        const uint FileShareRead=0x00000001u, FileShareWrite=0x00000002u, FileShareDelete=0x00000004u;
        const uint OpenExisting=3u, FileFlagBackupSemantics=0x02000000u, FileFlagOpenReparsePoint=0x00200000u;

        [StructLayout(LayoutKind.Sequential)] struct ByHandleFileInformation {
            public uint FileAttributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
            public uint VolumeSerialNumber;
            public uint FileSizeHigh;
            public uint FileSizeLow;
            public uint NumberOfLinks;
            public uint FileIndexHigh;
            public uint FileIndexLow;
        }

        public static SelfProtectionPreflightResult Check(params string[] roots) {
            var observations=new List<SelfProtectionFileIdentityObservation>();
            var issues=new List<string>();
            if(roots==null || roots.Length==0) issues.Add("未提供保护根");
            else {
                foreach(string root in roots) {
                    if(String.IsNullOrWhiteSpace(root)) { issues.Add("保护根为空"); continue; }
                    string full;
                    try { full=Path.GetFullPath(root); } catch(Exception e) { issues.Add("保护根路径无效:"+root+":"+e.Message); continue; }
                    if(!Directory.Exists(full)) { issues.Add("保护根不存在:"+full); continue; }
                    Collect(full,observations,issues);
                }
            }
            return Evaluate(observations,issues);
        }

        // Kept public for portable tests: no Windows handle or filesystem is
        // touched when callers provide observations directly.
        public static SelfProtectionPreflightResult Evaluate(IEnumerable<SelfProtectionFileIdentityObservation> source) {
            return Evaluate(source,new List<string>());
        }

        static SelfProtectionPreflightResult Evaluate(IEnumerable<SelfProtectionFileIdentityObservation> source,IList<string> initialIssues) {
            var issues=new List<string>();
            if(initialIssues!=null) foreach(string issue in initialIssues) issues.Add(issue);
            var identities=new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);
            int scanned=0;
            if(source!=null) foreach(var item in source) {
                if(item==null) { issues.Add("文件身份记录为空"); continue; }
                scanned++;
                if(item.ReparsePoint) issues.Add("重解析点:"+item.Path);
                if(!item.Readable) issues.Add("无法读取文件身份:"+item.Path);
                if(item.Readable && !item.IsDirectory && item.LinkCount>1) issues.Add("文件存在多个硬链接:"+item.Path);
                if(!item.Readable || item.ReparsePoint) continue;
                string key=item.VolumeSerial.ToString("X8")+":"+item.FileIndex.ToString("X16");
                string previous;
                if(identities.TryGetValue(key,out previous) && !String.Equals(previous,item.Path,StringComparison.OrdinalIgnoreCase)) {
                    issues.Add("同一文件身份存在多个产品路径:"+previous+" <> "+item.Path);
                } else if(!identities.ContainsKey(key)) identities.Add(key,item.Path);
            }
            bool passed=issues.Count==0 && scanned>0;
            return new SelfProtectionPreflightResult(passed,scanned,issues);
        }

        static void Collect(string root,IList<SelfProtectionFileIdentityObservation> observations,IList<string> issues) {
            var pending=new Stack<string>(); pending.Push(root);
            while(pending.Count>0) {
                string current=pending.Pop(); bool isDirectory;
                SelfProtectionFileIdentityObservation observation=ReadIdentity(current,out isDirectory);
                observations.Add(observation);
                if(!isDirectory || observation.ReparsePoint || !observation.Readable) continue;
                string[] entries;
                try { entries=Directory.GetFileSystemEntries(current); }
                catch(Exception e) { issues.Add("无法枚举保护目录:"+current+":"+e.Message); continue; }
                foreach(string entry in entries) pending.Push(entry);
            }
        }

        static SelfProtectionFileIdentityObservation ReadIdentity(string path,out bool isDirectory) {
            isDirectory=false;
            var result=new SelfProtectionFileIdentityObservation { Path=path,Readable=false };
            try {
                FileAttributes attributes=File.GetAttributes(path);
                isDirectory=(attributes&FileAttributes.Directory)!=0;
                result.IsDirectory=isDirectory;
                result.ReparsePoint=(attributes&FileAttributes.ReparsePoint)!=0;
                if(result.ReparsePoint) { result.Readable=true; return result; }
            } catch { result.Path=path; return result; }
            using(var handle=CreateFile(path,0,FileShareRead|FileShareWrite|FileShareDelete,IntPtr.Zero,OpenExisting,FileFlagBackupSemantics|FileFlagOpenReparsePoint,IntPtr.Zero)) {
                if(handle==null || handle.IsInvalid) return result;
                ByHandleFileInformation information;
                if(!GetFileInformationByHandle(handle,out information)) return result;
                result.VolumeSerial=information.VolumeSerialNumber;
                result.FileIndex=((ulong)information.FileIndexHigh<<32)|information.FileIndexLow;
                result.LinkCount=information.NumberOfLinks;
                result.Readable=true;
            }
            return result;
        }

        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
        static extern SafeFileHandle CreateFile(string name,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
        [DllImport("kernel32.dll",SetLastError=true)]
        static extern bool GetFileInformationByHandle(SafeFileHandle handle,out ByHandleFileInformation information);
    }
}
