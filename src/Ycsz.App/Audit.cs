using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Runtime.InteropServices;
using System.Xml;

namespace Ycsz {
    public sealed class Audit : IDisposable {
        static readonly Guid Subcategory = new Guid("0cce9226-69ae-11d9-bed3-505054503030");
        EventLogWatcher watcher;
        readonly Action<SecurityEvent> report; readonly Wfp wfp;
        readonly Dictionary<string,DateTime> recent = new Dictionary<string,DateTime>();
        public Audit(Settings settings,Wfp firewall,Action<SecurityEvent> callback) {
            report = callback; wfp = firewall; Privileges.EnableAudit();
            var info = Query();
            if (settings.PreviousAudit < 0) { settings.PreviousAudit = (int)info.Flags; Store.Save("settings.bin",settings); }
            info.Flags = (info.Flags & ~4u) | 2u;
            if (!AuditSetSystemPolicy(ref info,1)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            watcher = new EventLogWatcher(new EventLogQuery("Security",PathType.LogName,"*[System[(EventID=5157)]]"));
            watcher.EventRecordWritten += Recorded; watcher.Enabled = true;
        }
        void Recorded(object sender,EventRecordWrittenEventArgs args) {
            if (args.EventException != null) { report(new SecurityEvent { Kind="audit_error",Detail=args.EventException.Message }); return; }
            if (args.EventRecord == null) return;
            using (var record = args.EventRecord) {
                try {
                    var doc = new XmlDocument { XmlResolver = null }; doc.LoadXml(record.ToXml());
                    var fields = new Dictionary<string,string>(); foreach (XmlNode node in doc.GetElementsByTagName("Data")) if (node.Attributes["Name"] != null) fields[node.Attributes["Name"].Value] = node.InnerText;
                    ulong id; if (!fields.ContainsKey("FilterRTID") || !UInt64.TryParse(fields["FilterRTID"],out id) || !wfp.OwnsBlock(id)) return;
                    string detail = Get(fields,"Application")+" → "+Get(fields,"DestAddress")+":"+Get(fields,"DestPort")+" protocol="+Get(fields,"Protocol");
                    lock (recent) { DateTime last; if (recent.TryGetValue(detail,out last) && DateTime.UtcNow-last < TimeSpan.FromSeconds(30)) return; if (recent.Count > 4096) recent.Clear(); recent[detail]=DateTime.UtcNow; }
                    report(new SecurityEvent { Kind="blocked_connection",Detail=detail,Success=true });
                } catch (Exception e) { Store.Log("Audit parse: "+e.Message); }
            }
        }
        static string Get(Dictionary<string,string> d,string key) { string value; return d.TryGetValue(key,out value) ? value : "?"; }
        static Info Query() { var guid = Subcategory; IntPtr ptr; if (!AuditQuerySystemPolicy(ref guid,1,out ptr)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()); try { return (Info)Marshal.PtrToStructure(ptr,typeof(Info)); } finally { AuditFree(ptr); } }
        public static void Restore(Settings settings) {
            if (settings.PreviousAudit < 0) return;
            Privileges.EnableAudit();
            var info = Query(); // Preserve independent changes to success auditing.
            if ((settings.PreviousAudit & 2) == 0) info.Flags &= ~2u;
            if ((info.Flags & 3) == 0) info.Flags = 4;
            if (!AuditSetSystemPolicy(ref info,1)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            settings.PreviousAudit = -1; Store.Save("settings.bin",settings);
        }
        public void Dispose() { if (watcher != null) { watcher.Enabled = false; watcher.Dispose(); watcher = null; } }
        [StructLayout(LayoutKind.Sequential)] struct Info { public Guid Subcategory; public uint Flags; public Guid Category; }
        [DllImport("advapi32.dll",SetLastError=true)] static extern bool AuditQuerySystemPolicy(ref Guid subcategory,uint count,out IntPtr info);
        [DllImport("advapi32.dll",SetLastError=true)] static extern bool AuditSetSystemPolicy(ref Info info,uint count);
        [DllImport("advapi32.dll")] static extern void AuditFree(IntPtr ptr);
    }
}
