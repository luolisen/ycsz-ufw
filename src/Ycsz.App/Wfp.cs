using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace Ycsz {
    // x64 Windows ABI. Kept explicit and covered by portable layout tests.
    public sealed class Wfp : IDisposable {
        public static readonly Guid ProviderKey = new Guid("98bd74c1-15f8-4f17-a6d4-7454d018502a");
        public static readonly Guid SublayerKey = new Guid("410aa5dc-7951-491f-b771-419e7883d21e");
        static readonly Guid V4 = new Guid("c38d57d1-05a7-4c33-904f-7fbceee60e82"), V6 = new Guid("4a72393b-319f-44bc-84c3-ba54dcb3b6b4");
        static readonly Guid RemoteAddress = new Guid("b235ae9a-1d64-49b8-a44c-5ff3d9095045"), RemotePort = new Guid("c35a604d-d22b-4e1a-91b4-68f674ee674b"), Protocol = new Guid("3971ef2b-623e-4f9a-8cb1-6e79b806b9a7"), AppId = new Guid("d78e1e87-8644-4ea5-9437-d809ecfbc971");
        IntPtr engine; readonly object sync = new object(); HashSet<ulong> blockIds = new HashSet<ulong>();
        public Wfp() {
            if (IntPtr.Size != 8) throw new PlatformNotSupportedException("仅支持 x64");
            Check(FwpmEngineOpen0(null,10,IntPtr.Zero,IntPtr.Zero,out engine),"open");
            var provider = new Provider { Key = ProviderKey, Display = Display.Named("YCSZ Education Firewall"), Flags = 1 };
            uint result = FwpmProviderAdd0(engine,ref provider,IntPtr.Zero); if (result != 0x80320009) Check(result,"provider");
            using (var arena = new Arena()) {
                var sub = new Sublayer { Key = SublayerKey, Display = Display.Named("YCSZ outbound whitelist"), Flags = 1, Provider = arena.Struct(ProviderKey), Weight = 0x7000 };
                result = FwpmSubLayerAdd0(engine,ref sub,IntPtr.Zero); if (result != 0x80320009) Check(result,"sublayer");
            }
        }
        public bool OwnsBlock(ulong id) { lock (sync) return blockIds.Contains(id); }
        public void Apply(Policy policy, Enrollment enrollment, Action<string> warning) {
            var targets = new HashSet<string>(); DateTime deadline=DateTime.UtcNow.AddSeconds(30);
            foreach (string entry in Rules.Validate(policy.Allow)) {
                if(policy.Thawed) break;
                if(DateTime.UtcNow>deadline) throw new TimeoutException("白名单 DNS 解析超过 30 秒，原规则保持不变");
                if (Rules.IsIp(entry)) { targets.Add(entry); continue; }
                try { foreach (var ip in Resolve(entry)) targets.Add(ip.ToString()); }
                catch (Exception e) { warning("域名解析失败，未放行："+entry+"；"+e.Message); }
            }
            if (targets.Count > 4096) throw new InvalidOperationException("解析地址超过 4096 个");
            var dns = NetworkInterface.GetAllNetworkInterfaces().SelectMany(n => n.GetIPProperties().DnsAddresses).Where(a=>!a.IsIPv6Multicast).Select(a=>a.ToString().Split('%')[0]).Distinct().ToList();
            var nextIds = new HashSet<ulong>();
            lock (sync) {
                Check(FwpmTransactionBegin0(engine,0),"begin");
                try {
                    RemoveFilters();
                    if (!policy.Thawed) {
                        string exe = System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName;
                        string svchost = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),"svchost.exe");
                        Add("Loopback IPv4","127.0.0.0/8",0,0,null,false);
                        Add("Loopback IPv6","::1",0,0,null,false);
                        foreach (var server in dns) foreach (var app in new[]{svchost,exe}) foreach (int proto in new[]{6,17}) Add("DNS",server,53,proto,app,false);
                        Add("DHCPv4","255.255.255.255",67,17,svchost,false);
                        // Unicast DHCP renewals only to current DHCP server addresses.
                        foreach (var server in NetworkInterface.GetAllNetworkInterfaces().SelectMany(n => n.GetIPProperties().DhcpServerAddresses).Select(a=>a.ToString()).Distinct()) if (server != "0.0.0.0") Add("DHCP renewal",server,67,17,svchost,false);
                        Add("DHCPv6","ff02::1:2",547,17,svchost,false);
                        // Management endpoint is a fixed IP and is permitted only for this executable.
                        Add("Management TLS",enrollment.Host,enrollment.Port,6,exe,false);
                        foreach (var target in targets) foreach (var port in new[]{80,443}) Add("Whitelist web",target,port,6,null,false);
                        nextIds.Add(Add("Default deny IPv4",null,0,0,null,false));
                        nextIds.Add(Add("Default deny IPv6",null,0,0,null,true));
                    }
                    Check(FwpmTransactionCommit0(engine),"commit"); if(blockIds.Count>256) blockIds.Clear(); blockIds.UnionWith(nextIds);
                } catch { FwpmTransactionAbort0(engine); throw; }
            }
        }
        public static IPAddress[] Resolve(string host) {
            var pending = Dns.BeginGetHostAddresses(host,null,null);
            using (pending.AsyncWaitHandle) if (!pending.AsyncWaitHandle.WaitOne(5000)) throw new TimeoutException("DNS timeout");
            return Dns.EndGetHostAddresses(pending).Where(ip=>ip.AddressFamily == AddressFamily.InterNetwork || ip.AddressFamily == AddressFamily.InterNetworkV6).ToArray();
        }
        ulong Add(string name,string address,int port,int proto,string executable,bool v6Block) {
            using (var arena = new Arena()) {
                bool v6 = v6Block; var conditions = new List<Condition>();
                if (address != null) {
                    string[] parts = address.Split('/'); var ip = IPAddress.Parse(parts[0]); var bytes = ip.GetAddressBytes(); v6 = bytes.Length == 16;
                    int prefix = parts.Length == 2 ? Int32.Parse(parts[1]) : (v6 ? 128 : 32);
                    if (v6) { var mask = new byte[17]; Buffer.BlockCopy(bytes,0,mask,0,16); mask[16] = (byte)prefix; conditions.Add(new Condition { Key = RemoteAddress, Value = Value.Pointer(257,arena.Bytes(mask)) }); }
                    else {
                        uint addr = ((uint)bytes[0]<<24)|((uint)bytes[1]<<16)|((uint)bytes[2]<<8)|bytes[3];
                        conditions.Add(new Condition { Key = RemoteAddress, Value = Value.Pointer(256,arena.Struct(new V4Mask { Address = addr, Mask = prefix == 0 ? 0 : UInt32.MaxValue << (32-prefix) })) });
                    }
                }
                if (port != 0) conditions.Add(new Condition { Key = RemotePort, Value = Value.Number(2,(uint)port) });
                if (proto != 0) conditions.Add(new Condition { Key = Protocol, Value = Value.Number(1,(uint)proto) });
                IntPtr app = IntPtr.Zero;
                try {
                    if (executable != null) { Check(FwpmGetAppIdFromFileName0(executable,out app),"appid"); conditions.Add(new Condition { Key = AppId, Value = Value.Pointer(12,app) }); }
                    var f = new Filter { Key = Guid.NewGuid(), Display = Display.Named("YCSZ "+name), Flags = 1, Provider = arena.Struct(ProviderKey), Layer = v6 ? V6 : V4, Sublayer = SublayerKey, Weight = Value.Number(1,(uint)(address == null ? 0 : 15)), Count = (uint)conditions.Count, Conditions = arena.Array(conditions.ToArray()), Action = new ActionType { Type = address == null ? 0x1001u : 0x1002u } };
                    ulong id; Check(FwpmFilterAdd0(engine,ref f,IntPtr.Zero,out id),name); return id;
                } finally { if (app != IntPtr.Zero) FwpmFreeMemory0(ref app); }
            }
        }
        void RemoveFilters() {
            IntPtr iterator; Check(FwpmFilterCreateEnumHandle0(engine,IntPtr.Zero,out iterator),"enumerate");
            var keys = new List<Guid>();
            try {
                while (true) {
                    IntPtr entries; uint count; Check(FwpmFilterEnum0(engine,iterator,256,out entries,out count),"enum page");
                    try { for (int i=0;i<count;i++) { var f = (Filter)Marshal.PtrToStructure(Marshal.ReadIntPtr(entries,i*IntPtr.Size),typeof(Filter)); if (f.Sublayer == SublayerKey && f.Provider != IntPtr.Zero && (Guid)Marshal.PtrToStructure(f.Provider,typeof(Guid)) == ProviderKey) keys.Add(f.Key); } }
                    finally { if (entries != IntPtr.Zero) FwpmFreeMemory0(ref entries); }
                    if (count < 256) break;
                }
            } finally { FwpmFilterDestroyEnumHandle0(engine,iterator); }
            foreach (var key in keys) { var k = key; Check(FwpmFilterDeleteByKey0(engine,ref k),"delete own filter"); }
        }
        public void RemoveAll() {
            lock (sync) { Check(FwpmTransactionBegin0(engine,0),"begin remove"); try { RemoveFilters(); var sub = SublayerKey; var provider = ProviderKey; Check(FwpmSubLayerDeleteByKey0(engine,ref sub),"remove sublayer"); Check(FwpmProviderDeleteByKey0(engine,ref provider),"remove provider"); Check(FwpmTransactionCommit0(engine),"commit remove"); blockIds.Clear(); } catch { FwpmTransactionAbort0(engine); throw; } }
        }
        public void Dispose() { if (engine != IntPtr.Zero) { FwpmEngineClose0(engine); engine = IntPtr.Zero; } }
        static void Check(uint code,string operation) { if (code != 0) throw new Win32Exception(unchecked((int)code),"WFP "+operation+" 0x"+code.ToString("X8")); }
        [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] public struct Display { [MarshalAs(UnmanagedType.LPWStr)] public string Name; [MarshalAs(UnmanagedType.LPWStr)] public string Description; public static Display Named(string s) { return new Display { Name = s, Description = "YCSZ managed education firewall" }; } }
        [StructLayout(LayoutKind.Sequential)] public struct Blob { public uint Size; public IntPtr Data; }
        [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] public struct Provider { public Guid Key; public Display Display; public uint Flags; public Blob Data; [MarshalAs(UnmanagedType.LPWStr)] public string Service; }
        [StructLayout(LayoutKind.Sequential)] public struct Sublayer { public Guid Key; public Display Display; public uint Flags; public IntPtr Provider; public Blob Data; public ushort Weight; }
        [StructLayout(LayoutKind.Explicit,Size=16)] public struct Value { [FieldOffset(0)] public uint Type; [FieldOffset(8)] public ulong NumberValue; [FieldOffset(8)] public IntPtr PointerValue; public static Value Number(uint type,uint value) { return new Value { Type=type,NumberValue=value }; } public static Value Pointer(uint type,IntPtr ptr) { return new Value { Type=type,PointerValue=ptr }; } }
        [StructLayout(LayoutKind.Explicit,Size=40)] public struct Condition { [FieldOffset(0)] public Guid Key; [FieldOffset(16)] public uint Match; [FieldOffset(24)] public Value Value; }
        [StructLayout(LayoutKind.Sequential)] public struct ActionType { public uint Type; public Guid Key; }
        [StructLayout(LayoutKind.Explicit,Size=16)] public struct Context { [FieldOffset(0)] public ulong Raw; [FieldOffset(0)] public Guid Key; }
        [StructLayout(LayoutKind.Explicit,Size=200)] public struct Filter { [FieldOffset(0)] public Guid Key; [FieldOffset(16)] public Display Display; [FieldOffset(32)] public uint Flags; [FieldOffset(40)] public IntPtr Provider; [FieldOffset(48)] public Blob Data; [FieldOffset(64)] public Guid Layer; [FieldOffset(80)] public Guid Sublayer; [FieldOffset(96)] public Value Weight; [FieldOffset(112)] public uint Count; [FieldOffset(120)] public IntPtr Conditions; [FieldOffset(128)] public ActionType Action; [FieldOffset(152)] public Context Context; [FieldOffset(168)] public IntPtr Reserved; [FieldOffset(176)] public ulong Id; [FieldOffset(184)] public Value EffectiveWeight; }
        [StructLayout(LayoutKind.Sequential)] struct V4Mask { public uint Address,Mask; }
        sealed class Arena : IDisposable {
            readonly List<IntPtr> pointers = new List<IntPtr>();
            public IntPtr Struct<T>(T value) { var ptr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(T))); pointers.Add(ptr); Marshal.StructureToPtr(value,ptr,false); return ptr; }
            public IntPtr Bytes(byte[] value) { var ptr = Marshal.AllocHGlobal(value.Length); pointers.Add(ptr); Marshal.Copy(value,0,ptr,value.Length); return ptr; }
            public IntPtr Array<T>(T[] value) { if (value.Length == 0) return IntPtr.Zero; int size = Marshal.SizeOf(typeof(T)); var ptr = Marshal.AllocHGlobal(size*value.Length); pointers.Add(ptr); for (int i=0;i<value.Length;i++) Marshal.StructureToPtr(value[i],IntPtr.Add(ptr,i*size),false); return ptr; }
            public void Dispose() { foreach (var ptr in pointers) Marshal.FreeHGlobal(ptr); }
        }
        [DllImport("fwpuclnt.dll",CharSet=CharSet.Unicode)] static extern uint FwpmEngineOpen0(string server,uint auth,IntPtr identity,IntPtr session,out IntPtr engine);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmEngineClose0(IntPtr engine);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmProviderAdd0(IntPtr engine,ref Provider provider,IntPtr security);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmSubLayerAdd0(IntPtr engine,ref Sublayer sublayer,IntPtr security);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterAdd0(IntPtr engine,ref Filter filter,IntPtr security,out ulong id);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmTransactionBegin0(IntPtr engine,uint flags);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmTransactionCommit0(IntPtr engine);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmTransactionAbort0(IntPtr engine);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterCreateEnumHandle0(IntPtr engine,IntPtr template,out IntPtr iterator);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterEnum0(IntPtr engine,IntPtr iterator,uint requested,out IntPtr entries,out uint count);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterDestroyEnumHandle0(IntPtr engine,IntPtr iterator);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterDeleteByKey0(IntPtr engine,ref Guid key);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmSubLayerDeleteByKey0(IntPtr engine,ref Guid key);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmProviderDeleteByKey0(IntPtr engine,ref Guid key);
        [DllImport("fwpuclnt.dll")] static extern void FwpmFreeMemory0(ref IntPtr memory);
        [DllImport("fwpuclnt.dll",CharSet=CharSet.Unicode)] static extern uint FwpmGetAppIdFromFileName0(string file,out IntPtr appId);
    }
}
