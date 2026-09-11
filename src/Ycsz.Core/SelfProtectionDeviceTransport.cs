using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Ycsz {
    // Fixed-buffer user-mode view of drivers/YcszProtection/ycsz_protection_protocol.h.
    // The driver is never loaded by this class; it only opens the already-installed
    // device and reports an unavailable/failed state when the device is absent.
    public sealed class WindowsSelfProtectionTransport : ISelfProtectionTransport {
        const uint GenericRead=0x80000000u, GenericWrite=0x40000000u;
        const uint FileShareRead=0x00000001u, FileShareWrite=0x00000002u;
        const uint OpenExisting=3u;
        const uint IoctlActivate=0x8000e000u;
        const uint IoctlEnterMaintenance=0x8000e004u;
        const uint IoctlExitMaintenance=0x8000e008u;
        const uint IoctlQueryStatus=0x8000e00cu;
        const uint IoctlPrepareUnload=0x8000e010u;
        const uint IoctlRegisterTray=0x8000e014u;
        const uint IoctlUnregisterTray=0x8000e018u;

        const uint StateActive=0x00000001u;
        const uint StateProcessCallback=0x00000002u;
        const uint StateFileFilter=0x00000004u;
        const uint StateMaintenance=0x00000008u, StateUnloadPrepared=0x00000010u;
        const uint StateTrayRegistered=0x00000020u, StateDataRoot=0x00000040u;
        const uint StateError=0x80000000u;
        const int MaxPathChars=512;
        readonly string protectedDataRoot;

        [StructLayout(LayoutKind.Sequential, Pack=8)] struct NativeHeader {
            public uint Size; public uint Version; public ulong RequestId;
        }
        [StructLayout(LayoutKind.Sequential, Pack=8)] struct NativeIdentity {
            public uint ProcessId; public uint SessionId; public long CreateTime100ns;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst=32, ArraySubType=UnmanagedType.U1)] public byte[] ImageSha256;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst=16, ArraySubType=UnmanagedType.U1)] public byte[] InstanceNonce;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst=MaxPathChars, ArraySubType=UnmanagedType.U2)] public ushort[] ImagePath;
        }
        [StructLayout(LayoutKind.Sequential, Pack=8)] struct NativeActivateRequest {
            public NativeHeader Header; public NativeIdentity Identity;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst=MaxPathChars, ArraySubType=UnmanagedType.U2)] public ushort[] ProtectedRoot;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst=MaxPathChars, ArraySubType=UnmanagedType.U2)] public ushort[] ProtectedDataRoot;
        }
        [StructLayout(LayoutKind.Sequential, Pack=8)] struct NativeTrayRequest {
            public NativeHeader Header; public NativeIdentity Identity;
        }
        [StructLayout(LayoutKind.Sequential, Pack=8)] struct NativeMaintenanceRequest {
            public NativeHeader Header;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst=16, ArraySubType=UnmanagedType.U1)] public byte[] LeaseId;
            public long ExpiresAt100ns;
        }
        [StructLayout(LayoutKind.Sequential, Pack=8)] struct NativeUnloadRequest {
            public NativeHeader Header;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst=16, ArraySubType=UnmanagedType.U1)] public byte[] LeaseId;
        }
        [StructLayout(LayoutKind.Sequential, Pack=8)] struct NativeStatus {
            public uint Size; public uint Version; public uint State; public uint LastStatus;
            public uint TargetPid; public uint TargetSessionId; public long TargetCreateTime100ns; public long MaintenanceExpiresAt100ns;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst=16, ArraySubType=UnmanagedType.U1)] public byte[] LeaseId;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst=32, ArraySubType=UnmanagedType.U1)] public byte[] ImageSha256;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst=16, ArraySubType=UnmanagedType.U1)] public byte[] InstanceNonce;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst=MaxPathChars, ArraySubType=UnmanagedType.U2)] public ushort[] ImagePath;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst=MaxPathChars, ArraySubType=UnmanagedType.U2)] public ushort[] ProtectedRoot;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst=MaxPathChars, ArraySubType=UnmanagedType.U2)] public ushort[] ProtectedDataRoot;
            public NativeIdentity TrayIdentity;
        }

        public WindowsSelfProtectionTransport() : this(null) { }
        public WindowsSelfProtectionTransport(string protectedDataRoot) {
            this.protectedDataRoot=String.IsNullOrWhiteSpace(protectedDataRoot)?null:Path.GetFullPath(protectedDataRoot);
        }

        // Exposed only for isolated ABI tests; no test uses or fakes a kernel
        // handle.  These values must stay aligned with the shared C header.
        public static int ControlHeaderSize { get { return Marshal.SizeOf(typeof(NativeHeader)); } }
        public static int ProcessIdentitySize { get { return Marshal.SizeOf(typeof(NativeIdentity)); } }
        public static int ActivateRequestSize { get { return Marshal.SizeOf(typeof(NativeActivateRequest)); } }
        public static int TrayRequestSize { get { return Marshal.SizeOf(typeof(NativeTrayRequest)); } }
        public static int MaintenanceRequestSize { get { return Marshal.SizeOf(typeof(NativeMaintenanceRequest)); } }
        public static int UnloadRequestSize { get { return Marshal.SizeOf(typeof(NativeUnloadRequest)); } }
        public static uint PrepareUnloadIoctl { get { return IoctlPrepareUnload; } }
        public static int StatusSize { get { return Marshal.SizeOf(typeof(NativeStatus)); } }
        public static uint ActivateIoctl { get { return IoctlActivate; } }
        public static uint EnterMaintenanceIoctl { get { return IoctlEnterMaintenance; } }
        public static uint ExitMaintenanceIoctl { get { return IoctlExitMaintenance; } }
        public static uint QueryStatusIoctl { get { return IoctlQueryStatus; } }
        public static uint RegisterTrayIoctl { get { return IoctlRegisterTray; } }
        public static uint UnregisterTrayIoctl { get { return IoctlUnregisterTray; } }

        public SelfProtectionReply Send(SelfProtectionRequest request) {
            if(request==null) throw new ArgumentNullException("request");
            request.Validate(DateTime.UtcNow);
            using(var device=OpenDevice()) {
                if(request.Operation==SelfProtectionOperation.Activate) {
                    var native=BuildActivate(request);
                    SendNoOutput(device,IoctlActivate,ref native);
                } else if(request.Operation==SelfProtectionOperation.RegisterTray || request.Operation==SelfProtectionOperation.UnregisterTray) {
                    var native=new NativeTrayRequest { Header=BuildHeader(request.RequestId,TrayRequestSize),Identity=BuildIdentity(request.TrayIdentity,ToKernelPath(request.TrayIdentity.ImagePath)) };
                    SendNoOutput(device,request.Operation==SelfProtectionOperation.RegisterTray?IoctlRegisterTray:IoctlUnregisterTray,ref native);
                } else if(request.Operation==SelfProtectionOperation.PrepareUnload) {
                    var native=new NativeUnloadRequest { Header=BuildHeader(request.RequestId,UnloadRequestSize),LeaseId=FromHex(request.MaintenanceLeaseId,16) };
                    SendNoOutput(device,IoctlPrepareUnload,ref native);
                } else {
                    var native=BuildMaintenance(request);
                    SendNoOutput(device,request.Operation==SelfProtectionOperation.EnterMaintenance?IoctlEnterMaintenance:IoctlExitMaintenance,ref native);
                }
                return QueryStatus(device,request);
            }
        }

        SafeFileHandle OpenDevice() {
            var handle=CreateFile(SelfProtectionProtocol.DevicePath,GenericRead|GenericWrite,FileShareRead|FileShareWrite,IntPtr.Zero,OpenExisting,0,IntPtr.Zero);
            if(handle==null || handle.IsInvalid) {
                int error=Marshal.GetLastWin32Error(); if(handle!=null) handle.Dispose();
                throw new Win32Exception(error,"无法打开 YCSZ 自保护设备");
            }
            return handle;
        }

        NativeActivateRequest BuildActivate(SelfProtectionRequest request) {
            string image=ToKernelPath(request.Identity.ImagePath);
            string root=Path.GetDirectoryName(request.Identity.ImagePath);
            if(String.IsNullOrWhiteSpace(root)) throw new InvalidDataException("无法确定 YCSZ 安装根目录");
            root=ToKernelPath(root);
            string dataRoot=String.IsNullOrWhiteSpace(request.ProtectedDataRoot)?protectedDataRoot:request.ProtectedDataRoot;
            if(String.IsNullOrWhiteSpace(dataRoot)) throw new InvalidDataException("未配置 YCSZ ProgramData 保护根");
            return new NativeActivateRequest {
                Header=BuildHeader(request.RequestId,Marshal.SizeOf(typeof(NativeActivateRequest))),
                Identity=BuildIdentity(request.Identity,image),
                ProtectedRoot=ToFixedWchar(root),
                ProtectedDataRoot=ToFixedWchar(ToKernelPath(dataRoot))
            };
        }

        static NativeIdentity BuildIdentity(ProtectionIdentity identity,string kernelImagePath) {
            return new NativeIdentity {
                ProcessId=checked((uint)identity.ProcessId),
                SessionId=checked((uint)identity.SessionId),
                CreateTime100ns=identity.StartTimeUtcFileTime,
                ImageSha256=FromHex(identity.ImageSha256,32),
                InstanceNonce=FromHex(identity.InstanceNonce,16),
                ImagePath=ToFixedWchar(kernelImagePath)
            };
        }

        static NativeMaintenanceRequest BuildMaintenance(SelfProtectionRequest request) {
            return new NativeMaintenanceRequest {
                Header=BuildHeader(request.RequestId,Marshal.SizeOf(typeof(NativeMaintenanceRequest))),
                LeaseId=FromHex(request.MaintenanceLeaseId,16),
                ExpiresAt100ns=request.Operation==SelfProtectionOperation.EnterMaintenance?request.MaintenanceExpiresUtcFileTime:0
            };
        }

        static NativeHeader BuildHeader(string requestId,int size) {
            Guid id; if(!Guid.TryParseExact(requestId,"N",out id)) throw new InvalidDataException("自保护请求 ID 无效");
            byte[] bytes=id.ToByteArray(); ulong value=BitConverter.ToUInt64(bytes,0);
            if(value==0) value=1;
            return new NativeHeader { Size=checked((uint)size),Version=SelfProtectionProtocol.Version,RequestId=value };
        }

        static void SendNoOutput<T>(SafeFileHandle device,uint code,ref T value) where T:struct {
            int size=Marshal.SizeOf(typeof(T)); IntPtr buffer=Marshal.AllocHGlobal(size);
            try {
                Marshal.StructureToPtr(value,buffer,false); uint returned;
                if(!DeviceIoControl(device,code,buffer,(uint)size,IntPtr.Zero,0,out returned,IntPtr.Zero)) ThrowIoctl(code);
            } finally { Marshal.DestroyStructure(buffer,typeof(T)); Marshal.FreeHGlobal(buffer); }
        }

        SelfProtectionReply QueryStatus(SafeFileHandle device,SelfProtectionRequest request) {
            int size=StatusSize; IntPtr buffer=Marshal.AllocHGlobal(size);
            try {
                uint returned;
                if(!DeviceIoControl(device,IoctlQueryStatus,IntPtr.Zero,0,buffer,(uint)size,out returned,IntPtr.Zero)) ThrowIoctl(IoctlQueryStatus);
                if(returned!=(uint)size) throw new InvalidDataException("驱动应答长度错误");
                var bytes=new byte[size]; Marshal.Copy(buffer,bytes,0,size);
                string dataRoot=String.IsNullOrWhiteSpace(request.ProtectedDataRoot)?protectedDataRoot:request.ProtectedDataRoot;
                return DecodeStatus(bytes,request,ToKernelPath(request.Identity.ImagePath),ToKernelPath(Path.GetDirectoryName(request.Identity.ImagePath)),String.IsNullOrWhiteSpace(dataRoot)?null:ToKernelPath(dataRoot));
            } finally { Marshal.FreeHGlobal(buffer); }
        }

        // Pure wire validation, also used by isolated tests with no device access.
        public static SelfProtectionReply DecodeStatus(byte[] bytes,SelfProtectionRequest request,string expectedImage,string expectedRoot) {
            if(request==null || String.IsNullOrWhiteSpace(request.ProtectedDataRoot)) throw new InvalidDataException("状态核验必须绑定 ProgramData 保护根");
            return DecodeStatus(bytes,request,expectedImage,expectedRoot,request.ProtectedDataRoot);
        }

        public static SelfProtectionReply DecodeStatus(byte[] bytes,SelfProtectionRequest request,string expectedImage,string expectedRoot,string expectedDataRoot) {
            if(bytes==null || bytes.Length!=StatusSize || request==null || request.Identity==null) throw new InvalidDataException("驱动应答长度或请求无效");
            IntPtr buffer=Marshal.AllocHGlobal(bytes.Length);
            NativeStatus status;
            try { Marshal.Copy(bytes,0,buffer,bytes.Length); status=(NativeStatus)Marshal.PtrToStructure(buffer,typeof(NativeStatus)); }
            finally { Marshal.FreeHGlobal(buffer); }
            if(status.Size!=StatusSize || status.Version!=SelfProtectionProtocol.Version ||
                (status.State&~(StateActive|StateProcessCallback|StateFileFilter|StateMaintenance|StateUnloadPrepared|StateTrayRegistered|StateDataRoot|StateError))!=0)
                throw new InvalidDataException("驱动应答协议不匹配");
            if(status.LastStatus!=0 || (status.State&StateError)!=0 || (status.State&StateActive)==0)
                throw new InvalidDataException("驱动未确认激活成功");
            var identity=request.Identity;
            if(status.TargetPid!=identity.ProcessId || status.TargetSessionId!=(uint)identity.SessionId || status.TargetCreateTime100ns!=identity.StartTimeUtcFileTime ||
                !EqualBytes(status.ImageSha256,FromHex(identity.ImageSha256,32)) || !EqualBytes(status.InstanceNonce,FromHex(identity.InstanceNonce,16)) ||
                !String.Equals(ReadWchar(status.ImagePath),expectedImage,StringComparison.OrdinalIgnoreCase) ||
                !String.Equals(ReadWchar(status.ProtectedRoot),expectedRoot,StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("驱动应答不属于当前服务实例或安装目录");
            if((status.State&StateDataRoot)==0 || (expectedDataRoot!=null && !String.Equals(ReadWchar(status.ProtectedDataRoot),expectedDataRoot,StringComparison.OrdinalIgnoreCase)))
                throw new InvalidDataException("驱动应答缺少或错配 ProgramData 保护根");
            if(request.Operation==SelfProtectionOperation.RegisterTray) {
                if((status.State&StateTrayRegistered)==0 || request.TrayIdentity==null || !StatusIdentityMatches(status.TrayIdentity,request.TrayIdentity)) throw new InvalidDataException("驱动未确认当前托盘实例登记");
            } else if(request.Operation==SelfProtectionOperation.UnregisterTray &&
                ((status.State&StateTrayRegistered)!=0 || status.TrayIdentity.ProcessId!=0)) {
                throw new InvalidDataException("驱动未确认托盘实例注销");
            }
            bool maintenance=(status.State&StateMaintenance)!=0;
            if(request.Operation==SelfProtectionOperation.EnterMaintenance || request.Operation==SelfProtectionOperation.PrepareUnload) {
                bool prepared=request.Operation==SelfProtectionOperation.PrepareUnload;
                if(!maintenance || ((status.State&StateUnloadPrepared)!=0)!=prepared || status.MaintenanceExpiresAt100ns!=request.MaintenanceExpiresUtcFileTime ||
                    !EqualBytes(status.LeaseId,FromHex(request.MaintenanceLeaseId,16))) throw new InvalidDataException("驱动维护租约不匹配");
            } else if(request.Operation!=SelfProtectionOperation.UnregisterTray &&
                (maintenance || (status.State&StateUnloadPrepared)!=0 || status.MaintenanceExpiresAt100ns!=0 || !EqualBytes(status.LeaseId,new byte[16]))) {
                throw new InvalidDataException("驱动尚未退出维护状态");
            }
            SelfProtectionCapability capabilities=SelfProtectionCapability.None;
            if(!maintenance && (status.State&StateProcessCallback)!=0) capabilities|=SelfProtectionCapability.ProcessTermination;
            if((status.State&StateFileFilter)!=0) capabilities|=SelfProtectionCapability.FileMutation;
            return new SelfProtectionReply { Accepted=true,DriverLoaded=true,Capabilities=capabilities };
        }

        static bool StatusIdentityMatches(NativeIdentity status,ProtectionIdentity expected) {
            return expected!=null && status.ProcessId==(uint)expected.ProcessId && status.SessionId==(uint)expected.SessionId &&
                status.CreateTime100ns==expected.StartTimeUtcFileTime && EqualBytes(status.ImageSha256,FromHex(expected.ImageSha256,32)) &&
                EqualBytes(status.InstanceNonce,FromHex(expected.InstanceNonce,16)) &&
                String.Equals(ReadWchar(status.ImagePath),ToKernelPath(expected.ImagePath),StringComparison.OrdinalIgnoreCase);
        }

        static bool EqualBytes(byte[] first,byte[] second) {
            if(first==null || second==null || first.Length!=second.Length) return false;
            int difference=0; for(int i=0;i<first.Length;i++) difference|=first[i]^second[i]; return difference==0;
        }
        static string ReadWchar(ushort[] value) {
            int end=Array.IndexOf(value,(ushort)0);
            if(end<=0) throw new InvalidDataException("驱动路径缺少终止符或为空");
            var chars=new char[end]; for(int i=0;i<end;i++) chars[i]=(char)value[i]; return new string(chars);
        }

        static byte[] FromHex(string text,int bytes) {
            if(String.IsNullOrWhiteSpace(text) || text.Length!=bytes*2) throw new InvalidDataException("自保护十六进制身份字段无效");
            var result=new byte[bytes]; for(int i=0;i<bytes;i++) { int high=Hex(text[i*2]),low=Hex(text[i*2+1]); if(high<0||low<0) throw new InvalidDataException("自保护十六进制身份字段无效"); result[i]=(byte)((high<<4)|low); } return result;
        }
        static int Hex(char c) { if(c>='0'&&c<='9') return c-'0'; if(c>='a'&&c<='f') return c-'a'+10; if(c>='A'&&c<='F') return c-'A'+10; return -1; }

        static ushort[] ToFixedWchar(string text) {
            if(String.IsNullOrWhiteSpace(text) || text.Length>=MaxPathChars) throw new InvalidDataException("自保护路径过长或为空");
            var result=new ushort[MaxPathChars]; for(int i=0;i<text.Length;i++) result[i]=text[i]; return result;
        }

        static string ToKernelPath(string path) {
            if(String.IsNullOrWhiteSpace(path)) throw new InvalidDataException("自保护映像路径为空");
            if(path.StartsWith("\\Device\\",StringComparison.OrdinalIgnoreCase)) return path;
            string full=Path.GetFullPath(path);
            if(full.StartsWith("\\\\?\\",StringComparison.Ordinal)) full=full.Substring(4);
            if(full.StartsWith("\\\\",StringComparison.Ordinal)) throw new InvalidDataException("自保护暂不接受 UNC 安装路径");
            if(full.Length<3 || full[1]!=':' || full[2]!='\\') throw new InvalidDataException("自保护必须使用本地固定盘符路径");
            string drive=full.Substring(0,2); var device=new System.Text.StringBuilder(512); uint length=QueryDosDevice(drive,device,(uint)device.Capacity);
            if(length==0) throw new Win32Exception(Marshal.GetLastWin32Error(),"无法解析安装盘符");
            string suffix=full.Substring(2); if(suffix=="\\") suffix="";
            return device.ToString()+suffix;
        }

        static void ThrowIoctl(uint code) { throw new Win32Exception(Marshal.GetLastWin32Error(),"YCSZ 自保护 IOCTL 失败：0x"+code.ToString("X8")); }

        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern SafeFileHandle CreateFile(string name,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool DeviceIoControl(SafeFileHandle device,uint code,IntPtr input,uint inputLength,IntPtr output,uint outputLength,out uint returned,IntPtr overlapped);
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern uint QueryDosDevice(string device,System.Text.StringBuilder target,uint max);
    }
}
