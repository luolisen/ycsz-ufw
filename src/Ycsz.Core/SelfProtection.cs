using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;

namespace Ycsz {
    public static class SelfProtectionProtocol {
        public const int Version=1;
        public const string DevicePath=@"\\.\YcszProtection";
        public const string ControlPipeName="YcszFirewall.SelfProtection.v1";
    }

    [Flags]
    public enum SelfProtectionCapability {
        None = 0,
        ProcessTermination = 1,
        FileMutation = 2,
        ServiceStop = 4
    }

    public enum SelfProtectionState {
        Unavailable,
        Starting,
        Degraded,
        Active,
        Maintenance,
        Failed
    }

    public enum SelfProtectionOperation {
        Activate,
        EnterMaintenance,
        ExitMaintenance,
        PrepareUnload
    }

    public sealed class ProtectionIdentity {
        public const string ExpectedServiceName = "YcszFirewall";
        public string ServiceName;
        public int ProcessId;
        public long StartTimeUtcFileTime;
        public string ImagePath;
        public string ImageSha256;
        public string InstanceNonce;

        public static ProtectionIdentity CaptureCurrent(string expectedImagePath) {
            if (String.IsNullOrWhiteSpace(expectedImagePath)) throw new ArgumentException("expectedImagePath");
            string expected=Path.GetFullPath(expectedImagePath);
            using(var process=Process.GetCurrentProcess()) {
                string actual=Path.GetFullPath(process.MainModule.FileName);
                if(!String.Equals(actual,expected,StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("服务进程路径与固定安装路径不一致");
                return new ProtectionIdentity { ServiceName=ExpectedServiceName,ProcessId=process.Id,StartTimeUtcFileTime=process.StartTime.ToUniversalTime().ToFileTimeUtc(),ImagePath=actual,ImageSha256=HashFile(actual),InstanceNonce=Guid.NewGuid().ToString("N") };
            }
        }

        public void Validate() {
            if(ServiceName!=ExpectedServiceName || ProcessId<=0 || StartTimeUtcFileTime<=0) throw new InvalidDataException("自保护进程身份无效");
            if(String.IsNullOrWhiteSpace(ImagePath) || !Path.IsPathRooted(ImagePath) || !String.Equals(Path.GetFileName(ImagePath),"Ycsz.exe",StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("自保护映像路径无效");
            if(!IsSha256(ImageSha256) || String.IsNullOrWhiteSpace(InstanceNonce) || InstanceNonce.Length!=32 || !IsHex(InstanceNonce)) throw new InvalidDataException("自保护映像身份摘要无效");
        }

        static string HashFile(string path) {
            using(var sha=SHA256.Create()) using(var stream=File.OpenRead(path)) return BitConverter.ToString(sha.ComputeHash(stream)).Replace("-","").ToLowerInvariant();
        }
        static bool IsSha256(string value) { return value!=null && value.Length==64 && IsHex(value); }
        static bool IsHex(string value) { if(value==null) return false; foreach(char c in value) if(!((c>='0'&&c<='9')||(c>='a'&&c<='f')||(c>='A'&&c<='F'))) return false; return true; }
    }

    public sealed class SelfProtectionRequest {
        public const int CurrentVersion=SelfProtectionProtocol.Version;
        public int Version=CurrentVersion;
        public string RequestId;
        public SelfProtectionOperation Operation;
        public ProtectionIdentity Identity;
        public string MaintenanceLeaseId;
        public long MaintenanceExpiresUtcFileTime;

        public void Validate(DateTime utcNow) {
            if(Version!=CurrentVersion || String.IsNullOrWhiteSpace(RequestId) || RequestId.Length!=32) throw new InvalidDataException("自保护请求版本或 ID 无效");
            Guid ignored; if(!Guid.TryParseExact(RequestId,"N",out ignored)) throw new InvalidDataException("自保护请求 ID 无效");
            if(Identity==null) throw new InvalidDataException("缺少自保护进程身份");
            Identity.Validate();
            if(Operation!=SelfProtectionOperation.Activate && Operation!=SelfProtectionOperation.EnterMaintenance && Operation!=SelfProtectionOperation.ExitMaintenance && Operation!=SelfProtectionOperation.PrepareUnload) throw new InvalidDataException("自保护操作无效");
            if(Operation==SelfProtectionOperation.Activate) { if(MaintenanceLeaseId!=null || MaintenanceExpiresUtcFileTime!=0) throw new InvalidDataException("激活请求不得携带维护租约"); return; }
            if(String.IsNullOrWhiteSpace(MaintenanceLeaseId) || MaintenanceLeaseId.Length!=32 || !Guid.TryParseExact(MaintenanceLeaseId,"N",out ignored)) throw new InvalidDataException("维护租约无效");
            if((Operation==SelfProtectionOperation.EnterMaintenance || Operation==SelfProtectionOperation.PrepareUnload) && MaintenanceExpiresUtcFileTime<=utcNow.ToFileTimeUtc()) throw new InvalidDataException("维护租约已过期");
        }

        public static SelfProtectionRequest Create(SelfProtectionOperation operation,ProtectionIdentity identity,string leaseId,DateTime expiresUtc) {
            var request=new SelfProtectionRequest { RequestId=Guid.NewGuid().ToString("N"),Operation=operation,Identity=identity,MaintenanceLeaseId=leaseId,MaintenanceExpiresUtcFileTime=expiresUtc==DateTime.MinValue?0:expiresUtc.ToFileTimeUtc() };
            request.Validate(DateTime.UtcNow);
            return request;
        }
        public static SelfProtectionRequest Create(SelfProtectionOperation operation,ProtectionIdentity identity,string leaseId,DateTime expiresUtc,DateTime validationUtc) {
            var request=new SelfProtectionRequest { RequestId=Guid.NewGuid().ToString("N"),Operation=operation,Identity=identity,MaintenanceLeaseId=leaseId,MaintenanceExpiresUtcFileTime=expiresUtc==DateTime.MinValue?0:expiresUtc.ToFileTimeUtc() };
            request.Validate(validationUtc.ToUniversalTime());
            return request;
        }
    }

    public sealed class SelfProtectionReply {
        public bool Accepted;
        public bool DriverLoaded;
        public SelfProtectionCapability Capabilities;
        public string Error;

        public void Validate() {
            const SelfProtectionCapability all=SelfProtectionCapability.ProcessTermination|SelfProtectionCapability.FileMutation|SelfProtectionCapability.ServiceStop;
            if((Capabilities&~all)!=0 || (!DriverLoaded && Capabilities!=SelfProtectionCapability.None)) throw new InvalidDataException("自保护驱动能力报告无效");
        }
    }

    public interface ISelfProtectionTransport {
        SelfProtectionReply Send(SelfProtectionRequest request);
    }

    public sealed class SelfProtectionStatus {
        public SelfProtectionState State;
        public bool DriverLoaded;
        public SelfProtectionCapability Capabilities;
        public string Failure;
        public string MaintenanceLeaseId;
        public DateTime MaintenanceUntilUtc;

        public bool ProcessProtectionActive { get { return (Capabilities&SelfProtectionCapability.ProcessTermination)!=0; } }
        public bool FileProtectionActive { get { return (Capabilities&SelfProtectionCapability.FileMutation)!=0; } }
        public bool ServiceStopProtectionActive { get { return (Capabilities&SelfProtectionCapability.ServiceStop)!=0; } }

        public static SelfProtectionStatus Unavailable(string reason) { return new SelfProtectionStatus { State=SelfProtectionState.Unavailable,Failure=reason??"驱动未加载" }; }
        public SelfProtectionStatus Copy() { return new SelfProtectionStatus { State=State,DriverLoaded=DriverLoaded,Capabilities=Capabilities,Failure=Failure,MaintenanceLeaseId=MaintenanceLeaseId,MaintenanceUntilUtc=MaintenanceUntilUtc }; }
        public string UserText() {
            if(State==SelfProtectionState.Active) return "内核自保护已启用（进程句柄/文件过滤；服务停止需认证维护）";
            if(State==SelfProtectionState.Maintenance) return "内核自保护维护窗口已授权（最长 15 分钟）";
            if(State==SelfProtectionState.Degraded) return "内核自保护不完整，未满足全部保护能力";
            if(State==SelfProtectionState.Starting) return "内核自保护正在初始化";
            if(State==SelfProtectionState.Failed) return "内核自保护未启用："+(Failure??"驱动通信失败");
            return "内核自保护未启用："+(Failure??"驱动未加载");
        }
        public static string Append(string baseText,SelfProtectionStatus protection) { return (baseText??"")+"；"+(protection??Unavailable(null)).UserText(); }
    }

    // User-mode coordinator only. A production transport must authenticate the
    // service image and instance in the driver; a password or arbitrary PID is
    // never sent over this protocol.
    public sealed class SelfProtectionCoordinator {
        // ServiceStop is deliberately not a kernel capability.  SCM stop must be
        // handled by the authenticated service lifecycle, while the driver reports
        // only the two capabilities it actually implements.
        static readonly SelfProtectionCapability Required=SelfProtectionCapability.ProcessTermination|SelfProtectionCapability.FileMutation;
        readonly object sync=new object(); readonly ISelfProtectionTransport transport; readonly Func<ProtectionIdentity> identityFactory; readonly Func<string,SelfProtectionOperation,bool> authorizer; readonly TimeSpan maintenanceWindow; string maintenanceSession;
        ProtectionIdentity registeredIdentity;
        SelfProtectionStatus status=SelfProtectionStatus.Unavailable("驱动未构建或未加载");

        public SelfProtectionCoordinator(ISelfProtectionTransport transport,Func<ProtectionIdentity> identityFactory,Func<string,SelfProtectionOperation,bool> authorizer,TimeSpan maintenanceWindow) {
            if(transport==null) throw new ArgumentNullException("transport"); if(identityFactory==null) throw new ArgumentNullException("identityFactory"); if(authorizer==null) throw new ArgumentNullException("authorizer");
            if(maintenanceWindow<=TimeSpan.Zero || maintenanceWindow>TimeSpan.FromMinutes(15)) throw new ArgumentOutOfRangeException("maintenanceWindow");
            this.transport=transport; this.identityFactory=identityFactory; this.authorizer=authorizer; this.maintenanceWindow=maintenanceWindow;
        }
        public SelfProtectionStatus Status { get { lock(sync) return status.Copy(); } }

        public bool Activate(DateTime utcNow) {
            lock(sync) {
                status.State=SelfProtectionState.Starting; status.Failure=null;
                try { registeredIdentity=identityFactory(); return ApplyReply(transport.Send(SelfProtectionRequest.Create(SelfProtectionOperation.Activate,registeredIdentity,null,DateTime.MinValue,utcNow))); }
                catch(Exception e) { Fail(e.Message); return false; }
            }
        }

        public bool BeginMaintenance(string authenticatedSession,DateTime utcNow) {
            lock(sync) {
                if(status.State!=SelfProtectionState.Active || String.IsNullOrWhiteSpace(authenticatedSession)) return false;
                bool allowed; try { allowed=authorizer(authenticatedSession,SelfProtectionOperation.EnterMaintenance); } catch { allowed=false; }
                if(!allowed) return false;
                string lease=Guid.NewGuid().ToString("N"); DateTime until=utcNow.ToUniversalTime().Add(maintenanceWindow); status.MaintenanceLeaseId=lease; status.MaintenanceUntilUtc=until; maintenanceSession=authenticatedSession;
                try {
                    var reply=transport.Send(SelfProtectionRequest.Create(SelfProtectionOperation.EnterMaintenance,registeredIdentity,lease,until,utcNow)); reply.Validate();
                    if(!reply.Accepted || !reply.DriverLoaded) { Fail(reply.Error??"驱动拒绝维护窗口"); return false; }
                    status.DriverLoaded=true; status.Capabilities=reply.Capabilities; status.State=SelfProtectionState.Maintenance; status.Failure=null; return true;
                } catch(Exception e) { Fail(e.Message); return false; }
            }
        }

        public bool EndMaintenance(string authenticatedSession,DateTime utcNow) {
            lock(sync) {
                if((status.State!=SelfProtectionState.Maintenance && status.State!=SelfProtectionState.Failed) || String.IsNullOrWhiteSpace(status.MaintenanceLeaseId) || !String.Equals(maintenanceSession,authenticatedSession,StringComparison.Ordinal)) return false;
                bool allowed; try { allowed=authorizer(authenticatedSession,SelfProtectionOperation.ExitMaintenance); } catch { allowed=false; }
                if(!allowed) return false;
                return CloseMaintenanceLocked(utcNow);
            }
        }

        public bool PrepareUnload(string authenticatedSession,DateTime utcNow) {
            lock(sync) {
                if(!CanStopService(authenticatedSession,utcNow)) return false;
                bool allowed; try { allowed=authorizer(authenticatedSession,SelfProtectionOperation.PrepareUnload); } catch { allowed=false; }
                if(!allowed) return false;
                try {
                    var reply=transport.Send(SelfProtectionRequest.Create(SelfProtectionOperation.PrepareUnload,registeredIdentity,status.MaintenanceLeaseId,status.MaintenanceUntilUtc,utcNow));
                    reply.Validate();
                    if(!reply.Accepted || !reply.DriverLoaded || reply.Capabilities!=SelfProtectionCapability.None) { Fail(reply.Error??"驱动拒绝准备卸载"); return false; }
                    return true;
                } catch(Exception e) { Fail(e.Message); return false; }
            }
        }

        public void Tick(DateTime utcNow) {
            lock(sync) if((status.State==SelfProtectionState.Maintenance || status.State==SelfProtectionState.Failed) && !String.IsNullOrWhiteSpace(status.MaintenanceLeaseId) && utcNow.ToUniversalTime()>=status.MaintenanceUntilUtc) CloseMaintenanceLocked(utcNow);
        }

        public bool CanStopService(string authenticatedSession,DateTime utcNow) {
            Tick(utcNow);
            lock(sync) return status.State==SelfProtectionState.Maintenance && String.Equals(maintenanceSession,authenticatedSession,StringComparison.Ordinal) && utcNow.ToUniversalTime()<status.MaintenanceUntilUtc;
        }

        // If a protection service is registered but failed to load, SCM Stop is
        // intentionally still closed.  The authenticated IPC path must remain
        // usable so an administrator can recover the application without
        // opening Stop to every local administrator.  This path never claims
        // that kernel protection is active.
        public bool CanStopForRecovery(string authenticatedSession,DateTime utcNow) {
            Tick(utcNow);
            lock(sync) {
                return !String.IsNullOrWhiteSpace(authenticatedSession) &&
                    (status.State==SelfProtectionState.Unavailable || status.State==SelfProtectionState.Failed);
            }
        }

        bool CloseMaintenanceLocked(DateTime utcNow) {
            try {
                var reply=transport.Send(SelfProtectionRequest.Create(SelfProtectionOperation.ExitMaintenance,registeredIdentity,status.MaintenanceLeaseId,DateTime.MinValue,utcNow)); reply.Validate();
                if(!reply.Accepted || !reply.DriverLoaded) { Fail(reply.Error??"驱动拒绝关闭维护窗口"); return false; }
                status.DriverLoaded=true; status.Capabilities=reply.Capabilities; status.State=CapabilitiesComplete()?SelfProtectionState.Active:SelfProtectionState.Degraded; status.MaintenanceLeaseId=null; status.MaintenanceUntilUtc=DateTime.MinValue; maintenanceSession=null; status.Failure=null; return true;
            } catch(Exception e) { Fail(e.Message); return false; }
        }
        bool ApplyReply(SelfProtectionReply reply) {
            if(reply==null) throw new InvalidDataException("驱动没有返回状态"); reply.Validate();
            if(!reply.Accepted || !reply.DriverLoaded) { Fail(reply.Error??"驱动未加载或拒绝注册"); return false; }
            status.DriverLoaded=true; status.Capabilities=reply.Capabilities; status.State=CapabilitiesComplete()?SelfProtectionState.Active:SelfProtectionState.Degraded; status.MaintenanceLeaseId=null; status.MaintenanceUntilUtc=DateTime.MinValue; maintenanceSession=null; status.Failure=null; return status.State==SelfProtectionState.Active;
        }
        bool CapabilitiesComplete() { return status.DriverLoaded && (status.Capabilities&Required)==Required; }
        void Fail(string error) { status.State=SelfProtectionState.Failed; status.DriverLoaded=false; status.Capabilities=SelfProtectionCapability.None; status.Failure=error??"自保护失败"; /* Retain an uncertain lease so expiry and explicit exit can retry. */ }
    }
}
