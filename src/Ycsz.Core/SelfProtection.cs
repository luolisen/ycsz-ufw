using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;

namespace Ycsz {
    public static class SelfProtectionProtocol {
        public const int Version=3;
        public const string DevicePath=@"\\.\YcszProtection";
        public const string ControlPipeName="YcszFirewall.SelfProtection.v3";
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
        Initializing,
        Degraded,
        Active,
        Maintenance,
        Failed
    }

    public enum SelfProtectionOperation {
        BeginInitialize,
        CommitInitialize,
        AbortInitialize,
        EnterMaintenance,
        ExitMaintenance,
        PrepareUnload,
        RegisterTray,
        UnregisterTray
    }

    public enum SelfProtectionPhase {
        Active,
        Initializing,
        Maintenance,
        Unavailable
    }

    public sealed class ProtectionIdentity {
        public const string ExpectedServiceName = "YcszFirewall";
        public string ServiceName;
        public int ProcessId;
        public int SessionId;
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
                return new ProtectionIdentity { ServiceName=ExpectedServiceName,ProcessId=process.Id,SessionId=process.SessionId,StartTimeUtcFileTime=process.StartTime.ToUniversalTime().ToFileTimeUtc(),ImagePath=actual,ImageSha256=HashFile(actual),InstanceNonce=Guid.NewGuid().ToString("N") };
            }
        }

        public static ProtectionIdentity CaptureProcess(int processId,string expectedImagePath,int expectedSessionId) {
            if (processId<=0 || expectedSessionId<=0 || String.IsNullOrWhiteSpace(expectedImagePath)) throw new ArgumentException("tray identity");
            string expected=Path.GetFullPath(expectedImagePath);
            using(var process=Process.GetProcessById(processId)) {
                if(process.HasExited || process.SessionId!=expectedSessionId) throw new InvalidOperationException("托盘进程会话已变化");
                string actual=Path.GetFullPath(process.MainModule.FileName);
                if(!String.Equals(actual,expected,StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("托盘进程路径与固定安装路径不一致");
                return new ProtectionIdentity { ServiceName=ExpectedServiceName,ProcessId=process.Id,SessionId=process.SessionId,StartTimeUtcFileTime=process.StartTime.ToUniversalTime().ToFileTimeUtc(),ImagePath=actual,ImageSha256=HashFile(actual),InstanceNonce=Guid.NewGuid().ToString("N") };
            }
        }

        public void Validate() {
            if(ServiceName!=ExpectedServiceName || ProcessId<=0 || SessionId<0 || StartTimeUtcFileTime<=0) throw new InvalidDataException("自保护进程身份无效");
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
        public ProtectionIdentity TrayIdentity;
        public string ProtectedDataRoot;
        public string MaintenanceLeaseId;
        public long MaintenanceExpiresUtcFileTime;
        public int InitializationExpectedEntries;

        public void Validate(DateTime utcNow) {
            if(Version!=CurrentVersion || String.IsNullOrWhiteSpace(RequestId) || RequestId.Length!=32) throw new InvalidDataException("自保护请求版本或 ID 无效");
            Guid ignored; if(!Guid.TryParseExact(RequestId,"N",out ignored)) throw new InvalidDataException("自保护请求 ID 无效");
            if(Identity==null) throw new InvalidDataException("缺少自保护进程身份");
            Identity.Validate();
            if(Operation!=SelfProtectionOperation.BeginInitialize && Operation!=SelfProtectionOperation.CommitInitialize && Operation!=SelfProtectionOperation.AbortInitialize && Operation!=SelfProtectionOperation.EnterMaintenance && Operation!=SelfProtectionOperation.ExitMaintenance && Operation!=SelfProtectionOperation.PrepareUnload && Operation!=SelfProtectionOperation.RegisterTray && Operation!=SelfProtectionOperation.UnregisterTray) throw new InvalidDataException("自保护操作无效");
            if(Identity.SessionId!=0) throw new InvalidDataException("服务身份必须属于 session 0");
            if(Operation==SelfProtectionOperation.BeginInitialize || Operation==SelfProtectionOperation.CommitInitialize || Operation==SelfProtectionOperation.AbortInitialize) {
                if(MaintenanceLeaseId!=null || MaintenanceExpiresUtcFileTime!=0 || TrayIdentity!=null) throw new InvalidDataException("初始化请求不得携带维护租约或托盘身份");
                if(Operation==SelfProtectionOperation.CommitInitialize && InitializationExpectedEntries<=0) throw new InvalidDataException("初始化提交必须携带扫描项数");
                if(Operation!=SelfProtectionOperation.CommitInitialize && InitializationExpectedEntries!=0) throw new InvalidDataException("非提交初始化请求不得携带扫描项数");
                return;
            }
            if(InitializationExpectedEntries!=0) throw new InvalidDataException("维护请求不得携带初始化扫描项数");
            if(Operation==SelfProtectionOperation.RegisterTray || Operation==SelfProtectionOperation.UnregisterTray) {
                if(!String.IsNullOrWhiteSpace(MaintenanceLeaseId) || MaintenanceExpiresUtcFileTime!=0 || TrayIdentity==null) throw new InvalidDataException("托盘登记请求字段无效");
                TrayIdentity.Validate(); if(TrayIdentity.SessionId<=0) throw new InvalidDataException("托盘必须属于用户会话"); return;
            }
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
        public static SelfProtectionRequest CreateTray(SelfProtectionOperation operation,ProtectionIdentity serviceIdentity,ProtectionIdentity trayIdentity,DateTime validationUtc) {
            var request=new SelfProtectionRequest { RequestId=Guid.NewGuid().ToString("N"),Operation=operation,Identity=serviceIdentity,TrayIdentity=trayIdentity };
            request.Validate(validationUtc.ToUniversalTime()); return request;
        }
        public static SelfProtectionRequest CreateCommit(ProtectionIdentity identity,int expectedEntries,DateTime validationUtc) {
            var request=new SelfProtectionRequest { RequestId=Guid.NewGuid().ToString("N"),Operation=SelfProtectionOperation.CommitInitialize,Identity=identity,InitializationExpectedEntries=expectedEntries };
            request.Validate(validationUtc.ToUniversalTime()); return request;
        }
    }

    public sealed class SelfProtectionReply {
        public bool Accepted;
        public bool DriverLoaded;
        public SelfProtectionCapability Capabilities;
        public string Error;
        public SelfProtectionPhase Phase=SelfProtectionPhase.Active;

        public void Validate() {
            const SelfProtectionCapability all=SelfProtectionCapability.ProcessTermination|SelfProtectionCapability.FileMutation|SelfProtectionCapability.ServiceStop;
            if((Capabilities&~all)!=0 || (!DriverLoaded && Capabilities!=SelfProtectionCapability.None)) throw new InvalidDataException("自保护驱动能力报告无效");
            if(Phase<SelfProtectionPhase.Active || Phase>SelfProtectionPhase.Unavailable) throw new InvalidDataException("自保护驱动阶段报告无效");
        }
    }

    public interface ISelfProtectionTransport {
        SelfProtectionReply Send(SelfProtectionRequest request);
    }

    public sealed class SelfProtectionStatus {
        public SelfProtectionState State;
        public bool DriverLoaded;
        // This is an activation/writeback precondition, not a claim that the
        // minifilter can deny arbitrary Cache Manager mapped writes.
        public bool MappingWritebackConditionMet;
        public SelfProtectionCapability Capabilities;
        public string Failure;
        public string MaintenanceLeaseId;
        public DateTime MaintenanceUntilUtc;

        public bool ProcessProtectionActive { get { return (Capabilities&SelfProtectionCapability.ProcessTermination)!=0; } }
        public bool FileProtectionActive { get { return (Capabilities&SelfProtectionCapability.FileMutation)!=0; } }
        public bool ServiceStopProtectionActive { get { return (Capabilities&SelfProtectionCapability.ServiceStop)!=0; } }

        public static SelfProtectionStatus Unavailable(string reason) { return new SelfProtectionStatus { State=SelfProtectionState.Unavailable,Failure=reason??"驱动未加载" }; }
        public SelfProtectionStatus Copy() { return new SelfProtectionStatus { State=State,DriverLoaded=DriverLoaded,MappingWritebackConditionMet=MappingWritebackConditionMet,Capabilities=Capabilities,Failure=Failure,MaintenanceLeaseId=MaintenanceLeaseId,MaintenanceUntilUtc=MaintenanceUntilUtc }; }
        public string UserText() {
            if(State==SelfProtectionState.Active) return "内核自保护已启用（进程句柄/文件过滤；服务停止需认证维护）"+(MappingWritebackConditionMet?"":"；可写映射写回条件未满足");
            if(State==SelfProtectionState.Maintenance) return "内核自保护维护窗口已授权（最长 15 分钟；安装目录与 ProgramData 文件过滤仍在）"+(MappingWritebackConditionMet?"":"；可写映射写回条件未满足");
            if(State==SelfProtectionState.Degraded) return "内核自保护不完整，未满足全部保护能力";
            if(State==SelfProtectionState.Starting) return "内核自保护正在初始化";
            if(State==SelfProtectionState.Initializing) return "内核自保护正在扫描并确认保护文件";
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
        readonly object sync=new object(); readonly ISelfProtectionTransport transport; readonly Func<ProtectionIdentity> identityFactory; readonly Func<string,SelfProtectionOperation,bool> authorizer; readonly Func<SelfProtectionPreflightResult> preflight; readonly TimeSpan maintenanceWindow; string maintenanceSession;
        ProtectionIdentity registeredIdentity;
        ProtectionIdentity registeredTray;
        SelfProtectionStatus status=SelfProtectionStatus.Unavailable("驱动未构建或未加载");

        public SelfProtectionCoordinator(ISelfProtectionTransport transport,Func<ProtectionIdentity> identityFactory,Func<string,SelfProtectionOperation,bool> authorizer,TimeSpan maintenanceWindow) : this(transport,identityFactory,authorizer,maintenanceWindow,null) {}
        public SelfProtectionCoordinator(ISelfProtectionTransport transport,Func<ProtectionIdentity> identityFactory,Func<string,SelfProtectionOperation,bool> authorizer,TimeSpan maintenanceWindow,Func<SelfProtectionPreflightResult> preflight) {
            if(transport==null) throw new ArgumentNullException("transport"); if(identityFactory==null) throw new ArgumentNullException("identityFactory"); if(authorizer==null) throw new ArgumentNullException("authorizer");
            if(maintenanceWindow<=TimeSpan.Zero || maintenanceWindow>TimeSpan.FromMinutes(15)) throw new ArgumentOutOfRangeException("maintenanceWindow");
            this.transport=transport; this.identityFactory=identityFactory; this.authorizer=authorizer; this.maintenanceWindow=maintenanceWindow; this.preflight=preflight;
        }
        public SelfProtectionStatus Status { get { lock(sync) return status.Copy(); } }

        public bool Activate(DateTime utcNow) {
            lock(sync) {
                if(status.State==SelfProtectionState.Active) return true;
                if(status.State==SelfProtectionState.Maintenance || status.State==SelfProtectionState.Initializing) return false;
                status.State=SelfProtectionState.Starting; status.Failure=null;
                bool initializationStarted=false;
                try {
                    if(preflight==null) { Fail("激活前必须配置文件身份 preflight"); return false; }
                    SelfProtectionPreflightResult first=preflight==null?null:preflight();
                    if(preflight!=null && (first==null || !first.Passed)) { status.MappingWritebackConditionMet=false; Fail(first==null?"文件身份 preflight 未返回结果":first.Summary); return false; }
                    registeredIdentity=identityFactory(); registeredTray=null;
                    initializationStarted=true;
                    var beginReply=transport.Send(SelfProtectionRequest.Create(SelfProtectionOperation.BeginInitialize,registeredIdentity,null,DateTime.MinValue,utcNow));
                    if(!ApplyInitializingReply(beginReply)) {
                        TryAbortInitialization(utcNow);
                        initializationStarted=false;
                        Fail(beginReply==null?"驱动没有返回初始化状态":beginReply.Error??"驱动未进入初始化阶段");
                        return false;
                    }
                    SelfProtectionPreflightResult second=preflight==null?null:preflight();
                    if(preflight!=null && (second==null || !second.Passed)) {
                        TryAbortInitialization(utcNow);
                        Fail(second==null?"第二次文件身份 preflight 未返回结果":second.Summary);
                        return false;
                    }
                    var commitReply=transport.Send(SelfProtectionRequest.CreateCommit(registeredIdentity,second==null?0:second.ScannedEntries,utcNow));
                    bool commitAccepted=commitReply!=null && commitReply.Accepted && commitReply.DriverLoaded && commitReply.Phase==SelfProtectionPhase.Active;
                    bool accepted=ApplyActiveReply(commitReply);
                    if(!commitAccepted) TryAbortInitialization(utcNow);
                    status.MappingWritebackConditionMet=accepted && second!=null && second.MappingWritebackConditionMet;
                    initializationStarted=false;
                    return accepted;
                }
                catch(Exception e) { if(initializationStarted) TryAbortInitialization(utcNow); Fail(e.Message); return false; }
            }
        }

        public bool RegisterTray(ProtectionIdentity trayIdentity,DateTime utcNow) {
            lock(sync) {
                if(status.State!=SelfProtectionState.Active || registeredIdentity==null || trayIdentity==null) return false;
                try {
                    var reply=transport.Send(SelfProtectionRequest.CreateTray(SelfProtectionOperation.RegisterTray,registeredIdentity,trayIdentity,utcNow));
                    reply.Validate();
                    if(!reply.Accepted || !reply.DriverLoaded || (reply.Capabilities&Required)!=Required) { Fail(reply.Error??"驱动拒绝登记托盘"); return false; }
                    registeredTray=trayIdentity; status.DriverLoaded=true; status.Capabilities=reply.Capabilities; status.Failure=null; return true;
                } catch(Exception e) { Fail(e.Message); return false; }
            }
        }

        public bool UnregisterTray(ProtectionIdentity trayIdentity,DateTime utcNow) {
            lock(sync) {
                if(registeredIdentity==null || registeredTray==null) return true;
                if(trayIdentity==null || trayIdentity.ProcessId!=registeredTray.ProcessId || trayIdentity.StartTimeUtcFileTime!=registeredTray.StartTimeUtcFileTime || !String.Equals(trayIdentity.InstanceNonce,registeredTray.InstanceNonce,StringComparison.Ordinal)) return false;
                try {
                    var reply=transport.Send(SelfProtectionRequest.CreateTray(SelfProtectionOperation.UnregisterTray,registeredIdentity,trayIdentity,utcNow));
                    reply.Validate();
                    if(!reply.Accepted || !reply.DriverLoaded) { Fail(reply.Error??"驱动拒绝注销托盘"); return false; }
                    registeredTray=null; status.DriverLoaded=true; status.Capabilities=reply.Capabilities; status.Failure=null; return true;
                } catch(Exception e) { Fail(e.Message); return false; }
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
                    if(!reply.Accepted || !reply.DriverLoaded || reply.Capabilities!=SelfProtectionCapability.FileMutation) { Fail(reply.Error??"驱动拒绝准备卸载"); return false; }
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
        bool ApplyInitializingReply(SelfProtectionReply reply) {
            if(reply==null) return false;
            reply.Validate();
            if(!reply.Accepted || !reply.DriverLoaded || reply.Capabilities!=SelfProtectionCapability.None || reply.Phase!=SelfProtectionPhase.Initializing) return false;
            status.DriverLoaded=true; status.Capabilities=SelfProtectionCapability.None; status.State=SelfProtectionState.Initializing; status.Failure=null; return true;
        }
        bool ApplyActiveReply(SelfProtectionReply reply) {
            if(reply==null) { Fail("驱动没有返回状态"); return false; }
            reply.Validate();
            if(!reply.Accepted || !reply.DriverLoaded || reply.Phase!=SelfProtectionPhase.Active) { Fail(reply.Error??"驱动未确认初始化提交"); return false; }
            status.DriverLoaded=true; status.Capabilities=reply.Capabilities; status.State=CapabilitiesComplete()?SelfProtectionState.Active:SelfProtectionState.Degraded; status.MaintenanceLeaseId=null; status.MaintenanceUntilUtc=DateTime.MinValue; maintenanceSession=null; status.Failure=null; return status.State==SelfProtectionState.Active;
        }
        void TryAbortInitialization(DateTime utcNow) {
            if(registeredIdentity==null) return;
            try { transport.Send(SelfProtectionRequest.Create(SelfProtectionOperation.AbortInitialize,registeredIdentity,null,DateTime.MinValue,utcNow)); }
            catch { }
        }
        bool ApplyReply(SelfProtectionReply reply) {
            if(reply==null) throw new InvalidDataException("驱动没有返回状态"); reply.Validate();
            if(!reply.Accepted || !reply.DriverLoaded) { Fail(reply.Error??"驱动未加载或拒绝注册"); return false; }
            status.DriverLoaded=true; status.Capabilities=reply.Capabilities; status.State=CapabilitiesComplete()?SelfProtectionState.Active:SelfProtectionState.Degraded; status.MaintenanceLeaseId=null; status.MaintenanceUntilUtc=DateTime.MinValue; maintenanceSession=null; status.Failure=null; return status.State==SelfProtectionState.Active;
        }
        bool CapabilitiesComplete() { return status.DriverLoaded && (status.Capabilities&Required)==Required; }
        void Fail(string error) { status.State=SelfProtectionState.Failed; status.DriverLoaded=false; status.MappingWritebackConditionMet=false; status.Capabilities=SelfProtectionCapability.None; status.Failure=error??"自保护失败"; /* Retain an uncertain lease so expiry and explicit exit can retry. */ }
    }
}
