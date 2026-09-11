using System;
using System.Threading;

namespace Ycsz {
    public static class TrayIdentity {
        public const string LegacyMutexName = @"Local\YcszFirewall.Tray";
        public static string GlobalMutexName(int sessionId) {
            if (sessionId <= 0) throw new ArgumentOutOfRangeException("sessionId");
            return @"Global\YcszFirewall.Tray." + sessionId;
        }
    }

    public interface IInteractiveSessionSource {
        int? GetActiveSessionId();
    }

    public interface ITrayProcess : IDisposable {
        int ProcessId { get; }
        bool HasExited { get; }
    }

    public interface ITrayRuntime {
        ITrayProcess FindExisting(int sessionId);
        ITrayProcess Start(int sessionId);
    }

    public enum TrayStopReason {
        ServiceStopping,
        Maintenance,
        SystemShutdown
    }

    public sealed class TraySupervisorOptions {
        public TimeSpan PollInterval = TimeSpan.FromSeconds(5);
        public TimeSpan InitialRetryDelay = TimeSpan.FromSeconds(5);
        public TimeSpan MaximumRetryDelay = TimeSpan.FromMinutes(5);
        public TimeSpan StableUptime = TimeSpan.FromMinutes(1);
        public TimeSpan LogThrottle = TimeSpan.FromMinutes(1);

        public void Validate() {
            if (PollInterval <= TimeSpan.Zero) throw new ArgumentOutOfRangeException("PollInterval");
            if (InitialRetryDelay <= TimeSpan.Zero) throw new ArgumentOutOfRangeException("InitialRetryDelay");
            if (MaximumRetryDelay < InitialRetryDelay) throw new ArgumentOutOfRangeException("MaximumRetryDelay");
            if (StableUptime <= TimeSpan.Zero) throw new ArgumentOutOfRangeException("StableUptime");
            if (LogThrottle <= TimeSpan.Zero) throw new ArgumentOutOfRangeException("LogThrottle");
        }
    }

    // Platform-independent lifecycle state machine. Windows APIs are injected by
    // Ycsz.App so this class can be tested without a desktop, service or token.
    public sealed class TraySupervisor : IDisposable {
        readonly object sync = new object();
        readonly IInteractiveSessionSource sessions;
        readonly ITrayRuntime runtime;
        readonly Action<string> logger;
        readonly TraySupervisorOptions options;
        readonly AutoResetEvent wake = new AutoResetEvent(false);
        Thread worker;
        ITrayProcess process;
        int sessionId = -1;
        int failures;
        DateTime nextAttemptUtc = DateTime.MinValue;
        DateTime healthySinceUtc = DateTime.MinValue;
        DateTime lastFailureLogUtc = DateTime.MinValue;
        bool stopping;
        bool disposed;

        public TraySupervisor(IInteractiveSessionSource sessions, ITrayRuntime runtime, Action<string> logger, TraySupervisorOptions options = null) {
            if (sessions == null) throw new ArgumentNullException("sessions");
            if (runtime == null) throw new ArgumentNullException("runtime");
            this.sessions = sessions;
            this.runtime = runtime;
            this.logger = logger ?? delegate { };
            this.options = options ?? new TraySupervisorOptions();
            this.options.Validate();
        }

        public int CurrentSessionId { get { lock (sync) return sessionId; } }
        public int ConsecutiveFailures { get { lock (sync) return failures; } }
        public DateTime NextAttemptUtc { get { lock (sync) return nextAttemptUtc; } }
        public bool IsStopping { get { lock (sync) return stopping || disposed; } }

        public void Start() {
            lock (sync) {
                if (disposed) throw new ObjectDisposedException("TraySupervisor");
                if (worker != null) throw new InvalidOperationException("托盘监督器已启动");
                stopping = false;
                worker = new Thread(Run) { IsBackground = true, Name = "Ycsz tray supervisor" };
                worker.Start();
            }
        }

        public void Tick(DateTime utcNow) {
            lock (sync) {
                if (stopping || disposed) return;
                TickLocked(utcNow);
            }
        }

        void Run() {
            while (true) {
                lock (sync) if (stopping || disposed) return;
                try { Tick(DateTime.UtcNow); }
                catch (Exception e) { lock (sync) if (!stopping && !disposed) RegisterFailure(DateTime.UtcNow, "监督器异常：" + e.Message); }
                try { wake.WaitOne(options.PollInterval); } catch (ObjectDisposedException) { return; }
            }
        }

        void TickLocked(DateTime utcNow) {
            int? active;
            try { active = sessions.GetActiveSessionId(); }
            catch (Exception e) { RegisterFailure(utcNow, "查询交互会话失败：" + e.Message); return; }
            if (!active.HasValue || active.Value <= 0) {
                ReleaseProcessLocked();
                sessionId = -1;
                failures = 0;
                nextAttemptUtc = DateTime.MinValue;
                return;
            }

            if (sessionId != active.Value) {
                ReleaseProcessLocked();
                sessionId = active.Value;
                failures = 0;
                lastFailureLogUtc = DateTime.MinValue;
                nextAttemptUtc = utcNow;
            }

            if (process != null) {
                bool exited;
                try { exited = process.HasExited; }
                catch (Exception e) { ReleaseProcessLocked(); RegisterFailure(utcNow, "读取托盘状态失败：" + e.Message); return; }
                if (!exited) { if (utcNow - healthySinceUtc >= options.StableUptime) failures = 0; return; }
                ReleaseProcessLocked();
                RegisterFailure(utcNow, "托盘实例异常退出");
            }

            ITrayProcess existing;
            try { existing = runtime.FindExisting(active.Value); }
            catch (Exception e) { RegisterFailure(utcNow, "检查托盘实例失败：" + e.Message); return; }
            if (existing != null) {
                bool exited;
                try { exited = existing.HasExited; }
                catch (Exception e) { SafeDispose(existing); RegisterFailure(utcNow, "读取已有托盘状态失败：" + e.Message); return; }
                if (!exited) {
                    process = existing;
                    healthySinceUtc = utcNow;
                    nextAttemptUtc = DateTime.MaxValue;
                    return;
                }
                SafeDispose(existing);
            }

            if (utcNow < nextAttemptUtc) return;
            try {
                var started = runtime.Start(active.Value);
                if (started == null) throw new InvalidOperationException("托盘启动器没有返回进程句柄");
                process = started;
                healthySinceUtc = utcNow;
                nextAttemptUtc = DateTime.MaxValue;
            } catch (Exception e) { RegisterFailure(utcNow, "启动托盘失败：" + e.Message); }
        }

        void RegisterFailure(DateTime utcNow, string detail) {
            failures = Math.Min(failures + 1, 30);
            TimeSpan delay = options.InitialRetryDelay;
            for (int i = 1; i < failures && delay < options.MaximumRetryDelay; i++) {
                double nextTicks = delay.Ticks * 2.0;
                delay = nextTicks >= options.MaximumRetryDelay.Ticks ? options.MaximumRetryDelay : TimeSpan.FromTicks((long)nextTicks);
            }
            nextAttemptUtc = utcNow + delay;
            if (lastFailureLogUtc == DateTime.MinValue || utcNow - lastFailureLogUtc >= options.LogThrottle) {
                lastFailureLogUtc = utcNow;
                try { logger(detail + "；将在 " + delay.TotalSeconds.ToString("0") + " 秒后重试"); } catch { }
            }
        }

        void ReleaseProcessLocked() {
            if (process == null) return;
            var old = process;
            process = null;
            SafeDispose(old);
        }

        static void SafeDispose(ITrayProcess value) {
            try { value.Dispose(); } catch { }
        }

        public void Stop(TrayStopReason reason) {
            Thread thread;
            bool firstStop;
            lock (sync) {
                if (disposed) return;
                firstStop = !stopping;
                stopping = true;
                ReleaseProcessLocked();
                thread = worker;
                wake.Set();
            }
            if (thread != null && thread != Thread.CurrentThread) thread.Join(5000);
            if (firstStop) try { logger("托盘监督器已停止：" + reason); } catch { }
        }

        public void Dispose() {
            Stop(TrayStopReason.ServiceStopping);
            lock (sync) { disposed = true; worker = null; }
            wake.Dispose();
        }
    }
}
