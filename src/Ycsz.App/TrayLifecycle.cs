using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Runtime.InteropServices;
using System.Threading;

namespace Ycsz {
    public sealed class TrayInstanceLock : IDisposable {
        readonly Mutex global, legacy;
        readonly bool globalOwned, legacyOwned;
        bool released;

        TrayInstanceLock(Mutex global, bool globalOwned, Mutex legacy, bool legacyOwned) {
            this.global=global; this.globalOwned=globalOwned; this.legacy=legacy; this.legacyOwned=legacyOwned;
        }

        public static TrayInstanceLock Acquire(int sessionId, out bool acquired) {
            acquired=false;
            Mutex global=null, legacy=null; bool globalCreated=false, legacyCreated=false;
            try {
                try { global=new Mutex(true,TrayIdentity.GlobalMutexName(sessionId),out globalCreated); } catch(UnauthorizedAccessException) { global=null; }
                legacy=new Mutex(true,TrayIdentity.LegacyMutexName,out legacyCreated);
                if(!legacyCreated || (global!=null && !globalCreated)) { if(globalCreated) { try { global.ReleaseMutex(); } catch {} } if(global!=null) global.Dispose(); if(legacyCreated) { try { legacy.ReleaseMutex(); } catch {} } if(legacy!=null) legacy.Dispose(); return null; }
                acquired=true; return new TrayInstanceLock(global,globalCreated,legacy,legacyCreated);
            } catch {
                if(globalCreated) { try { global.ReleaseMutex(); } catch {} }
                if(legacyCreated) { try { legacy.ReleaseMutex(); } catch {} }
                if(global!=null) global.Dispose();
                if(legacy!=null) legacy.Dispose();
                throw;
            }
        }

        public void ReleaseMutex() { Dispose(); }
        public void Dispose() {
            if(released) return;
            released=true;
            if(legacyOwned) { try { legacy.ReleaseMutex(); } catch {} }
            if(legacy!=null) legacy.Dispose();
            if(globalOwned) { try { global.ReleaseMutex(); } catch {} }
            if(global!=null) global.Dispose();
        }
    }

    public sealed class WindowsInteractiveSessionSource : IInteractiveSessionSource {
        const int WtsActive = 0;
        const uint InvalidSessionId = 0xffffffff;

        public int? GetActiveSessionId() {
            IntPtr buffer = IntPtr.Zero;
            int count = 0;
            try {
                if (!WTSEnumerateSessions(IntPtr.Zero, 0, 1, out buffer, out count)) throw LastError("WTSEnumerateSessions");
                int size = Marshal.SizeOf(typeof(WtsSessionInfo));
                uint console = WTSGetActiveConsoleSessionId();
                int? fallback = null;
                for (int i = 0; i < count; i++) {
                    var info = (WtsSessionInfo)Marshal.PtrToStructure(new IntPtr(buffer.ToInt64() + i * size), typeof(WtsSessionInfo));
                    if (info.State != WtsActive || info.SessionId <= 0) continue;
                    if (console != InvalidSessionId && info.SessionId == (int)console) return info.SessionId;
                    if (!fallback.HasValue) fallback = info.SessionId;
                }
                return fallback;
            } finally { if (buffer != IntPtr.Zero) WTSFreeMemory(buffer); }
        }

        static Win32Exception LastError(string operation) { return new Win32Exception(Marshal.GetLastWin32Error(), operation); }

        [StructLayout(LayoutKind.Sequential)] struct WtsSessionInfo {
            public int SessionId;
            public IntPtr WinStationName;
            public int State;
        }
        [DllImport("wtsapi32.dll", SetLastError = true)] static extern bool WTSEnumerateSessions(IntPtr server, int reserved, int version, out IntPtr sessions, out int count);
        [DllImport("wtsapi32.dll")] static extern void WTSFreeMemory(IntPtr memory);
        [DllImport("kernel32.dll")] static extern uint WTSGetActiveConsoleSessionId();
    }

    // The service owns this class. It never accepts a caller-supplied executable
    // or argument; both are fixed to the installed Ycsz.exe --tray entry point.
    public sealed class WindowsTrayRuntime : ITrayRuntime {
        readonly string executable;

        public WindowsTrayRuntime() {
            executable = Path.GetFullPath(Path.Combine(Store.Bin, "Ycsz.exe"));
            if (!String.Equals(executable, Path.Combine(Store.Bin, "Ycsz.exe"), StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("托盘程序路径无效");
        }

        public ITrayProcess FindExisting(int sessionId) {
            if (sessionId <= 0) return null;
            // Check the actual command line: a management window uses the same
            // executable and session but must never stand in for a tray instance.
            var candidates = Process.GetProcessesByName(Path.GetFileNameWithoutExtension(executable));
            Process match = null;
            try {
                foreach (var candidate in candidates) {
                    try {
                        if (candidate.SessionId != sessionId || candidate.HasExited) continue;
                        if (!String.Equals(Path.GetFullPath(candidate.MainModule.FileName), executable, StringComparison.OrdinalIgnoreCase)) continue;
                        using (var query = new ManagementObject("Win32_Process.Handle='" + candidate.Id + "'")) {
                            string command = query["CommandLine"] as string;
                            if (!IsTrayCommand(command)) continue;
                        }
                        if (candidate.HasExited) continue;
                        match = candidate;
                        return new WindowsTrayProcess(match, IntPtr.Zero);
                    } catch (Win32Exception) { }
                    catch (InvalidOperationException) { }
                    catch (ManagementException) { }
                }
                return null;
            } finally { foreach (var candidate in candidates) if (candidate != match) candidate.Dispose(); }
        }

        static bool IsTrayCommand(string command) {
            if (String.IsNullOrWhiteSpace(command)) return false;
            int count;
            IntPtr arguments = CommandLineToArgvW(command, out count);
            if (arguments == IntPtr.Zero) throw LastError("CommandLineToArgvW");
            try {
                return count == 2 && String.Equals(Marshal.PtrToStringUni(Marshal.ReadIntPtr(arguments, IntPtr.Size)), "--tray", StringComparison.Ordinal);
            } finally { LocalFree(arguments); }
        }

        public ITrayProcess Start(int sessionId) {
            if (sessionId <= 0) throw new ArgumentOutOfRangeException("sessionId");
            IntPtr token;
            if (!WTSQueryUserToken((uint)sessionId, out token)) throw LastError("WTSQueryUserToken");
            IntPtr environment = IntPtr.Zero;
            try {
                if (!CreateEnvironmentBlock(out environment, token, false)) throw LastError("CreateEnvironmentBlock");
                var startup = new StartupInfo { cb = Marshal.SizeOf(typeof(StartupInfo)), desktop = "winsta0\\default" };
                ProcessInformation info;
                var command = new System.Text.StringBuilder("\"" + executable + "\" --tray");
                const uint CreateUnicodeEnvironment = 0x00000400;
                if (!CreateProcessAsUser(token, executable, command, IntPtr.Zero, IntPtr.Zero, false, CreateUnicodeEnvironment, environment, Path.GetDirectoryName(executable), ref startup, out info)) throw LastError("CreateProcessAsUser");
                CloseHandle(info.Thread);
                return new WindowsTrayProcess(null, info.Process, (int)info.ProcessId);
            } finally {
                if (environment != IntPtr.Zero) DestroyEnvironmentBlock(environment);
                CloseHandle(token);
            }
        }

        static Win32Exception LastError(string operation) { return new Win32Exception(Marshal.GetLastWin32Error(), operation); }

        sealed class WindowsTrayProcess : ITrayProcess {
            readonly Process process;
            readonly IntPtr processHandle;
            readonly IntPtr mutexHandle;
            readonly int processId;
            bool disposed;

            public WindowsTrayProcess(Process process, IntPtr mutexHandle) {
                this.process = process;
                this.mutexHandle = mutexHandle;
                processId = process == null ? 0 : process.Id;
            }
            public WindowsTrayProcess(Process process, IntPtr processHandle, int processId) {
                this.process = process;
                this.processHandle = processHandle;
                this.processId = processId;
            }
            public int ProcessId { get { return processId; } }
            public bool HasExited {
                get {
                    if (disposed) return true;
                    if (process != null) return process.HasExited;
                    if (mutexHandle != IntPtr.Zero) {
                        uint result = WaitForSingleObject(mutexHandle, 0);
                        return result == 0 || result == 0x00000080;
                    }
                    uint code;
                    return !GetExitCodeProcess(processHandle, out code) || code != 259;
                }
            }
            public void Dispose() {
                if (disposed) return;
                disposed = true;
                if (process != null) process.Dispose();
                if (processHandle != IntPtr.Zero) CloseHandle(processHandle);
                if (mutexHandle != IntPtr.Zero) CloseHandle(mutexHandle);
            }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] struct StartupInfo {
            public int cb;
            public string reserved;
            public string desktop;
            public string title;
            public int x, y, xSize, ySize, xCountChars, yCountChars, fillAttribute, flags;
            public short showWindow, reserved2;
            public IntPtr reserved2Ptr;
            public IntPtr standardInput, standardOutput, standardError;
        }
        [StructLayout(LayoutKind.Sequential)] struct ProcessInformation {
            public IntPtr Process;
            public IntPtr Thread;
            public uint ProcessId;
            public uint ThreadId;
        }
        [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern IntPtr CommandLineToArgvW(string command, out int count);
        [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr memory);
        [DllImport("kernel32.dll", SetLastError = true)] static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetExitCodeProcess(IntPtr process, out uint code);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool CloseHandle(IntPtr handle);
        [DllImport("wtsapi32.dll", SetLastError = true)] static extern bool WTSQueryUserToken(uint sessionId, out IntPtr token);
        [DllImport("userenv.dll", SetLastError = true)] static extern bool CreateEnvironmentBlock(out IntPtr environment, IntPtr token, bool inherit);
        [DllImport("userenv.dll", SetLastError = true)] static extern bool DestroyEnvironmentBlock(IntPtr environment);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool CreateProcessAsUser(IntPtr token, string applicationName, System.Text.StringBuilder commandLine, IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles, uint creationFlags, IntPtr environment, string currentDirectory, ref StartupInfo startup, out ProcessInformation information);
    }
}
