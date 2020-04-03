using System;
using System.Diagnostics;
using System.DirectoryServices.AccountManagement;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using CreateAsUserWithSpecificParentProcess.Win32;
using CreateAsUserWithSpecificParentProcess.Win32.Enums;
using CreateAsUserWithSpecificParentProcess.Win32.Structs;
using Microsoft.VisualStudio.Threading;

namespace CreateAsUserWithSpecificParentProcess
{
    public class CreateAsUserWithSpecificParentProcess
    {
        public static int CreateProcess(string userName, string fileName, string args, int parentProcessId, bool waitingExitCode = false, bool elevated = false)
        {
            int result = -1;
            if (GetExistSessions(new SafeHandle(IntPtr.Zero, false), out var sessions))
            {
                var targetUserIdentity =
                    UserPrincipal.FindByIdentity(new PrincipalContext(ContextType.Machine),
                        IdentityType.Name, userName);
                if (targetUserIdentity == null)
                    return result;

                foreach (WTS_SESSION_INFO info in sessions)
                {
                    if (info.SessionId == 0)
                    {
                        continue;
                    }

                    if (info.State == WTS_CONNECTSTATE_CLASS.WTSActive || info.State == WTS_CONNECTSTATE_CLASS.WTSDisconnected)
                    {
                        if (WtsApi32.WTSQueryUserToken(info.SessionId, out SafeHandle userHandle))
                        {
                            var windowsIdentity = new WindowsIdentity(userHandle.DangerousGetHandle());

                            if (windowsIdentity.Name == targetUserIdentity.Name)
                            {
                                try
                                {
                                    result = CreateProcess(fileName, args, info.SessionId, parentProcessId, userHandle.DangerousGetHandle(), waitingExitCode, elevated);
                                    break;
                                }
                                finally
                                {
                                    userHandle?.Dispose();
                                    windowsIdentity?.Dispose();
                                }
                            }
                        }
                    }
                }
            }

            return result;
        }

        private static bool GetExistSessions(SafeHandle handle, out WTS_SESSION_INFO[] sessions)
        {
            IntPtr buf = IntPtr.Zero;

            try
            {
                bool result = WtsApi32.WTSEnumerateSessions(handle, 0, 1, out buf, out var count);

                if (result)
                {
                    IntPtr current = buf;
                    int dSize = Marshal.SizeOf(new WTS_SESSION_INFO());
                    var retValue = new WTS_SESSION_INFO[count];
                    for (int i = 0; i < count; i++)
                    {
                        retValue[i] = (WTS_SESSION_INFO)Marshal.PtrToStructure(current, typeof(WTS_SESSION_INFO));
                        current += dSize;
                    }

                    sessions = retValue;
                    return true;
                }
                else
                {
                    sessions = null;
                    return false;
                }
            }
            finally
            {
                if (buf != IntPtr.Zero)
                {
                    WtsApi32.WTSFreeMemory(buf);
                }
            }
        }

        private static int CreateProcess(string fileName, string args, uint sessionId, int parentProcessId, IntPtr hToken, bool waitingExitCode, bool elevated)
        {
            var exitCode = 0;

            //args must start with a space
            if (args != null && !args.StartsWith(" "))
            {
                args = $" {args}";
            }

            var environmentPtr = IntPtr.Zero;
            var createEnvResult = UserEnv.CreateEnvironmentBlock(ref environmentPtr, hToken, false);
            if (!createEnvResult)
            {
                ExitWithWin32Error();
            }

            var dwCreationFlags = (uint)(PROCESS_CREATION_FLAGS.NORMAL_PRIORITY_CLASS |
                                           PROCESS_CREATION_FLAGS.CREATE_UNICODE_ENVIRONMENT |
                                           PROCESS_CREATION_FLAGS.EXTENDED_STARTUPINFO_PRESENT);

            var sInfoEx = new STARTUPINFOEX();
            sInfoEx.StartupInfo.cb = Marshal.SizeOf(sInfoEx);

            var lpValue = IntPtr.Zero;

            //will run as System
            if (elevated)
            {
                var hPToken = GetOpenedWinLogonToken(sessionId, out var logonPid);
                SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
                sa.Length = Marshal.SizeOf(sa);

                Kernal32.CloseHandle(hToken);

                if (!AdvApi32.DuplicateTokenEx(hPToken, MAXIMUM_ALLOWED, ref sa,
                    (int)SECURITY_IMPERSONATION_LEVEL.SecurityIdentification,
                    (int)TOKEN_TYPE.TokenPrimary, ref hToken))
                {
                    ExitWithWin32Error();
                }
                Kernal32.CloseHandle(hPToken);
            }
            else if (parentProcessId != 0)
            {
                var lpSize = IntPtr.Zero;
                var initSuccess = Kernal32.InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref lpSize);
                if (!initSuccess)
                {
                    ExitWithWin32Error();
                }

                sInfoEx.lpAttributeList = Marshal.AllocHGlobal(lpSize);
                initSuccess = Kernal32.InitializeProcThreadAttributeList(sInfoEx.lpAttributeList, 1, 0, ref lpSize);
                if (!initSuccess)
                {
                    ExitWithWin32Error();
                }
                var parentProcess = Process.GetProcessById(parentProcessId);
                if (parentProcess.Handle != IntPtr.Zero)
                {
                    var parentHandle = parentProcess.Handle;

                    lpValue = Marshal.AllocHGlobal(IntPtr.Size);
                    Marshal.WriteIntPtr(lpValue, parentHandle);

                    var updateResult = Kernal32.UpdateProcThreadAttribute(
                        sInfoEx.lpAttributeList,
                        0,
                        (IntPtr)0x00020000,//PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
                        lpValue,
                        (IntPtr)IntPtr.Size,
                        IntPtr.Zero,
                        IntPtr.Zero);
                    if (!updateResult)
                    {
                        ExitWithWin32Error();
                    }
                }
            }

            var processCreateResult = AdvApi32.CreateProcessAsUser(hToken, fileName, args, IntPtr.Zero, IntPtr.Zero,
                false, dwCreationFlags, environmentPtr, Path.GetDirectoryName(fileName), ref sInfoEx,
                out var tProcessInfo);

            if (!processCreateResult)
            {
                ExitWithWin32Error();
            }
            try
            {
                if (waitingExitCode)
                {
                    exitCode =
                        Process.GetProcesses().FirstOrDefault(p => p.Id == tProcessInfo.dwProcessId)?.WaitForExitAsync()
                            .Result ?? int.MinValue;
                }
            }
            finally
            {
                try
                {
                    Kernal32.CloseHandle(tProcessInfo.hThread);
                    Kernal32.CloseHandle(tProcessInfo.hProcess);
                    if (sInfoEx.lpAttributeList != IntPtr.Zero)
                    {
                        Kernal32.DeleteProcThreadAttributeList(sInfoEx.lpAttributeList);
                        Marshal.FreeHGlobal(sInfoEx.lpAttributeList);
                    }
                    Marshal.FreeHGlobal(lpValue);
                    Kernal32.CloseHandle(hToken);
                }
                catch
                {
                    //ignore
                }
            }

            return exitCode;
        }

        private static void ExitWithWin32Error()
        {
            var lastError = Marshal.GetLastWin32Error();
            throw new Exception($"Error Code:{lastError}");
        }

        private static IntPtr GetOpenedWinLogonToken(uint sessionId, out uint pid)
        {
            const int TOKEN_DUPLICATE = 0x0002;
            uint winLogonPid = 0;
            var processes = Process.GetProcessesByName("winlogon");
            foreach (var p in processes)
            {
                if (p.SessionId == sessionId)
                {
                    winLogonPid = (uint)p.Id;
                }
            }

            var hPToken = IntPtr.Zero;
            var hProcess = Kernal32.OpenProcess(MAXIMUM_ALLOWED, false, winLogonPid);
            AdvApi32.OpenProcessToken(hProcess, TOKEN_DUPLICATE, ref hPToken);
            pid = winLogonPid;
            return hPToken;
        }

        private const uint MAXIMUM_ALLOWED = 0x2000000;
    }
}
