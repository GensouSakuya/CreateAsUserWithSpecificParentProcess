using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
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
        public static int CreateProcess(string userName, string fileName, string args, int parentProcessId = 0, bool waitingExitCode = false, ElevatedLevel elevatedLevel = ElevatedLevel.Normal)
        {
            int result = -1;
            if (GetExistSessions(new SafeHandle(IntPtr.Zero, false), out var sessions))
            {
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

                            if (windowsIdentity.Name == userName)
                            {
                                try
                                {
                                    result = CreateProcess(fileName, args, info.SessionId, parentProcessId, userHandle.DangerousGetHandle(), waitingExitCode, elevatedLevel);
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

        public static uint FindExistSessionId()
        {
            if (GetExistSessions(new SafeHandle(IntPtr.Zero, false), out var sessions))
            {
                foreach (WTS_SESSION_INFO info in sessions)
                {
                    if (info.SessionId == 0)
                    {
                        continue;
                    }

                    return info.SessionId;
                }
            }

            return 0;
        }

        public static WindowsIdentity GetSessionUserIdentity(uint sessionId)
        {
            if (WtsApi32.WTSQueryUserToken(sessionId, out SafeHandle userHandle))
            {
                return new WindowsIdentity(userHandle.DangerousGetHandle());
            }
            return null;
        }

        private static bool GetExistSessions(SafeHandle handle, out WTS_SESSION_INFO[] sessions)
        {
            var buf = IntPtr.Zero;

            try
            {
                bool result = WtsApi32.WTSEnumerateSessions(handle, 0, 1, out buf, out var count);

                if (result)
                {
                    var current = buf;
                    var dSize = Marshal.SizeOf(new WTS_SESSION_INFO());
                    var retValue = new WTS_SESSION_INFO[count];
                    for (var i = 0; i < count; i++)
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

        private static int CreateProcess(string fileName, string args, uint sessionId, int parentProcessId, IntPtr hToken, bool waitingExitCode, ElevatedLevel elevatedLevel)
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
            if (elevatedLevel == ElevatedLevel.System)
            {
                var hPToken = GetOpenedWinLogonToken(sessionId, out var logonPid);
                var sa = new SECURITY_ATTRIBUTES();
                sa.Length = Marshal.SizeOf(sa);

                if (!AdvApi32.DuplicateTokenEx(hPToken, MAXIMUM_ALLOWED, ref sa,
                    (int)SECURITY_IMPERSONATION_LEVEL.SecurityIdentification,
                    (int)TOKEN_TYPE.TokenPrimary, ref hToken))
                {
                    ExitWithWin32Error();
                }
            }
            else if (elevatedLevel == ElevatedLevel.Admin)
            {
                hToken = ElevationPrivilege(hToken);
            }

            if (parentProcessId != 0)
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
                    var process = Process.GetProcessById(tProcessInfo.dwProcessId);
                    exitCode = process
                                   ?.WaitForExitAsync()
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
                        Marshal.FreeHGlobal(lpValue);
                    }
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

        private static void SetHighIntegrityLevel(IntPtr hToken)
        {
            var pTokenInfo = IntPtr.Zero;
            try
            {
                //S-1-16-12288 is the high integrity level sid
                if (!AdvApi32.ConvertStringSidToSid("S-1-16-12288", out var sid))
                {
                    var errorCode = Marshal.GetLastWin32Error();
                    throw new Exception("ConvertStringSidToSid:" + errorCode);
                }

                var tml = new TOKEN_MANDATORY_LABEL();
                tml.Label.Attributes = 0x00000020;//SE_GROUP_INTEGRITY
                tml.Label.Sid = sid;

                var cbTokenInfo = Marshal.SizeOf(tml);
                pTokenInfo = Marshal.AllocHGlobal(cbTokenInfo);
                Marshal.StructureToPtr(tml, pTokenInfo, false);

                if (!AdvApi32.SetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, pTokenInfo,
                    cbTokenInfo + AdvApi32.GetLengthSid(tml.Label.Sid)))
                {
                    var errorCode = Marshal.GetLastWin32Error();
                    throw new Exception("SetTokenInformation:" + errorCode);
                }
            }
            finally
            {
                Kernal32.CloseHandle(pTokenInfo);
            }
        }

        //Get elevated token
        private static IntPtr ElevationPrivilege(IntPtr hToken)
        {
            var pLinkedToken = IntPtr.Zero;
            try
            {
                var linkedToken = new TOKEN_LINKED_TOKEN();

                var length = Marshal.SizeOf(linkedToken);
                pLinkedToken = Marshal.AllocHGlobal(length);
                Marshal.StructureToPtr(linkedToken, pLinkedToken, false);
                var res = AdvApi32.GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenLinkedToken, pLinkedToken,
                    length,
                    out length);
                if (!res)
                {
                    var errorCode = Marshal.GetLastWin32Error();
                    throw new Exception("GetTokenInformation:" + errorCode);
                }

                linkedToken = (TOKEN_LINKED_TOKEN) Marshal.PtrToStructure(pLinkedToken, typeof(TOKEN_LINKED_TOKEN));

                if (linkedToken.LinkedToken == IntPtr.Zero)
                {
                    throw new Exception("No linked token");
                }

                Kernal32.CloseHandle(hToken);

                return linkedToken.LinkedToken;
            }
            catch
            {
                if (pLinkedToken != IntPtr.Zero)
                {
                    Kernal32.CloseHandle(pLinkedToken);
                }
                return hToken;
            }
        }

        //Can only enable permissions and not add
        private static void EnablePrivilege(IntPtr hToken)
        {
            var privilegeList = new List<string>
            {
                "SeCreateTokenPrivilege",
                "SeAssignPrimaryTokenPrivilege",
                "SeLockMemoryPrivilege",
                "SeIncreaseQuotaPrivilege",
                "SeUnsolicitedInputPrivilege",
                "SeMachineAccountPrivilege",
                "SeTcbPrivilege",
                "SeSecurityPrivilege",
                "SeTakeOwnershipPrivilege",
                "SeLoadDriverPrivilege",
                "SeSystemProfilePrivilege",
                "SeSystemtimePrivilege",
                "SeProfileSingleProcessPrivilege",
                "SeIncreaseBasePriorityPrivilege",
                "SeCreatePagefilePrivilege",
                "SeCreatePermanentPrivilege",
                "SeBackupPrivilege",
                "SeRestorePrivilege",
                "SeShutdownPrivilege",
                "SeDebugPrivilege",
                "SeAuditPrivilege",
                "SeSystemEnvironmentPrivilege",
                "SeChangeNotifyPrivilege",
                "SeRemoteShutdownPrivilege",
                "SeUndockPrivilege",
                "SeSyncAgentPrivilege",
                "SeEnableDelegationPrivilege",
                "SeManageVolumePrivilege",
                "SeImpersonatePrivilege",
                "SeCreateGlobalPrivilege",
                "SeTrustedCredManAccessPrivilege",
                "SeRelabelPrivilege",
                "SeIncreaseWorkingSetPrivilege",
                "SeTimeZonePrivilege",
                "SeCreateSymbolicLinkPrivilege",
                "SeDelegateSessionUserImpersonatePrivilege"
            };

            privilegeList.ForEach(p =>
            {
                try
                {
                    SetPrivilege(hToken, p);
                }
                catch
                {
                    //ignore
                }
            });
        }
        private static void SetPrivilege(IntPtr hToken, string privilegeName)
        {
            var tp = new TOKEN_PRIVILEGES();
            var luidSecurity = new LUID();

            if (!(AdvApi32.LookupPrivilegeValue(null, privilegeName, ref luidSecurity)))
            {
                var errorCode = Marshal.GetLastWin32Error();
                throw new Exception("LookupPrivilegeValue:" + errorCode);
            }

            tp.PrivilegeCount = 1;
            tp.Privileges = new LUID_AND_ATTRIBUTES[1];
            tp.Privileges[0].Luid = luidSecurity;
            tp.Privileges[0].Attributes = 0x00000002;//SE_PRIVILEGE_ENABLED

            if (!(AdvApi32.AdjustTokenPrivileges(hToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero)))
            {
                var errorCode = Marshal.GetLastWin32Error();
                throw new Exception("AdjustTokenPrivileges:" + errorCode);
            }
        }
    }
}
