using System;
using System.Runtime.InteropServices;

namespace CreateAsUserWithSpecificParentProcess.Win32
{
    internal class WtsApi32
    {

        [DllImport("wtsapi32.dll", EntryPoint = "WTSEnumerateSessionsW", SetLastError = true, CharSet = CharSet.Unicode, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
        public static extern bool WTSEnumerateSessions(SafeHandle serverHandle, uint reserved, uint version, out IntPtr pSessionInfo, out uint count);

        [DllImport("wtsapi32.dll", SetLastError = false, CharSet = CharSet.Unicode, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
        public static extern void WTSFreeMemory(IntPtr pSessionInfo);

        [DllImport("wtsapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool WTSQueryUserToken(uint SessionId, out SafeHandle Token);
    }
}
