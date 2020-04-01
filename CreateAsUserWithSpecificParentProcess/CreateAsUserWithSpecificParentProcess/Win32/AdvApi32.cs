using System;
using System.Runtime.InteropServices;
using CreateAsUserWithSpecificParentProcess.Win32.Structs;

namespace CreateAsUserWithSpecificParentProcess.Win32
{
    internal class AdvApi32
    {
        [DllImport("ADVAPI32.DLL", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool CreateProcessAsUser(IntPtr hToken, string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes,
            bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFOEX lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
    }
}
