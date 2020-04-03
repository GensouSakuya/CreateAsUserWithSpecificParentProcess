using System;
using System.Runtime.InteropServices;
using System.Security;
using CreateAsUserWithSpecificParentProcess.Win32.Structs;

namespace CreateAsUserWithSpecificParentProcess.Win32
{
    internal class AdvApi32
    {
        [DllImport("ADVAPI32.DLL", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool CreateProcessAsUser(IntPtr hToken, string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes,
            bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFOEX lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
        
        [DllImport("advapi32", SetLastError = true), SuppressUnmanagedCodeSecurity]
        public static extern bool OpenProcessToken(IntPtr processHandle, int desiredAccess, ref IntPtr tokenHandle);

        [DllImport("advapi32.dll", EntryPoint = "DuplicateTokenEx")]
        public static extern bool DuplicateTokenEx(IntPtr existingTokenHandle, uint dwDesiredAccess,
            ref SECURITY_ATTRIBUTES lpThreadAttributes, int tokenType, int impersonationLevel,
            ref IntPtr duplicateTokenHandle);
    }
}
