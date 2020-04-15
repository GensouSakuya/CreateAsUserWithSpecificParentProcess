using System;
using System.Runtime.InteropServices;
using System.Security;
using CreateAsUserWithSpecificParentProcess.Win32.Enums;
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

        [DllImport("advapi32.dll", EntryPoint = "DuplicateTokenEx", SetLastError = true)]
        public static extern bool DuplicateTokenEx(IntPtr existingTokenHandle, uint dwDesiredAccess,
            ref SECURITY_ATTRIBUTES lpThreadAttributes, int tokenType, int impersonationLevel,
            ref IntPtr duplicateTokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool GetTokenInformation(IntPtr tokenHandle, TOKEN_INFORMATION_CLASS tokenInformationClass,
            IntPtr tokenInformation, int tokenInformationLength, out int returnLength);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern int GetLengthSid(IntPtr sid);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool ConvertStringSidToSid(string stringSid,out IntPtr ptrSid);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool SetTokenInformation(IntPtr hToken, TOKEN_INFORMATION_CLASS informationClass,
            IntPtr tokenInformation, int tokenInformationLength);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, ref LUID lpLuid);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool AdjustTokenPrivileges(IntPtr tokenHandle,
            [MarshalAs(UnmanagedType.Bool)] bool disableAllPrivileges,
            ref TOKEN_PRIVILEGES newState, uint zero, IntPtr null1, IntPtr null2);
    }
}
