using System.Runtime.InteropServices;

namespace CreateAsUserWithSpecificParentProcess.Win32.Structs
{
    internal struct TOKEN_PRIVILEGES
    {
        public int PrivilegeCount;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public LUID_AND_ATTRIBUTES[] Privileges;
    }
}
