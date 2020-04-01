using System;
using System.Runtime.InteropServices;

namespace CreateAsUserWithSpecificParentProcess.Win32
{
    internal class UserEnv
    {

        [DllImport("userenv.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool CreateEnvironmentBlock(ref IntPtr lpEnvironment, IntPtr hToken, bool bInherit);
    }
}
