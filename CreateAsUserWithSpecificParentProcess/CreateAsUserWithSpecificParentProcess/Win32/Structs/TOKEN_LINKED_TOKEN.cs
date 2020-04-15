using System;
using System.Runtime.InteropServices;

namespace CreateAsUserWithSpecificParentProcess.Win32.Structs
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_LINKED_TOKEN
    {
        public IntPtr LinkedToken;
    }
}
