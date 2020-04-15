using System.Runtime.InteropServices;

namespace CreateAsUserWithSpecificParentProcess.Win32.Structs
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_MANDATORY_LABEL
    {
        public SID_AND_ATTRIBUTES Label;
    }
}
