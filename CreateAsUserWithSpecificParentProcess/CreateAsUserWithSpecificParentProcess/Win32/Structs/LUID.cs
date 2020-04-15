using System.Runtime.InteropServices;

namespace CreateAsUserWithSpecificParentProcess.Win32.Structs
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }
}
