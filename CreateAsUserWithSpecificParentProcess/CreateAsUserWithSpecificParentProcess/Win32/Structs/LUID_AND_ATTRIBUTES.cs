using System.Runtime.InteropServices;

namespace CreateAsUserWithSpecificParentProcess.Win32.Structs
{
    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    internal struct LUID_AND_ATTRIBUTES
    {
        public LUID Luid;
        public uint Attributes;
    }
}
