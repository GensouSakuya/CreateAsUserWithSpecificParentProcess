using System;

namespace CreateAsUserWithSpecificParentProcess.Win32.Enums
{
    [Flags]
    internal enum PROCESS_CREATION_FLAGS
    {
        NORMAL_PRIORITY_CLASS = 0x00000020,
        CREATE_UNICODE_ENVIRONMENT = 0x00000400,
        EXTENDED_STARTUPINFO_PRESENT = 0x00080000
    }
}
