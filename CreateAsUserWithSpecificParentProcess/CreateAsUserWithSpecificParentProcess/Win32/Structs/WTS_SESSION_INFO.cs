using System;
using System.Runtime.InteropServices;
using CreateAsUserWithSpecificParentProcess.Win32.Enums;

namespace CreateAsUserWithSpecificParentProcess.Win32.Structs
{
    [StructLayout(LayoutKind.Sequential)]
    public struct WTS_SESSION_INFO
    {
        public UInt32 SessionId;

        [MarshalAs(UnmanagedType.LPWStr)]
        public string pWinStationName;

        public WTS_CONNECTSTATE_CLASS State;
    }
}
