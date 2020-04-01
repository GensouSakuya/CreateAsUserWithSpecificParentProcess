using System;
using System.Security;
using CreateAsUserWithSpecificParentProcess.Win32;
using Microsoft.Win32.SafeHandles;

namespace CreateAsUserWithSpecificParentProcess
{

    internal sealed class SafeHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeHandle() : base(true)
        {
        }

        [SecurityCritical]
        public SafeHandle(IntPtr handle, bool ownsHandle) : base(ownsHandle)
        {
            SetHandle(handle);
        }

        protected override bool ReleaseHandle()
        {
            return Kernal32.CloseHandle(handle);
        }
    }
}
