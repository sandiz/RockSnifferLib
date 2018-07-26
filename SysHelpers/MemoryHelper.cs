using RockSnifferLib.RSHelpers;
using RockSnifferLib.Logging;
using System;
using System.Runtime.InteropServices;

namespace RockSnifferLib.SysHelpers
{
    class MemoryHelper
    {
        static uint task = 0;
        /// <summary>
        /// Read a number of bytes from a processes memory into given byte array buffer
        /// </summary>
        /// <param name="processHandle"></param>
        /// <param name="address"></param>
        /// <param name="bytes"></param>
        /// <returns>bytes read</returns>
        public static int ReadBytesFromMemory(RSMemoryReader.ProcessInfo pInfo, IntPtr address, int bytes, ref byte[] buffer)
        {
            int bytesRead = 0;
            switch (Environment.OSVersion.Platform)
            {
                case PlatformID.MacOSX:
                case PlatformID.Unix:
                    if (task == 0)
                        MacOSAPI.task_for_pid_wrapper(pInfo.PID, out task);
                    IntPtr ptr;
                    int ret = MacOSAPI.vm_read_wrapper(task, (ulong)address, (ulong)bytes, out ptr, out bytesRead);
                    if (ret == 0)
                        Marshal.Copy(ptr, buffer, 0, bytesRead);
                    break;
                case PlatformID.Win32Windows:
                case PlatformID.Win32NT:
                    Win32API.ReadProcessMemory((int)pInfo.rsProcessHandle, (int)address, buffer, bytes, ref bytesRead);
                    break;
            }
            if (Logger.logMemoryReadout)
            {
                Logger.Log(string.Format("ReadBytesFromMemory: Address: {0} Bytes: {1} BytesRead: {2}", address.ToString("X8"), bytes, bytesRead));
                Logger.Log(string.Format("RawBytes: {0}", BitConverter.ToString(buffer)));
            }
            return bytesRead;
        }

        /// <summary>
        /// Read a number of bytes from a processes memory into a byte array
        /// </summary>
        /// <param name="pInfo"></param>
        /// <param name="address"></param>
        /// <param name="bytes"></param>
        /// <returns>bytes read</returns>
        public static byte[] ReadBytesFromMemory(RSMemoryReader.ProcessInfo pInfo, IntPtr address, int bytes)
        {
            int bytesRead = 0;
            byte[] buf = new byte[bytes];

            switch (Environment.OSVersion.Platform)
            {
                case PlatformID.MacOSX:
                case PlatformID.Unix:
                    if (task == 0)
                        MacOSAPI.task_for_pid_wrapper(pInfo.PID, out task);
                    //Console.WriteLine(string.Format("task_for_pid: task: {0}", task));

                    IntPtr ptr;
                    int ret = MacOSAPI.vm_read_wrapper(task, (ulong)address, (ulong)bytes, out ptr, out bytesRead);
                    //Console.WriteLine(string.Format("vm_read_wrapper: address: {0} bytes: {1} outptr: {2} bytesRead: {3}", (ulong)address, (ulong)bytes, ptr, bytesRead));

                    if (ret == 0)
                        Marshal.Copy(ptr, buf, 0, bytesRead);
                    break;
                case PlatformID.Win32Windows:
                case PlatformID.Win32NT:
                    Win32API.ReadProcessMemory((int)pInfo.rsProcessHandle, (int)address, buf, bytes, ref bytesRead);
                    break;
            }
            if (Logger.logMemoryReadout)
            {
                Logger.Log(string.Format("ReadBytesFromMemory: Address: {0} Bytes: {1} BytesRead: {2}", address.ToString("X8"), bytes, bytesRead));
                Logger.Log(string.Format("RawBytes: {0}", BitConverter.ToString(buf)));
            }
            return buf;
        }

        /// <summary>
        /// Reads an Int32 from a processes memory
        /// </summary>
        /// <param name="processHandle"></param>
        /// <param name="address"></param>
        /// <returns></returns>
        public static int ReadInt32FromMemory(RSMemoryReader.ProcessInfo processHandle, IntPtr address)
        {
            return BitConverter.ToInt32(ReadBytesFromMemory(processHandle, address, 4), 0);
        }

        /// <summary>
        /// Reads a single byte from a processes memory
        /// </summary>
        /// <param name="processHandle"></param>
        /// <param name="address"></param>
        /// <returns></returns>
        public static byte ReadByteFromMemory(RSMemoryReader.ProcessInfo processHandle, IntPtr address)
        {
            return ReadBytesFromMemory(processHandle, address, 1)[0];
        }

        /// <summary>
        /// Follows a pointer by reading destination address from process memory and applying offset
        /// <para></para>
        /// Returns the new pointer
        /// </summary>
        /// <param name="processHandle"></param>
        /// <param name="address"></param>
        /// <param name="offset"></param>
        /// <returns></returns>
        public static IntPtr FollowPointer(RSMemoryReader.ProcessInfo processHandle, IntPtr address, int offset)
        {
            Logger.Log(string.Format("PreFollow Pointer: Address:{0} offset: {1}", address.ToString("X8"), offset));
            IntPtr readPointer = (IntPtr)ReadInt32FromMemory(processHandle, address);

            return IntPtr.Add(readPointer, offset);
        }

        /// <summary>
        /// Reads a float from a processes memory
        /// </summary>
        /// <param name="processHandle"></param>
        /// <param name="address"></param>
        /// <returns></returns>
        public static float ReadFloatFromMemory(RSMemoryReader.ProcessInfo processHandle, IntPtr address)
        {
            return BitConverter.ToSingle(ReadBytesFromMemory(processHandle, address, 4), 0);
        }
    }
}
