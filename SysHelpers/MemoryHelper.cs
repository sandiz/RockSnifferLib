﻿using RockSnifferLib.RSHelpers;
using RockSnifferLib.Logging;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Diagnostics;
namespace RockSnifferLib.SysHelpers
{
    public struct ProcessInfo
    {
        //Process handles
        public Process rsProcess;
        public IntPtr rsProcessHandle;
        public ulong PID;
        /* mac os task port */
        public uint Task;
    }
    class MemoryHelper
    {
        public static ulong ScanMemChar(ProcessInfo pInfo, IntPtr ptr, int bytesRead, ulong dataIndex, byte[] b1, byte[] b2, int region)
        {
            ulong ret = MacOSAPI.scan_mem_char(pInfo.Task, (ulong)ptr, (ulong)bytesRead,
            dataIndex, b1, b1.Length, b2, b2.Length, region);
            return ret;
        }
        /* Scan Memory pointed by ptr for the magic int  */
        public static ulong ScanMem(ProcessInfo pInfo, IntPtr ptr, int bytesRead, ulong dataIndex, int magic)
        {
            return MacOSAPI.scan_mem(pInfo.Task, (ulong)ptr, (ulong)bytesRead, dataIndex, magic);
        }
        /// <summary>
        /// Read a number of bytes from a processes memory into given byte array buffer
        /// </summary>
        /// <param name="processHandle"></param>
        /// <param name="address"></param>
        /// <param name="bytes"></param>
        /// <returns>bytes read</returns>
        public static int ReadBytesFromMemory(ProcessInfo pInfo, IntPtr address, int bytes, ref byte[] buffer)
        {
            int bytesRead = 0;
            switch (Environment.OSVersion.Platform)
            {
                case PlatformID.MacOSX:
                case PlatformID.Unix:
                    IntPtr ptr;
                    int ret = MacOSAPI.vm_read_wrapper(pInfo.Task, (ulong)address, (ulong)bytes, out ptr, out bytesRead);
                    if (ret == 0)
                    {
                        Marshal.Copy(ptr, buffer, 0, bytesRead);
                        MacOSAPI.vm_deallocate_wrapper(pInfo.Task, (ulong)ptr, (ulong)bytesRead);
                    }
                    break;
                default:
                    Win32API.ReadProcessMemory((int)pInfo.rsProcessHandle, (int)address, buffer, bytes, ref bytesRead);
                    break;
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
        public static byte[] ReadBytesFromMemory(ProcessInfo pInfo, IntPtr address, int bytes)
        {
            int bytesRead = 0;
            byte[] buf = new byte[bytes];

            switch (Environment.OSVersion.Platform)
            {
                case PlatformID.MacOSX:
                case PlatformID.Unix:
                    IntPtr ptr;
                    int ret = MacOSAPI.vm_read_wrapper(pInfo.Task, (ulong)address, (ulong)bytes, out ptr, out bytesRead);
                    //Logger.Log(bytes.ToString() + " " + bytesRead.ToString() + " " + ret.ToString());
                    if (ret == 0)
                    {
                        Marshal.Copy(ptr, buf, 0, bytesRead);
                        MacOSAPI.vm_deallocate_wrapper(pInfo.Task, (ulong)ptr, (ulong)bytesRead);
                    }
                    MacOSAPI.free_wrapper(ptr);
                    break;
                default:
                    Win32API.ReadProcessMemory((int)pInfo.rsProcessHandle, (int)address, buf, bytes, ref bytesRead);
                    break;
            }
            return buf;
        }

        /// <summary>
        /// Reads an Int32 from a processes memory
        /// </summary>
        /// <param name="processHandle"></param>
        /// <param name="address"></param>
        /// <returns></returns>
        public static int ReadInt32FromMemory(ProcessInfo processHandle, IntPtr address)
        {
            return BitConverter.ToInt32(ReadBytesFromMemory(processHandle, address, 4), 0);
        }

        /// <summary>
        /// Reads an Int64 from a processes memory
        /// </summary>
        /// <param name="processHandle"></param>
        /// <param name="address"></param>
        /// <returns></returns>
        public static Int64 ReadInt64FromMemory(ProcessInfo processHandle, IntPtr address)
        {
            return BitConverter.ToInt64(ReadBytesFromMemory(processHandle, address, 8), 0);
        }

        /// <summary>
        /// Reads a single byte from a processes memory
        /// </summary>
        /// <param name="processHandle"></param>
        /// <param name="address"></param>
        /// <returns></returns>
        public static byte ReadByteFromMemory(ProcessInfo processHandle, IntPtr address)
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
        public static IntPtr FollowPointer(ProcessInfo processHandle, IntPtr address, int offset)
        {
            //Logger.Log(string.Format("PreFollow Pointer: Address:{0} offset: {1}", address.ToString("X8"), offset));
            switch (Environment.OSVersion.Platform)
            {
                case PlatformID.MacOSX:
                case PlatformID.Unix:
                    IntPtr readPointer64 = (IntPtr)ReadInt64FromMemory(processHandle, address);
                    return IntPtr.Add(readPointer64, offset);
                default:
                    IntPtr readPointer = (IntPtr)ReadInt32FromMemory(processHandle, address);
                    return IntPtr.Add(readPointer, offset);
            }
        }

        /// <summary>
        /// Reads a float from a processes memory
        /// </summary>
        /// <param name="processHandle"></param>
        /// <param name="address"></param>
        /// <returns></returns>
        public static float ReadFloatFromMemory(ProcessInfo processHandle, IntPtr address)
        {
            return BitConverter.ToSingle(ReadBytesFromMemory(processHandle, address, 4), 0);
        }

        /// <summary>
        /// get user_tag associated with a memory region
        /// </summary>
        /// <param name="pInfo"></param>
        /// <param name="Address"></param>
        /// <param name="size"></param>
        /// <returns></returns>
        public static UInt32 GetUserTag(ProcessInfo pInfo, ulong Address, ulong size)
        {
            UInt32 userTag = 0;
            int ret = MacOSAPI.mach_vm_region_recurse_wrapper(pInfo.Task, out Address, out size, out userTag);
            return userTag;
        }

        /// <summary>
        /// get all memory regions of a process
        /// </summary>
        /// <param name="pInfo"></param>
        /// <param name="begin"></param>
        /// <param name="end"></param>
        /// <returns></returns>
        public static List<MacOSAPI.Region> GetAllRegionsMacOS(ProcessInfo pInfo, ulong begin, ulong end)
        {
            List<MacOSAPI.Region> Regions = new List<MacOSAPI.Region>();
            ulong address = 0;
            while (true)
            {
                ulong size = 0;
                int protection = 0;
                int ret = MacOSAPI.mach_vm_region_wrapper(pInfo.Task, out address, out size, out protection);
                if (ret != 0)
                    break;
                //Logger.Log(string.Format("Ret: {0} Address: {1} Size: {2}", ret, address, size));
                MacOSAPI.Region reg = new MacOSAPI.Region()
                {
                    Address = address,
                    Size = size,
                    Protection = protection
                };
                if (reg.Address < end && (reg.Address + size) > begin && ((reg.Protection & 0x02) == 2)) /* writable protection */
                    Regions.Add(reg);
                address += size;
            }
            return Regions;
        }

        public static bool MaskCheck(byte[] buffer, int nOffset, byte[] btPattern, byte[] btPattern2, string strMask)
        {
            bool hint1pass = true;
            bool hint2pass = true;
            // Loop the pattern and compare to the mask and dump. 
            for (int x = 0; x < btPattern.Length; x++)
            {
                if (nOffset + x >= buffer.Length)
                    return false;
                // If the mask char is a wildcard, just continue. 
                if (strMask[x] == '?')
                    continue;

                // If the mask char is not a wildcard, ensure a match is made in the pattern. 
                if ((strMask[x] == 'x') && (btPattern[x] != buffer[nOffset + x]))
                    hint1pass = false;
                if ((strMask[x] == 'x') && (btPattern2[x] != buffer[nOffset + x]))
                    hint2pass = false;
            }

            // The loop was successful so we found the pattern. 
            return hint1pass || hint2pass;
        }
        public static int IndexOfBytes(byte[] array, byte[] pattern, byte[] pattern2, int startIndex, int count)
        {
            if (array == null || array.Length == 0 || pattern == null || pattern.Length == 0 || count == 0)
            {
                return -1;
            }
            int i = startIndex;
            int endIndex = count > 0 ? Math.Min(startIndex + count, array.Length) : array.Length;
            int fidx = 0;
            int lastFidx = 0;
            while (i < endIndex)
            {
                lastFidx = fidx;
                fidx = (array[i] == pattern[fidx] || array[i] == pattern2[fidx]) ? ++fidx : 0;
                if (fidx == pattern.Length)
                {
                    return (i - fidx + 1);
                }
                if (lastFidx > 0 && fidx == 0)
                {
                    i = i - lastFidx;
                    lastFidx = 0;
                }
                i++;
            }
            return -1;
        }
        public static List<Win32API.Region> GetAllRegionsWin32(ProcessInfo processInfo)
        {
            List<Win32API.Region> regions = new List<Win32API.Region>();
            Win32API.SYSTEM_INFO sys_info = new Win32API.SYSTEM_INFO();
            Win32API.GetSystemInfo(out sys_info);

            IntPtr proc_min_address = sys_info.minimumApplicationAddress;
            IntPtr proc_max_address = sys_info.maximumApplicationAddress;

            // saving the values as long ints so I won't have to do a lot of casts later
            long proc_min_address_l = proc_min_address.ToInt64();
            long proc_max_address_l = proc_max_address.ToInt64();
            Win32API.MEMORY_BASIC_INFORMATION mem_basic_info = new Win32API.MEMORY_BASIC_INFORMATION();
            int idx = 0;
            while (proc_min_address_l < proc_max_address_l)
            {
                // 28 = sizeof(MEMORY_BASIC_INFORMATION)
                int ret = Win32API.VirtualQueryEx(processInfo.rsProcessHandle, proc_min_address, out mem_basic_info, 28);

                // if this memory chunk is accessible
                if (ret == 28)
                {
                    if (mem_basic_info.Protect ==
                    Win32API.PAGE_READWRITE && mem_basic_info.State == Win32API.MEM_COMMIT &&
                    (mem_basic_info.Type == Win32API.MEM_MAPPED || mem_basic_info.Type == Win32API.MEM_PRIVATE))
                    {
                        //Logger.Log("ret: {3} Region: {0} Address: {1} Size: {2}", idx, proc_min_address.ToString("X8"), mem_basic_info.RegionSize, ret);

                        Win32API.Region reg = new Win32API.Region()
                        {
                            Address = (ulong)mem_basic_info.BaseAddress,
                            Size = (ulong)mem_basic_info.RegionSize,
                            Protection = mem_basic_info.Protect,
                        };
                        regions.Add(reg);
                    }
                }

                // move to the next memory chunk
                proc_min_address_l += (long)mem_basic_info.RegionSize;
                proc_min_address = (IntPtr)(proc_min_address_l);
                idx++;
            }
            return regions;
        }
    }
}
