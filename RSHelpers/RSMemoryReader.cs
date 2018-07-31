using RockSnifferLib.SysHelpers;
using RockSnifferLib.Logging;
using System;
using System.Diagnostics;
using System.Collections.Generic;

namespace RockSnifferLib.RSHelpers
{
    public class RSMemoryReader
    {
        private RSMemoryReadout readout = new RSMemoryReadout();
        private RSMemoryReadout prevReadout = new RSMemoryReadout();

        public struct ProcessInfo
        {
            //Process handles
            public Process rsProcess;
            public IntPtr rsProcessHandle;
            public ulong PID;
        }
        ProcessInfo PInfo = new ProcessInfo();

        public RSMemoryReader(Process rsProcess)
        {
            this.PInfo.rsProcess = rsProcess;

            this.PInfo.rsProcessHandle = rsProcess.Handle;
            this.PInfo.PID = (ulong)rsProcess.Id;
        }

        /// <summary>
        /// Read song timer and note data from memory
        /// </summary>
        /// <returns></returns>
        public RSMemoryReadout DoReadout()
        {
            // SONG ID
            //
            // Seems to be a zero terminated string in the format: Song_SONGID_Preview
            //
            //Candidate #1: FollowPointers(0x00F5C494, new int[] { 0xBC, 0x0 })
            //Candidate #2: FollowPointers(0x00F80CEC, new int[] { 0x598, 0x1B8, 0x0 })
            //Candidate #3: FollowPointers(0x00F5DAFC, new int[] { 0x608, 0x1B8, 0x0 })
            byte[] bytes = MemoryHelper.ReadBytesFromMemory(PInfo, FollowPointers(0x00F5C494, new int[] { 0xBC, 0x0 }), 128);

            //Find the first 0 in the array
            int end = Array.IndexOf<byte>(bytes, 0);

            //If there was a 0 in the array
            if (end > 0)
            {
                //Copy into a char array
                char[] chars = new char[end];

                Array.Copy(bytes, chars, end);

                //Create string from char array
                string preview_name = new string(chars);

                //Verify Play_ prefix and _Preview suffix
                if (preview_name.StartsWith("Play_") && preview_name.EndsWith("_Preview"))
                {
                    //Remove Play_ prefix and _Preview suffix
                    string song_id = preview_name.Substring(5, preview_name.Length - 13);

                    //Assign to readout
                    readout.songID = song_id;
                }
            }

            // SONG TIMER
            //
            //Weird static address: FollowPointers(0x01567AB0, new int[]{ 0x80, 0x20, 0x10C, 0x244 })
            //Candidate #1: FollowPointers(0x00F5C5AC, new int[] { 0xB0, 0x538, 0x8 })
            //Candidate #2: FollowPointers(0x00F5C4CC, new int[] { 0x5F0, 0x538, 0x8 })
            ReadSongTimer(FollowPointers(0x00F5C5AC, new int[] { 0xB0, 0x538, 0x8 }));

            // NOTE DATA
            //
            //Candidate #1: FollowPointers(0x00F5C5AC, new int[] {0xB0, 0x18, 0x4, 0x84, 0x30})
            //Candidate #2: FollowPointers(0x00F5C4CC, new int[] {0x5F0, 0x18, 0x4, 0x84, 0x30})
            ReadNoteData(FollowPointers(0x00F5C5AC, new int[] { 0xB0, 0x18, 0x4, 0x84, 0x30 }));

            //Copy over everything when a song is running
            if (readout.songTimer > 0)
            {
                readout.CopyTo(ref prevReadout);
            }

            //Always copy over important fields
            prevReadout.songID = readout.songID;
            prevReadout.songTimer = readout.songTimer;

            return prevReadout;
        }

        public List<uint> PointerScan(uint Target, uint maxAdd, uint maxDepth)
        {
            ulong baseadd;
            long end = 0x7FFFFFF;
            end = 0x1004;
            maxAdd = 5;
            MacOSAPI.mach_vm_region_recurse_wrapper(PInfo.PID, out baseadd);
            Logger.Log("Starting pointer scan: base: " + baseadd.ToString("X8"));
            for (uint address = (uint)baseadd; address <= end; address += 4)
            {
                List<uint> ret = rScan(address, Target, maxAdd, maxDepth, 1);
                if (ret.Count > 0)
                {
                    ret.Insert(0, address);
                    return ret;
                }
            }
            return new List<uint>();
        }
        List<uint> rScan(uint address, uint Target, uint maxAdd, uint maxDepth, uint currDepth)
        {
            if (currDepth == 1)
                Logger.Log("Base Scan: " + address.ToString("X8"));
            else
                Logger.Log(string.Format(new String('\t', (int)currDepth) + "Depth Scan: Depth: {0} Address: {1} ", currDepth, address.ToString("X8")));

            uint value = (uint)MemoryHelper.ReadInt32FromMemory(PInfo, new IntPtr(address));

            for (int offset = 0; offset <= maxAdd; offset += 4)
            {
                if (value + offset == Target)
                {
                    return new List<uint> { (uint)offset };
                }
            }
            if (currDepth < maxDepth)
            {
                currDepth++;
                for (uint offset = 0; offset <= maxAdd; offset += 4)
                {
                    Logger.Log(new String('\t', (int)currDepth) + "Offset: " + offset);
                    List<uint> ret = rScan(value + offset, Target, maxAdd, maxDepth, currDepth);
                    if (ret.Count > 0)
                    {
                        ret.Insert(0, (uint)offset);
                        return ret;
                    }
                }
            }
            return new List<uint>();
        }

        private IntPtr FollowPointers(int entryAddress, int[] offsets)
        {
            //Get base address
            IntPtr baseAddress = PInfo.rsProcess.MainModule.BaseAddress;
            ulong Offset;
            MacOSAPI.mach_vm_region_recurse_wrapper(PInfo.PID, out Offset);
            Logger.Log("MacVM~Offset: " + (IntPtr)Offset);
            baseAddress = (IntPtr)Offset;

            //Add entry address
            IntPtr finalAddress = IntPtr.Add(baseAddress, entryAddress);
            Logger.Log("Base Address: {0} EntryAdress: {1} Final Address: {2}", baseAddress.ToString("X8"), entryAddress.ToString("X8"), finalAddress.ToString("X8"));

            //Add offsets
            foreach (int offset in offsets)
            {
                finalAddress = MemoryHelper.FollowPointer(PInfo, finalAddress, offset);
            }
            Logger.Log("OffsetFinalized Address: " + finalAddress.ToString("X8"));
            //Return the final address
            return finalAddress;
        }

        private void ReadSongTimer(IntPtr timerAddress)
        {
            //Read float from memory and assign field on readout
            readout.songTimer = MemoryHelper.ReadFloatFromMemory(PInfo, timerAddress);
        }

        private void ReadNoteData(IntPtr structAddress)
        {
            //Riff repeater data:
            //
            //Offsets
            //0000 - total notes hit
            //0004 - current note streak
            //0008 - unknown
            //000C - highest note streak
            //0010 - total notes missed
            //0014 - missed note streak

            //Read and assign all fields
            readout.totalNotesHit = MemoryHelper.ReadInt32FromMemory(PInfo, structAddress);
            readout.currentHitStreak = MemoryHelper.ReadInt32FromMemory(PInfo, IntPtr.Add(structAddress, 0x0004));
            readout.unknown = MemoryHelper.ReadInt32FromMemory(PInfo, IntPtr.Add(structAddress, 0x0008));
            readout.highestHitStreak = MemoryHelper.ReadInt32FromMemory(PInfo, IntPtr.Add(structAddress, 0x000C));
            readout.totalNotesMissed = MemoryHelper.ReadInt32FromMemory(PInfo, IntPtr.Add(structAddress, 0x0010));
            readout.currentMissStreak = MemoryHelper.ReadInt32FromMemory(PInfo, IntPtr.Add(structAddress, 0x0014));
        }
    }
}
