﻿using RocksmithToolkitLib.PsarcLoader;
using RockSnifferLib.Logging;
using RockSnifferLib.Sniffing;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;

namespace RockSnifferLib.RSHelpers
{
    public class PSARCUtil
    {
        /// <summary>
        /// Extracts a 256x256 bitmap album art from PsarcLoader by artFile file path
        /// </summary>
        /// <param name="loader"></param>
        /// <param name="artFile"></param>
        /// <returns></returns>
        internal static Bitmap ExtractAlbumArt(LazyPsarcLoader loader, string artFile)
        {
            //Select the correct entry and load it into the memory stream
            using (MemoryStream ms = loader.ExtractEntryData(x => (x.Name == "gfxassets/album_art/" + artFile.Substring(14) + "_256.dds")))
            {
                //Create a Pfim image from memory stream
                Pfim.Dds img = Pfim.Dds.Create(ms);

                //Create bitmap
                Bitmap bm = new Bitmap(img.Width, img.Height);

                //Convert Pfim image to bitmap
                int bytesPerPixel = img.BytesPerPixel;
                for (int i = 0; i < img.Data.Length; i += bytesPerPixel)
                {
                    //Calculate pixel X and Y coordinates
                    int x = (i / bytesPerPixel) % img.Width;
                    int y = (i / bytesPerPixel) / img.Width;

                    //Get color from the Pfim image data array
                    Color c = Color.FromArgb(255, img.Data[i + 2], img.Data[i + 1], img.Data[i]);

                    //Set pixel in bitmap
                    bm.SetPixel(x, y, c);
                }

                //Return bitmap
                return bm;
            }
        }

        /// <summary>
        /// Reads psarc file from filepath and populates details with information
        /// </summary>
        /// <param name="filepath"></param>
        /// <param name="details"></param>
        internal static Dictionary<string, SongDetails> ReadPSARCHeaderData(string filepath)
        {
            //Check that the file exists, just in case
            if (!File.Exists(filepath))
            {
                Logger.LogError("Warning! Psarc file {0} does not exist!", filepath);
                return null;
            }

            var sw = new Stopwatch();
            sw.Start();

            //If its big, print a warning
            var fileinfo = new FileInfo(filepath);
            long size = fileinfo.Length;

            var detailsDict = new Dictionary<string, SongDetails>();

            using (LazyPsarcLoader loader = new LazyPsarcLoader(filepath))
            {
                //Extract toolkit info
                var tkInfo = loader.ExtractToolkitInfo();

                //Extract all arrangements
                foreach (var v in loader.ExtractJsonManifests())
                {
                    var attr = v.Entries.ToArray()[0].Value.ToArray()[0].Value;

                    if (attr.Phrases != null)
                    {
                        if (!detailsDict.ContainsKey(attr.SongKey))
                        {
                            detailsDict[attr.SongKey] = new SongDetails();
                        }

                        SongDetails details = detailsDict[attr.SongKey];

                        if (details.albumArt == null)
                        {
                            try
                            {
                                details.albumArt = ExtractAlbumArt(loader, attr.AlbumArt);
                            }
                            catch (Exception)
                            {
                                Logger.LogError("Warning: couldn't extract album art for {0}", attr.SongName);

                                details.albumArt = new Bitmap(1, 1);
                            }
                        }

                        details.songID = attr.SongKey;
                        details.songLength = (float)(attr.SongLength ?? 0);
                        details.songName = attr.SongName;
                        details.artistName = attr.ArtistName;
                        details.albumName = attr.AlbumName;
                        details.albumYear = attr.SongYear ?? 0;
                        details.numArrangements++;

                        details.toolkit = new ToolkitDetails
                        {
                            version = tkInfo.PackageVersion,
                            author = tkInfo.PackageAuthor,
                            comment = tkInfo.PackageComment,
                            package_version = tkInfo.PackageVersion
                        };
                    }
                }

                sw.Stop();

                Logger.Log("Parsed {0} ({1}mb) in {2}ms and found {3} songs", fileinfo.Name, fileinfo.Length / 1024 / 1024, sw.ElapsedMilliseconds, detailsDict.Count);

                return detailsDict;
            }

        }
    }
}
