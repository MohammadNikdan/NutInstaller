using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace NutriculaInstaller
{
    /// <summary>
    /// Finds and deletes every file in a MetaTrader terminal that is
    /// recognisably Nutricula, wherever it sits and whatever it is called.
    ///
    /// WHY THIS EXISTS
    /// ---------------
    /// The Coordinator's integrity check measures what is actually running
    /// (see RuntimeMeasure.h in the Coordinator sources). One of its rules is
    /// that EVERY recognisable Nutricula program in a terminal's
    /// Experts/Indicators/Scripts trees must hash to the value in the signed
    /// manifest - so a single leftover copy from an OLDER build, sitting in
    /// some backup subfolder, is enough to put an otherwise perfectly
    /// legitimate customer at -2 after an upgrade. The manifest carries one
    /// expected hash per MQL generation, so "old but genuine" and "modified"
    /// look identical to it, by design.
    ///
    /// The installer therefore sweeps a terminal clean before writing the
    /// fresh files into it, and the uninstaller sweeps it on the way out so
    /// that a non-default install location does not leave an orphan behind.
    /// Deleting a tampered copy buys no security on its own - whoever
    /// tampered with it will not run the installer - and that is not the
    /// point: the point is that a reinstall reliably returns a machine to a
    /// state the integrity check accepts.
    ///
    /// HOW A FILE IS RECOGNISED
    /// ------------------------
    /// By byte markers, searched in both ASCII and UTF-16LE and
    /// case-insensitively, because MQL stores strings as Unicode while a
    /// compiled DLL carries them as plain bytes:
    ///
    ///   * the License Check DLL's exported entry-point names. A compiled MQL
    ///     program carries the name of every imported function it calls, and
    ///     a DLL carries the name of everything it exports. MQL resolves both
    ///     by name at run time, never by ordinal, so these cannot be removed
    ///     from anything that still works.
    ///   * the Machine ID DLL's exported names, same reasoning.
    ///   * the shipped DLL file names, which an importing program must spell
    ///     out as a literal.
    ///   * the explicit build marker in the EA source - redundancy only, since
    ///     it is the one marker a patched copy could simply delete.
    ///
    /// KEEP THE TWO MARKER LISTS IN SYNC with LICENSE_DLL_ENTRY_POINTS and
    /// MACHINEID_ENTRY_POINTS in Coordinator/RuntimeMeasure.cpp. If they ever
    /// drift apart, this sweep stops cleaning exactly the files that check
    /// would go on to reject.
    /// </summary>
    internal static class NutriculaSweeper
    {
        // Program file extensions, by terminal generation.
        private const string Mql4ProgramExtension = ".ex4";
        private const string Mql5ProgramExtension = ".ex5";

        // The three folders MetaTrader will load a compiled MQL program from.
        private static readonly string[] ProgramSubfolders = { "Experts", "Indicators", "Scripts" };

        // See the class comment. NxD/NxW are deliberately absent: at two and
        // three characters they would match arbitrary bytes constantly.
        private static readonly string[] Markers =
        {
            "Vela_Boot_84", "Pavo_Sync_85", "Indus_Auth_86",
            "Phoenix_State_87", "Dorado_Flag_88", "Carina_Span_89",
            "Nutricula_GenerateMachineId", "Nutricula_GetDeviceKeyHash",
            "Nutricula_SignChallenge", "Nutricula_GetLicensePath",
            "NutriculaLicenseCheck32.dll", "NutriculaLicenseCheck64.dll",
            "NTRCLA-EA-MARK-7F3A91C4",
        };

        // Bounds, so a pathological tree cannot stall an install. A genuine
        // Experts tree is a few dozen files of a few hundred KB each.
        private const int MaxDepth = 16;
        private const int MaxFiles = 3000;
        private const long MaxFileBytes = 32L * 1024 * 1024;

        private static byte[][] markerPatternsCache;

        /// <summary>
        /// Deletes every recognisable Nutricula file from this terminal: any
        /// .ex4/.ex5 under Experts/Indicators/Scripts, and any file at all
        /// under Libraries. Returns the number of files deleted.
        ///
        /// Never throws. A file that cannot be deleted (locked by a running
        /// terminal, for instance) is reported through <paramref name="log"/>
        /// and the sweep carries on - failing an install over it would be
        /// worse than leaving it, and the caller is about to overwrite the
        /// canonical paths anyway. A leftover that could not be removed is
        /// worth seeing in the log, because it is what a later -2 would be
        /// about.
        /// </summary>
        public static int Sweep(TerminalInfo terminal, Action<string> log)
        {
            if (terminal == null) return 0;

            int deleted = 0;
            int filesSeen = 0;
            try
            {
                bool isMt4 = terminal.Type == TerminalType.MT4;
                string mqlRoot = Path.Combine(terminal.TerminalPath, isMt4 ? "MQL4" : "MQL5");
                string programExtension = isMt4 ? Mql4ProgramExtension : Mql5ProgramExtension;

                foreach (string subfolder in ProgramSubfolders)
                {
                    SweepDirectory(Path.Combine(mqlRoot, subfolder), programExtension,
                        0, ref filesSeen, ref deleted, log);
                }

                // Libraries holds DLLs only, so there is no extension to
                // filter by - a renamed copy of our DLL could be called
                // anything at all. Recognition is by marker either way.
                SweepDirectory(Path.Combine(mqlRoot, "Libraries"), null,
                    0, ref filesSeen, ref deleted, log);
            }
            catch (Exception ex)
            {
                log("WARNING: could not finish checking " + terminal.TerminalPath +
                    " for leftover Nutricula files (" + ex.Message + "). Installation continues.");
            }

            if (deleted > 0)
            {
                log("Removed " + deleted + " existing Nutricula file(s) from " + terminal.TerminalPath + ".");
            }
            return deleted;
        }

        private static void SweepDirectory(string dir, string extensionFilter, int depth,
            ref int filesSeen, ref int deleted, Action<string> log)
        {
            if (depth > MaxDepth || filesSeen >= MaxFiles) return;
            if (!Directory.Exists(dir)) return;

            string[] files;
            string[] subdirs;
            try
            {
                files = Directory.GetFiles(dir);
                subdirs = Directory.GetDirectories(dir);
            }
            catch (Exception ex)
            {
                log("WARNING: could not read " + dir + " (" + ex.Message + ").");
                return;
            }

            foreach (string file in files)
            {
                if (filesSeen >= MaxFiles) return;
                if (extensionFilter != null &&
                    !file.EndsWith(extensionFilter, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                filesSeen++;
                if (!LooksLikeNutricula(file, log)) continue;

                try
                {
                    File.SetAttributes(file, FileAttributes.Normal); // clears read-only
                    File.Delete(file);
                    deleted++;
                    log("Removed existing Nutricula file: " + file);
                }
                catch (Exception ex)
                {
                    log("WARNING: found an existing Nutricula file but could not remove it: " +
                        file + " (" + ex.Message + "). Close MetaTrader and reinstall if the EA " +
                        "later reports an integrity problem.");
                }
            }

            foreach (string sub in subdirs)
            {
                // Never follow a junction/symlink: it can point back up the
                // tree or out of the terminal entirely.
                try
                {
                    var attrs = new DirectoryInfo(sub).Attributes;
                    if ((attrs & FileAttributes.ReparsePoint) != 0) continue;
                }
                catch (Exception)
                {
                    continue;
                }
                SweepDirectory(sub, extensionFilter, depth + 1, ref filesSeen, ref deleted, log);
            }
        }

        /// <summary>
        /// True if this file carries any Nutricula marker. A file that cannot
        /// be read is reported as NOT ours: deleting something unidentifiable
        /// out of a customer's terminal is the one outcome worth avoiding
        /// outright.
        /// </summary>
        private static bool LooksLikeNutricula(string path, Action<string> log)
        {
            byte[] content;
            try
            {
                var info = new FileInfo(path);
                if (info.Length <= 0 || info.Length > MaxFileBytes) return false;
                content = File.ReadAllBytes(path);
            }
            catch (Exception)
            {
                return false;
            }

            // Fold to lower case once, then look for every pattern in it.
            for (int i = 0; i < content.Length; i++)
            {
                byte b = content[i];
                if (b >= (byte)'A' && b <= (byte)'Z') content[i] = (byte)(b - 'A' + 'a');
            }

            foreach (byte[] pattern in MarkerPatterns())
            {
                if (Contains(content, pattern)) return true;
            }
            return false;
        }

        private static byte[][] MarkerPatterns()
        {
            if (markerPatternsCache != null) return markerPatternsCache;

            var patterns = new List<byte[]>(Markers.Length * 2);
            foreach (string marker in Markers)
            {
                string folded = marker.ToLowerInvariant();
                // ASCII form, and the UTF-16LE form the MQL compiler stores
                // string literals as.
                patterns.Add(Encoding.ASCII.GetBytes(folded));
                patterns.Add(Encoding.Unicode.GetBytes(folded));
            }
            markerPatternsCache = patterns.ToArray();
            return markerPatternsCache;
        }

        private static bool Contains(byte[] haystack, byte[] needle)
        {
            if (needle.Length == 0 || needle.Length > haystack.Length) return false;
            byte first = needle[0];
            int last = haystack.Length - needle.Length;
            for (int i = 0; i <= last; i++)
            {
                if (haystack[i] != first) continue;
                int j = 1;
                while (j < needle.Length && haystack[i + j] == needle[j]) j++;
                if (j == needle.Length) return true;
            }
            return false;
        }
    }
}
