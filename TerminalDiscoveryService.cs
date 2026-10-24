using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;

namespace NutriculaInstaller
{
    internal sealed class TerminalDiscoveryService
    {
        private readonly Dictionary<string, TerminalInfo> terminals = new Dictionary<string, TerminalInfo>(StringComparer.OrdinalIgnoreCase);

        public List<TerminalInfo> DiscoverAll(Action<string> log)
        {
            terminals.Clear();

            string roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            string metaQuotesTerminalRoot = Path.Combine(roaming, "MetaQuotes", "Terminal");
            DiscoverStandardDataDirectories(metaQuotesTerminalRoot, log);

            DiscoverRunningTerminals(log);
            DiscoverRegistryInstallations(log);
            DiscoverCommonProgramFiles(log);

            // 2026 Wine hardening: every method above is completely
            // unchanged and still only ever sees THIS process's own Wine
            // prefix (or, on real Windows, the one and only install) -
            // nothing about them changes on Windows. On Wine only, ALSO
            // scan every OTHER Wine prefix on this real host for
            // MetaTrader installations, so one Installer run on Mac/Linux
            // covers MT4 and MT5 wherever each one actually lives, the
            // same way a single run already does on Windows. See
            // DiscoverWinePrefixes's own comment for exactly which
            // locations are checked and why.
            if (MachineIdService.IsWineEnvironment())
            {
                DiscoverWinePrefixes(log);
            }

            return terminals.Values
                .OrderBy(t => t.Type)
                .ThenBy(t => t.TerminalPath, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }

        private void DiscoverStandardDataDirectories(string root, Action<string> log)
        {
            if (!Directory.Exists(root))
                return;

            try
            {
                foreach (string child in Directory.EnumerateDirectories(root))
                {
                    string mql4 = Path.Combine(child, "MQL4", "Experts");
                    string mql5 = Path.Combine(child, "MQL5", "Experts");

                    if (Directory.Exists(mql4))
                        Add(TerminalType.MT4, child, "%APPDATA%\\MetaQuotes\\Terminal", log);
                    if (Directory.Exists(mql5))
                        Add(TerminalType.MT5, child, "%APPDATA%\\MetaQuotes\\Terminal", log);
                }
            }
            catch (Exception ex)
            {
                log("MetaQuotes data-directory scan warning: " + ex.Message);
            }
        }

        private void DiscoverRunningTerminals(Action<string> log)
        {
            try
            {
                foreach (Process process in Process.GetProcesses())
                {
                    try
                    {
                        string exe = process.MainModule == null ? null : process.MainModule.FileName;
                        if (string.IsNullOrEmpty(exe))
                            continue;

                        string name = Path.GetFileName(exe);
                        if (!name.Equals("terminal.exe", StringComparison.OrdinalIgnoreCase) &&
                            !name.Equals("terminal64.exe", StringComparison.OrdinalIgnoreCase))
                            continue;

                        string exeDir = Path.GetDirectoryName(exe);
                        if (exeDir == null)
                            continue;

                        string mql4 = Path.Combine(exeDir, "MQL4", "Experts");
                        string mql5 = Path.Combine(exeDir, "MQL5", "Experts");
                        if (Directory.Exists(mql4))
                            Add(TerminalType.MT4, exeDir, "Running terminal (portable/installation directory)", log);
                        if (Directory.Exists(mql5))
                            Add(TerminalType.MT5, exeDir, "Running terminal (portable/installation directory)", log);
                    }
                    catch
                    {
                        // Access to another process can fail without administrator rights. Ignore and continue.
                    }
                    finally
                    {
                        process.Dispose();
                    }
                }
            }
            catch (Exception ex)
            {
                log("Running-terminal scan warning: " + ex.Message);
            }
        }

        private void DiscoverRegistryInstallations(Action<string> log)
        {
            string[] uninstallRoots =
            {
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
            };

            foreach (RegistryHive hive in new[] { RegistryHive.CurrentUser, RegistryHive.LocalMachine })
            {
                foreach (string root in uninstallRoots)
                {
                    try
                    {
                        using (RegistryKey baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64))
                        using (RegistryKey uninstall = baseKey.OpenSubKey(root))
                        {
                            if (uninstall == null)
                                continue;
                            foreach (string subName in uninstall.GetSubKeyNames())
                            {
                                try
                                {
                                    using (RegistryKey sub = uninstall.OpenSubKey(subName))
                                    {
                                        string displayName = Convert.ToString(sub == null ? null : sub.GetValue("DisplayName"));
                                        string installLocation = Convert.ToString(sub == null ? null : sub.GetValue("InstallLocation"));
                                        if (!IsMetaTraderName(displayName) || string.IsNullOrWhiteSpace(installLocation))
                                            continue;

                                        TryDiscoverInstallationPath(installLocation, "Windows uninstall registry", log);
                                    }
                                }
                                catch
                                {
                                }
                            }
                        }
                    }
                    catch
                    {
                        // Registry view can fail on some systems; the alternate discovery sources still run.
                    }
                }
            }
        }

        private void DiscoverCommonProgramFiles(Action<string> log)
        {
            string[] roots =
            {
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)
            };

            foreach (string root in roots.Where(r => !string.IsNullOrWhiteSpace(r)).Distinct(StringComparer.OrdinalIgnoreCase))
            {
                SearchForTerminalExecutables(root, 4, log);
            }
        }

        private void SearchForTerminalExecutables(string root, int maxDepth, Action<string> log)
        {
            if (!Directory.Exists(root))
                return;

            try
            {
                SearchRecursive(root, 0, maxDepth, log);
            }
            catch (Exception ex)
            {
                log("Program-files scan warning: " + ex.Message);
            }
        }

        private void SearchRecursive(string directory, int depth, int maxDepth, Action<string> log)
        {
            if (depth > maxDepth)
                return;

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(directory, "terminal*.exe", SearchOption.TopDirectoryOnly);
            }
            catch
            {
                return;
            }

            foreach (string file in files)
            {
                string name = Path.GetFileName(file);
                if (!name.Equals("terminal.exe", StringComparison.OrdinalIgnoreCase) &&
                    !name.Equals("terminal64.exe", StringComparison.OrdinalIgnoreCase))
                    continue;

                string dir = Path.GetDirectoryName(file);
                if (dir == null)
                    continue;

                TryDiscoverInstallationPath(dir, "Filesystem executable scan", log);
            }

            if (depth == maxDepth)
                return;

            IEnumerable<string> directories;
            try
            {
                directories = Directory.EnumerateDirectories(directory);
            }
            catch
            {
                return;
            }

            foreach (string child in directories)
            {
                string leaf = Path.GetFileName(child);
                if (leaf.Equals("Windows", StringComparison.OrdinalIgnoreCase) ||
                    leaf.Equals("System Volume Information", StringComparison.OrdinalIgnoreCase))
                    continue;

                SearchRecursive(child, depth + 1, maxDepth, log);
            }
        }

        private void TryDiscoverInstallationPath(string path, string source, Action<string> log)
        {
            if (string.IsNullOrWhiteSpace(path))
                return;

            string full;
            try { full = Path.GetFullPath(path.Trim().Trim('"')); }
            catch { return; }

            string mql4 = Path.Combine(full, "MQL4", "Experts");
            string mql5 = Path.Combine(full, "MQL5", "Experts");
            if (Directory.Exists(mql4))
                Add(TerminalType.MT4, full, source, log);
            if (Directory.Exists(mql5))
                Add(TerminalType.MT5, full, source, log);
        }

        private void Add(TerminalType type, string path, string source, Action<string> log)
        {
            string normalized = NormalizePath(path);
            if (string.IsNullOrWhiteSpace(normalized))
                return;

            if (!terminals.ContainsKey(type + "|" + normalized))
            {
                terminals[type + "|" + normalized] = new TerminalInfo(type, normalized, source);
                log("Found " + type + ": " + normalized);
            }
        }

        private static bool IsMetaTraderName(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return false;
            string s = value.ToLowerInvariant();
            return s.Contains("metatrader") || s.Contains("mt4") || s.Contains("mt5") || s.Contains("metaquotes");
        }

        private static string NormalizePath(string value)
        {
            try
            {
                string p = Path.GetFullPath(value.Trim().Trim('"'));
                return p.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            }
            catch
            {
                return null;
            }
        }

        // ====================================================================
        // Wine multi-prefix discovery (2026 hardening). Wine/macOS and
        // Wine/Linux ONLY - never called on real Windows (see DiscoverAll's
        // IsWineEnvironment() gate above).
        //
        // On Wine, this Installer process runs inside exactly ONE
        // WINEPREFIX, with its own private drive_c - its own registry, its
        // own "Program Files", its own per-user AppData. A MetaTrader
        // installed in a DIFFERENT prefix (the extremely common case of
        // one prefix for MT4 and a separate one for MT5, or MetaQuotes'
        // own official per-build Mac installers) is therefore completely
        // invisible to DiscoverRegistryInstallations and
        // DiscoverCommonProgramFiles above, which only ever look at THIS
        // process's own environment and registry.
        //
        // Fix: reach every OTHER prefix's drive_c the same way
        // InstallerService.GetCommonLicensePath() already reaches the
        // shared license file - through Wine's own WINEHOMEDIR/"Z:" real-
        // host-path mapping, which exposes the genuine Unix home directory
        // to every prefix identically (see that method's comment for the
        // already-proven, already-shipping precedent this follows). Each
        // candidate prefix found this way gets scanned with the exact
        // same, already-existing methods used for the current prefix
        // (SearchForTerminalExecutables, DiscoverStandardDataDirectories) -
        // nothing about HOW a terminal is recognized changes, only WHERE
        // these methods are told to look.
        //
        // Coverage is deliberately best-effort, not exhaustive: it covers
        // MetaQuotes' own official Mac installer path (documented, and by
        // far the most common real-world case), the default Wine prefix
        // naming convention on Linux, and CrossOver/PlayOnMac's own
        // Mac-specific bottle layouts. A MetaTrader installed in a prefix
        // with a genuinely custom name/location that matches none of
        // these will still need its own Installer run inside that prefix,
        // exactly like today - this closes the common case, not every
        // conceivable one.
        // ====================================================================
        /// <summary>
        /// Every OTHER Wine prefix's drive_c root this real host is known to
        /// have, that actually exists right now - the set InstallerService
        /// also uses (see its InstallCoordinatorIntoOtherWinePrefixesAsync)
        /// to decide where else the Broker itself needs installing, so both
        /// "which prefixes get an EA copied in" and "which prefixes get
        /// their own Broker" always agree on the exact same list. Reached
        /// through Wine's own WINEHOMEDIR/"Z:" real-host-path mapping - see
        /// InstallerService.GetCommonLicensePath's identical, already-
        /// shipping precedent for why this reaches every prefix the same
        /// way. Wine/macOS and Wine/Linux ONLY - callers gate this behind
        /// MachineIdService.IsWineEnvironment().
        ///
        /// Deliberately best-effort, not exhaustive - see DiscoverWinePrefixes's
        /// own comment below for exactly which locations are covered and why.
        /// </summary>
        public List<string> GetExistingWinePrefixDriveCRoots(Action<string> log)
        {
            var existing = new List<string>();
            string home = Environment.GetEnvironmentVariable("HOME");
            if (string.IsNullOrWhiteSpace(home) || !home.StartsWith("/", StringComparison.Ordinal))
            {
                log("Wine prefix scan skipped: HOME is not set to a Unix path.");
                return existing;
            }
            string wineMappedHome = "Z:" + home.Replace('/', '\\');

            var candidatePrefixDriveCRoots = new List<string>();

            // MetaQuotes' own official Mac installer(s) - predictable,
            // documented path. Checked first: by far the most common real-
            // world case this is meant to close.
            candidatePrefixDriveCRoots.Add(Path.Combine(wineMappedHome,
                "Library", "Application Support", "net.metaquotes.wine.metatrader5", "drive_c"));
            candidatePrefixDriveCRoots.Add(Path.Combine(wineMappedHome,
                "Library", "Application Support", "net.metaquotes.wine.metatrader4", "drive_c"));

            // CrossOver (Mac) - one drive_c per named "bottle"; PlayOnMac -
            // one drive_c per prefix under its own wineprefix folder.
            // Mac-specific layouts, best-effort.
            AddBottleDriveCRoots(Path.Combine(wineMappedHome, "Library", "Application Support", "CrossOver", "Bottles"),
                candidatePrefixDriveCRoots, log);
            AddBottleDriveCRoots(Path.Combine(wineMappedHome, "Library", "PlayOnMac", "wineprefix"),
                candidatePrefixDriveCRoots, log);

            // Default/vanilla Wine prefixes (common on Linux, and some
            // Mac setups using plain Wine instead of the official
            // installer): "~/.wine" is the WINEPREFIX default, and some
            // users run a second one under a differently-named folder for
            // a different MetaTrader build - matching "~/.wine*" by name
            // catches ".wine", ".wine32", ".wine-mt5" and similar without
            // having to know every possible name in advance.
            try
            {
                foreach (string prefixDir in Directory.EnumerateDirectories(wineMappedHome, ".wine*"))
                {
                    candidatePrefixDriveCRoots.Add(Path.Combine(prefixDir, "drive_c"));
                }
            }
            catch (Exception ex)
            {
                log("Wine prefix scan warning (home directory): " + ex.Message);
            }

            foreach (string driveC in candidatePrefixDriveCRoots.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                if (Directory.Exists(driveC)) existing.Add(driveC);
            }
            return existing;
        }

        // ====================================================================
        // Wine multi-prefix discovery (2026 hardening). Wine/macOS and
        // Wine/Linux ONLY - never called on real Windows (see DiscoverAll's
        // IsWineEnvironment() gate above).
        //
        // On Wine, this Installer process runs inside exactly ONE
        // WINEPREFIX, with its own private drive_c - its own registry, its
        // own "Program Files", its own per-user AppData. A MetaTrader
        // installed in a DIFFERENT prefix (the extremely common case of
        // one prefix for MT4 and a separate one for MT5, or MetaQuotes'
        // own official per-build Mac installers) is therefore completely
        // invisible to DiscoverRegistryInstallations and
        // DiscoverCommonProgramFiles above, which only ever look at THIS
        // process's own environment and registry.
        //
        // Fix: reach every OTHER prefix's drive_c via
        // GetExistingWinePrefixDriveCRoots above, then scan each one with
        // the exact same, already-existing methods used for the current
        // prefix (SearchForTerminalExecutables, DiscoverStandardDataDirectories) -
        // nothing about HOW a terminal is recognized changes, only WHERE
        // these methods are told to look.
        // ====================================================================
        private void DiscoverWinePrefixes(Action<string> log)
        {
            foreach (string driveC in GetExistingWinePrefixDriveCRoots(log))
            {
                SearchForTerminalExecutables(Path.Combine(driveC, "Program Files"), 4, log);
                SearchForTerminalExecutables(Path.Combine(driveC, "Program Files (x86)"), 4, log);

                // Each Windows user profile inside THIS prefix's drive_c
                // may hold its own MetaQuotes\Terminal data directory
                // (the same per-user layout DiscoverStandardDataDirectories
                // already expects for the current prefix) - enumerate
                // every profile rather than assuming this process's own
                // Windows user name, since a differently-configured
                // prefix is not guaranteed to use the same one.
                string usersRoot = Path.Combine(driveC, "users");
                if (!Directory.Exists(usersRoot))
                    continue;
                try
                {
                    foreach (string userDir in Directory.EnumerateDirectories(usersRoot))
                    {
                        string metaQuotesTerminalRoot = Path.Combine(userDir, "AppData", "Roaming", "MetaQuotes", "Terminal");
                        DiscoverStandardDataDirectories(metaQuotesTerminalRoot, log);
                    }
                }
                catch (Exception ex)
                {
                    log("Wine prefix scan warning (" + usersRoot + "): " + ex.Message);
                }
            }
        }

        private static void AddBottleDriveCRoots(string bottlesRoot, List<string> outRoots, Action<string> log)
        {
            if (!Directory.Exists(bottlesRoot))
                return;
            try
            {
                foreach (string bottle in Directory.EnumerateDirectories(bottlesRoot))
                {
                    outRoots.Add(Path.Combine(bottle, "drive_c"));
                }
            }
            catch (Exception ex)
            {
                log("Wine prefix scan warning (" + bottlesRoot + "): " + ex.Message);
            }
        }
    }
}
