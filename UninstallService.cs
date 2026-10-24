using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using Microsoft.Win32;

namespace NutriculaInstaller
{
    /// <summary>
    /// Full removal of everything the Installer (in any mode - Free,
    /// Premium, or Transfer) may have put on this computer: the user-session
    /// License Broker and its HKCU Run-key / Scheduled Task auto-start
    /// registrations (the Broker is the sole Coordinator host - the Windows
    /// Service was removed in 2026), the single per-user Coordinator install
    /// directory under %LocalAppData% that every mode shares (see
    /// InstallerService.GetCoordinatorInstallDir's own comment), the EA/DLL
    /// files copied into every detected MetaTrader terminal, the local device
    /// key and shared license files, and finally the per-user "Apps &
    /// Features" registry entry (HKCU) this same Installer registers at the
    /// end of a successful install (see InstallerService.RegisterUninstaller).
    ///
    /// No Administrator rights are needed for any of this - the whole product
    /// is a per-user, non-elevated install (nothing under %ProgramFiles%, no
    /// HKLM, no Windows Service).
    ///
    /// Entirely synchronous and self-contained on purpose: this runs from
    /// Program.Main when launched with a single "/uninstall" argument (see
    /// Program.cs), which is a short one-shot operation with no need for
    /// InstallerService's async/progress-reporting machinery that exists
    /// for the much longer, network-involving install flow.
    ///
    /// Every step here is best-effort: one file being locked or one
    /// registry key being missing must never stop the rest of the cleanup
    /// from running, so failures are collected into Warnings rather than
    /// thrown.
    /// </summary>
    internal static class UninstallService
    {
        /// <summary>
        /// Registry key name under HKCU\...\Uninstall - shared with
        /// InstallerService.RegisterUninstaller so both sides always agree on
        /// where the per-user "Apps & Features" entry lives.
        /// </summary>
        public const string UninstallRegistryKeyName = "NutriculaExpert";

        public sealed class UninstallOutcome
        {
            public List<string> Log { get; } = new List<string>();
            public List<string> Warnings { get; } = new List<string>();

            /// <summary>
            /// Set when a Nutricula root directory contained this process's
            /// own running .exe (i.e. this is the "Uninstall.exe" copy
            /// launched from inside the install directory - see
            /// DeleteDirectoryBestEffort). Everything else in that directory
            /// has already been deleted; only this one locked file plus the
            /// now near-empty directory remain, and only because Windows
            /// will not let a running process delete its own image file.
            /// The caller finishes the job with ScheduleSelfDelete once this
            /// process is about to exit.
            /// </summary>
            public string PendingSelfDeleteDirectory { get; set; }
        }

        public static UninstallOutcome PerformUninstall()
        {
            var outcome = new UninstallOutcome();
            Action<string> log = outcome.Log.Add;

            // 2026 Wine hardening: signal every OTHER Wine prefix's own
            // Broker to exit BEFORE touching any directory - see
            // SignalOtherWineBrokersToExit's own comment for why this is
            // needed at all (Process.GetProcessesByName, used by
            // RemoveBroker right below for THIS prefix's own Broker,
            // cannot see a Broker running under a different prefix's
            // separate wineserver). No-op, no filesystem access at all, on
            // real Windows.
            SignalOtherWineBrokersToExit(log);

            RemoveBroker(log);
            RemoveCoordinatorDirectories(outcome, log);
            RemoveCoordinatorDirectoriesFromOtherWinePrefixes(outcome, log);
            RemoveTerminalFiles(outcome, log);
            RemoveDeviceIdentityAndLicenseFiles(log);
            RemoveUninstallRegistryEntries(log);

            // Always last: never leave this signal file lying around, or a
            // future reinstall's freshly-launched Broker would see a stale
            // "please exit" the moment it starts (harmless - the DLL would
            // just relaunch it again - but pointless and worth cleaning up).
            RemoveWineUninstallSignalFile(log);

            return outcome;
        }

        /// <summary>
        /// Stops the License Broker (the sole Coordinator host) and removes
        /// its automatic-startup registrations (HKCU Run key + per-user
        /// Scheduled Task watchdog). Best-effort and needs no elevation -
        /// everything it touches is per-user.
        /// </summary>
        private static void RemoveBroker(Action<string> log)
        {
            try
            {
                foreach (Process proc in Process.GetProcessesByName("NutriculaLicenseBroker"))
                {
                    try { proc.Kill(); proc.WaitForExit(5000); }
                    catch { /* best-effort */ }
                }
            }
            catch { /* best-effort */ }

            try
            {
                using (RegistryKey runKey = Registry.CurrentUser.OpenSubKey(
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Run", writable: true))
                {
                    runKey?.DeleteValue("NutriculaLicenseBroker", throwOnMissingValue: false);
                }
            }
            catch { /* best-effort */ }

            try { RunHidden("schtasks.exe", "/Delete /F /TN \"NutriculaLicenseBrokerWatchdog\"", 10000); }
            catch { /* best-effort - harmless if the task was never registered */ }

            log("Stopped the License Broker and removed its automatic-startup registrations.");
        }

        /// <summary>
        /// 2026 Wine hardening: writes a small sentinel file into the SAME
        /// shared, host-level directory every Wine prefix already reads and
        /// writes the license file from (see
        /// InstallerService.GetCommonLicensePath's own Wine branch, and
        /// CoordinatorCore.cpp's GetWineUninstallSignalFilePathW on the
        /// native side, which derives the exact same path from the exact
        /// same license path so both sides always agree on it without
        /// either one hard-coding it independently).
        ///
        /// WHY this is needed at all: every Wine prefix runs its own,
        /// separate wineserver, so a Broker launched inside a DIFFERENT
        /// prefix is not visible to Process.GetProcessesByName from this
        /// one, from any prefix - RemoveBroker's direct Kill() only ever
        /// reaches THIS prefix's own Broker. Left alone, every other
        /// prefix's Broker would keep running and keep its own Broker.exe
        /// locked, so RemoveCoordinatorDirectoriesFromOtherWinePrefixes
        /// could delete everything else in that prefix's install folder
        /// but not the running .exe itself.
        ///
        /// Every Broker on this host, in every prefix, polls for this exact
        /// file (CoordinatorCore.cpp's WorkerLoop, via
        /// WineUninstallRequested/WineAwareWait) and exits on its own,
        /// typically within a few seconds - purely through the filesystem,
        /// no cross-process Windows API involved at all, so the same
        /// per-prefix wineserver wall never comes into play.
        ///
        /// The short sleep afterward is a courtesy, not a guarantee - a
        /// Broker mid-way through a long operation may take a little
        /// longer to notice. That is exactly why every deletion downstream
        /// already treats a locked file as a best-effort warning, never a
        /// fatal error: this makes the common case fast and clean without
        /// making the uncommon case any worse than it already was.
        ///
        /// No-op (and no filesystem access at all) on real Windows, where
        /// there is only ever one prefix and RemoveBroker's direct Kill
        /// already handles it immediately.
        /// </summary>
        private static void SignalOtherWineBrokersToExit(Action<string> log)
        {
            try
            {
                if (!MachineIdService.IsWineEnvironment()) return;

                string signalPath = GetWineUninstallSignalPath();
                if (string.IsNullOrEmpty(signalPath)) return;

                File.WriteAllText(signalPath, "uninstall requested " + DateTime.UtcNow.ToString("O"));
                log("Signaled every Wine prefix's License Broker to exit.");

                System.Threading.Thread.Sleep(4000);
            }
            catch (Exception ex)
            {
                log("Could not write the Wine cross-prefix uninstall signal (best-effort, not fatal): " + ex.Message);
            }
        }

        /// <summary>
        /// Deletes the sentinel SignalOtherWineBrokersToExit writes - always
        /// called last in PerformUninstall, so it never lingers into a
        /// future reinstall. No-op on real Windows.
        /// </summary>
        private static void RemoveWineUninstallSignalFile(Action<string> log)
        {
            try
            {
                if (!MachineIdService.IsWineEnvironment()) return;
                string signalPath = GetWineUninstallSignalPath();
                if (string.IsNullOrEmpty(signalPath)) return;
                DeleteFileBestEffort(signalPath, log);
            }
            catch
            {
                // Best-effort - see RemoveWineUninstallSignalFile's own
                // summary for why leaving this behind in a truly unusual
                // failure case is not fatal either way.
            }
        }

        /// <summary>
        /// Same path CoordinatorCore.cpp's GetWineUninstallSignalFilePathW
        /// computes natively (license path + ".uninstall_requested") -
        /// reusing InstallerService.GetCommonLicensePath keeps both sides
        /// derived from the exact same single source instead of two
        /// independent hard-coded conventions that could ever drift apart.
        /// </summary>
        private static string GetWineUninstallSignalPath()
        {
            string licensePath = new InstallerService().GetCommonLicensePath();
            if (string.IsNullOrEmpty(licensePath)) return null;
            return licensePath + ".uninstall_requested";
        }

        private static void RemoveCoordinatorDirectories(UninstallOutcome outcome, Action<string> log)
        {
            // %LocalAppData%\Nutricula is EVERY mode's root (see
            // InstallerService.GetCoordinatorInstallDir's own comment: Free,
            // Premium and Transfer all install the user-session Broker here,
            // per-user, no elevation). It holds the Broker, its MachineId
            // dependency DLL, the signed manifest, and the Uninstall.exe copy.
            string localAppDataNutricula = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Nutricula");
            if (Directory.Exists(localAppDataNutricula))
            {
                DeleteDirectoryBestEffort(localAppDataNutricula, outcome, log);
            }
        }

        /// <summary>
        /// 2026 Wine hardening: removes the per-prefix Broker install
        /// InstallerService.InstallCoordinatorIntoOtherWinePrefixesAsync
        /// puts into every OTHER Wine prefix's own
        /// "%LocalAppData%\Nutricula\" equivalent - without this, running
        /// "Uninstall" from just ONE prefix (the normal way, via Apps &
        /// Features or this same /uninstall flow) would clean up this
        /// prefix and every discovered terminal's EA/DLL files (see
        /// RemoveTerminalFiles, which already reaches every prefix the
        /// same way the Installer does) but leave a stale, no-longer-
        /// matched Broker + manifest + MachineId DLL sitting in each other
        /// prefix. Reached the same way the Installer reaches them -
        /// TerminalDiscoveryService.GetExistingWinePrefixDriveCRoots, so
        /// both sides always agree on exactly which prefixes those are.
        ///
        /// CORRECTION (2026, found on review): an earlier version of this
        /// comment claimed RemoveBroker's Process.GetProcessesByName
        /// already catches a Broker running in another prefix "for free",
        /// by image name alone. That is not actually true - each Wine
        /// prefix runs its own, separate wineserver, so a process started
        /// under a DIFFERENT WINEPREFIX is not visible to that call from
        /// this one, regardless of name. PerformUninstall now calls
        /// SignalOtherWineBrokersToExit (see its own comment) before this
        /// method runs, specifically to close that gap through a shared
        /// file instead of a cross-process Windows API that cannot reach
        /// across prefixes at all.
        /// </summary>
        private static void RemoveCoordinatorDirectoriesFromOtherWinePrefixes(UninstallOutcome outcome, Action<string> log)
        {
            try
            {
                if (!MachineIdService.IsWineEnvironment()) return;

                var discovery = new TerminalDiscoveryService();
                foreach (string driveC in discovery.GetExistingWinePrefixDriveCRoots(log))
                {
                    string usersRoot = Path.Combine(driveC, "users");
                    if (!Directory.Exists(usersRoot)) continue;

                    IEnumerable<string> userDirs;
                    try { userDirs = Directory.EnumerateDirectories(usersRoot); }
                    catch (Exception ex)
                    {
                        outcome.Warnings.Add("Could not scan " + usersRoot + " for another Wine prefix's Coordinator: " + ex.Message);
                        continue;
                    }

                    foreach (string userDir in userDirs)
                    {
                        string nutriculaRoot = Path.Combine(userDir, "AppData", "Local", "Nutricula");
                        if (Directory.Exists(nutriculaRoot))
                        {
                            DeleteDirectoryBestEffort(nutriculaRoot, outcome, log);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                outcome.Warnings.Add("Could not clean up the License Coordinator in other Wine prefixes: " + ex.Message);
            }
        }

        private static void RemoveTerminalFiles(UninstallOutcome outcome, Action<string> log)
        {
            try
            {
                var discovery = new TerminalDiscoveryService();
                List<TerminalInfo> terminals = discovery.DiscoverAll(log);
                string[] libraryFiles =
                {
                    "NutriculaLicenseCheck32.dll", "NutriculaLicenseCheck64.dll",
                    "MachineId32.dll", "MachineId64.dll"
                };

                foreach (TerminalInfo terminal in terminals)
                {
                    // The fixed-name deletions below only cover the paths the
                    // Installer itself writes to. An EA copied into a
                    // subfolder, or renamed, or a leftover from an older
                    // build, would survive them and keep sitting in the
                    // customer's terminal after an uninstall. This finds
                    // every recognisable Nutricula file wherever it is and
                    // whatever it is called - see NutriculaSweeper.cs - and
                    // runs first so the named deletions afterwards are just a
                    // backstop for anything it could not identify.
                    NutriculaSweeper.Sweep(terminal, log);

                    foreach (string fileName in libraryFiles)
                    {
                        DeleteFileBestEffort(Path.Combine(terminal.LibrariesPath, fileName), log);
                    }
                    string eaFile = terminal.Type == TerminalType.MT4 ? "Nutricula.ex4" : "Nutricula.ex5";
                    DeleteFileBestEffort(Path.Combine(terminal.ExpertsPath, eaFile), log);
                    if (terminal.Type == TerminalType.MT4)
                    {
                        DeleteFileBestEffort(Path.Combine(terminal.TerminalPath, "MQL4", "Files", "Outfit-Regular.ttf"), log);
                    }
                }
                log("Removed Nutricula files from " + terminals.Count + " MetaTrader terminal(s).");
            }
            catch (Exception ex)
            {
                outcome.Warnings.Add("Could not clean up MetaTrader terminal files: " + ex.Message);
            }
        }

        private static void RemoveDeviceIdentityAndLicenseFiles(Action<string> log)
        {
            // Matches NutriculaMachineId.cpp's GetDeviceKeyPath for the
            // non-Wine case: %APPDATA%\Nutricula\DeviceKey.bin. There is no
            // exported native function that returns this raw path (only
            // derived values such as the public key or its hash), so the
            // path convention is duplicated here deliberately - it is a
            // simple, stable convention, not something expected to change
            // without a matching change on the native side too.
            DeleteFileBestEffort(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Nutricula", "DeviceKey.bin"), log);

            // Wine device key: under Wine, NutriculaMachineId.cpp's
            // GetDeviceKeyPath stores the key at $HOME/.nutricula/DeviceKey.bin
            // (host-level, not per-WINEPREFIX - same place the Wine license
            // file lives), reached from Windows-side code via the Z:\ mapping.
            // The %APPDATA% delete above does NOT cover this, so a Wine
            // uninstall would otherwise leave the device key behind. Mirror
            // InstallerService.GetCommonLicensePath's own Wine branch.
            try
            {
                if (MachineIdService.IsWineEnvironment())
                {
                    string home = Environment.GetEnvironmentVariable("HOME");
                    if (!string.IsNullOrWhiteSpace(home) && home.StartsWith("/", StringComparison.Ordinal))
                    {
                        string wineMappedHome = "Z:" + home.Replace('/', '\\');
                        DeleteFileBestEffort(Path.Combine(wineMappedHome, ".nutricula", "DeviceKey.bin"), log);
                    }
                }
            }
            catch
            {
                // Best-effort - an unusual Wine setup with no readable $HOME
                // is not fatal to the rest of removal.
            }

            try
            {
                string licensePath = new InstallerService().GetCommonLicensePath();
                DeleteFileBestEffort(licensePath, log);
            }
            catch
            {
                // GetCommonLicensePath can throw on an unusual Wine setup
                // with no readable $HOME - not fatal to the rest of removal.
            }
        }

        private static void RemoveUninstallRegistryEntries(Action<string> log)
        {
            // HKCU is where the install registers its per-user "Apps &
            // Features" entry (see InstallerService.RegisterUninstaller's own
            // comment) - no elevation needed to remove it.
            try
            {
                Registry.CurrentUser.DeleteSubKeyTree(
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" + UninstallRegistryKeyName,
                    throwOnMissingSubKey: false);
            }
            catch { /* best-effort */ }

            log("Removed Nutricula from Apps & Features.");
        }

        private static void DeleteDirectoryBestEffort(string dir, UninstallOutcome outcome, Action<string> log)
        {
            try
            {
                if (!Directory.Exists(dir)) return;

                // If this directory contains the .exe THIS PROCESS IS
                // CURRENTLY RUNNING FROM (true whenever uninstall was
                // launched the normal way - via Apps & Features, which runs
                // "<install dir>\Uninstall.exe /uninstall" directly), a
                // plain recursive delete fails on exactly that one file:
                // Windows will not let a running process delete its own
                // locked image file ("Access to the path 'Uninstall.exe' is
                // denied" - the exact error this is fixing). Delete
                // everything else now; the file itself and the directory
                // get cleaned up by ScheduleSelfDelete after this process
                // has exited and released the lock.
                string runningExe = Assembly.GetExecutingAssembly().Location;
                string dirWithSeparator = dir.TrimEnd('\\', '/') + Path.DirectorySeparatorChar;
                bool containsSelf = !string.IsNullOrEmpty(runningExe) &&
                    runningExe.StartsWith(dirWithSeparator, StringComparison.OrdinalIgnoreCase);

                if (!containsSelf)
                {
                    Directory.Delete(dir, recursive: true);
                    log("Removed " + dir);
                    return;
                }

                foreach (string entry in Directory.GetFileSystemEntries(dir))
                {
                    if (string.Equals(entry, runningExe, StringComparison.OrdinalIgnoreCase)) continue;
                    try
                    {
                        if (Directory.Exists(entry)) Directory.Delete(entry, recursive: true);
                        else File.Delete(entry);
                    }
                    catch (Exception ex)
                    {
                        outcome.Warnings.Add("Could not fully remove " + entry + ": " + ex.Message);
                    }
                }

                outcome.PendingSelfDeleteDirectory = dir;
                log("Removed " + dir + " (final cleanup finishes automatically once this window closes).");
            }
            catch (Exception ex)
            {
                outcome.Warnings.Add("Could not fully remove " + dir + ": " + ex.Message);
            }
        }

        /// <summary>
        /// Deletes the uninstaller's own running .exe plus the directory
        /// that held it, AFTER this process has fully exited. Windows will
        /// not delete a currently-running .exe's locked image file - the
        /// standard, dependency-free fix (no helper .exe needed) is to hand
        /// the final deletion off to a short cmd.exe script launched
        /// detached from this process, with a short retrying delay so it
        /// only proceeds once the OS has actually released the file.
        ///
        /// Call this once, right before the process that performed the
        /// uninstall is about to exit - see Program.cs's uninstall flow.
        /// Pass UninstallOutcome.PendingSelfDeleteDirectory; a null/empty
        /// value (the common case - the installer wasn't launched from the
        /// install directory itself) means there is nothing to do here.
        /// </summary>
        public static void ScheduleSelfDelete(string directory)
        {
            if (string.IsNullOrEmpty(directory)) return;

            try
            {
                string exePath = Path.Combine(directory, "Uninstall.exe");
                string cleanDir = directory.TrimEnd('\\', '/');

                string script =
                    "@echo off\r\n" +
                    "set count=0\r\n" +
                    ":retry\r\n" +
                    "set /a count+=1\r\n" +
                    "del /f /q \"" + exePath + "\" >nul 2>nul\r\n" +
                    "if exist \"" + exePath + "\" if %count% LSS 10 (\r\n" +
                    "  ping -n 2 127.0.0.1 >nul\r\n" +
                    "  goto retry\r\n" +
                    ")\r\n" +
                    "rmdir /s /q \"" + cleanDir + "\" >nul 2>nul\r\n" +
                    "del /f /q \"%~f0\"\r\n";

                string scriptPath = Path.Combine(
                    Path.GetTempPath(), "NutriculaUninstallCleanup_" + Guid.NewGuid().ToString("N") + ".cmd");
                AtomicFile.WriteAllText(scriptPath, script);

                Process.Start(new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = "/c \"" + scriptPath + "\"",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden
                });
            }
            catch
            {
                // Best-effort - worst case, Uninstall.exe and an otherwise-
                // empty folder are left behind for manual deletion; every
                // part of the removal that actually matters (service,
                // broker, DLLs, EA files, registry) is already done by the
                // time this runs.
            }
        }

        /// <summary>
        /// Cheap, read-only check for whether Nutricula has any footprint
        /// left on this computer at all - used by MainForm to decide
        /// whether to show its "Uninstall Nutricula" button. Deliberately
        /// broad: a false positive just means the button is shown when, in
        /// the worst case, only a harmless leftover registry key remains to
        /// remove - never a real problem. A false NEGATIVE (genuine
        /// leftovers with no way to reach them from here) is the actual
        /// mistake this guards against, so every install surface this
        /// Installer itself can create is checked.
        /// </summary>
        public static bool AnyTraceFound()
        {
            try
            {
                if (Process.GetProcessesByName("NutriculaLicenseBroker").Length > 0) return true;
            }
            catch { /* best-effort */ }

            string localAppDataNutricula = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Nutricula");
            if (Directory.Exists(localAppDataNutricula)) return true;

            try
            {
                if (Registry.CurrentUser.OpenSubKey(
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" + UninstallRegistryKeyName) != null)
                {
                    return true;
                }
            }
            catch { /* best-effort */ }

            try
            {
                var discovery = new TerminalDiscoveryService();
                List<TerminalInfo> terminals = discovery.DiscoverAll(delegate { });
                string[] libraryFiles =
                {
                    "NutriculaLicenseCheck32.dll", "NutriculaLicenseCheck64.dll",
                    "MachineId32.dll", "MachineId64.dll"
                };
                foreach (TerminalInfo terminal in terminals)
                {
                    foreach (string fileName in libraryFiles)
                    {
                        if (File.Exists(Path.Combine(terminal.LibrariesPath, fileName))) return true;
                    }
                    string eaFile = terminal.Type == TerminalType.MT4 ? "Nutricula.ex4" : "Nutricula.ex5";
                    if (File.Exists(Path.Combine(terminal.ExpertsPath, eaFile))) return true;
                }
            }
            catch { /* best-effort */ }

            return false;
        }

        private static void DeleteFileBestEffort(string path, Action<string> log)
        {
            try
            {
                if (File.Exists(path))
                {
                    File.Delete(path);
                    log("Removed " + path);
                }
            }
            catch
            {
                // Best-effort - a file still locked by a running process
                // isn't fatal to the rest of the uninstall.
            }
        }

        private static void RunHidden(string fileName, string arguments, int timeoutMs)
        {
            try
            {
                var startInfo = new ProcessStartInfo
                {
                    FileName = fileName,
                    Arguments = arguments,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                };
                using (Process p = Process.Start(startInfo))
                {
                    p?.WaitForExit(timeoutMs);
                }
            }
            catch
            {
                // Best-effort - e.g. schtasks.exe missing on an unusual
                // system, or the target was already gone.
            }
        }
    }
}
