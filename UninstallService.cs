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

            RemoveBroker(log);
            RemoveCoordinatorDirectories(outcome, log);
            RemoveTerminalFiles(outcome, log);
            RemoveDeviceIdentityAndLicenseFiles(log);
            RemoveUninstallRegistryEntries(log);

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
                    foreach (string fileName in libraryFiles)
                    {
                        DeleteFileBestEffort(Path.Combine(terminal.LibrariesPath, fileName), log);
                    }
                    string eaFile = terminal.Type == TerminalType.MT4 ? "Nutricula.ex4" : "Nutricula.ex5";
                    DeleteFileBestEffort(Path.Combine(terminal.ExpertsPath, eaFile), log);
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
                File.WriteAllText(scriptPath, script);

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
