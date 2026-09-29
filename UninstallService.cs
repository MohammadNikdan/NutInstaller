using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.ServiceProcess;
using Microsoft.Win32;

namespace NutriculaInstaller
{
    /// <summary>
    /// Full removal of everything the Installer (in any mode - Free,
    /// Premium, or Transfer) may have put on this computer: the Windows
    /// Service, the user-level Broker (and its HKCU Run-key / Scheduled
    /// Task auto-start registrations), BOTH possible Coordinator install
    /// locations (see InstallerService.GetCoordinatorInstallDir's own
    /// comment for why Free and Premium/Transfer deliberately use two
    /// different roots - %LocalAppData% and %ProgramFiles% - and why both
    /// can exist at once after a Free -> Premium/Transfer upgrade), the
    /// EA/DLL files copied into every detected MetaTrader terminal, the
    /// local device key and shared license files, and finally the
    /// "Apps & Features" registry entries this same Installer registers at
    /// the end of a successful install (see
    /// InstallerService.RegisterUninstaller).
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
        /// Registry key name under both HKCU\...\Uninstall and
        /// HKLM\...\Uninstall - shared with InstallerService.RegisterUninstaller
        /// so both sides always agree on where the entry lives.
        /// </summary>
        public const string UninstallRegistryKeyName = "NutriculaExpert";

        public sealed class UninstallOutcome
        {
            public List<string> Log { get; } = new List<string>();
            public List<string> Warnings { get; } = new List<string>();

            /// <summary>
            /// True if something that needs Administrator rights (the
            /// Windows Service, or files under %ProgramFiles%) could not be
            /// removed because the CURRENT process is not elevated.
            /// </summary>
            public bool NeedsAdministratorForRemainder { get; set; }
        }

        /// <summary>
        /// Checked up front (before doing any work) so the caller can offer
        /// to relaunch elevated before starting, rather than the user only
        /// discovering partway through that some of it silently failed.
        /// </summary>
        public static bool WillNeedAdministrator()
        {
            if (IsRunningAsAdministrator()) return false;

            try
            {
                if (ServiceController.GetServices().Any(s =>
                    string.Equals(s.ServiceName, "NutriculaLicenseService", StringComparison.OrdinalIgnoreCase)))
                {
                    return true;
                }
            }
            catch
            {
                // If we can't even enumerate services, err on the side of
                // asking for elevation rather than silently under-cleaning.
                return true;
            }

            string programFilesNutricula = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Nutricula");
            return Directory.Exists(programFilesNutricula);
        }

        public static bool IsRunningAsAdministrator()
        {
            try
            {
                using (var identity = System.Security.Principal.WindowsIdentity.GetCurrent())
                {
                    var principal = new System.Security.Principal.WindowsPrincipal(identity);
                    return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
                }
            }
            catch
            {
                return false;
            }
        }

        public static UninstallOutcome PerformUninstall()
        {
            var outcome = new UninstallOutcome();
            Action<string> log = outcome.Log.Add;

            RemoveWindowsService(outcome, log);
            RemoveFreeBroker(log);
            RemoveCoordinatorDirectories(outcome, log);
            RemoveTerminalFiles(outcome, log);
            RemoveDeviceIdentityAndLicenseFiles(log);
            RemoveUninstallRegistryEntries(log);

            return outcome;
        }

        private static void RemoveWindowsService(UninstallOutcome outcome, Action<string> log)
        {
            try
            {
                bool serviceExists = ServiceController.GetServices().Any(s =>
                    string.Equals(s.ServiceName, "NutriculaLicenseService", StringComparison.OrdinalIgnoreCase));
                if (!serviceExists) return;

                if (!IsRunningAsAdministrator())
                {
                    outcome.NeedsAdministratorForRemainder = true;
                    outcome.Warnings.Add(
                        "The Nutricula License Service is still installed - restart this uninstaller " +
                        "as Administrator to remove it.");
                    return;
                }

                RunHidden("sc.exe", "stop NutriculaLicenseService", 15000);
                RunHidden("sc.exe", "delete NutriculaLicenseService", 15000);
                log("Removed the Nutricula License Service.");
            }
            catch (Exception ex)
            {
                outcome.Warnings.Add("Could not remove the Nutricula License Service: " + ex.Message);
            }
        }

        private static void RemoveFreeBroker(Action<string> log)
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
            // Free's root - always removable without elevation.
            string localAppDataNutricula = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Nutricula");
            DeleteDirectoryBestEffort(localAppDataNutricula, outcome, log);

            // Premium/Transfer's root - needs elevation.
            string programFilesNutricula = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Nutricula");
            if (Directory.Exists(programFilesNutricula))
            {
                if (IsRunningAsAdministrator())
                {
                    DeleteDirectoryBestEffort(programFilesNutricula, outcome, log);
                }
                else
                {
                    outcome.NeedsAdministratorForRemainder = true;
                    outcome.Warnings.Add(
                        "Files under Program Files\\Nutricula could not be removed - restart this " +
                        "uninstaller as Administrator to remove them.");
                }
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
            try
            {
                Registry.CurrentUser.DeleteSubKeyTree(
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" + UninstallRegistryKeyName,
                    throwOnMissingSubKey: false);
            }
            catch { /* best-effort */ }

            if (IsRunningAsAdministrator())
            {
                try
                {
                    Registry.LocalMachine.DeleteSubKeyTree(
                        "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" + UninstallRegistryKeyName,
                        throwOnMissingSubKey: false);
                }
                catch { /* best-effort */ }
            }

            log("Removed Nutricula from Apps & Features.");
        }

        private static void DeleteDirectoryBestEffort(string dir, UninstallOutcome outcome, Action<string> log)
        {
            try
            {
                if (Directory.Exists(dir))
                {
                    Directory.Delete(dir, recursive: true);
                    log("Removed " + dir);
                }
            }
            catch (Exception ex)
            {
                outcome.Warnings.Add("Could not fully remove " + dir + ": " + ex.Message);
            }
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
                // Best-effort - e.g. sc.exe/schtasks.exe missing on an
                // unusual system, or the target was already gone.
            }
        }
    }
}
