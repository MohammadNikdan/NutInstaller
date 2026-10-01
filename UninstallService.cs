using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.ServiceProcess;
using Microsoft.Win32;

namespace NutriculaInstaller
{
    /// <summary>
    /// Full removal of everything the Installer (in any mode - Free,
    /// Premium, or Transfer) may have put on this computer: the Windows
    /// Service (if that's what got installed on this machine), the
    /// user-level Broker and its HKCU Run-key / Scheduled Task auto-start
    /// registrations (if that's what it fell back to instead - see
    /// InstallerService.InstallCoordinatorAsync's own comment), the single
    /// Coordinator install directory under %ProgramFiles% that every mode
    /// shares (see InstallerService.GetCoordinatorInstallDir's own
    /// comment), the EA/DLL files copied into every detected MetaTrader
    /// terminal, the local device key and shared license files, and
    /// finally the "Apps & Features" registry entries this same Installer
    /// registers at the end of a successful install (see
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
            RemoveBroker(log);
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

                // Actually WAIT for the service to stop (rather than firing
                // "sc stop" and immediately moving on) - this used to be the
                // root cause of "Access to the path ...MachineId64.dll is
                // denied": sc.exe's stop command returns as soon as the
                // request is accepted, not once the underlying
                // NutriculaLicenseService.exe process has actually exited
                // and released the DLLs it had loaded (MachineId64.dll in
                // particular), so the very next step - deleting the
                // Program Files\Nutricula folder - could run while that
                // process (and its loaded DLL) was still shutting down.
                try
                {
                    using (var sc = new ServiceController("NutriculaLicenseService"))
                    {
                        sc.Refresh();
                        if (sc.Status != ServiceControllerStatus.Stopped)
                        {
                            sc.Stop();
                            sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(15));
                        }
                    }
                }
                catch
                {
                    // The service may already be stopping, refuse the stop
                    // command, or have gone away mid-call - the forced
                    // process wait/kill below and the sc.exe delete that
                    // follows are the real guarantees either way.
                }

                // Belt-and-suspenders beyond the SCM's own bookkeeping above:
                // give the actual process a short grace period to fully
                // unload, then force it if it is somehow still alive.
                WaitForProcessExit("NutriculaLicenseService", TimeSpan.FromSeconds(5));

                RunHidden("sc.exe", "delete NutriculaLicenseService", 15000);
                log("Removed the Nutricula License Service.");
            }
            catch (Exception ex)
            {
                outcome.Warnings.Add("Could not remove the Nutricula License Service: " + ex.Message);
            }
        }

        private static void WaitForProcessExit(string processName, TimeSpan timeout)
        {
            try
            {
                DateTime deadline = DateTime.UtcNow + timeout;
                while (DateTime.UtcNow < deadline)
                {
                    Process[] procs = Process.GetProcessesByName(processName);
                    if (procs.Length == 0) return;
                    foreach (Process p in procs)
                    {
                        try { p.WaitForExit(500); }
                        finally { p.Dispose(); }
                    }
                }

                // Still alive after the grace period - stop waiting politely.
                foreach (Process p in Process.GetProcessesByName(processName))
                {
                    try { p.Kill(); p.WaitForExit(2000); }
                    catch { /* best-effort */ }
                    finally { p.Dispose(); }
                }
            }
            catch { /* best-effort */ }
        }

        /// <summary>
        /// Stops the License Broker and removes its automatic-startup
        /// registrations - run unconditionally, regardless of install mode.
        /// 2026 hardening: the Broker is no longer a Free-specific thing: it
        /// is whatever Coordinator mechanism InstallerService fell back to
        /// when a real Windows Service couldn't be installed on THIS
        /// machine (Wine, or sc.exe failing for any other reason), so any
        /// of Free/Premium/Transfer could in principle have ended up with
        /// it running. Best-effort and harmless to run even when a Service
        /// was installed instead - there is simply nothing here to remove
        /// in that case.
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
            // Program Files\Nutricula is EVERY mode's root now (2026 path
            // consolidation - see InstallerService.GetCoordinatorInstallDir's
            // own comment: Free, Premium and Transfer all install here,
            // since every install mode is elevated via app.manifest). This
            // uninstaller is launched from the exact same .exe, with the
            // exact same manifest, so IsRunningAsAdministrator() below is
            // always true in practice - the check and its warning are kept
            // only as a defensive fallback, not a real per-mode branch.
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
            // HKLM is where every CURRENT install mode registers (2026 path
            // consolidation - see InstallerService.RegisterUninstaller's own
            // comment). IsRunningAsAdministrator() is always true here in
            // practice (same app.manifest as the installer itself), so this
            // is a defensive fallback, not a real branch.
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
                if (ServiceController.GetServices().Any(s =>
                    string.Equals(s.ServiceName, "NutriculaLicenseService", StringComparison.OrdinalIgnoreCase)))
                {
                    return true;
                }
            }
            catch { /* best-effort */ }

            try
            {
                if (Process.GetProcessesByName("NutriculaLicenseBroker").Length > 0) return true;
                if (Process.GetProcessesByName("NutriculaLicenseService").Length > 0) return true;
            }
            catch { /* best-effort */ }

            string localAppDataNutricula = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Nutricula");
            if (Directory.Exists(localAppDataNutricula)) return true;

            string programFilesNutricula = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Nutricula");
            if (Directory.Exists(programFilesNutricula)) return true;

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
                if (Registry.LocalMachine.OpenSubKey(
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
                // Best-effort - e.g. sc.exe/schtasks.exe missing on an
                // unusual system, or the target was already gone.
            }
        }
    }
}
