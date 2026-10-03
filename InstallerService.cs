using System;
using Microsoft.Win32;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace NutriculaInstaller
{
    internal sealed class InstallerService
    {
        // Server endpoints are now sourced from Config\AppConfig.txt (edit-and-
        // rebuild), not hardcoded here. Kept as these same names so every
        // existing call site (e.g. RequestLicenseAsync's baseUrl) is unchanged.
        public static string PremiumUrl => AppConfig.SignupUrl;
        public static string TransferUrl => AppConfig.TransferUrl;
        private const string LicenseFileName = "NutriculaLicense.txt";
        private readonly TerminalDiscoveryService discovery = new TerminalDiscoveryService();

        public string GetCommonLicensePath()
        {
            /* On Wine/macOS the license is deliberately host-level, not per WINEPREFIX. */
            if (MachineIdService.IsWineEnvironment())
            {
                string home = Environment.GetEnvironmentVariable("HOME");
                if (!string.IsNullOrWhiteSpace(home) && home.StartsWith("/", StringComparison.Ordinal))
                {
                    string wineMappedHome = "Z:" + home.Replace('/', '\\');
                    string hostDirectory = Path.Combine(wineMappedHome, ".nutricula");
                    Directory.CreateDirectory(hostDirectory);
                    return Path.Combine(hostDirectory, LicenseFileName);
                }
            }

            string roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            return Path.Combine(roaming, "MetaQuotes", "Terminal", "Common", "Files", LicenseFileName);
        }

        public List<TerminalInfo> DiscoverTerminals(Action<string> log)
        {
            return discovery.DiscoverAll(log);
        }

        /// <summary>
        /// Shows a confirmation dialog and returns the user's choice.
        /// Parameters: (message body, "yes/proceed" button text, "no/cancel"
        /// button text) -> true if the user chose to proceed. Supplied by
        /// MainForm - InstallerService itself has no UI. Used in two
        /// situations (see RunAsync): the mandatory Linux/VPS warning
        /// (always shown, before any network call), and the physical
        /// Windows machine_requires_confirmation fallback (shown only if
        /// the server reports the primary machine_id is already taken by
        /// a different active license).
        /// </summary>
        public async Task<InstallResult> RunAsync(
            InstallMode mode,
            string email,
            string purchaseKey,
            string transferKey,
            CancellationToken token,
            IProgress<ProgressUpdate> progress,
            Action<string> log,
            Func<string, string, string, Task<bool>> confirmAsync)
        {
            InstallResult result = new InstallResult();

            List<TerminalInfo> terminals = await Task.Run(
                () => DiscoverTerminals(log)
            ).ConfigureAwait(true);

            result.Mt4Count = terminals.Count(t => t.Type == TerminalType.MT4);
            result.Mt5Count = terminals.Count(t => t.Type == TerminalType.MT5);

            if (terminals.Count == 0)
            {
                result.Errors.Add("No MetaTrader 4 or MetaTrader 5 terminal was found on this computer.");
                result.FinalMessage = Messages.NoTerminalFound;
                result.FilesInstalled = false;
                result.ServerRequestFinished = mode == InstallMode.Free;
                result.LicenseFileOperationFinished = mode == InstallMode.Free;
                result.LicenseSucceeded = mode == InstallMode.Free;
                result.OverallSuccess = false;
                return result;
            }

            if (mode == InstallMode.Free)
            {
                Task<FileInstallOutcome> freeInstallTask = InstallFilesAsync(mode, terminals, token, progress, log);

                /* Device key creation is a REQUIRED step for a Free install
                   to report success - the free-tier statistics table
                   identifies a computer by machine_id and/or
                   device_key_hash, and without at least the device key,
                   this install could never be recognized in a later
                   free_checkin (and if machine_id also can't be produced
                   on this particular system, the device key becomes the
                   ONLY identifier available at all). */
                Task<bool> freeIdentityTask = TryEnsureDeviceIdentityAsync(log);

                await Task.WhenAll(freeInstallTask, freeIdentityTask).ConfigureAwait(true);
                FileInstallOutcome freeOutcome = freeInstallTask.Result;
                bool deviceIdentityOk = freeIdentityTask.Result;
                bool freeSucceeded = freeOutcome.AllSucceeded && deviceIdentityOk;

                result.FilesInstalled = freeOutcome.AllSucceeded;
                if (freeOutcome.AllSucceeded) RegisterUninstaller(log);
                result.ServerRequestFinished = true;
                result.LicenseFileOperationFinished = true;
                result.LicenseSucceeded = freeSucceeded;
                result.OverallSuccess = freeSucceeded;
                string freeBaseMessage = freeSucceeded
                    ? Messages.FreeSuccess
                    : (!freeOutcome.AllSucceeded
                        ? Messages.ForFileFailure(freeOutcome.FailureKind)
                        : Messages.FreeDeviceIdentityFailure);
                // See FileInstallOutcome.CoordinatorWarning / TerminalWarning -
                // both used to be swallowed into a log line nobody ever saw.
                if (freeOutcome.CoordinatorWarning != null) freeBaseMessage += "\n\n" + freeOutcome.CoordinatorWarning;
                if (freeOutcome.TerminalWarning != null) freeBaseMessage += "\n\n" + freeOutcome.TerminalWarning;
                result.FinalMessage = freeBaseMessage;
                return result;
            }

            /* 2026 hardening - platform-aware identity warning. Determined
               via a throwaway machine_id generation purely to read
               platform_profile (GenerateComputerId/WithGuid are
               idempotent - this does not create or change anything, it
               just needs to run once before we know which platform we're
               on). For Linux and VPS (device_type=windows_vm), the
               warning is UNCONDITIONAL and shown BEFORE any network call
               at all - unlike physical Windows, these platforms have no
               fallback identity to offer, so there's no point contacting
               the server first only to reject afterward; the user must
               accept the "OS change loses this license" trade-off up
               front, or the whole operation is cancelled locally with no
               purchase_key/transfer_key ever consumed. Mac never shows
               this warning at all - its hardware-level identity signals
               (IOPlatformUUID/Serial) are stable across a macOS reinstall,
               so there is nothing to warn about. */
            string earlyPlatformProfile;
            try
            {
                MachineIdService.GenerateComputerId();
                earlyPlatformProfile = MachineIdService.GetLastPlatformProfile();
            }
            catch (Exception)
            {
                earlyPlatformProfile = string.Empty;
            }

            bool isLinuxOrVps = earlyPlatformProfile == "LINUX_WINE" || earlyPlatformProfile == "WINDOWS_VM";
            if (mode != InstallMode.Free && isLinuxOrVps)
            {
                bool platformIsVps = earlyPlatformProfile == "WINDOWS_VM";
                string warningMessage = mode == InstallMode.Premium
                    ? (platformIsVps ? Messages.VpsIdentityWarningSignup : Messages.LinuxIdentityWarningSignup)
                    : (platformIsVps ? Messages.VpsIdentityWarningTransfer : Messages.LinuxIdentityWarningTransfer);
                string yesButton = mode == InstallMode.Premium ? Messages.IdentityWarningYesSignup : Messages.IdentityWarningYesTransfer;
                string noButton = mode == InstallMode.Premium ? Messages.IdentityWarningNoSignup : Messages.IdentityWarningNoTransfer;

                bool proceed = confirmAsync == null || await confirmAsync(warningMessage, yesButton, noButton).ConfigureAwait(true);
                if (!proceed)
                {
                    result.FilesInstalled = false;
                    result.ServerRequestFinished = false;
                    result.LicenseFileOperationFinished = false;
                    result.LicenseSucceeded = false;
                    result.OverallSuccess = false;
                    result.FinalMessage = mode == InstallMode.Premium
                        ? Messages.SignupCancelledByUser
                        : Messages.TransferCancelledByUser;
                    return result;
                }
            }

            Task<FileInstallOutcome> installTask = InstallFilesAsync(mode, terminals, token, progress, log);
            Task<ServerResult> serverTask = RequestLicenseAsync(mode, email, purchaseKey, transferKey, token, log);

            FileInstallOutcome fileOutcome = new FileInstallOutcome(false, LocalFileFailureKind.Unknown);
            ServerResult serverResult = null;

            try
            {
                await Task.WhenAll(installTask, serverTask).ConfigureAwait(true);
                fileOutcome = installTask.Result;
                serverResult = serverTask.Result;
            }
            catch (Exception)
            {
                log("An internal error occurred during installation.");
                if (installTask.Status == TaskStatus.RanToCompletion) fileOutcome = installTask.Result;
                if (serverTask.Status == TaskStatus.RanToCompletion) serverResult = serverTask.Result;
            }

            /* 2026 hardening - physical Windows machine_requires_confirmation
               fallback. Only ever returned for device_type=windows physical
               (see nutricula_computer_based_signup.php's own comment) - the
               primary (no-GUID) machine_id is already tied to a different
               active license, but the secondary (WithGuid) variant is free.
               Files are already installed at this point (installTask ran
               concurrently above) - only the server request itself needs
               retrying, now with machine_id_alt_confirmed=1 so the server
               skips straight to the secondary variant instead of
               re-evaluating the primary one again. */
            if (serverResult != null && serverResult.Completed && serverResult.ServerReturnedNo &&
                serverResult.RejectReason == "machine_requires_confirmation")
            {
                string warningMessage = mode == InstallMode.Premium
                    ? Messages.WindowsIdentityWarningSignup
                    : Messages.WindowsIdentityWarningTransfer;
                string yesButton = mode == InstallMode.Premium ? Messages.IdentityWarningYesSignup : Messages.IdentityWarningYesTransfer;
                string noButton = mode == InstallMode.Premium ? Messages.IdentityWarningNoSignup : Messages.IdentityWarningNoTransfer;

                bool proceed = confirmAsync != null && await confirmAsync(warningMessage, yesButton, noButton).ConfigureAwait(true);
                if (proceed)
                {
                    log("Retrying with an alternate device identifier...");
                    try
                    {
                        serverResult = await RequestLicenseAsync(mode, email, purchaseKey, transferKey, token, log, machineIdAltConfirmed: true).ConfigureAwait(true);
                    }
                    catch (Exception)
                    {
                        log("An internal error occurred while retrying.");
                    }
                }
                else
                {
                    result.FilesInstalled = fileOutcome.AllSucceeded;
                    result.ServerRequestFinished = false;
                    result.LicenseFileOperationFinished = false;
                    result.LicenseSucceeded = false;
                    result.OverallSuccess = false;
                    result.FinalMessage = mode == InstallMode.Premium
                        ? Messages.SignupCancelledByUser
                        : Messages.TransferCancelledByUser;
                    return result;
                }
            }

            result.FilesInstalled = fileOutcome.AllSucceeded;
            if (fileOutcome.AllSucceeded) RegisterUninstaller(log);
            result.ServerRequestFinished = serverResult != null && serverResult.Completed;
            result.ServerResponse = serverResult == null ? null : serverResult.RawResponse;

            bool licenseFileOk = false;
            bool licenseSuccess = false;

            if (serverResult != null && serverResult.Completed)
            {
                if (serverResult.ServerReturnedNo)
                {
                    /* Deliberately does NOT touch any existing license file
                       here, under any rejection reason (including too_early).
                       The local file is never itself a security boundary -
                       the EA still has to pass a live challenge/verify
                       against the server every cycle regardless of what's in
                       this file - so there is no benefit to clearing it, and
                       real harm in doing so: this same code path is reached
                       by a harmless retry (too_early) exactly as often as by
                       a genuine rejection, and on a computer that already had
                       a perfectly valid, currently-working license (e.g.
                       installing Nutricula onto an additional MetaTrader
                       terminal on the same machine), wiping that file would
                       break a working setup for no real reason. */
                    licenseFileOk = true;
                    licenseSuccess = false;
                    log("Server rejected the request - the existing license file (if any) was left untouched.");
                }
                else
                {
                    licenseFileOk = WriteRawLicenseFile(serverResult.RawResponseBytes, log);
                    licenseSuccess = licenseFileOk;
                }
            }

            result.LicenseFileOperationFinished = licenseFileOk;
            result.LicenseSucceeded = licenseSuccess;
            result.OverallSuccess = fileOutcome.AllSucceeded && result.ServerRequestFinished && licenseFileOk && licenseSuccess;
            result.FinalMessage = BuildFinalMessage(mode, fileOutcome, serverResult, licenseFileOk);

            return result;
        }

        /// <summary>
        /// Single, explicit decision tree covering every outcome. Each branch
        /// maps to exactly one of the numbered messages in <see cref="Messages"/>
        /// so every case can be identified and revised individually.
        /// </summary>
        private static string BuildFinalMessage(
            InstallMode mode,
            FileInstallOutcome fileOutcome,
            ServerResult serverResult,
            bool licenseFileOk)
        {
            // Local file installation is a prerequisite for everything else -
            // if it failed, that's the blocking problem regardless of what
            // happened (or didn't happen) with the server.
            if (!fileOutcome.AllSucceeded)
            {
                return Messages.ForFileFailure(fileOutcome.FailureKind);
            }

            // Files installed, but we never got a completed server exchange.
            if (serverResult == null || !serverResult.Completed)
            {
                return Messages.ForIncompleteServerRequest(serverResult);
            }

            // Server responded, but rejected the request (either a specific
            // reason, or the generic legacy "no").
            if (serverResult.ServerReturnedNo)
            {
                return Messages.ForRejection(mode, serverResult.RejectReason);
            }

            // Server approved the request, but we couldn't save the result locally.
            if (!licenseFileOk)
            {
                return Messages.LicenseFileSaveFailed;
            }

            // Everything succeeded - except the Coordinator install itself
            // may still have failed (see FileInstallOutcome.CoordinatorWarning's
            // own comment): the license was activated and saved fine, but
            // without a working Coordinator the EA can never actually
            // refresh/verify it afterward, so this must not be silently
            // dropped from the message the user sees.
            string successMessage = mode == InstallMode.Premium ? Messages.PremiumSuccess : Messages.TransferSuccess;
            if (fileOutcome.CoordinatorWarning != null) successMessage += "\n\n" + fileOutcome.CoordinatorWarning;
            // Write-protected terminals that were skipped (see
            // FileInstallOutcome.TerminalWarning) - the install still succeeded
            // overall, but tell the user which terminals need extra steps.
            if (fileOutcome.TerminalWarning != null) successMessage += "\n\n" + fileOutcome.TerminalWarning;
            return successMessage;
        }

        /// <summary>
        /// Creates (or confirms) this computer's machine ID and device key
        /// pair for Free installs. This is a REQUIRED step - a Free install
        /// only reports success if the device key was actually created or
        /// already existed and loaded correctly, because the free-tier
        /// statistics table identifies a computer by machine_id and/or
        /// device_key_hash; without at least the device key, this
        /// install could never be recognized in a later free_checkin, and
        /// (if machine_id also can't be generated on this computer) the
        /// device key becomes the ONLY identifier available at all.
        /// </summary>
        private static Task<bool> TryEnsureDeviceIdentityAsync(Action<string> log)
        {
            return Task.Run(delegate
            {
                // BUG FIX (found from a real report, confirmed to happen even
                // with an all-ASCII Windows user name, so it is NOT the
                // APPDATA/non-ASCII-user-name issue fixed earlier in
                // MachineIdService.EnsureLoaded): the free install failed
                // once with this exact "device identity" error, then
                // succeeded immediately on "Try Again" with nothing else
                // changed. "Try Again" re-runs inside the SAME process (see
                // MainForm.OnTryAgainTapped), so the only thing different on
                // the second attempt is time elapsed - the signature of a
                // one-time, transient slow/failed first call, not a
                // permanent problem. The per-DLL-load retry already added to
                // EnsureLoaded() only covers the specific case of the DLL
                // file itself being briefly locked; it does not cover other
                // plausible first-call delays such as the native DLL's WMI/
                // COM initialization (used to read hardware identifiers)
                // genuinely taking longer than usual the very first time a
                // process touches WMI, or a real-time antivirus product
                // momentarily delaying the DLL's actual first EXECUTION
                // (not just its load) while it is inspected. Rather than
                // depend on the user clicking "Try Again" themselves, the
                // whole sequence below is now retried a few times, with a
                // real pause between attempts, before actually giving up.
                const int maxAttempts = 3;
                const int retryDelayMs = 1500;
                Exception lastException = null;
                for (int attempt = 1; attempt <= maxAttempts; attempt++)
                {
                    try
                    {
                        // Machine ID is attempted but its success is NOT
                        // required here (see the free_checkin design: a device
                        // key alone is sufficient to identify this computer in
                        // the unlicensed-usage table if machine_id can't be
                        // produced on this particular system - very rare, but
                        // possible, e.g. inside certain restricted containers).
                        // 2026 hardening: Free installs always use the WithGuid
                        // variant (never the primary/no-GUID one) - Free's
                        // machine_id exists purely for check-in statistics and
                        // never gates activation, so there's no reason to
                        // prefer the "stable across OS reinstall" property
                        // here. This matches what CoordinatorCore.cpp's own
                        // free_checkin path sends.
                        MachineIdService.GenerateComputerIdWithGuid();
                        string devicePublicKey = MachineIdService.GetDevicePublicKey();
                        if (!string.IsNullOrEmpty(devicePublicKey))
                        {
                            log("Free install setup completed" + (attempt > 1 ? " (attempt " + attempt + ")." : "."));
                            return true;
                        }
                        lastException = null;
                    }
                    catch (Exception ex)
                    {
                        lastException = ex;
                    }

                    if (attempt < maxAttempts) Thread.Sleep(retryDelayMs);
                }

                log("Device key could not be created or loaded during the free install after " +
                    maxAttempts + " attempts." + (lastException != null ? " (" + lastException.Message + ")" : ""));
                return false;
            });
        }

        private async Task<FileInstallOutcome> InstallFilesAsync(
            InstallMode mode,
            List<TerminalInfo> terminals,
            CancellationToken token,
            IProgress<ProgressUpdate> progress,
            Action<string> log)
        {
            // Named variables instead of a numerically-indexed array on
            // purpose - resources[N] broke twice already when items were
            // added/removed and the numeric indices below weren't all
            // updated together. Each variable is self-explanatory at its
            // use site, so removing/adding an item can never silently shift
            // which file another line actually copies.
            ResourceItem resEx5 = new ResourceItem("Nutricula.ex5", "NutriculaInstaller.Assets.Nutricula.ex5");
            ResourceItem resEx4 = new ResourceItem("Nutricula.ex4", "NutriculaInstaller.Assets.Nutricula.ex4");
            ResourceItem resLicenseDll32 = new ResourceItem("NutriculaLicenseCheck32.dll", "NutriculaInstaller.Assets.NutriculaLicenseCheck32.dll");
            ResourceItem resLicenseDll64 = new ResourceItem("NutriculaLicenseCheck64.dll", "NutriculaInstaller.Assets.NutriculaLicenseCheck64.dll");
            ResourceItem resMachineId32 = new ResourceItem("MachineId32.dll", "NutriculaInstaller.Assets.MachineId32.dll");
            ResourceItem resMachineId64 = new ResourceItem("MachineId64.dll", "NutriculaInstaller.Assets.MachineId64.dll");

            // --- The Coordinator (the user-session Broker) + its signed
            // manifest - installed ONCE per machine (not per-terminal, per
            // architecture point 63: exactly one Coordinator process total),
            // into a protected, non-per-terminal location. See
            // InstallCoordinatorAsync below for the exact path and for why
            // the Windows Service hosting was removed in favor of the Broker
            // for every mode.
            // Both 32-bit and 64-bit builds of the Coordinator are needed -
            // unlike the DLLs above (which must match the TERMINAL's
            // bitness, since MT4 is a 32-bit process and can only load
            // 32-bit DLLs), the Coordinator is its own independent process
            // that talks to the DLL over Named Pipe IPC - a bitness-
            // agnostic transport. The only thing that actually constrains
            // the Coordinator's own bitness is the HOST OPERATING SYSTEM:
            // a 64-bit exe simply cannot run at all on a 32-bit Windows
            // install (e.g. 32-bit Windows tablets, a real customer case).
            // See InstallCoordinatorAsync below for the OS-bitness-based
            // selection logic. (The Windows Service binaries were removed
            // entirely in 2026 - the Broker is the sole Coordinator host -
            // so they are no longer embedded, constructed, or installed.)
            ResourceItem resBroker32 = new ResourceItem("NutriculaLicenseBroker32.exe", "NutriculaInstaller.Assets.NutriculaLicenseBroker32.exe");
            ResourceItem resBroker64 = new ResourceItem("NutriculaLicenseBroker64.exe", "NutriculaInstaller.Assets.NutriculaLicenseBroker64.exe");
            ResourceItem resManifest = new ResourceItem("manifest.txt", "NutriculaInstaller.Assets.manifest.txt");

            int totalOperations = terminals.Count * 3 + 1; // +1 for the one-time Coordinator install (not per-terminal)
            int completed = 0;
            int allSucceededFlag = 1;
            int succeededCount = 0;
            object progressLock = new object();
            object failureLock = new object();
            LocalFileFailureKind worstFailure = LocalFileFailureKind.None;
            var inaccessibleTerminals = new List<string>();

            var tasks = terminals.Select(async terminal =>
            {
                try
                {
                    token.ThrowIfCancellationRequested();
                    await EnsureDirectoryAsync(terminal.LibrariesPath).ConfigureAwait(true);
                    await EnsureDirectoryAsync(terminal.ExpertsPath).ConfigureAwait(true);

                    // License Check DLL + Machine ID DLL, matching this
                    // terminal's bitness (MT4=32-bit, MT5=64-bit) - both go
                    // into the terminal's own Libraries folder, since MQL
                    // only ever imports DLLs from there, and
                    // MachineIdBridge::Load() looks for its neighbor DLL in
                    // the same directory the calling DLL itself is in - so
                    // these files must always travel together.
                    ResourceItem licenseDll = terminal.Type == TerminalType.MT4 ? resLicenseDll32 : resLicenseDll64;
                    ResourceItem machineIdDll = terminal.Type == TerminalType.MT4 ? resMachineId32 : resMachineId64;

                    await CopyEmbeddedResourceAsync(licenseDll, terminal.LibrariesPath, token).ConfigureAwait(true);
                    await CopyEmbeddedResourceAsync(machineIdDll, terminal.LibrariesPath, token).ConfigureAwait(true);
                    VerifyInstalledFile(Path.Combine(terminal.LibrariesPath, licenseDll.FileName));
                    VerifyInstalledFile(Path.Combine(terminal.LibrariesPath, machineIdDll.FileName));
                    log("Copied " + licenseDll.FileName + " + " + machineIdDll.FileName + " -> " + terminal.LibrariesPath);

                    lock (progressLock)
                    {
                        completed += 2;
                        progress.Report(new ProgressUpdate(completed, totalOperations));
                    }

                    if (terminal.Type == TerminalType.MT4)
                    {
                        await CopyEmbeddedResourceAsync(resEx4, terminal.ExpertsPath, token).ConfigureAwait(true);
                        VerifyInstalledFile(Path.Combine(terminal.ExpertsPath, resEx4.FileName));
                    }
                    else
                    {
                        await CopyEmbeddedResourceAsync(resEx5, terminal.ExpertsPath, token).ConfigureAwait(true);
                        VerifyInstalledFile(Path.Combine(terminal.ExpertsPath, resEx5.FileName));
                    }

                    lock (progressLock)
                    {
                        completed += 1;
                        progress.Report(new ProgressUpdate(completed, totalOperations));
                    }

                    log("Installed " + terminal.Type + " files -> " + terminal.TerminalPath);
                    Interlocked.Increment(ref succeededCount);
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    LocalFileFailureKind kind = ClassifyLocalFileException(ex);
                    if (kind == LocalFileFailureKind.AccessDenied)
                    {
                        // Non-elevated (asInvoker) install: a terminal whose
                        // folder is write-protected (classically a portable
                        // MetaTrader under %ProgramFiles%) genuinely cannot be
                        // written without Administrator. Do NOT fail the whole
                        // install for this - the license still activates and
                        // every user-writable terminal still gets its files.
                        // Record it as a per-terminal warning; if it turns out
                        // NO terminal succeeded at all, this is promoted to a
                        // real AccessDenied failure after the loop.
                        lock (failureLock)
                        {
                            inaccessibleTerminals.Add(terminal.Type + " - " + terminal.TerminalPath);
                        }
                        log("SKIPPED " + terminal.Type + " -> " + terminal.TerminalPath +
                            " | folder is write-protected (needs Administrator, or reinstall MetaTrader outside Program Files)");
                    }
                    else
                    {
                        Interlocked.Exchange(ref allSucceededFlag, 0);
                        lock (failureLock)
                        {
                            // Keep the first-seen, most-specific failure kind so the
                            // final message reflects a real, diagnosable cause
                            // rather than just "something went wrong" whenever
                            // possible - Unknown is the lowest priority and only
                            // wins if nothing more specific was ever classified.
                            if (worstFailure == LocalFileFailureKind.None ||
                                (worstFailure == LocalFileFailureKind.Unknown && kind != LocalFileFailureKind.Unknown))
                            {
                                worstFailure = kind;
                            }
                        }
                        log("FAILED " + terminal.Type + " -> " + terminal.TerminalPath + " | " + ex.Message);
                    }
                }
            }).ToArray();

            await Task.WhenAll(tasks).ConfigureAwait(true);
            bool allSucceeded = Interlocked.CompareExchange(ref allSucceededFlag, 0, 0) == 1;

            // Resolve the write-protected (AccessDenied) terminals, if any,
            // into either a soft warning (at least one terminal DID get its
            // files) or a hard failure (nothing could be written anywhere).
            string terminalWarning = null;
            if (inaccessibleTerminals.Count > 0)
            {
                if (succeededCount == 0)
                {
                    // Every discovered terminal was write-protected - nothing
                    // was installed, so this is a genuine failure, not a
                    // partial-success warning.
                    allSucceeded = false;
                    lock (failureLock)
                    {
                        if (worstFailure == LocalFileFailureKind.None) worstFailure = LocalFileFailureKind.AccessDenied;
                    }
                }
                else
                {
                    terminalWarning =
                        "Some MetaTrader terminals could not be set up because their folder is write-protected " +
                        "(typically a portable MetaTrader installed under Program Files):\n- " +
                        string.Join("\n- ", inaccessibleTerminals) +
                        "\n\nThe other terminal(s) were set up correctly and your license is active. To add " +
                        "Nutricula to the terminal(s) above as well, either run this installer as Administrator, " +
                        "or reinstall that MetaTrader somewhere inside your user profile (not under Program Files).";
                }
            }

            // --- New: one-time Coordinator (the user-session Broker) install
            // - architecture point 63: exactly ONE Coordinator per machine,
            // never one per terminal. Deliberately best-effort: a failure
            // here does not fail the overall install outcome (the EA/DLL
            // files are already correctly placed either way), but IS
            // logged clearly, since without a working Coordinator the
            // License DLL can never reach Tier 2 (architecture point 100:
            // no direct-to-server fallback exists). ---
            string coordinatorWarning = null;
            try
            {
                await InstallCoordinatorAsync(
                    resBroker32, resBroker64,
                    resManifest, resEx5, resEx4, resLicenseDll32, resLicenseDll64,
                    resMachineId32, resMachineId64,
                    token, log).ConfigureAwait(true);
                completed++;
                progress.Report(new ProgressUpdate(completed, totalOperations));
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                coordinatorWarning = "The License Coordinator (background service that talks to the Nutricula " +
                    "server) could not be installed (" + ex.Message + "). Your EA/indicator files were installed " +
                    "successfully and will still open normally, but license activation and check-ins will not " +
                    "work until this is resolved - please contact Nutricula support with this message.";
                log("WARNING: License Coordinator install did not complete (" + ex.Message + "). " +
                    "EA/DLL files were installed successfully, but License activation will not work until this is resolved.");
            }

            return new FileInstallOutcome(allSucceeded, allSucceeded ? LocalFileFailureKind.None : worstFailure)
            {
                CoordinatorWarning = coordinatorWarning,
                TerminalWarning = terminalWarning
            };
        }

        /// <summary>
        /// Where the Coordinator (always the user-session Broker - see
        /// InstallCoordinatorAsync's own comment for why the Windows Service
        /// hosting was removed) lives - the SAME single PER-USER path for
        /// every install mode (Free, Premium, Transfer) on every platform.
        ///
        /// %LocalAppData%\Nutricula\LicenseService\. This is a per-user,
        /// NON-elevated location on purpose (2026): the whole product is now
        /// per-user (the Broker runs in the user's session, the device key
        /// and license file live under the user's own %APPDATA%), so there is
        /// nothing left that needs Administrator at all - no Windows Service
        /// to register, no %ProgramFiles% write, no HKLM write. The Installer
        /// therefore runs as a normal (asInvoker) process with no UAC prompt.
        ///
        /// %LocalAppData% (unlike %ProgramFiles%) is NOT split into a 32-bit
        /// "(x86)" variant, so a 32-bit MT4 DLL and a 64-bit MT5 DLL both
        /// resolve LOCALAPPDATA to the exact same folder the (32-bit)
        /// Installer wrote to - see NutriculaLicenseCheckThin.cpp
        /// EnsureCoordinatorRunning, which derives this same path. On Wine,
        /// LOCALAPPDATA maps inside the prefix, so the identical logic covers
        /// Wine on macOS/Linux with no special case.
        /// </summary>
        private static string GetCoordinatorInstallDir()
        {
            return Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Nutricula", "LicenseService");
        }

        /// <summary>
        /// Registers Nutricula in Windows "Apps & Features" / "Programs and
        /// Features" so the user has an ordinary, discoverable way to remove
        /// everything this Installer put on the machine (see
        /// UninstallService.cs for the actual removal logic) - previously
        /// there was no uninstall path at all.
        ///
        /// Scope: HKCU, per-user (2026) - the whole product is now a per-user,
        /// non-elevated install (see GetCoordinatorInstallDir's own comment),
        /// so the "Apps & Features" entry is registered in the current user's
        /// own HKCU\...\Uninstall rather than machine-wide HKLM. It shows up
        /// in Settings > Apps for the user who installed, which is exactly the
        /// user who should be able to remove it - and needs no Administrator.
        ///
        /// The installer's own .exe is copied next to the other Coordinator
        /// files as "Uninstall.exe" because the ORIGINAL downloaded file the
        /// person double-clicked may since have been moved, renamed, or
        /// deleted - the UninstallString registered here must keep working
        /// regardless of what happens to that original download.
        ///
        /// Deliberately best-effort: a failure here (e.g. some unexpected
        /// registry permission issue) must never fail or roll back an
        /// otherwise-successful install, so any exception is caught and only
        /// logged - the person can still be walked through manual removal by
        /// support if this one small step didn't take.
        /// </summary>
        private static void RegisterUninstaller(Action<string> log)
        {
            try
            {
                string nutriculaRoot = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Nutricula");
                Directory.CreateDirectory(nutriculaRoot);

                string uninstallExePath = Path.Combine(nutriculaRoot, "Uninstall.exe");
                string thisExePath = System.Reflection.Assembly.GetExecutingAssembly().Location;
                if (!string.IsNullOrEmpty(thisExePath) && File.Exists(thisExePath))
                {
                    File.Copy(thisExePath, uninstallExePath, overwrite: true);
                }

                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" + UninstallService.UninstallRegistryKeyName))
                {
                    // "Nutricula EA" (not just "Nutricula") is what the
                    // project owner wants shown in Apps & Features - and
                    // DisplayIcon points at the Uninstall.exe copy just made
                    // above, which already carries the real Nutricula icon
                    // via <ApplicationIcon>icon.ico</ApplicationIcon> in the
                    // .csproj, so Windows has an icon to show there too
                    // (previously unset, which is why none appeared).
                    key.SetValue("DisplayName", "Nutricula EA");
                    key.SetValue("DisplayIcon", uninstallExePath);
                    key.SetValue("DisplayVersion", AppConfig.Version);
                    key.SetValue("UninstallString", "\"" + uninstallExePath + "\" /uninstall");
                    key.SetValue("Publisher", "Nutricula");
                    key.SetValue("InstallLocation", nutriculaRoot);
                    key.SetValue("NoModify", 1, RegistryValueKind.DWord);
                    key.SetValue("NoRepair", 1, RegistryValueKind.DWord);
                }
                log("Registered Nutricula in Apps & Features for easy removal.");
            }
            catch (Exception ex)
            {
                log("WARNING: could not register Nutricula in Apps & Features (" + ex.Message +
                    "). Nutricula was installed successfully regardless - this only affects how it can later be uninstalled.");
            }
        }

        private async Task InstallCoordinatorAsync(
            ResourceItem resBroker32, ResourceItem resBroker64,
            ResourceItem resManifest, ResourceItem resEx5, ResourceItem resEx4,
            ResourceItem resLicenseDll32, ResourceItem resLicenseDll64,
            ResourceItem resMachineId32, ResourceItem resMachineId64,
            CancellationToken token, Action<string> log)
        {
            string installDir = GetCoordinatorInstallDir();

            // 2026 decision (project owner, after a full cross-component
            // audit): the Coordinator runs as the user-session BROKER for
            // EVERY mode (Free/Premium/Transfer) on EVERY platform (real
            // Windows and Wine alike). The Windows Service hosting was
            // removed entirely because it is structurally incompatible with
            // this product's per-user identity model - a Service runs as
            // NT AUTHORITY\LocalService, a different account/profile, and:
            //   1. the device key is DPAPI user-scoped and stored under the
            //      user's %APPDATA% (MachineId DLL GetDeviceKeyPath),
            //   2. the license file lives under the user's %APPDATA% too,
            //   3. the IPC handshake requires the connecting EA to have the
            //      SAME user SID as the Coordinator (NamedPipeIpc.h
            //      VerifyConnectedClientIdentity).
            // So a LocalService Coordinator could neither read the user's
            // device key / license file nor pass the same-user pipe
            // handshake - it would leave even a paid Premium license stuck
            // at TIER_FREE. The Broker always runs in the user's own session
            // (started here at install, restarted by the HKCU Run key at
            // login and by the Scheduled Task watchdog if it crashes, and
            // launched on demand by the DLL itself the instant an EA
            // attaches; see NutriculaLicenseCheckThin.cpp
            // EnsureCoordinatorRunning), so it always runs as exactly the
            // right user. Real-world security is unchanged: the decisive
            // checks (the DLL's own anti-tamper hardening and the server's
            // RSA signature, re-verified independently inside the DLL) do
            // not depend on which account hosts the Coordinator. Because the
            // Broker needs no elevation and this install location is per-user
            // (%LocalAppData%), the whole install runs without Administrator.

            // Stop any existing Broker and clear its auto-start registrations
            // BEFORE copying fresh files into the install directory an old
            // Broker might still be running from and have open (see
            // StopAndDisableExistingBroker).
            StopAndDisableExistingBroker(installDir, log);

            await EnsureDirectoryAsync(installDir).ConfigureAwait(true);

            bool osIs64Bit = Environment.Is64BitOperatingSystem;
            ResourceItem selectedBroker = osIs64Bit ? resBroker64 : resBroker32;
            log("Host OS is " + (osIs64Bit ? "64-bit" : "32-bit") + " - selecting the matching Coordinator (Broker) build.");

            // Install the OS-bitness-selected Broker under a FIXED name (see
            // the method doc comment). The Windows Service binary is no
            // longer installed - the Broker is the sole Coordinator host.
            await CopyEmbeddedResourceAsync(selectedBroker, installDir, token, overrideFileName: "NutriculaLicenseBroker.exe").ConfigureAwait(true);
            VerifyInstalledFile(Path.Combine(installDir, "NutriculaLicenseBroker.exe"));

            // CRITICAL: MachineIdBridge::Load() (called by the Coordinator
            // itself at startup, from its OWN directory) needs
            // MachineId32.dll or MachineId64.dll matching the COORDINATOR's
            // architecture (never the terminal's MT4/MT5 architecture)
            // sitting right next to it - required for the Coordinator to
            // generate a machine_id or sign a challenge at all. Installed
            // under its own real name (not overridden, unlike the Broker)
            // since MachineIdBridge.cpp looks for exactly
            // "MachineId32.dll" / "MachineId64.dll" via #ifdef _WIN64.
            ResourceItem selectedMachineId = osIs64Bit ? resMachineId64 : resMachineId32;
            await CopyEmbeddedResourceAsync(selectedMachineId, installDir, token).ConfigureAwait(true);
            VerifyInstalledFile(Path.Combine(installDir, selectedMachineId.FileName));
            log("Copied " + selectedMachineId.FileName + " -> " + installDir + " (Coordinator's own machine ID dependency)");

            ResourceItem[] sharedResources = new ResourceItem[] { resManifest, resEx5, resEx4, resLicenseDll32, resLicenseDll64 };
            foreach (ResourceItem item in sharedResources)
            {
                await CopyEmbeddedResourceAsync(item, installDir, token).ConfigureAwait(true);
                VerifyInstalledFile(Path.Combine(installDir, item.FileName));
            }
            log("Copied License Coordinator files -> " + installDir);

            bool isWine = MachineIdService.IsWineEnvironment();
            string brokerPath = Path.Combine(installDir, "NutriculaLicenseBroker.exe");

            // The Coordinator must stay available across reboots/logins, and
            // must also come up the instant an EA attaches. Three cooperating
            // mechanisms, all pointing at the SAME user-session Broker:
            //   (a) HKCU Run key  - starts it at every user login,
            //   (b) immediate launch below - starts it right now, at install,
            //   (c) Scheduled Task watchdog - restarts it if it ever crashes,
            // plus the DLL's own on-demand launch the moment an EA attaches
            // (NutriculaLicenseCheckThin.cpp EnsureCoordinatorRunning), which
            // needs no registry at all - it derives this same install path
            // from %LocalAppData% (see GetCoordinatorInstallDir). HKCU Run needs no
            // elevation and is read by the standard Windows startup sequence
            // at every login - and by Wine's own explorer.exe equivalent at
            // Wine session start, so the SAME mechanism covers Windows and
            // Wine (macOS/Linux) without any Wine-specific branch. A
            // duplicate trigger (e.g. the Run key firing while the Broker is
            // already alive) is harmless: the Broker's own singleton mutex
            // (see NutriculaLicenseBroker.cpp) makes any second instance exit
            // immediately rather than compete.
            try
            {
                using (RegistryKey runKey = Registry.CurrentUser.OpenSubKey(
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Run", writable: true))
                {
                    runKey?.SetValue("NutriculaLicenseBroker", "\"" + brokerPath + "\"", RegistryValueKind.String);
                }
                log("Registered License Broker for automatic startup (survives reboot/logoff).");
            }
            catch (Exception ex)
            {
                log("WARNING: could not register the License Broker for automatic startup (" + ex.Message +
                    "). It will still run for this session, but will need to be started manually after a reboot until this is fixed.");
            }

            try
            {
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                {
                    FileName = brokerPath,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden,
                });
                log("License Broker started (" + (isWine ? "Wine" : "Windows") + " mode).");
            }
            catch (Exception ex)
            {
                log("Could not start the License Broker: " + ex.Message);
                throw;
            }

            // Watchdog: the HKCU Run key above only re-launches the Broker
            // at the next login - it does nothing if the Broker crashes or
            // is killed mid-session. A Scheduled Task that just re-runs the
            // same executable every few minutes closes that gap cheaply:
            // thanks to the Broker's own singleton mutex, running it again
            // while a healthy instance is already active is a harmless
            // immediate no-op, and running it again when the previous
            // instance died is exactly the recovery we want. No admin
            // rights needed for a per-user Scheduled Task.
            try
            {
                RunHidden("schtasks.exe",
                    "/Create /F /SC MINUTE /MO 5 /TN \"NutriculaLicenseBrokerWatchdog\" /TR \"\\\"" + brokerPath + "\\\"\"",
                    15000);
                log("Registered License Broker watchdog (re-checks every 5 minutes).");
            }
            catch (Exception ex)
            {
                log("WARNING: could not register the License Broker watchdog (" + ex.Message +
                    "). The Broker will still restart at next login via the Run key, just not automatically if it crashes mid-session.");
            }
        }

        /// <summary>
        /// Stops any running Broker process and removes its auto-start
        /// registrations (Run key + Scheduled Task watchdog), then deletes
        /// brokerInstallDir - prevents a leftover Broker from ever competing
        /// with a Service on the same Named Pipe name (architecture point
        /// 63: exactly one Coordinator), and - since the 2026 path
        /// consolidation - also clears the way before copying fresh files
        /// into the shared install directory an old Broker might still be
        /// running from and have open (see InstallCoordinatorAsync's own
        /// comment on its call site, near the top of that function, before
        /// any files are copied).
        ///
        /// The process kill and registration cleanup match by NAME
        /// (Process.GetProcessesByName, and the fixed Run-key/Scheduled-Task
        /// names), so they work regardless of which directory the Broker
        /// actually ran from; brokerInstallDir only needs to be exactly
        /// right for the final directory-delete step.
        /// </summary>
        private static void StopAndDisableExistingBroker(string brokerInstallDir, Action<string> log)
        {
            try
            {
                foreach (var proc in System.Diagnostics.Process.GetProcessesByName("NutriculaLicenseBroker"))
                {
                    try { proc.Kill(); proc.WaitForExit(5000); }
                    catch { /* best-effort - a process that already exited or that we can't signal isn't fatal here */ }
                }
            }
            catch { }

            try
            {
                using (RegistryKey runKey = Registry.CurrentUser.OpenSubKey(
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Run", writable: true))
                {
                    runKey?.DeleteValue("NutriculaLicenseBroker", throwOnMissingValue: false);
                }
            }
            catch { }

            try
            {
                RunHidden("schtasks.exe", "/Delete /F /TN \"NutriculaLicenseBrokerWatchdog\"", 10000);
            }
            catch { }

            // The Broker process we just killed above may hold the directory
            // open for a brief moment after Kill() returns - WaitForExit(5000)
            // above already gives it time to release its own files, so this
            // is best-effort but should normally succeed. Never fatal to the
            // install proceeding either way (a leftover, inert old folder is
            // harmless clutter, not a functional problem) - the fresh copy
            // right after this call recreates whatever is actually needed.
            try
            {
                if (!string.IsNullOrEmpty(brokerInstallDir) && Directory.Exists(brokerInstallDir))
                {
                    Directory.Delete(brokerInstallDir, recursive: true);
                    log("Removed the leftover License Broker folder (" + brokerInstallDir + ").");
                }
            }
            catch (Exception ex)
            {
                log("WARNING: could not remove the leftover License Broker folder (" + ex.Message +
                    "). This is harmless clutter, not a functional problem.");
            }

            log("Stopped and disabled any existing License Broker before installing fresh Coordinator files.");
        }

        /// <summary>
        /// Runs a process hidden and waits for it to exit, ignoring its exit
        /// code (callers that care about the result use Process.Start
        /// directly instead - this helper is for fire-and-forget commands
        /// like schtasks.exe where "best effort" is enough).
        /// </summary>
        private static void RunHidden(string fileName, string arguments, int timeoutMs)
        {
            using (var p = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments,
                UseShellExecute = false,
                CreateNoWindow = true,
            }))
            {
                p.WaitForExit(timeoutMs);
            }
        }

        /// <summary>
        /// Recovers the underlying Win32 error code from a .NET IOException's
        /// HResult (HRESULT = 0x8007xxxx for FACILITY_WIN32, so the low 16
        /// bits are the original Win32 error code) to distinguish disk-full,
        /// sharing-violation ("file in use"), and similar specific causes
        /// from a generic I/O failure.
        /// </summary>
        private static LocalFileFailureKind ClassifyLocalFileException(Exception ex)
        {
            // Checked before the generic IOException case below, since
            // FileVerificationException IS an IOException and would
            // otherwise be caught by that broader check first.
            if (ex is FileVerificationException) return LocalFileFailureKind.VerificationFailed;
            if (ex is UnauthorizedAccessException) return LocalFileFailureKind.AccessDenied;
            if (ex is PathTooLongException) return LocalFileFailureKind.PathTooLong;
            if (ex is DirectoryNotFoundException) return LocalFileFailureKind.PathNotFound;

            IOException io = ex as IOException;
            if (io != null)
            {
                int win32Code = io.HResult & 0xFFFF;
                switch (win32Code)
                {
                    case 112: // ERROR_DISK_FULL
                        return LocalFileFailureKind.DiskFull;
                    case 32:  // ERROR_SHARING_VIOLATION
                    case 33:  // ERROR_LOCK_VIOLATION
                        return LocalFileFailureKind.FileInUse;
                    case 5:   // ERROR_ACCESS_DENIED (sometimes surfaces as IOException, not UnauthorizedAccessException)
                        return LocalFileFailureKind.AccessDenied;
                    case 3:   // ERROR_PATH_NOT_FOUND
                    case 2:   // ERROR_FILE_NOT_FOUND
                        return LocalFileFailureKind.PathNotFound;
                }
            }

            return LocalFileFailureKind.Unknown;
        }

        private async Task<ServerResult> RequestLicenseAsync(
            InstallMode mode,
            string email,
            string purchaseKey,
            string transferKey,
            CancellationToken token,
            Action<string> log,
            bool machineIdAltConfirmed = false)
        {
            // Anti-tamper (see SelfIntegrityCheck.cs for full scope/limits):
            // fail closed before consuming a purchase key or transfer key if
            // this installer's own binary does not match its vendor-signed
            // trailer. A Free install is NOT gated on this (see the Free
            // branch above) - Free installs cannot consume any
            // purchase/transfer key at all, so there is nothing here to
            // protect for that path.
            if (!Program.SelfIntegrityVerified)
            {
                return ServerResult.Failed(ServerFailureKind.SelfIntegrityFailed, null);
            }

            string machineId;
            string machineIdAlt;
            try
            {
                machineId = MachineIdService.GenerateComputerId();
                // Secondary variant (2026 hardening) - byte-identical to
                // machineId on every platform other than physical Windows
                // (see GenerateComputerIdWithGuid's own comment), so it is
                // always safe to generate and send both together
                // regardless of which platform this actually is - no
                // platform-specific branching needed here at all.
                machineIdAlt = MachineIdService.GenerateComputerIdWithGuid();
            }
            catch (Exception ex)
            {
                return ServerResult.Failed(ServerFailureKind.MachineIdUnavailable, ex);
            }

            // Device key: only created if none exists yet on this computer;
            // if one already exists (from an earlier signup, transfer, or
            // even a prior Free install), that SAME key is reused as-is,
            // in every install mode - this method never forces a new one.
            // Re-signup with the same purchase key on the same computer,
            // and Transfer identity changes, are both handled entirely
            // server-side via the rotating refresh-token state machine
            // (see nutricula_check_and_rotate_token in license_common.php)
            // - not by rotating the local device key.
            string devicePublicKey;
            try
            {
                devicePublicKey = MachineIdService.GetDevicePublicKey();
            }
            catch (Exception ex)
            {
                return ServerResult.Failed(ServerFailureKind.DeviceSecurityUnavailable, ex);
            }

            string localIp = MachineIdService.GetLastClientIp();
            string platformProfile = MachineIdService.GetLastPlatformProfile();
            string rndNumber = CryptoService.Generate32DigitRandomNumber();

            string encodedPostData;
            try
            {
                encodedPostData = CryptoService.BuildPostData(
                    email,
                    purchaseKey,
                    machineId,
                    rndNumber,
                    mode == InstallMode.Transfer ? transferKey : null,
                    localIp,
                    devicePublicKey,
                    platformProfile,
                    machineIdAlt,
                    machineIdAltConfirmed
                );
            }
            catch (Exception ex)
            {
                return ServerResult.Failed(ServerFailureKind.DeviceSecurityUnavailable, ex);
            }

            string baseUrl = mode == InstallMode.Premium ? PremiumUrl : TransferUrl;
            log("This computer's setup is ready.");
            log("Sending license request...");

            try
            {
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls;

                using (HttpClientHandler handler = new HttpClientHandler())
                using (HttpClient client = new HttpClient(handler))
                using (HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, baseUrl))
                {
                    client.Timeout = TimeSpan.FromSeconds(60);
                    request.Headers.UserAgent.ParseAdd("NutriculaExpertInstaller/2.0");
                    request.Content = new FormUrlEncodedContent(new[]
                    {
                        new KeyValuePair<string, string>("data", encodedPostData)
                    });

                    HttpResponseMessage response;
                    try
                    {
                        response = await client.SendAsync(request, HttpCompletionOption.ResponseContentRead, token).ConfigureAwait(true);
                    }
                    catch (TaskCanceledException ex)
                    {
                        if (token.IsCancellationRequested) throw;
                        // HttpClient surfaces its own Timeout as a TaskCanceledException
                        // that is NOT tied to our CancellationToken - this is the
                        // only reliable way to tell "the request timed out" apart
                        // from "the user clicked Cancel".
                        return ServerResult.Failed(ServerFailureKind.Timeout, ex);
                    }

                    using (response)
                    {
                        log("Received a response from the server.");

                        if (response.StatusCode != HttpStatusCode.OK)
                        {
                            return ServerResult.HttpFailed((int)response.StatusCode);
                        }

                        byte[] rawBytes = await response.Content.ReadAsByteArrayAsync().ConfigureAwait(true);
                        if (rawBytes == null || rawBytes.Length == 0)
                        {
                            return ServerResult.Failed(
                                ServerFailureKind.EmptyResponse,
                                new InvalidOperationException("Server returned an empty response."));
                        }

                        string rawResponse = Encoding.UTF8.GetString(rawBytes);
                        string decryptedResponse;

                        try
                        {
                            decryptedResponse = CryptoService.DecryptServerResponse(rawResponse);
                        }
                        catch (Exception ex)
                        {
                            log("The server's response could not be processed.");
                            return new ServerResult
                            {
                                Completed = false,
                                FailureKind = ServerFailureKind.DecryptionFailed,
                                RawResponse = rawResponse,
                                RawResponseBytes = rawBytes,
                                Error = ex
                            };
                        }

                        return InterpretDecryptedResponse(decryptedResponse, rawResponse, rawBytes);
                    }
                }
            }
            catch (OperationCanceledException ex)
            {
                if (token.IsCancellationRequested) throw;
                return ServerResult.Failed(ServerFailureKind.ConnectionProblem, ex);
            }
            catch (Exception ex)
            {
                return ServerResult.Failed(ServerFailureKind.ConnectionProblem, ex);
            }
        }

        /// <summary>
        /// The decrypted body is always exactly one of: the literal "no",
        /// "NL3-REJECT|reason=...|..." (structured rejection), or
        /// "NL3|...|server_signature=..." (success). Anything else means the
        /// server and installer have drifted out of protocol sync.
        /// </summary>
        private static ServerResult InterpretDecryptedResponse(string decryptedResponse, string rawResponse, byte[] rawBytes)
        {
            if (string.Equals(decryptedResponse, "no", StringComparison.Ordinal))
            {
                return new ServerResult
                {
                    Completed = true,
                    FailureKind = ServerFailureKind.None,
                    ServerReturnedNo = true,
                    RejectReason = null,
                    RawResponse = rawResponse,
                    RawResponseBytes = rawBytes
                };
            }

            if (decryptedResponse != null && decryptedResponse.StartsWith("NL3-REJECT|", StringComparison.Ordinal))
            {
                return new ServerResult
                {
                    Completed = true,
                    FailureKind = ServerFailureKind.None,
                    ServerReturnedNo = true,
                    RejectReason = ExtractField(decryptedResponse, "reason"),
                    RawResponse = rawResponse,
                    RawResponseBytes = rawBytes
                };
            }

            if (decryptedResponse != null && decryptedResponse.StartsWith("NL3|", StringComparison.Ordinal))
            {
                return new ServerResult
                {
                    Completed = true,
                    FailureKind = ServerFailureKind.None,
                    ServerReturnedNo = false,
                    RawResponse = rawResponse,
                    RawResponseBytes = rawBytes
                };
            }

            return new ServerResult
            {
                Completed = false,
                FailureKind = ServerFailureKind.UnrecognizedFormat,
                RawResponse = rawResponse,
                RawResponseBytes = rawBytes,
                Error = new InvalidOperationException("Unrecognized response format.")
            };
        }

        /// <summary>Extracts one "key=value" segment from a "|"-delimited canonical string.</summary>
        private static string ExtractField(string canonical, string fieldName)
        {
            string prefix = fieldName + "=";
            string[] parts = canonical.Split('|');
            for (int i = 0; i < parts.Length; i++)
            {
                if (parts[i].StartsWith(prefix, StringComparison.Ordinal))
                {
                    return parts[i].Substring(prefix.Length);
                }
            }
            return null;
        }

        private bool WriteRawLicenseFile(byte[] rawResponseBytes, Action<string> log)
        {
            try
            {
                string path = LongPath(GetCommonLicensePath());
                string dir = Path.GetDirectoryName(path);
                if (string.IsNullOrEmpty(dir)) throw new IOException("Could not determine Common\\Files directory.");
                Directory.CreateDirectory(dir);
                if (File.Exists(path)) File.Delete(path);
                File.WriteAllBytes(path, rawResponseBytes ?? new byte[0]);
                if (!File.Exists(path)) throw new IOException("License file was not created.");
                if (rawResponseBytes != null && new FileInfo(path).Length != rawResponseBytes.Length)
                    throw new IOException("License file size verification failed.");
                log("License response saved: " + path);
                return true;
            }
            catch (Exception)
            {
                log("License file could not be saved.");
                return false;
            }
        }

        /// <summary>
        /// MetaTrader cannot be relocated, so however long its installation
        /// path happens to be, Nutricula must still install into it - there
        /// is no reasonable way to ask the user to "move MetaTrader
        /// somewhere shorter". This prefixes any path with the Windows
        /// extended-length syntax (\\?\, or \\?\UNC\ for network paths),
        /// which makes File/Directory APIs ignore the traditional ~260
        /// character MAX_PATH limit entirely. Applied everywhere a path is
        /// used for actual file I/O in this class, so a long path is simply
        /// never a reason installation can fail.
        /// </summary>
        private static string LongPath(string path)
        {
            if (string.IsNullOrEmpty(path)) return path;
            if (path.StartsWith(@"\\?\", StringComparison.Ordinal)) return path;
            string full = Path.GetFullPath(path);
            if (full.StartsWith(@"\\", StringComparison.Ordinal))
            {
                return @"\\?\UNC\" + full.Substring(2);
            }
            return @"\\?\" + full;
        }

        private static Task EnsureDirectoryAsync(string path)
        {
            Directory.CreateDirectory(LongPath(path));
            return Task.FromResult(true);
        }

        private static void VerifyInstalledFile(string path)
        {
            string longPath = LongPath(path);
            if (!File.Exists(longPath)) throw new FileVerificationException("The file could not be verified after installation: " + path);
            if (new FileInfo(longPath).Length <= 0) throw new FileVerificationException("The installed file is empty: " + path);
        }

        private static async Task CopyEmbeddedResourceAsync(ResourceItem item, string destinationDirectory, CancellationToken token, string overrideFileName = null)
        {
            var assembly = typeof(InstallerService).Assembly;
            using (Stream input = assembly.GetManifestResourceStream(item.ManifestName))
            {
                if (input == null) throw new FileNotFoundException("Embedded resource not found: " + item.ManifestName);
                string destinationFileName = overrideFileName ?? item.FileName;
                string destination = LongPath(Path.Combine(destinationDirectory, destinationFileName));
                string temp = destination + ".nutricula_tmp";
                using (FileStream output = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.None, 64 * 1024, true))
                    await input.CopyToAsync(output, 64 * 1024, token).ConfigureAwait(true);
                if (File.Exists(destination)) File.Delete(destination);
                File.Move(temp, destination);
            }
        }

        private sealed class ResourceItem
        {
            public string FileName { get; private set; }
            public string ManifestName { get; private set; }
            public ResourceItem(string fileName, string manifestName)
            {
                FileName = fileName;
                ManifestName = manifestName;
            }
        }

        private enum ServerFailureKind
        {
            None,
            ConnectionProblem,
            Timeout,
            HttpError,
            EmptyResponse,
            DecryptionFailed,
            UnrecognizedFormat,
            MachineIdUnavailable,
            DeviceSecurityUnavailable,
            SelfIntegrityFailed
        }

        private enum LocalFileFailureKind
        {
            None,
            DiskFull,
            AccessDenied,
            FileInUse,
            PathTooLong,
            PathNotFound,
            VerificationFailed,
            Unknown
        }

        /// <summary>
        /// Thrown only by VerifyInstalledFile below, when a file this
        /// installer just wrote to disk is missing or empty right
        /// afterwards - never a real OS-level I/O error (no sharing
        /// violation, no access-denied, nothing an antivirus or "close
        /// MetaTrader" advice could fix). The most likely real cause is that
        /// this installer's OWN embedded copy of that file (baked in at
        /// build time from the Assets folder) is itself empty or corrupted -
        /// e.g. a 0-byte or truncated file was accidentally committed/
        /// uploaded before the GitHub Actions build ran. A plain IOException
        /// would fall through ClassifyLocalFileException's switch (its
        /// default HResult matches none of the specific Win32 codes there)
        /// and be misreported as a generic "unexpected file system error" -
        /// which used to send users looking for a permissions or
        /// disk-space problem that was never the real cause. This subtype
        /// is classified explicitly instead, so the on-screen message names
        /// the real, fixable problem.
        /// </summary>
        private sealed class FileVerificationException : IOException
        {
            public FileVerificationException(string message) : base(message) { }
        }

        private sealed class FileInstallOutcome
        {
            public bool AllSucceeded { get; private set; }
            public LocalFileFailureKind FailureKind { get; private set; }
            /// <summary>
            /// Null when the Coordinator (Service/Broker) installed and
            /// started cleanly. Otherwise, a short, user-facing explanation
            /// of what went wrong with it.
            ///
            /// BUG FIX (found from a real report): the Coordinator install
            /// used to be wrapped in a try/catch that only called log(...) -
            /// which, per AppendLog's own doc comment, is never actually
            /// shown anywhere on screen during install. That meant a
            /// Coordinator failure (e.g. the Program-Files-permissions bug
            /// this field was added to surface) was completely invisible:
            /// the EA/DLL files installed fine, so the user saw "install
            /// successful" with no indication that license activation /
            /// free-tier check-ins would silently never work. This field
            /// carries that failure into the final on-screen message
            /// instead.
            /// </summary>
            public string CoordinatorWarning { get; set; }
            /// <summary>
            /// Null when every discovered terminal received its files.
            /// Otherwise a user-facing note listing terminals that were
            /// SKIPPED because their folder is write-protected (e.g. a
            /// portable MetaTrader under %ProgramFiles%, which a non-elevated
            /// asInvoker install cannot write to). This is deliberately NOT a
            /// hard failure as long as at least one terminal succeeded - the
            /// license still activates and the other terminals work - so it is
            /// surfaced as a warning rather than masking the whole install as
            /// "failed". If NO terminal could be written, that becomes a real
            /// AccessDenied failure instead (AllSucceeded=false).
            /// </summary>
            public string TerminalWarning { get; set; }
            public FileInstallOutcome(bool allSucceeded, LocalFileFailureKind failureKind)
            {
                AllSucceeded = allSucceeded;
                FailureKind = failureKind;
            }
        }

        private sealed class ServerResult
        {
            public bool Completed { get; set; }
            public bool ServerReturnedNo { get; set; }
            public string RejectReason { get; set; }
            public int HttpStatusCode { get; set; }
            public string RawResponse { get; set; }
            public byte[] RawResponseBytes { get; set; }
            public Exception Error { get; set; }
            public ServerFailureKind FailureKind { get; set; }

            public static ServerResult Failed(ServerFailureKind kind, Exception ex)
            {
                return new ServerResult { Completed = false, FailureKind = kind, Error = ex };
            }

            public static ServerResult HttpFailed(int statusCode)
            {
                return new ServerResult
                {
                    Completed = false,
                    FailureKind = ServerFailureKind.HttpError,
                    HttpStatusCode = statusCode,
                    Error = new HttpRequestException("Unexpected HTTP status: " + statusCode)
                };
            }
        }

        /// <summary>
        /// Every user-facing red/green message the installer can show, in one
        /// place, each reachable through exactly one path in
        /// <see cref="BuildFinalMessage"/>. Numbered in the accompanying
        /// documentation so any single message can be revised by number.
        /// </summary>
        private static class Messages
        {
            private const string ToolsOptionsReminder =
                "\n\nDon't forget that in MetaTrader, you need to open \"Tools\" \u2192 \"Options\", go to the " +
                "\"Experts\" tab, enable Allow algorithmic (automated) trading and Allow DLL imports, and " +
                "disable all other options.";

            // ---- Success (green) ----
            public const string FreeSuccess =
                "Nutricula Free Version was installed successfully." + ToolsOptionsReminder;

            public const string FreeDeviceIdentityFailure =
                "Nutricula could not complete the free installation because it was unable to create or " +
                "read a required device identity file on this computer. Please make sure the installer is " +
                "running with sufficient permissions and try again, or contact Nutricula support.";

            public const string PremiumSuccess =
                "Your license was successfully activated and Nutricula was installed on your computer. " +
                "You can now use the Pro version of Nutricula." + ToolsOptionsReminder;

            public const string TransferSuccess =
                "Your license was successfully transferred and Nutricula was installed on your computer. " +
                "You can now use the Pro version of Nutricula on this computer." + ToolsOptionsReminder;

            // ---- Identity warning dialog (2026 hardening) ----
            // Shown in three distinct situations - see RunAsync's own
            // comments for exactly when each fires:
            //   1. Physical Windows: only if the primary (no-GUID)
            //      machine_id is already taken by a different active
            //      license (rare) - the fallback ties the license to this
            //      exact Windows install.
            //   2. Linux: ALWAYS, before any network call - Linux has no
            //      fallback identity at all, every activation is
            //      inherently tied to this exact Linux installation.
            //   3. VPS (device_type=windows_vm): ALWAYS, before any network
            //      call - same reasoning as Linux, a VPS's Windows install
            //      is not expected to be stable across reinstalls/reimages.
            // Two full message/button sets exist for each platform - one
            // for Signup, one for Transfer - since the wording needs to
            // talk about "activating" vs. "transferring" a license, and
            // the two buttons need to reflect the same distinction.

            public const string WindowsIdentityWarningSignup =
                "Because your device's identifying information is not complete, if you continue with this " +
                "activation, your license will be lost if you replace or reinstall Windows on this computer. " +
                "In other words, on this computer you will only be able to use your Nutricula license for as " +
                "long as you keep using this exact Windows installation.";

            public const string WindowsIdentityWarningTransfer =
                "Because your device's identifying information is not complete, if you continue with this " +
                "transfer, your license will be lost if you replace or reinstall Windows on this computer. " +
                "In other words, on this computer you will only be able to use your Nutricula license for as " +
                "long as you keep using this exact Windows installation.";

            public const string LinuxIdentityWarningSignup =
                "On Linux, Nutricula ties your license to this exact Linux installation. If you reinstall your " +
                "Linux distribution (or switch to a different one) on this computer, your license will be lost " +
                "and you will need to activate it again. In other words, you will only be able to use your " +
                "Nutricula license for as long as you keep using this exact Linux installation.";

            public const string LinuxIdentityWarningTransfer =
                "On Linux, Nutricula ties your license to this exact Linux installation. If you reinstall your " +
                "Linux distribution (or switch to a different one) on this computer, your license will be lost " +
                "and you will need to transfer it again. In other words, you will only be able to use your " +
                "Nutricula license for as long as you keep using this exact Linux installation.";

            public const string VpsIdentityWarningSignup =
                "On a VPS, Nutricula ties your license to this exact Windows installation on this virtual " +
                "machine. If this VPS is reinstalled, reimaged, or replaced, your license will be lost and you " +
                "will need to activate it again. In other words, you will only be able to use your Nutricula " +
                "license for as long as you keep using this exact Windows installation on this VPS.";

            public const string VpsIdentityWarningTransfer =
                "On a VPS, Nutricula ties your license to this exact Windows installation on this virtual " +
                "machine. If this VPS is reinstalled, reimaged, or replaced, your license will be lost and you " +
                "will need to transfer it again. In other words, you will only be able to use your Nutricula " +
                "license for as long as you keep using this exact Windows installation on this VPS.";

            public const string IdentityWarningYesSignup =
                "It doesn't matter. Activate my license on this computer.";

            public const string IdentityWarningNoSignup =
                "Stop the activation. I'd rather activate my license on a different computer.";

            public const string IdentityWarningYesTransfer =
                "It doesn't matter. Transfer my license to this computer.";

            public const string IdentityWarningNoTransfer =
                "Stop the transfer. I'd rather transfer my license to a different computer.";

            public const string SignupCancelledByUser =
                "Activation was cancelled. Your purchase key was not used, and no license was activated on " +
                "this computer. You can run this installer again on a different computer whenever you're ready.";

            public const string TransferCancelledByUser =
                "The transfer was cancelled. Your transfer key was not used, and no license was moved to this " +
                "computer. You can run this installer again on a different computer whenever you're ready.";

            // ---- Pre-flight ----
            public const string NoTerminalFound =
                "No MetaTrader 4 or MetaTrader 5 installation was found on this computer. " +
                "Please install MetaTrader first, then run this installer again.";

            // ---- Local file installation failures ----
            // (path length is deliberately NOT a case here anymore - see the
            // LongPath() helper, which makes installation work regardless of
            // how long MetaTrader's own path is, since it cannot be moved.)
            public static string ForFileFailure(LocalFileFailureKind kind)
            {
                switch (kind)
                {
                    case LocalFileFailureKind.DiskFull:
                        return "Nutricula could not be installed because there is not enough free disk space. " +
                               "Please free up some space and try again.";
                    case LocalFileFailureKind.AccessDenied:
                        // Reached only when EVERY discovered terminal's folder is
                        // write-protected (see InstallFilesAsync) - i.e. all are in
                        // a location like Program Files. Admin IS a valid remedy
                        // here, but so is moving MetaTrader into the user profile
                        // (the installer itself needs no admin otherwise).
                        return "Nutricula could not be installed because the MetaTrader folder is write-protected " +
                               "(this usually means MetaTrader is installed under Program Files). Please either run " +
                               "this installer as Administrator, or reinstall MetaTrader inside your user profile, then try again.";
                    case LocalFileFailureKind.FileInUse:
                        return "Nutricula could not be installed because one of its files is currently in use. " +
                               "Please close MetaTrader completely and try again.";
                    case LocalFileFailureKind.PathNotFound:
                        return "Nutricula could not be installed because part of the MetaTrader folder could not be found. " +
                               "Please make sure MetaTrader is installed correctly and try again.";
                    case LocalFileFailureKind.VerificationFailed:
                        return "Nutricula could not be installed because one of its own installation files is missing or " +
                               "corrupted inside this installer. This is not a problem with your computer - please " +
                               "re-download the Nutricula installer (or rebuild it, if you are the developer) and try again.";
                    default:
                        return "Nutricula could not be installed due to an unexpected file system error. " +
                               "Please close MetaTrader and try again.";
                }
            }

            // ---- Server request never completed (network/local key issues) ----
            //
            // Security note: HTTP status codes, and the distinction between an
            // empty/corrupted/undecryptable/malformed response, are deliberately
            // NOT exposed here anymore - each of those specifics is still fully
            // captured in the log for support purposes, but showing them in the
            // banner would let anyone probing the installer's behavior fingerprint
            // the server (e.g. confirm a WAF/rate-limiter exists, or confirm a
            // decryption step exists) without offering the legitimate user any
            // extra way to fix the problem beyond "check your connection and
            // try again" / "try again later" anyway.
            public static string ForIncompleteServerRequest(ServerResult serverResult)
            {
                if (serverResult == null)
                {
                    return "We couldn't connect to the Nutricula server. Please check your internet connection and try again.";
                }

                switch (serverResult.FailureKind)
                {
                    // Security note: merged into one generic message -
                    // separately naming "computer identity" and "device
                    // security key" as distinct failure points would confirm
                    // to anyone probing the installer that two separate,
                    // named mechanisms exist internally. A single vague
                    // message gives a legitimate user the same next step
                    // (retry, then contact support) without confirming
                    // anything about how the client-side identity/security
                    // layer is actually built.
                    case ServerFailureKind.MachineIdUnavailable:
                    case ServerFailureKind.DeviceSecurityUnavailable:
                        return "We couldn't complete this operation on this computer. " +
                               "Please try again, or contact support if this continues.";
                    case ServerFailureKind.SelfIntegrityFailed:
                        return "This installer file appears to be corrupted or damaged and cannot be used. Please " +
                               "download a fresh copy of the Nutricula installer from the official Nutricula " +
                               "website: www.NutriculaExpert.com";
                    case ServerFailureKind.Timeout:
                        return "The Nutricula server did not respond in time. Please check your internet connection and try again.";
                    case ServerFailureKind.HttpError:
                    case ServerFailureKind.EmptyResponse:
                    case ServerFailureKind.DecryptionFailed:
                    case ServerFailureKind.UnrecognizedFormat:
                        return "The Nutricula server could not process the request right now. Please try again in a few minutes.";
                    case ServerFailureKind.ConnectionProblem:
                    default:
                        return "We couldn't connect to the Nutricula server. Please check your internet connection and try again.";
                }
            }

            // ---- Structured/legacy rejection from the server ----
            //
            // Security note: signup_identity_mismatch, transfer_key_invalid,
            // transfer_key_already_used, purchase_key_invalid, and transfer's
            // license_not_found are deliberately merged into ONE message below.
            // Signup and Transfer validate several things in a fixed order
            // (transfer key, then purchase key, then the matching license
            // record) - showing a DIFFERENT message for each specific step
            // would let someone probing with a stolen/guessed value learn
            // exactly which one of their guesses was correct, one field at a
            // time. A single, undifferentiated "please double-check your
            // information" response gives a legitimate customer everything
            // they actually need to act on, without leaking which check they
            // passed. The real, specific reason is still recorded server-side
            // and in this app's log for support to look up directly if needed.
            public static string ForRejection(InstallMode mode, string reason)
            {
                if (string.IsNullOrEmpty(reason))
                {
                    return mode == InstallMode.Premium
                        ? "Your license could not be activated. Please make sure the email and purchase key you " +
                          "entered are correct. You can currently only use the free version of Nutricula."
                        : "Your license could not be transferred. Please make sure the information you entered is " +
                          "correct. You can currently only use the free version of Nutricula.";
                }

                switch (reason)
                {
                    // Shared between Signup and Transfer - reaching either of
                    // these already required the correct email + purchase key
                    // for a real, matching license, so distinguishing them
                    // doesn't help anyone but the legitimate account holder.
                    case "license_inactive":
                        return "This license has been deactivated. Please contact support.";
                    case "license_expired":
                        return "This license has expired. Please renew your license to continue.";

                    // Reaching too_early already required an exact match on
                    // email, purchase key, this computer's machine ID, AND its
                    // device key - i.e. genuinely being the license's existing,
                    // already-verified owner. Safe to state plainly.
                    case "too_early":
                        return "This license was checked very recently. Please wait a while and try again.";

                    // Clone-detection block (see the rotating refresh-token
                    // design) - reaching this already required the correct
                    // email + purchase key, so it's safe to state plainly.
                    case "blocked":
                        return "Your license has been temporarily restricted. Please try again after 24 hours. " +
                               "For more information, please contact Nutricula support.";

                    // Transfer only - already implies genuine ownership of a
                    // valid, matching transfer key and license, so no
                    // enumeration concern.
                    case "transfer_same_machine":
                        return "This license is already active on this computer. No transfer is needed.";

                    // Internal server-side error conditions - merged into one,
                    // since distinguishing "conflict" from "failed" reveals
                    // implementation detail (e.g. a database race) with no
                    // benefit to the user.
                    // This device (its cryptographic device key) already
                    // holds a different, existing license for this exact
                    // product - reached from either signup.php's INSERT or
                    // transfer.php's UPDATE hitting the same uq_product_device
                    // database constraint. Deliberately NOT grouped with the
                    // generic "temporary server error" messages below - this
                    // is a permanent, non-retryable outcome for this exact
                    // device, with clear, specific guidance for the user.
                    // VPS IP-Binding: reached when this install was detected
                    // as a VPS (device_type=windows_vm) but the server could
                    // not determine a valid connecting IP to bind the
                    // license to at all - should be essentially unreachable
                    // in practice (nutricula_client_ip() already validates
                    // REMOTE_ADDR before this point), so this message stays
                    // generic rather than exposing the internal reason.
                    case "vps_ip_unavailable":
                        return "This license could not be activated on this VPS right now. " +
                               "Please try again in a moment, or contact Nutricula support if this continues.";

                    case "device_already_licensed":
                        return "This device has already been used to register another license. " +
                               "Please either activate your license on a different device, or contact support.";

                    // 2026 hardening: both of this computer's possible
                    // identifiers already belong to OTHER, genuinely
                    // different computers' active licenses - an extremely
                    // rare hardware-signal coincidence. Distinct from
                    // device_already_licensed above (which fires when the
                    // conflict is proven to be THIS exact computer).
                    case "machine_already_licensed":
                        return "This computer's identifying information conflicts with another active license, " +
                               "and no fallback identifier is available either. Please contact Nutricula support " +
                               "for help activating your license on this computer.";

                    case "signup_conflict":
                    case "signup_failed":
                    case "transfer_failed":
                        return "A temporary server error occurred. Please try again in a moment.";

                    // See the security note above the method - these five are
                    // deliberately indistinguishable from each other.
                    case "signup_identity_mismatch":
                    case "transfer_key_invalid":
                    case "transfer_key_already_used":
                    case "purchase_key_invalid":
                    case "license_not_found":
                        return mode == InstallMode.Transfer
                            ? "The information you entered could not be verified. Please double-check your email, " +
                              "purchase key, and transfer key, and try again, or contact support."
                            : "The information you entered could not be verified. Please double-check your email " +
                              "and purchase key, and try again, or contact support.";

                    default:
                        // Forward-compatibility: a reason code the installer doesn't
                        // recognize yet (e.g. added to the server after this build).
                        return "Your request was rejected by the Nutricula server. Please try again, " +
                               "or contact support if this continues.";
                }
            }

            // ---- Approved by the server, but couldn't be saved locally ----
            // Security note: no longer says "verified, but could not be
            // saved" - that phrasing confirms a two-stage process (server
            // verification succeeds, THEN a separate local-save step can
            // fail), which is more architectural detail than a user needs to
            // act on the problem.
            // The license file is saved under the user's own
            // %APPDATA%\MetaQuotes\...\Common\Files, a per-user location, so
            // running as Administrator would NOT help - the only useful advice
            // is to close MetaTrader (in case it has the file locked) and
            // retry. (Previously this wrongly suggested running as Admin.)
            public const string LicenseFileSaveFailed =
                "The installation could not be completed on this computer. Please close MetaTrader " +
                "completely and try again. If this keeps happening, contact Nutricula support.";
        }
    }

    internal sealed class ProgressUpdate
    {
        public int Completed { get; private set; }
        public int Total { get; private set; }
        public int Percent
        {
            get
            {
                if (Total <= 0) return 0;
                return Math.Max(0, Math.Min(100, (int)Math.Round(Completed * 100.0 / Total)));
            }
        }
        public ProgressUpdate(int completed, int total)
        {
            Completed = completed;
            Total = total;
        }
    }
}
