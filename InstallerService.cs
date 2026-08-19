using System;
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
        public const string PremiumUrl = "https://nutriculaexpert.com/login2/nutricula_computer_based_signup.php";
        public const string TransferUrl = "https://nutriculaexpert.com/login2/nutricula_computer_based_signup_transfer.php";
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

        public async Task<InstallResult> RunAsync(
            InstallMode mode,
            string email,
            string purchaseKey,
            string transferKey,
            CancellationToken token,
            IProgress<ProgressUpdate> progress,
            Action<string> log)
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
                Task<FileInstallOutcome> freeInstallTask = InstallFilesAsync(terminals, token, progress, log);

                /* Best-effort only: creates (or confirms) this computer's
                   machine ID and device key pair so an identity already
                   exists locally for later use (e.g. unlicensed-usage
                   statistics, or a future upgrade to Premium) - but a Free
                   install must always proceed regardless of whether this
                   succeeds, unlike Premium/Transfer where the same failure
                   is blocking. Deliberately not awaited together with a
                   throwing continuation - failures are only logged. */
                Task freeIdentityTask = TryEnsureDeviceIdentityAsync(log);

                await Task.WhenAll(freeInstallTask, freeIdentityTask).ConfigureAwait(true);
                FileInstallOutcome freeOutcome = freeInstallTask.Result;

                result.FilesInstalled = freeOutcome.AllSucceeded;
                result.ServerRequestFinished = true;
                result.LicenseFileOperationFinished = true;
                result.LicenseSucceeded = freeOutcome.AllSucceeded;
                result.OverallSuccess = freeOutcome.AllSucceeded;
                result.FinalMessage = freeOutcome.AllSucceeded
                    ? Messages.FreeSuccess
                    : Messages.ForFileFailure(freeOutcome.FailureKind);
                return result;
            }

            Task<FileInstallOutcome> installTask = InstallFilesAsync(terminals, token, progress, log);
            Task<ServerResult> serverTask = RequestLicenseAsync(mode, email, purchaseKey, transferKey, token, log);

            FileInstallOutcome fileOutcome = new FileInstallOutcome(false, LocalFileFailureKind.Unknown);
            ServerResult serverResult = null;

            try
            {
                await Task.WhenAll(installTask, serverTask).ConfigureAwait(true);
                fileOutcome = installTask.Result;
                serverResult = serverTask.Result;
            }
            catch (Exception ex)
            {
                log("Parallel operation error: " + ex.Message);
                if (installTask.Status == TaskStatus.RanToCompletion) fileOutcome = installTask.Result;
                if (serverTask.Status == TaskStatus.RanToCompletion) serverResult = serverTask.Result;
            }

            result.FilesInstalled = fileOutcome.AllSucceeded;
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

            // Everything succeeded.
            return mode == InstallMode.Premium ? Messages.PremiumSuccess : Messages.TransferSuccess;
        }

        /// <summary>
        /// Best-effort only - creates (or confirms) this computer's machine ID
        /// and device key pair for Free installs, purely so an identity
        /// already exists locally for later use. Never throws: any failure
        /// is caught and logged, never surfaced as an error to the user,
        /// since a Free install must always be allowed to proceed regardless
        /// of machine identity issues (unlike Premium/Transfer, where the
        /// same failure blocks the license request - see RequestLicenseAsync).
        /// </summary>
        private static Task TryEnsureDeviceIdentityAsync(Action<string> log)
        {
            return Task.Run(delegate
            {
                try
                {
                    string machineId = MachineIdService.GenerateComputerId();
                    MachineIdService.GetDevicePublicKey();
                    log("Device identity confirmed for free install (machine ID: " + machineId + ").");
                }
                catch (Exception ex)
                {
                    // Non-blocking by design - see summary above. This is a
                    // plain diagnostic log line, not a user-facing message -
                    // it never affects the install's success/failure or the
                    // final banner shown to the user.
                    log("Device identity could not be set up during free install (does not affect the install): " + ex.Message);
                }
            });
        }

        private async Task<FileInstallOutcome> InstallFilesAsync(
            List<TerminalInfo> terminals,
            CancellationToken token,
            IProgress<ProgressUpdate> progress,
            Action<string> log)
        {
            ResourceItem[] resources = new ResourceItem[]
            {
                new ResourceItem("Nutricula.ex5", "NutriculaInstaller.Assets.Nutricula.ex5"),
                new ResourceItem("Nutricula.ex4", "NutriculaInstaller.Assets.Nutricula.ex4"),
                new ResourceItem("Nutricula.ex5.sig", "NutriculaInstaller.Assets.Nutricula.ex5.sig"),
                new ResourceItem("Nutricula.ex4.sig", "NutriculaInstaller.Assets.Nutricula.ex4.sig"),
                new ResourceItem("MathUtils.dll", "NutriculaInstaller.Assets.MathUtils.dll")
            };

            int totalOperations = terminals.Count * 3;
            int completed = 0;
            int allSucceededFlag = 1;
            object progressLock = new object();
            object failureLock = new object();
            LocalFileFailureKind worstFailure = LocalFileFailureKind.None;

            var tasks = terminals.Select(async terminal =>
            {
                try
                {
                    token.ThrowIfCancellationRequested();
                    await EnsureDirectoryAsync(terminal.LibrariesPath).ConfigureAwait(true);
                    await EnsureDirectoryAsync(terminal.ExpertsPath).ConfigureAwait(true);

                    await CopyEmbeddedResourceAsync(resources[4], terminal.LibrariesPath, token).ConfigureAwait(true);
                    VerifyInstalledFile(Path.Combine(terminal.LibrariesPath, resources[4].FileName));
                    log("Copied MathUtils.dll -> " + terminal.LibrariesPath);

                    lock (progressLock)
                    {
                        completed++;
                        progress.Report(new ProgressUpdate(completed, totalOperations));
                    }

                    if (terminal.Type == TerminalType.MT4)
                    {
                        await CopyEmbeddedResourceAsync(resources[1], terminal.ExpertsPath, token).ConfigureAwait(true);
                        await CopyEmbeddedResourceAsync(resources[3], terminal.ExpertsPath, token).ConfigureAwait(true);
                        VerifyInstalledFile(Path.Combine(terminal.ExpertsPath, resources[1].FileName));
                        VerifyInstalledFile(Path.Combine(terminal.ExpertsPath, resources[3].FileName));
                    }
                    else
                    {
                        await CopyEmbeddedResourceAsync(resources[0], terminal.ExpertsPath, token).ConfigureAwait(true);
                        await CopyEmbeddedResourceAsync(resources[2], terminal.ExpertsPath, token).ConfigureAwait(true);
                        VerifyInstalledFile(Path.Combine(terminal.ExpertsPath, resources[0].FileName));
                        VerifyInstalledFile(Path.Combine(terminal.ExpertsPath, resources[2].FileName));
                    }

                    lock (progressLock)
                    {
                        completed += 2;
                        progress.Report(new ProgressUpdate(completed, totalOperations));
                    }

                    log("Installed " + terminal.Type + " files -> " + terminal.TerminalPath);
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    Interlocked.Exchange(ref allSucceededFlag, 0);
                    LocalFileFailureKind kind = ClassifyLocalFileException(ex);
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
            }).ToArray();

            await Task.WhenAll(tasks).ConfigureAwait(true);
            bool allSucceeded = Interlocked.CompareExchange(ref allSucceededFlag, 0, 0) == 1;
            return new FileInstallOutcome(allSucceeded, allSucceeded ? LocalFileFailureKind.None : worstFailure);
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
            Action<string> log)
        {
            string machineId;
            try
            {
                machineId = MachineIdService.GenerateComputerId();
            }
            catch (Exception ex)
            {
                return ServerResult.Failed(ServerFailureKind.MachineIdUnavailable, ex);
            }

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
                    devicePublicKey
                );
            }
            catch (Exception ex)
            {
                return ServerResult.Failed(ServerFailureKind.DeviceSecurityUnavailable, ex);
            }

            string baseUrl = mode == InstallMode.Premium ? PremiumUrl : TransferUrl;
            log("Machine ID generated: " + machineId);
            log("Device public key loaded.");
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
                        log("Server HTTP status: " + (int)response.StatusCode + " " + response.ReasonPhrase);

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
                            log("Server response authentication/decryption failed: " + ex.Message);
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
            catch (Exception ex)
            {
                log("License file write failed: " + ex.Message);
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
            if (!File.Exists(longPath)) throw new IOException("The file could not be verified after installation: " + path);
            if (new FileInfo(longPath).Length <= 0) throw new IOException("The installed file is empty: " + path);
        }

        private static async Task CopyEmbeddedResourceAsync(ResourceItem item, string destinationDirectory, CancellationToken token)
        {
            var assembly = typeof(InstallerService).Assembly;
            using (Stream input = assembly.GetManifestResourceStream(item.ManifestName))
            {
                if (input == null) throw new FileNotFoundException("Embedded resource not found: " + item.ManifestName);
                string destination = LongPath(Path.Combine(destinationDirectory, item.FileName));
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
            DeviceSecurityUnavailable
        }

        private enum LocalFileFailureKind
        {
            None,
            DiskFull,
            AccessDenied,
            FileInUse,
            PathTooLong,
            PathNotFound,
            Unknown
        }

        private sealed class FileInstallOutcome
        {
            public bool AllSucceeded { get; private set; }
            public LocalFileFailureKind FailureKind { get; private set; }
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

            public const string PremiumSuccess =
                "Your license was successfully activated and Nutricula was installed on your computer. " +
                "You can now use the Pro version of Nutricula." + ToolsOptionsReminder;

            public const string TransferSuccess =
                "Your license was successfully transferred and Nutricula was installed on your computer. " +
                "You can now use the Pro version of Nutricula on this computer." + ToolsOptionsReminder;

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
                        return "Nutricula could not be installed because access to the MetaTrader folder was denied. " +
                               "Please run this installer as Administrator and try again.";
                    case LocalFileFailureKind.FileInUse:
                        return "Nutricula could not be installed because one of its files is currently in use. " +
                               "Please close MetaTrader completely and try again.";
                    case LocalFileFailureKind.PathNotFound:
                        return "Nutricula could not be installed because part of the MetaTrader folder could not be found. " +
                               "Please make sure MetaTrader is installed correctly and try again.";
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
                    case ServerFailureKind.MachineIdUnavailable:
                        return "This computer's identity could not be determined, so a license could not be requested. " +
                               "Please try on another computer, or contact support if this continues.";
                    case ServerFailureKind.DeviceSecurityUnavailable:
                        return "This computer's device security key could not be created or loaded. " +
                               "Please try on another computer, or contact support if this continues.";
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

                    // Transfer only - already implies genuine ownership of a
                    // valid, matching transfer key and license, so no
                    // enumeration concern.
                    case "transfer_same_machine":
                        return "This license is already active on this computer. No transfer is needed.";

                    // Internal server-side error conditions - merged into one,
                    // since distinguishing "conflict" from "failed" reveals
                    // implementation detail (e.g. a database race) with no
                    // benefit to the user.
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
            public const string LicenseFileSaveFailed =
                "Your license was verified, but it could not be saved on this computer. Please close MetaTrader " +
                "and try again, or run this installer as Administrator.";
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
