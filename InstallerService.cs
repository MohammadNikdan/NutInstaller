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
                FileInstallOutcome freeOutcome = await InstallFilesAsync(terminals, token, progress, log).ConfigureAwait(true);
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
                    licenseFileOk = DeleteExistingLicenseFile(log);
                    licenseSuccess = false;
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
                string path = GetCommonLicensePath();
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

        private bool DeleteExistingLicenseFile(Action<string> log)
        {
            try
            {
                string path = GetCommonLicensePath();
                if (File.Exists(path)) File.Delete(path);
                log("Existing license file removed (server returned no).");
                return true;
            }
            catch (Exception ex)
            {
                log("Could not remove existing license file: " + ex.Message);
                return false;
            }
        }

        private static Task EnsureDirectoryAsync(string path)
        {
            Directory.CreateDirectory(path);
            return Task.FromResult(true);
        }

        private static void VerifyInstalledFile(string path)
        {
            if (!File.Exists(path)) throw new IOException("The file could not be verified after installation: " + path);
            if (new FileInfo(path).Length <= 0) throw new IOException("The installed file is empty: " + path);
        }

        private static async Task CopyEmbeddedResourceAsync(ResourceItem item, string destinationDirectory, CancellationToken token)
        {
            var assembly = typeof(InstallerService).Assembly;
            using (Stream input = assembly.GetManifestResourceStream(item.ManifestName))
            {
                if (input == null) throw new FileNotFoundException("Embedded resource not found: " + item.ManifestName);
                string destination = Path.Combine(destinationDirectory, item.FileName);
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
                "\n\nDon't forget to open Tools > Options in MetaTrader, go to the Experts tab, check " +
                "Allow algorithmic (automated) trading and Allow DLL imports, and uncheck the other options, " +
                "so Nutricula can work correctly.";

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
                    case LocalFileFailureKind.PathTooLong:
                        return "Nutricula could not be installed because the installation path is too long. " +
                               "Please move MetaTrader to a shorter path and try again.";
                    case LocalFileFailureKind.PathNotFound:
                        return "Nutricula could not be installed because part of the MetaTrader folder could not be found. " +
                               "Please make sure MetaTrader is installed correctly and try again.";
                    default:
                        return "Nutricula could not be installed due to an unexpected file system error. " +
                               "Please close MetaTrader and try again.";
                }
            }

            // ---- Server request never completed (network/local key issues) ----
            public static string ForIncompleteServerRequest(ServerResult serverResult)
            {
                if (serverResult == null)
                {
                    return "We couldn't connect to the license server. Please check your internet connection and try again.";
                }

                switch (serverResult.FailureKind)
                {
                    case ServerFailureKind.MachineIdUnavailable:
                        return "This computer's identity could not be determined, so a license could not be requested. " +
                               "Please try again.";
                    case ServerFailureKind.DeviceSecurityUnavailable:
                        return "This computer's device security key could not be created or loaded. Please try again.";
                    case ServerFailureKind.Timeout:
                        return "The license server did not respond in time. Please check your internet connection and try again.";
                    case ServerFailureKind.HttpError:
                        if (serverResult.HttpStatusCode == 404)
                            return "The license server address appears to be misconfigured (error 404). Please contact support.";
                        if (serverResult.HttpStatusCode == 429)
                            return "Too many requests were sent in a short time. Please wait a few minutes and try again.";
                        return "The license server encountered a problem (error " + serverResult.HttpStatusCode +
                               "). Please try again in a few minutes.";
                    case ServerFailureKind.EmptyResponse:
                        return "The license server returned an empty response. Please try again.";
                    case ServerFailureKind.DecryptionFailed:
                        return "The license server's response could not be verified. Please try again, " +
                               "or contact support if this continues.";
                    case ServerFailureKind.UnrecognizedFormat:
                        return "The license server returned an unexpected response. Please try again, " +
                               "or contact support if this continues.";
                    case ServerFailureKind.ConnectionProblem:
                    default:
                        return "We couldn't connect to the license server. Please check your internet connection and try again.";
                }
            }

            // ---- Structured/legacy rejection from the server ----
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
                    // Shared between Signup and Transfer
                    case "license_inactive":
                        return "This license has been deactivated. Please contact support.";
                    case "license_expired":
                        return "This license has expired. Please renew your license to continue.";

                    // Signup-specific
                    case "too_early":
                        return "This license was checked very recently. Please wait a while and try again.";
                    case "signup_identity_mismatch":
                        return "This purchase key is already registered to a different email or a different " +
                               "computer. Please contact support if you believe this is a mistake.";
                    case "signup_conflict":
                        return "This purchase key is already being used. Please try again in a moment.";
                    case "signup_failed":
                        return "Your license could not be created due to a server error. Please try again.";

                    // Transfer-specific
                    case "transfer_key_invalid":
                        return "The transfer key you entered is not valid, or does not match the email you entered. " +
                               "Please check and try again.";
                    case "transfer_key_already_used":
                        return "This transfer key has already been used. Each transfer key can only be used once.";
                    case "purchase_key_invalid":
                        return "The purchase key you entered is not valid, or does not match the email you entered. " +
                               "Please check and try again.";
                    case "license_not_found":
                        return "No active license was found for this purchase key. Please activate your license " +
                               "first before transferring it.";
                    case "transfer_same_machine":
                        return "This license is already active on this computer. No transfer is needed.";
                    case "transfer_failed":
                        return "Your license could not be transferred due to a server error. Please try again.";

                    default:
                        // Forward-compatibility: a reason code the installer doesn't
                        // recognize yet (e.g. added to the server after this build).
                        return "Your request was rejected by the license server. Please try again, " +
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
