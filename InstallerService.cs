using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace NutriculaInstaller
{
    internal sealed class InstallerService
    {
        // ===== EASY-TO-FIND SETTINGS =====
        public const string PremiumUrl = "https://nutriculaexpert.com/login2/nutricula_computer_based_signup.php";
        public const string TransferUrl = "https://nutriculaexpert.com/login2/nutricula_computer_based_signup_transfer.php";
        private const string LicenseFileName = "NutriculaLicense.txt";
        private readonly TerminalDiscoveryService discovery = new TerminalDiscoveryService();

        public string GetCommonLicensePath()
        {
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

            // DiscoverTerminals performs a synchronous disk/registry scan. Running it
            // directly here would block the calling (UI) thread until it finishes.
            // Task.Run moves that scan to a background thread; nothing about what it
            // does or what it returns changes.
            List<TerminalInfo> terminals = await Task.Run(
                () => DiscoverTerminals(log)
            ).ConfigureAwait(true);

            result.Mt4Count = terminals.Count(t => t.Type == TerminalType.MT4);
            result.Mt5Count = terminals.Count(t => t.Type == TerminalType.MT5);

            if (terminals.Count == 0)
            {
                result.Errors.Add("No MetaTrader 4 or MetaTrader 5 terminal was found on this computer.");
                result.FinalMessage = "No compatible MetaTrader installation was found.";
                result.FilesInstalled = false;
                result.ServerRequestFinished = mode == InstallMode.Free;
                result.LicenseFileOperationFinished = mode == InstallMode.Free;
                result.LicenseSucceeded = mode == InstallMode.Free;
                result.OverallSuccess = false;
                return result;
            }

            // ============================================================
            // FREE INSTALL
            // ============================================================
            if (mode == InstallMode.Free)
            {
                result.FilesInstalled = await InstallFilesAsync(
                    terminals,
                    token,
                    progress,
                    log
                ).ConfigureAwait(true);

                result.ServerRequestFinished = true;
                result.LicenseFileOperationFinished = true;
                result.LicenseSucceeded = result.FilesInstalled;
                result.OverallSuccess = result.FilesInstalled;

                result.FinalMessage = result.FilesInstalled
                    ? "Nutricula Free Version was installed successfully."
                    : "Nutricula could not be installed. Please close MetaTrader and try again.";

                return result;
            }

            // ============================================================
            // PREMIUM / TRANSFER
            //
            // Both operations begin without waiting for one another.
            // ============================================================
            Task<bool> installTask = InstallFilesAsync(
                terminals,
                token,
                progress,
                log
            );

            Task<ServerResult> serverTask = RequestLicenseAsync(
                mode,
                email,
                purchaseKey,
                transferKey,
                token,
                log
            );

            bool filesOk = false;
            ServerResult serverResult = null;

            try
            {
                await Task.WhenAll(installTask, serverTask).ConfigureAwait(true);

                filesOk = installTask.Result;
                serverResult = serverTask.Result;
            }
            catch (Exception ex)
            {
                log("Parallel operation error: " + ex.Message);

                if (installTask.Status == TaskStatus.RanToCompletion)
                    filesOk = installTask.Result;

                if (serverTask.Status == TaskStatus.RanToCompletion)
                    serverResult = serverTask.Result;
            }

            result.FilesInstalled = filesOk;
            result.ServerRequestFinished =
                serverResult != null && serverResult.Completed;

            result.ServerResponse =
                serverResult == null ? null : serverResult.RawResponse;

            bool licenseFileOk = false;
            bool licenseSuccess = false;

            // ============================================================
            // SERVER RESULT
            // ============================================================
            if (serverResult != null && serverResult.Completed)
            {
                // The server response has already been validated and
                // successfully decrypted inside RequestLicenseAsync().
                //
                // The decrypted response is used ONLY to determine whether
                // the server returned the exact plaintext value "no".
                //
                // For a successful non-"no" response, the EXACT ORIGINAL
                // encrypted bytes received from the server are saved.
                if (serverResult.ServerReturnedNo)
                {
                    licenseFileOk = DeleteExistingLicenseFile(log);
                    licenseSuccess = false;
                }
                else
                {
                    licenseFileOk = WriteRawLicenseFile(
                        serverResult.RawResponseBytes,
                        log
                    );

                    licenseSuccess = licenseFileOk;
                }
            }
            else
            {
                licenseFileOk = false;
                licenseSuccess = false;
            }

            result.LicenseFileOperationFinished = licenseFileOk;
            result.LicenseSucceeded = licenseSuccess;

            // EVERYTHING must succeed.
            result.OverallSuccess =
                filesOk &&
                result.ServerRequestFinished &&
                licenseFileOk &&
                licenseSuccess;

            // ============================================================
            // FINAL USER MESSAGE
            // ============================================================

            // 1. Installation itself failed.
            //
            // This is intentionally checked first because even if the server
            // operation also failed, the user must know that local file
            // installation was not completed successfully.
            if (!filesOk)
            {
                result.FinalMessage =
                    "Nutricula could not be installed completely. " +
                    "Please close MetaTrader and try again.";
            }

            // 2. No valid server response / network / HTTP problem.
            else if (!result.ServerRequestFinished)
            {
                if (serverResult != null &&
                    serverResult.FailureKind == ServerFailureKind.MachineIdUnavailable)
                {
                    result.FinalMessage =
                        "This computer's identity could not be determined, so a license " +
                        "could not be requested. Please try again, and if this keeps " +
                        "happening, contact support.";
                }
                else if (serverResult != null &&
                    serverResult.FailureKind == ServerFailureKind.InvalidResponse)
                {
                    result.FinalMessage =
                        "The license server returned an invalid response. " +
                        "Please try again.";
                }
                else
                {
                    result.FinalMessage =
                        "We couldn't connect to the license server. " +
                        "Please check your internet connection and try again.";
                }
            }

            // 3. Server returned a valid "no".
            else if (serverResult.ServerReturnedNo)
            {
                result.FinalMessage =
                    mode == InstallMode.Premium
                        ? "Your license was not activated. Please make sure the information you entered is correct. You can currently only use the free version of Nutricula."
                        : "Your license was not transferred to this computer. Please make sure the information you entered is correct. You can currently only use the free version of Nutricula.";
            }

            // 4. Server response was successful, but writing/removing the
            // local license file failed.
            else if (!licenseFileOk)
            {
                result.FinalMessage =
                    "Your license was verified, but it could not be saved on this computer. Please try again.";
            }

            // 5. EVERYTHING succeeded.
            else
            {
                result.FinalMessage =
                    mode == InstallMode.Premium
                        ? "Nutricula was installed and your license was successfully activated."
                        : "Nutricula was installed and your license was successfully transferred to this computer.";
            }

            return result;
        }

        private async Task<bool> InstallFilesAsync(
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

            var tasks = terminals.Select(async terminal =>
            {
                try
                {
                    token.ThrowIfCancellationRequested();

                    await EnsureDirectoryAsync(terminal.LibrariesPath)
                        .ConfigureAwait(true);

                    await EnsureDirectoryAsync(terminal.ExpertsPath)
                        .ConfigureAwait(true);

                    // MathUtils.dll
                    await CopyEmbeddedResourceAsync(
                        resources[4],
                        terminal.LibrariesPath,
                        token
                    ).ConfigureAwait(true);

                    // Make sure the file really exists after installation.
                    VerifyInstalledFile(
                        Path.Combine(terminal.LibrariesPath, resources[4].FileName)
                    );

                    ReportOne(
                        "Copied MathUtils.dll -> " +
                        terminal.LibrariesPath
                    );

                    lock (progressLock)
                    {
                        completed++;
                        progress.Report(
                            new ProgressUpdate(
                                completed,
                                totalOperations
                            )
                        );
                    }

                    // MT4
                    if (terminal.Type == TerminalType.MT4)
                    {
                        await CopyEmbeddedResourceAsync(
                            resources[1],
                            terminal.ExpertsPath,
                            token
                        ).ConfigureAwait(true);

                        await CopyEmbeddedResourceAsync(
                            resources[3],
                            terminal.ExpertsPath,
                            token
                        ).ConfigureAwait(true);

                        VerifyInstalledFile(
                            Path.Combine(
                                terminal.ExpertsPath,
                                resources[1].FileName
                            )
                        );

                        VerifyInstalledFile(
                            Path.Combine(
                                terminal.ExpertsPath,
                                resources[3].FileName
                            )
                        );
                    }
                    // MT5
                    else
                    {
                        await CopyEmbeddedResourceAsync(
                            resources[0],
                            terminal.ExpertsPath,
                            token
                        ).ConfigureAwait(true);

                        await CopyEmbeddedResourceAsync(
                            resources[2],
                            terminal.ExpertsPath,
                            token
                        ).ConfigureAwait(true);

                        VerifyInstalledFile(
                            Path.Combine(
                                terminal.ExpertsPath,
                                resources[0].FileName
                            )
                        );

                        VerifyInstalledFile(
                            Path.Combine(
                                terminal.ExpertsPath,
                                resources[2].FileName
                            )
                        );
                    }

                    lock (progressLock)
                    {
                        completed += 2;
                        progress.Report(
                            new ProgressUpdate(
                                completed,
                                totalOperations
                            )
                        );
                    }

                    ReportOne(
                        "Installed " +
                        terminal.Type +
                        " files -> " +
                        terminal.TerminalPath
                    );
                }
                catch (Exception ex)
                {
                    System.Threading.Interlocked.Exchange(
                        ref allSucceededFlag,
                        0
                    );

                    ReportOne(
                        "FAILED " +
                        terminal.Type +
                        " -> " +
                        terminal.TerminalPath +
                        " | " +
                        ex.Message
                    );
                }
            }).ToArray();

            await Task.WhenAll(tasks).ConfigureAwait(true);

            return
                System.Threading.Interlocked.CompareExchange(
                    ref allSucceededFlag,
                    0,
                    0
                ) == 1;

            void ReportOne(string message)
            {
                log(message);
            }
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
                // Previously this exception was left to fault the task, which made it
                // surface to the user as a generic "check your internet connection"
                // message - misleading, since the real cause has nothing to do with
                // connectivity. Reporting it as its own ServerResult with a distinct
                // FailureKind lets RunAsync show an accurate message instead.
                return new ServerResult
                {
                    Completed = false,
                    FailureKind = ServerFailureKind.MachineIdUnavailable,
                    Error = ex
                };
            }

            // Empty for physical machines - only VMs collect an IP at all. Sent
            // separately (not just inside the machine_id hash) because machine_id is
            // a one-way SHA-256 hash and the server cannot recover this value from
            // it afterwards; sending it lets the server compare it against the
            // connection's real, unforgeable source IP.
            string localIp = MachineIdService.GetLastClientIp();

            string rndNumber = CryptoService.Generate32DigitRandomNumber();

            string encodedPostData = CryptoService.BuildPostData(
                email,
                purchaseKey,
                machineId,
                rndNumber,
                mode == InstallMode.Transfer ? transferKey : null,
                localIp
            );

            string baseUrl =
                mode == InstallMode.Premium
                    ? PremiumUrl
                    : TransferUrl;

            log("Machine ID generated: " + machineId);
            log("Sending license request...");

            try
            {
                ServicePointManager.SecurityProtocol =
                    SecurityProtocolType.Tls12 |
                    SecurityProtocolType.Tls11 |
                    SecurityProtocolType.Tls;

                using (HttpClientHandler handler = new HttpClientHandler())
                using (HttpClient client = new HttpClient(handler))
                using (HttpRequestMessage request =
                    new HttpRequestMessage(HttpMethod.Post, baseUrl))
                {
                    client.Timeout = TimeSpan.FromSeconds(60);

                    request.Headers.UserAgent.ParseAdd(
                        "NutriculaExpertInstaller/1.0"
                    );

                    request.Content = new FormUrlEncodedContent(
                        new[]
                        {
                            new KeyValuePair<string, string>("data", encodedPostData)
                        }
                    );

                    using (HttpResponseMessage response =
                        await client.SendAsync(
                            request,
                            HttpCompletionOption.ResponseContentRead,
                            token
                        ).ConfigureAwait(true))
                    {
                        log(
                            "Server HTTP status: " +
                            (int)response.StatusCode +
                            " " +
                            response.ReasonPhrase
                        );

                        // ONLY HTTP 200 is accepted as a valid license response.
                        if (response.StatusCode != HttpStatusCode.OK)
                        {
                            log(
                                "License request failed because HTTP status was not 200."
                            );

                            return new ServerResult
                            {
                                Completed = false,
                                FailureKind = ServerFailureKind.ConnectionProblem,
                                Error = new HttpRequestException(
                                    "Unexpected HTTP status: " +
                                    (int)response.StatusCode +
                                    " " +
                                    response.ReasonPhrase
                                )
                            };
                        }

                        byte[] rawBytes =
                            await response.Content.ReadAsByteArrayAsync()
                                .ConfigureAwait(true);

                        log(
                            "Server response length: " +
                            rawBytes.Length +
                            " bytes"
                        );

                        // A 200 response with no body is not a valid license response.
                        if (rawBytes == null || rawBytes.Length == 0)
                        {
                            log("Server returned HTTP 200 with an empty body.");

                            return new ServerResult
                            {
                                Completed = false,
                                FailureKind = ServerFailureKind.InvalidResponse,
                                RawResponse = string.Empty,
                                RawResponseBytes = rawBytes,
                                Error = new InvalidOperationException(
                                    "Server returned an empty response."
                                )
                            };
                        }

                        string rawResponse =
                            Encoding.UTF8.GetString(rawBytes);

                        // Validate/decrypt the response HERE.
                        //
                        // This is important:
                        // A 200 response is NOT considered successful merely
                        // because it exists. It must also be a valid encrypted
                        // response that can be decrypted successfully.
                        string decryptedResponse;

                        try
                        {
                            decryptedResponse =
                                DecryptServerResponse(rawResponse);
                        }
                        catch (Exception ex)
                        {
                            log(
                                "Server response decryption failed: " +
                                ex.Message
                            );

                            return new ServerResult
                            {
                                Completed = false,
                                FailureKind = ServerFailureKind.InvalidResponse,
                                RawResponse = rawResponse,
                                RawResponseBytes = rawBytes,
                                Error = ex
                            };
                        }

                        bool serverReturnedNo =
                            string.Equals(
                                decryptedResponse,
                                "no",
                                StringComparison.Ordinal
                            );

                        log(
                            "Server response decrypted successfully for validation."
                        );

                        return new ServerResult
                        {
                            Completed = true,
                            FailureKind = ServerFailureKind.None,
                            RawResponse = rawResponse,
                            RawResponseBytes = rawBytes,
                            ServerReturnedNo = serverReturnedNo
                        };
                    }
                }
            }
            catch (OperationCanceledException ex)
            {
                // If the user/application itself cancelled the request,
                // keep the cancellation semantics intact.
                if (token.IsCancellationRequested)
                    throw;

                // HttpClient timeout arrives here as TaskCanceledException /
                // OperationCanceledException even though the user's token was
                // not cancelled. Treat it as a connection problem.
                log(
                    "Server request timed out: " +
                    ex.Message
                );

                return new ServerResult
                {
                    Completed = false,
                    FailureKind = ServerFailureKind.ConnectionProblem,
                    Error = ex
                };
            }
            catch (Exception ex)
            {
                log(
                    "Server request failed: " +
                    ex.Message
                );

                return new ServerResult
                {
                    Completed = false,
                    FailureKind = ServerFailureKind.ConnectionProblem,
                    Error = ex
                };
            }
        }

        private static string DecryptServerResponse(string rawResponse)
        {
            if (string.IsNullOrWhiteSpace(rawResponse))
                throw new InvalidOperationException(
                    "Server response is empty."
                );

            // This is the SAME AES-256 key and the SAME AES/ECB/ZeroPadding
            // configuration used by CryptoService.Encoder().
            // The response path is simply the reverse: Base64 decode first,
            // then AES decrypt.
            const string aesKey =
                "lj1@91!23867871jbhlk*&GS^madf^&!";

            byte[] key = Encoding.UTF8.GetBytes(aesKey);

            if (key.Length != 32)
                throw new InvalidOperationException(
                    "AES key must be exactly 32 bytes."
                );

            byte[] ciphertext =
                Convert.FromBase64String(rawResponse);

            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.Zeros;
                aes.IV = new byte[16];

                using (ICryptoTransform decryptor =
                    aes.CreateDecryptor())
                {
                    byte[] plaintext =
                        decryptor.TransformFinalBlock(
                            ciphertext,
                            0,
                            ciphertext.Length
                        );

                    return Encoding.UTF8
                        .GetString(plaintext)
                        .TrimEnd('\0');
                }
            }
        }

        private bool WriteRawLicenseFile(
            byte[] rawResponseBytes,
            Action<string> log)
        {
            try
            {
                string path = GetCommonLicensePath();
                string dir = Path.GetDirectoryName(path);

                if (string.IsNullOrEmpty(dir))
                    throw new IOException(
                        "Could not determine Common\\Files directory."
                    );

                Directory.CreateDirectory(dir);

                if (File.Exists(path))
                    File.Delete(path);

                // Write EXACT bytes received from the server.
                // No trim, parsing, decoding/re-encoding or transformation.
                File.WriteAllBytes(
                    path,
                    rawResponseBytes ?? new byte[0]
                );

                // Verify that the file actually exists and is non-empty.
                if (!File.Exists(path))
                    throw new IOException(
                        "License file was not created."
                    );

                if (rawResponseBytes != null &&
                    new FileInfo(path).Length != rawResponseBytes.Length)
                {
                    throw new IOException(
                        "License file size verification failed."
                    );
                }

                log(
                    "License response saved: " +
                    path
                );

                return true;
            }
            catch (Exception ex)
            {
                log(
                    "License file write failed: " +
                    ex.Message
                );

                return false;
            }
        }

        private bool DeleteExistingLicenseFile(
            Action<string> log)
        {
            try
            {
                string path = GetCommonLicensePath();

                if (File.Exists(path))
                    File.Delete(path);

                log(
                    "Existing license file removed " +
                    "(server returned no)."
                );

                return true;
            }
            catch (Exception ex)
            {
                log(
                    "Could not remove existing license file: " +
                    ex.Message
                );

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
            if (!File.Exists(path))
            {
                throw new IOException(
                    "The file could not be verified after installation: " +
                    path
                );
            }

            FileInfo info = new FileInfo(path);

            if (info.Length <= 0)
            {
                throw new IOException(
                    "The installed file is empty: " +
                    path
                );
            }
        }

        private static async Task CopyEmbeddedResourceAsync(
            ResourceItem item,
            string destinationDirectory,
            CancellationToken token)
        {
            var assembly = typeof(InstallerService).Assembly;

            using (Stream input =
                assembly.GetManifestResourceStream(
                    item.ManifestName))
            {
                if (input == null)
                {
                    throw new FileNotFoundException(
                        "Embedded resource not found: " +
                        item.ManifestName
                    );
                }

                string destination =
                    Path.Combine(
                        destinationDirectory,
                        item.FileName
                    );

                string temp =
                    destination +
                    ".nutricula_tmp";

                // Write to a temporary file first.
                //
                // If the target DLL/EX4/EX5 is locked by MetaTrader,
                // deleting/replacing the destination will fail here and
                // the whole terminal installation will be marked as failed.
                using (FileStream output =
                    new FileStream(
                        temp,
                        FileMode.Create,
                        FileAccess.Write,
                        FileShare.None,
                        64 * 1024,
                        true))
                {
                    await input.CopyToAsync(
                        output,
                        64 * 1024,
                        token
                    ).ConfigureAwait(true);
                }

                if (File.Exists(destination))
                    File.Delete(destination);

                File.Move(
                    temp,
                    destination
                );
            }
        }

        private sealed class ResourceItem
        {
            public string FileName { get; private set; }
            public string ManifestName { get; private set; }

            public ResourceItem(
                string fileName,
                string manifestName)
            {
                FileName = fileName;
                ManifestName = manifestName;
            }
        }

        private enum ServerFailureKind
        {
            None,
            ConnectionProblem,
            InvalidResponse,
            MachineIdUnavailable
        }

        private sealed class ServerResult
        {
            public bool Completed { get; set; }

            public bool ServerReturnedNo { get; set; }

            public string RawResponse { get; set; }

            public byte[] RawResponseBytes { get; set; }

            public Exception Error { get; set; }

            public ServerFailureKind FailureKind { get; set; }
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
                if (Total <= 0)
                    return 0;

                return Math.Max(
                    0,
                    Math.Min(
                        100,
                        (int)Math.Round(
                            Completed * 100.0 / Total
                        )
                    )
                );
            }
        }

        public ProgressUpdate(
            int completed,
            int total)
        {
            Completed = completed;
            Total = total;
        }
    }
}
