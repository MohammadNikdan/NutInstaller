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
            CancellationToken token,
            IProgress<ProgressUpdate> progress,
            Action<string> log)
        {
            InstallResult result = new InstallResult();
            List<TerminalInfo> terminals = DiscoverTerminals(log);

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

            if (mode == InstallMode.Free)
            {
                result.FilesInstalled = await InstallFilesAsync(terminals, token, progress, log).ConfigureAwait(true);
                result.ServerRequestFinished = true;
                result.LicenseFileOperationFinished = true;
                result.LicenseSucceeded = result.FilesInstalled;
                result.OverallSuccess = result.FilesInstalled;
                result.FinalMessage = result.FilesInstalled
                    ? "Nutricula Free Version was installed successfully."
                    : "Nutricula Free Version could not be installed.";
                return result;
            }

            // Both operations begin without waiting for one another.
            Task<bool> installTask = InstallFilesAsync(terminals, token, progress, log);
            Task<ServerResult> serverTask = RequestLicenseAsync(mode, email, purchaseKey, token, log);

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
                if (installTask.IsCompletedSuccessfully)
                    filesOk = installTask.Result;
                if (serverTask.IsCompletedSuccessfully)
                    serverResult = serverTask.Result;
            }

            result.FilesInstalled = filesOk;
            result.ServerRequestFinished = serverResult != null && serverResult.Completed;
            result.ServerResponse = serverResult == null ? null : serverResult.RawResponse;

            bool licenseFileOk = false;
            bool licenseSuccess = false;

            if (serverResult != null && serverResult.Completed)
            {
                if (string.Equals(serverResult.RawResponse, "no", StringComparison.Ordinal))
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
            else
            {
                licenseFileOk = false;
                licenseSuccess = false;
            }

            result.LicenseFileOperationFinished = licenseFileOk;
            result.LicenseSucceeded = licenseSuccess;
            result.OverallSuccess = filesOk && result.ServerRequestFinished && licenseFileOk && licenseSuccess;

            if (!result.ServerRequestFinished)
            {
                result.FinalMessage = mode == InstallMode.Premium
                    ? "Your license was not activated. Please make sure the information you entered is correct. You can currently only use the free version of Nutricula."
                    : "Your license was not transferred to this computer. Please make sure the information you entered is correct. You can currently only use the free version of Nutricula.";
            }
            else if (!filesOk || !licenseSuccess)
            {
                result.FinalMessage = mode == InstallMode.Premium
                    ? "Your license was not activated. Please make sure the information you entered is correct. You can currently only use the free version of Nutricula."
                    : "Your license was not transferred to this computer. Please make sure the information you entered is correct. You can currently only use the free version of Nutricula.";
            }
            else
            {
                result.FinalMessage = mode == InstallMode.Premium
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
                    await EnsureDirectoryAsync(terminal.LibrariesPath).ConfigureAwait(true);
                    await EnsureDirectoryAsync(terminal.ExpertsPath).ConfigureAwait(true);

                    await CopyEmbeddedResourceAsync(resources[4], terminal.LibrariesPath, token).ConfigureAwait(true);
                    ReportOne("Copied MathUtils.dll -> " + terminal.LibrariesPath);

                    lock (progressLock)
                    {
                        completed++;
                        progress.Report(new ProgressUpdate(completed, totalOperations));
                    }

                    if (terminal.Type == TerminalType.MT4)
                    {
                        await CopyEmbeddedResourceAsync(resources[1], terminal.ExpertsPath, token).ConfigureAwait(true);
                        await CopyEmbeddedResourceAsync(resources[3], terminal.ExpertsPath, token).ConfigureAwait(true);
                    }
                    else
                    {
                        await CopyEmbeddedResourceAsync(resources[0], terminal.ExpertsPath, token).ConfigureAwait(true);
                        await CopyEmbeddedResourceAsync(resources[2], terminal.ExpertsPath, token).ConfigureAwait(true);
                    }

                    lock (progressLock)
                    {
                        completed += 2;
                        progress.Report(new ProgressUpdate(completed, totalOperations));
                    }

                    ReportOne("Installed " + terminal.Type + " files -> " + terminal.TerminalPath);
                }
                catch (Exception ex)
                {
                    System.Threading.Interlocked.Exchange(ref allSucceededFlag, 0);
                    ReportOne("FAILED " + terminal.Type + " -> " + terminal.TerminalPath + " | " + ex.Message);
                }
            }).ToArray();

            await Task.WhenAll(tasks).ConfigureAwait(true);
            return System.Threading.Interlocked.CompareExchange(ref allSucceededFlag, 0, 0) == 1;

            void ReportOne(string message)
            {
                log(message);
            }
        }

        private async Task<ServerResult> RequestLicenseAsync(
            InstallMode mode,
            string email,
            string purchaseKey,
            CancellationToken token,
            Action<string> log)
        {
            string machineId = MachineIdService.GenerateComputerId();
            string rndNumber = CryptoService.Generate32DigitRandomNumber();
            string encodedPostData = CryptoService.BuildPostData(email, purchaseKey, machineId, rndNumber);
            string baseUrl = mode == InstallMode.Premium ? PremiumUrl : TransferUrl;
            string url = baseUrl + "?data=" + encodedPostData;

            log("Machine ID generated: " + machineId);
            log("Sending license request...");

            try
            {
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls;

                using (HttpClientHandler handler = new HttpClientHandler())
                using (HttpClient client = new HttpClient(handler))
                using (HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, url))
                {
                    client.Timeout = TimeSpan.FromSeconds(60);
                    request.Headers.UserAgent.ParseAdd("NutriculaExpertInstaller/1.0");

                    using (HttpResponseMessage response = await client.SendAsync(request, HttpCompletionOption.ResponseContentRead, token).ConfigureAwait(true))
                    {
                        byte[] rawBytes = await response.Content.ReadAsByteArrayAsync().ConfigureAwait(true);
                        string rawResponse = Encoding.UTF8.GetString(rawBytes);

                        // The protocol defines failure only when the exact response text is "no".
                        log("Server HTTP status: " + (int)response.StatusCode + " " + response.ReasonPhrase);
                        log("Server response length: " + rawBytes.Length + " bytes");

                        return new ServerResult
                        {
                            Completed = true,
                            RawResponse = rawResponse,
                            RawResponseBytes = rawBytes
                        };
                    }
                }
            }
            catch (Exception ex)
            {
                log("Server request failed: " + ex.Message);
                return new ServerResult { Completed = false, Error = ex };
            }
        }

        private bool WriteRawLicenseFile(byte[] rawResponseBytes, Action<string> log)
        {
            try
            {
                string path = GetCommonLicensePath();
                string dir = Path.GetDirectoryName(path);
                if (string.IsNullOrEmpty(dir))
                    throw new IOException("Could not determine Common\\Files directory.");

                Directory.CreateDirectory(dir);
                if (File.Exists(path))
                    File.Delete(path);

                // Write EXACT bytes received from the server. No trim, parsing, decoding/re-encoding or transformation.
                File.WriteAllBytes(path, rawResponseBytes ?? new byte[0]);
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
                if (File.Exists(path))
                    File.Delete(path);
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

        private static async Task CopyEmbeddedResourceAsync(ResourceItem item, string destinationDirectory, CancellationToken token)
        {
            var assembly = typeof(InstallerService).Assembly;
            using (Stream input = assembly.GetManifestResourceStream(item.ManifestName))
            {
                if (input == null)
                    throw new FileNotFoundException("Embedded resource not found: " + item.ManifestName);

                string destination = Path.Combine(destinationDirectory, item.FileName);
                string temp = destination + ".nutricula_tmp";

                using (FileStream output = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.None, 64 * 1024, true))
                {
                    await input.CopyToAsync(output, 64 * 1024, token).ConfigureAwait(true);
                }

                if (File.Exists(destination))
                    File.Delete(destination);
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

        private sealed class ServerResult
        {
            public bool Completed { get; set; }
            public string RawResponse { get; set; }
            public byte[] RawResponseBytes { get; set; }
            public Exception Error { get; set; }
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
