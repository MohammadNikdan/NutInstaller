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
    }
}
