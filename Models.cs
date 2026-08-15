using System;
using System.Collections.Generic;

namespace NutriculaInstaller
{
    internal enum InstallMode
    {
        Free,
        Premium,
        Transfer
    }

    internal enum TerminalType
    {
        MT4,
        MT5
    }

    internal sealed class TerminalInfo
    {
        public TerminalType Type { get; private set; }
        public string TerminalPath { get; private set; }
        public string ExpertsPath { get; private set; }
        public string LibrariesPath { get; private set; }
        public string DiscoverySource { get; private set; }

        public TerminalInfo(TerminalType type, string terminalPath, string discoverySource)
        {
            Type = type;
            TerminalPath = terminalPath;
            ExpertsPath = System.IO.Path.Combine(terminalPath, type == TerminalType.MT4 ? "MQL4\\Experts" : "MQL5\\Experts");
            LibrariesPath = System.IO.Path.Combine(terminalPath, type == TerminalType.MT4 ? "MQL4\\Libraries" : "MQL5\\Libraries");
            DiscoverySource = discoverySource;
        }

        public override string ToString()
        {
            return Type + " | " + TerminalPath;
        }
    }

    internal sealed class InstallResult
    {
        public bool FilesInstalled { get; set; }
        public bool ServerRequestFinished { get; set; }
        public bool LicenseFileOperationFinished { get; set; }
        public bool LicenseSucceeded { get; set; }
        public bool OverallSuccess { get; set; }
        public string ServerResponse { get; set; }
        public string FinalMessage { get; set; }
        public int Mt4Count { get; set; }
        public int Mt5Count { get; set; }
        public List<string> Errors { get; } = new List<string>();
    }
}
