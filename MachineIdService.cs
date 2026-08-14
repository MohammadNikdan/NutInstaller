using System;
using System.Collections.Generic;
using System.IO;
using System.Management;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32;

namespace NutriculaInstaller
{
    internal static class MachineIdService
    {
        public static string GenerateComputerId()
        {
            var components = new List<KeyValuePair<string, string>>
            {
                new KeyValuePair<string, string>("MACHINE_GUID", ReadMachineGuid()),
                new KeyValuePair<string, string>("BIOS_UUID", ReadWmiValue("Win32_ComputerSystemProduct", "UUID")),
                new KeyValuePair<string, string>("BIOS_SERIAL", ReadWmiValue("Win32_BIOS", "SerialNumber")),
                new KeyValuePair<string, string>("BASEBOARD_SERIAL", ReadWmiValue("Win32_BaseBoard", "SerialNumber")),
                new KeyValuePair<string, string>("CPU_ID", ReadWmiValue("Win32_Processor", "ProcessorId")),
                new KeyValuePair<string, string>("SYSTEM_DRIVE_SERIAL", ReadSystemDriveVolumeSerial())
            };

            // Fixed, documented ordering. Empty values are represented explicitly so another implementation
            // can reproduce the exact same byte sequence on the same machine.
            StringBuilder canonical = new StringBuilder();
            foreach (KeyValuePair<string, string> item in components)
            {
                canonical.Append(item.Key);
                canonical.Append('=');
                canonical.Append(Normalize(item.Value));
                canonical.Append('\n');
            }

            byte[] input = Encoding.UTF8.GetBytes(canonical.ToString());
            using (SHA256 sha = SHA256.Create())
            {
                return CryptoService.ToUpperHex(sha.ComputeHash(input));
            }
        }

        private static string Normalize(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return "";

            string s = value.Trim().ToUpperInvariant();
            StringBuilder sb = new StringBuilder(s.Length);
            bool lastWasSpace = false;
            foreach (char c in s)
            {
                if (char.IsWhiteSpace(c))
                {
                    if (!lastWasSpace)
                    {
                        sb.Append(' ');
                        lastWasSpace = true;
                    }
                }
                else
                {
                    sb.Append(c);
                    lastWasSpace = false;
                }
            }
            return sb.ToString();
        }

        private static string ReadMachineGuid()
        {
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography"))
                {
                    object value = key == null ? null : key.GetValue("MachineGuid");
                    return value == null ? "" : Convert.ToString(value);
                }
            }
            catch
            {
                return "";
            }
        }

        private static string ReadWmiValue(string className, string propertyName)
        {
            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT " + propertyName + " FROM " + className))
                using (ManagementObjectCollection results = searcher.Get())
                {
                    foreach (ManagementObject obj in results)
                    {
                        object value = obj[propertyName];
                        if (value != null)
                        {
                            string text = Convert.ToString(value);
                            if (!string.IsNullOrWhiteSpace(text) &&
                                !string.Equals(text, "To be filled by O.E.M.", StringComparison.OrdinalIgnoreCase) &&
                                !string.Equals(text, "Default string", StringComparison.OrdinalIgnoreCase) &&
                                !string.Equals(text, "None", StringComparison.OrdinalIgnoreCase))
                            {
                                return text;
                            }
                        }
                    }
                }
            }
            catch
            {
                // Missing/blocked WMI data becomes an empty component. The algorithm remains deterministic.
            }
            return "";
        }

        private static string ReadSystemDriveVolumeSerial()
        {
            try
            {
                string root = Path.GetPathRoot(Environment.SystemDirectory);
                if (string.IsNullOrEmpty(root))
                    return "";

                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(
                    "SELECT VolumeSerialNumber FROM Win32_LogicalDisk WHERE DeviceID='" + root.TrimEnd('\\') + "'"))
                using (ManagementObjectCollection results = searcher.Get())
                {
                    foreach (ManagementObject obj in results)
                    {
                        object value = obj["VolumeSerialNumber"];
                        return value == null ? "" : Convert.ToString(value);
                    }
                }
            }
            catch
            {
            }
            return "";
        }
    }
}
