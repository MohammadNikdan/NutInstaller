using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;

namespace NutriculaInstaller
{
    internal static class MachineIdService
    {
        // The installer builds as PlatformTarget=x86 (see the .csproj), so it always
        // runs as a 32-bit process regardless of the OS - only the 32-bit DLL is ever
        // needed here.
        private const string ResourceName =
            "NutriculaInstaller.Assets.MachineId32.dll";

        private const string DllFileName =
            "MachineId32.dll";

        private const int OutputCapacity = 65;

        private static readonly object SyncRoot = new object();

        private static IntPtr dllHandle = IntPtr.Zero;

        private static GenerateMachineIdDelegate generateMachineId;
        private static GetLastStatusDelegate getLastStatus;
        private static GetLastClientIpDelegate getLastClientIp;

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int GenerateMachineIdDelegate(
            IntPtr output,
            int outputCapacity
        );

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int GetLastStatusDelegate();

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int GetLastClientIpDelegate(
            IntPtr output,
            int outputCapacity
        );

        [DllImport(
            "kernel32.dll",
            CharSet = CharSet.Unicode,
            SetLastError = true
        )]
        private static extern IntPtr LoadLibraryW(
            string lpFileName
        );

        [DllImport(
            "kernel32.dll",
            CharSet = CharSet.Ansi,
            ExactSpelling = true,
            SetLastError = true
        )]
        private static extern IntPtr GetProcAddress(
            IntPtr hModule,
            string lpProcName
        );

        public static string GenerateComputerId()
        {
            EnsureLoaded();

            IntPtr buffer = IntPtr.Zero;

            try
            {
                buffer = Marshal.AllocHGlobal(OutputCapacity);

                for (int i = 0; i < OutputCapacity; i++)
                    Marshal.WriteByte(buffer, i, 0);

                int result = generateMachineId(
                    buffer,
                    OutputCapacity
                );

                if (result != 1)
                {
                    int status = SafeGetLastStatus();

                    throw new MachineIdException(
                        "Machine ID generation failed. " +
                        "DLL return code: " + result +
                        ", DLL status: " + status + "."
                    );
                }

                string machineId =
                    Marshal.PtrToStringAnsi(buffer);

                if (string.IsNullOrEmpty(machineId))
                {
                    throw new MachineIdException(
                        "Machine ID DLL returned an empty result."
                    );
                }

                if (machineId.Length != 64)
                {
                    throw new MachineIdException(
                        "Machine ID DLL returned an invalid " +
                        "length: " + machineId.Length + "."
                    );
                }

                for (int i = 0; i < machineId.Length; i++)
                {
                    char c = machineId[i];

                    bool valid =
                        (c >= '0' && c <= '9') ||
                        (c >= 'A' && c <= 'F');

                    if (!valid)
                    {
                        throw new MachineIdException(
                            "Machine ID DLL returned invalid " +
                            "hexadecimal data."
                        );
                    }
                }

                return machineId;
            }
            finally
            {
                if (buffer != IntPtr.Zero)
                    Marshal.FreeHGlobal(buffer);
            }
        }

        /// <summary>
        /// Returns the IP address that was folded into the hash on the most recent
        /// GenerateComputerId() call, or "" if the machine wasn't classified as a VM
        /// (physical machines never collect one) or no adapter IP was found.
        /// machine_id itself is a one-way SHA-256 hash, so this is the only way to
        /// recover the claimed IP - sent separately so the server can compare it
        /// against the connection's real, unforgeable source address.
        /// </summary>
        public static string GetLastClientIp()
        {
            EnsureLoaded();

            const int capacity = 256;
            IntPtr buffer = IntPtr.Zero;

            try
            {
                buffer = Marshal.AllocHGlobal(capacity);
                Marshal.WriteByte(buffer, 0, 0);

                int result = getLastClientIp(buffer, capacity);
                if (result != 1)
                    return string.Empty;

                return Marshal.PtrToStringAnsi(buffer) ?? string.Empty;
            }
            catch
            {
                // Best-effort only - never let this break the license request over
                // an optional, supplementary value.
                return string.Empty;
            }
            finally
            {
                if (buffer != IntPtr.Zero)
                    Marshal.FreeHGlobal(buffer);
            }
        }

        private static int SafeGetLastStatus()
        {
            try
            {
                return getLastStatus();
            }
            catch
            {
                return -999;
            }
        }

        private static void EnsureLoaded()
        {
            if (dllHandle != IntPtr.Zero &&
                generateMachineId != null &&
                getLastStatus != null &&
                getLastClientIp != null)
            {
                return;
            }

            lock (SyncRoot)
            {
                if (dllHandle != IntPtr.Zero &&
                    generateMachineId != null &&
                    getLastStatus != null &&
                    getLastClientIp != null)
                {
                    return;
                }

                string dllPath = ExtractDllToTemp();

                dllHandle = LoadLibraryW(dllPath);

                if (dllHandle == IntPtr.Zero)
                {
                    int error = Marshal.GetLastWin32Error();

                    throw new MachineIdException(
                        "Could not load MachineId32.dll. " +
                        "Win32 error: " + error +
                        ". Path: " + dllPath
                    );
                }

                // The DLL's exported functions are __cdecl, which MinGW never
                // decorates on x86 (unlike __stdcall, which gets an "@N" suffix) -
                // so a plain lookup by this clean name always works, regardless of
                // build tooling.
                IntPtr generateAddress =
                    GetProcAddress(
                        dllHandle,
                        "Nutricula_GenerateMachineId"
                    );

                if (generateAddress == IntPtr.Zero)
                {
                    throw new MachineIdException(
                        "The exported function " +
                        "'Nutricula_GenerateMachineId' " +
                        "was not found in MachineId32.dll."
                    );
                }

                IntPtr statusAddress =
                    GetProcAddress(
                        dllHandle,
                        "Nutricula_GetLastStatus"
                    );

                if (statusAddress == IntPtr.Zero)
                {
                    throw new MachineIdException(
                        "The exported function " +
                        "'Nutricula_GetLastStatus' " +
                        "was not found in MachineId32.dll."
                    );
                }

                IntPtr clientIpAddress =
                    GetProcAddress(
                        dllHandle,
                        "Nutricula_GetLastClientIp"
                    );

                if (clientIpAddress == IntPtr.Zero)
                {
                    throw new MachineIdException(
                        "The exported function " +
                        "'Nutricula_GetLastClientIp' " +
                        "was not found in MachineId32.dll."
                    );
                }

                generateMachineId =
                    Marshal.GetDelegateForFunctionPointer<
                        GenerateMachineIdDelegate
                    >(generateAddress);

                getLastStatus =
                    Marshal.GetDelegateForFunctionPointer<
                        GetLastStatusDelegate
                    >(statusAddress);

                getLastClientIp =
                    Marshal.GetDelegateForFunctionPointer<
                        GetLastClientIpDelegate
                    >(clientIpAddress);
            }
        }

        private static string ExtractDllToTemp()
        {
            string root =
                Path.Combine(
                    Path.GetTempPath(),
                    "NutriculaInstaller",
                    "MachineId"
                );

            Directory.CreateDirectory(root);

            string dllPath =
                Path.Combine(
                    root,
                    DllFileName
                );

            Assembly assembly =
                typeof(MachineIdService).Assembly;

            using (Stream input =
                assembly.GetManifestResourceStream(
                    ResourceName
                ))
            {
                if (input == null)
                {
                    throw new MachineIdException(
                        "Embedded Machine ID DLL resource was not found: " +
                        ResourceName
                    );
                }

                string tempPath =
                    dllPath + ".tmp";

                using (FileStream output =
                    new FileStream(
                        tempPath,
                        FileMode.Create,
                        FileAccess.Write,
                        FileShare.None
                    ))
                {
                    input.CopyTo(output);
                }

                if (File.Exists(dllPath))
                    File.Delete(dllPath);

                File.Move(
                    tempPath,
                    dllPath
                );
            }

            return dllPath;
        }

        internal sealed class MachineIdException : Exception
        {
            public MachineIdException(
                string message
            )
                : base(message)
            {
            }

            public MachineIdException(
                string message,
                Exception innerException
            )
                : base(message, innerException)
            {
            }
        }
    }
}
