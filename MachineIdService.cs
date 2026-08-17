using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;

namespace NutriculaInstaller
{
    internal static class MachineIdService
    {
        private const string ResourceName =
            "NutriculaInstaller.Assets.MachineId32.dll";

        private const string DllFileName =
            "MachineId32.dll";

        private const int OutputCapacity = 65;

        private static readonly object SyncRoot = new object();

        private static IntPtr dllHandle = IntPtr.Zero;

        private static GenerateMachineIdDelegate generateMachineId;
        private static GetLastStatusDelegate getLastStatus;

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int GenerateMachineIdDelegate(
            IntPtr output,
            int outputCapacity
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int GetLastStatusDelegate();

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
                getLastStatus != null)
            {
                return;
            }

            lock (SyncRoot)
            {
                if (dllHandle != IntPtr.Zero &&
                    generateMachineId != null &&
                    getLastStatus != null)
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

                generateMachineId =
                    Marshal.GetDelegateForFunctionPointer<
                        GenerateMachineIdDelegate
                    >(generateAddress);

                getLastStatus =
                    Marshal.GetDelegateForFunctionPointer<
                        GetLastStatusDelegate
                    >(statusAddress);
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
