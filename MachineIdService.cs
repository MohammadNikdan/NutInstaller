using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;

namespace NutriculaInstaller
{
    internal static class MachineIdService
    {
        private const string ResourceName = "NutriculaInstaller.Assets.MachineId32.dll";
        private const string DllFileName = "MachineId32.dll";
        private const int MachineIdOutputCapacity = 65;
        private const int DevicePublicKeyCapacity = 256;
        private const int DeviceKeyHashCapacity = 65;
        private const int LicensePathCapacity = 1024;
        private const int SignOutputCapacity = 128;
        private const int GcmOutputCapacity = 131072;
        private static readonly object SyncRoot = new object();
        private static IntPtr dllHandle = IntPtr.Zero;
        private static GenerateMachineIdDelegate generateMachineId;
        private static GetLastStatusDelegate getLastStatus;
        private static IsWineEnvironmentDelegate isWineEnvironment;
        private static GetLastPlatformProfileDelegate getLastPlatformProfile;
        private static GetDevicePublicKeyDelegate getDevicePublicKey;
        private static GetDeviceKeyHashDelegate getDeviceKeyHash;
        private static GetLicensePathDelegate getLicensePath;
        private static SignChallengeDelegate signChallenge;
        private static GcmProtectDelegate gcmProtect;
        private static GcmUnprotectDelegate gcmUnprotect;

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int GenerateMachineIdDelegate(IntPtr output, int outputCapacity);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int GetLastStatusDelegate();
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int IsWineEnvironmentDelegate();
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int GetLastPlatformProfileDelegate(IntPtr output, int outputCapacity);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int GetDevicePublicKeyDelegate(IntPtr output, int outputCapacity);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int GetDeviceKeyHashDelegate(IntPtr output, int outputCapacity);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int GetLicensePathDelegate(IntPtr output, int outputCapacity);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int SignChallengeDelegate(IntPtr message, int messageLength, IntPtr signature, int signatureCapacity);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int GcmProtectDelegate(IntPtr plaintext, int plaintextLength, IntPtr output, int outputCapacity);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int GcmUnprotectDelegate(IntPtr envelope, int envelopeLength, IntPtr output, int outputCapacity);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr LoadLibraryW(string lpFileName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        public static string GenerateComputerId()
        {
            EnsureLoaded();
            IntPtr buffer = IntPtr.Zero;
            try
            {
                buffer = Marshal.AllocHGlobal(MachineIdOutputCapacity);
                for (int i = 0; i < MachineIdOutputCapacity; i++) Marshal.WriteByte(buffer, i, 0);
                int result = generateMachineId(buffer, MachineIdOutputCapacity);
                if (result != 1)
                {
                    throw new MachineIdException("This computer's setup could not be completed.");
                }
                string machineId = Marshal.PtrToStringAnsi(buffer);
                if (string.IsNullOrEmpty(machineId) || machineId.Length != 64)
                    throw new MachineIdException("This computer's setup returned an unexpected result.");
                for (int i = 0; i < machineId.Length; i++)
                {
                    char c = machineId[i];
                    if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F')))
                        throw new MachineIdException("This computer's setup returned unexpected data.");
                }
                return machineId;
            }
            finally
            {
                if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
            }
        }

        /// <summary>
        /// Asks the DLL directly whether it detected a Wine/CrossOver environment,
        /// rather than the installer re-implementing (and potentially diverging
        /// from) the same detection logic - the DLL's check (wine_get_version
        /// export probe) is the more reliable one and should be the single
        /// source of truth.
        /// </summary>
        public static bool IsWineEnvironment()
        {
            EnsureLoaded();
            try { return isWineEnvironment() != 0; }
            catch { return false; }
        }

        // Rewritten 2026-08-22: no longer calls into MachineId32/64.dll at
        // all - the export this used to call (Nutricula_GetLastClientIp)
        // was removed from the DLL as presumed-dead code, which broke this
        // call outright (LoadDelegate throws on a missing export, taking
        // down the whole Installer with it). On top of that, even before
        // removal this export was ALREADY non-functional - the DLL's
        // underlying g_lastClientIp variable was never assigned anywhere,
        // so this always returned an empty string regardless. Rather than
        // resurrecting a DLL export whose only job was already broken,
        // this is now a genuine, working, purely-.NET implementation -
        // local_ip is only ever used server-side for logging/statistics
        // (never a security or license decision - see
        // nutricula_computer_based_signup.php's own comments on this),
        // so an empty result here (e.g. no active network interface) is
        // completely safe and simply means that log field stays blank.
        public static string GetLastClientIp()
        {
            try
            {
                foreach (var ni in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus != System.Net.NetworkInformation.OperationalStatus.Up) continue;
                    if (ni.NetworkInterfaceType == System.Net.NetworkInformation.NetworkInterfaceType.Loopback) continue;
                    foreach (var addr in ni.GetIPProperties().UnicastAddresses)
                    {
                        if (addr.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                            return addr.Address.ToString();
                    }
                }
            }
            catch { /* best-effort only - see comment above on why an empty result here is always safe */ }
            return string.Empty;
        }

        // Short, generic category label ("WINDOWS", "WINDOWS_VM",
        // "MACOS_WINE", "LINUX_WINE") for the most recently generated
        // machine_id - carries no raw hardware data or IP, safe to send to
        // the server for device_type classification and risk scoring
        // without needing IP at all.
        public static string GetLastPlatformProfile()
        {
            EnsureLoaded();
            const int capacity = 64;
            IntPtr buffer = IntPtr.Zero;
            try
            {
                buffer = Marshal.AllocHGlobal(capacity);
                for (int i = 0; i < capacity; i++) Marshal.WriteByte(buffer, i, 0);
                return getLastPlatformProfile(buffer, capacity) == 1
                    ? (Marshal.PtrToStringAnsi(buffer) ?? string.Empty)
                    : string.Empty;
            }
            catch { return string.Empty; }
            finally
            {
                if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
            }
        }

        public static string GetDevicePublicKey()
        {
            EnsureLoaded();
            IntPtr buffer = IntPtr.Zero;
            try
            {
                buffer = Marshal.AllocHGlobal(DevicePublicKeyCapacity);
                for (int i = 0; i < DevicePublicKeyCapacity; i++) Marshal.WriteByte(buffer, i, 0);
                int result = getDevicePublicKey(buffer, DevicePublicKeyCapacity);
                if (result != 1) throw new DeviceKeyException("This computer's setup is unavailable.");
                string key = Marshal.PtrToStringAnsi(buffer);
                if (string.IsNullOrEmpty(key)) throw new DeviceKeyException("This computer's setup returned no data.");
                return key;
            }
            finally
            {
                if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
            }
        }


        public static string GetDeviceKeyHash()
        {
            EnsureLoaded();
            IntPtr buffer = Marshal.AllocHGlobal(DeviceKeyHashCapacity);
            try
            {
                for (int i = 0; i < DeviceKeyHashCapacity; i++) Marshal.WriteByte(buffer, i, 0);
                int result = getDeviceKeyHash(buffer, DeviceKeyHashCapacity);
                if (result != 1) throw new DeviceKeyException("This computer's setup is unavailable.");
                return Marshal.PtrToStringAnsi(buffer) ?? throw new DeviceKeyException("This computer's setup returned no data.");
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }

        public static string GetLicensePath()
        {
            EnsureLoaded();
            IntPtr buffer = Marshal.AllocHGlobal(LicensePathCapacity);
            try
            {
                for (int i = 0; i < LicensePathCapacity; i++) Marshal.WriteByte(buffer, i, 0);
                int result = getLicensePath(buffer, LicensePathCapacity);
                if (result != 1) throw new DeviceKeyException("Could not determine a required file location.");
                return Marshal.PtrToStringAnsi(buffer) ?? string.Empty;
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }

        private static void SafeFreeHGlobal(IntPtr ptr, int length)
        {
            if (ptr == IntPtr.Zero) return;
            for (int i = 0; i < length; i++) Marshal.WriteByte(ptr, i, 0);
            Marshal.FreeHGlobal(ptr);
        }

        public static string ProtectPayloadGcm(string plaintext)
        {
            if (plaintext == null) throw new ArgumentNullException("plaintext");
            EnsureLoaded();
            byte[] input = System.Text.Encoding.UTF8.GetBytes(plaintext);
            IntPtr inputPtr = IntPtr.Zero;
            IntPtr outputPtr = IntPtr.Zero;
            try
            {
                inputPtr = Marshal.AllocHGlobal(input.Length == 0 ? 1 : input.Length);
                if (input.Length > 0) Marshal.Copy(input, 0, inputPtr, input.Length);
                outputPtr = Marshal.AllocHGlobal(GcmOutputCapacity);
                for (int i = 0; i < GcmOutputCapacity; i++) Marshal.WriteByte(outputPtr, i, 0);
                int result = gcmProtect(inputPtr, input.Length, outputPtr, GcmOutputCapacity);
                if (result <= 0) throw new CryptoException("Could not prepare the request.");
                return Marshal.PtrToStringAnsi(outputPtr) ?? throw new CryptoException("Could not prepare the request.");
            }
            finally
            {
                // inputPtr held the plaintext (email, purchase_key, device key, etc.) -
                // zero it before freeing, not just the managed copy.
                SafeFreeHGlobal(inputPtr, input.Length == 0 ? 1 : input.Length);
                if (outputPtr != IntPtr.Zero) Marshal.FreeHGlobal(outputPtr); // ciphertext, not sensitive
                Array.Clear(input, 0, input.Length);
            }
        }

        public static string UnprotectPayloadGcm(string envelope)
        {
            if (envelope == null) throw new ArgumentNullException("envelope");
            EnsureLoaded();
            byte[] input = System.Text.Encoding.ASCII.GetBytes(envelope);
            IntPtr inputPtr = IntPtr.Zero;
            IntPtr outputPtr = IntPtr.Zero;
            try
            {
                inputPtr = Marshal.AllocHGlobal(input.Length == 0 ? 1 : input.Length);
                if (input.Length > 0) Marshal.Copy(input, 0, inputPtr, input.Length);
                outputPtr = Marshal.AllocHGlobal(GcmOutputCapacity);
                for (int i = 0; i < GcmOutputCapacity; i++) Marshal.WriteByte(outputPtr, i, 0);
                int result = gcmUnprotect(inputPtr, input.Length, outputPtr, GcmOutputCapacity);
                if (result <= 0) throw new CryptoException("Could not process the response.");
                byte[] output = new byte[result];
                Marshal.Copy(outputPtr, output, 0, result);
                return System.Text.Encoding.UTF8.GetString(output);
            }
            finally
            {
                if (inputPtr != IntPtr.Zero) Marshal.FreeHGlobal(inputPtr); // ciphertext, not sensitive
                // outputPtr held the decrypted lease plaintext - zero it before freeing.
                SafeFreeHGlobal(outputPtr, GcmOutputCapacity);
                Array.Clear(input, 0, input.Length);
            }
        }

        public static string SignChallenge(string canonicalMessage)
        {
            if (canonicalMessage == null) throw new ArgumentNullException("canonicalMessage");
            EnsureLoaded();
            byte[] message = System.Text.Encoding.UTF8.GetBytes(canonicalMessage);
            IntPtr messagePtr = IntPtr.Zero;
            IntPtr signaturePtr = IntPtr.Zero;
            try
            {
                messagePtr = Marshal.AllocHGlobal(message.Length == 0 ? 1 : message.Length);
                if (message.Length > 0) Marshal.Copy(message, 0, messagePtr, message.Length);
                signaturePtr = Marshal.AllocHGlobal(SignOutputCapacity);
                for (int i = 0; i < SignOutputCapacity; i++) Marshal.WriteByte(signaturePtr, i, 0);
                int signatureLength = signChallenge(messagePtr, message.Length, signaturePtr, SignOutputCapacity);
                if (signatureLength <= 0) throw new DeviceKeyException("Could not complete a required step.");
                byte[] signature = new byte[signatureLength];
                Marshal.Copy(signaturePtr, signature, 0, signatureLength);
                return Convert.ToBase64String(signature);
            }
            finally
            {
                SafeFreeHGlobal(messagePtr, message.Length == 0 ? 1 : message.Length);
                if (signaturePtr != IntPtr.Zero) Marshal.FreeHGlobal(signaturePtr); // signature, not sensitive
                Array.Clear(message, 0, message.Length);
            }
        }

        private static int SafeGetLastStatus()
        {
            try { return getLastStatus(); } catch { return -999; }
        }

        private static void EnsureLoaded()
        {
            if (dllHandle != IntPtr.Zero && generateMachineId != null && getLastStatus != null && isWineEnvironment != null && getLastPlatformProfile != null && getDevicePublicKey != null && getDeviceKeyHash != null && getLicensePath != null && signChallenge != null && gcmProtect != null && gcmUnprotect != null) return;
            lock (SyncRoot)
            {
                if (dllHandle != IntPtr.Zero && generateMachineId != null && getLastStatus != null && isWineEnvironment != null && getLastPlatformProfile != null && getDevicePublicKey != null && getDeviceKeyHash != null && getLicensePath != null && signChallenge != null && gcmProtect != null && gcmUnprotect != null) return;
                string dllPath = ExtractDllToTemp();
                dllHandle = LoadLibraryW(dllPath);
                if (dllHandle == IntPtr.Zero) throw new MachineIdException("A required internal component could not be loaded.");

                generateMachineId = LoadDelegate<GenerateMachineIdDelegate>("Nutricula_GenerateMachineId");
                getLastStatus = LoadDelegate<GetLastStatusDelegate>("Nutricula_GetLastStatus");
                isWineEnvironment = LoadDelegate<IsWineEnvironmentDelegate>("Nutricula_IsWineEnvironment");
                getLastPlatformProfile = LoadDelegate<GetLastPlatformProfileDelegate>("Nutricula_GetLastPlatformProfile");
                getDevicePublicKey = LoadDelegate<GetDevicePublicKeyDelegate>("Nutricula_GetDevicePublicKey");
                getDeviceKeyHash = LoadDelegate<GetDeviceKeyHashDelegate>("Nutricula_GetDeviceKeyHash");
                getLicensePath = LoadDelegate<GetLicensePathDelegate>("Nutricula_GetLicensePath");
                signChallenge = LoadDelegate<SignChallengeDelegate>("Nutricula_SignChallenge");
                gcmProtect = LoadDelegate<GcmProtectDelegate>("Nutricula_ProtectPayloadGcm");
                gcmUnprotect = LoadDelegate<GcmUnprotectDelegate>("Nutricula_UnprotectPayloadGcm");
            }
        }

        private static T LoadDelegate<T>(string name) where T : class
        {
            IntPtr address = GetProcAddress(dllHandle, name);
            if (address == IntPtr.Zero) throw new MachineIdException("A required internal function could not be found.");
            return Marshal.GetDelegateForFunctionPointer(address, typeof(T)) as T;
        }

        private static string ExtractDllToTemp()
        {
            string root = Path.Combine(Path.GetTempPath(), "NutriculaInstaller", "MachineId");
            Directory.CreateDirectory(root);
            string dllPath = Path.Combine(root, DllFileName);
            Assembly assembly = typeof(MachineIdService).Assembly;
            using (Stream input = assembly.GetManifestResourceStream(ResourceName))
            {
                if (input == null) throw new MachineIdException("A required internal component was not found.");
                string tempPath = dllPath + ".tmp";
                using (FileStream output = new FileStream(tempPath, FileMode.Create, FileAccess.Write, FileShare.None)) input.CopyTo(output);
                if (File.Exists(dllPath)) File.Delete(dllPath);
                File.Move(tempPath, dllPath);
            }
            return dllPath;
        }

        internal sealed class MachineIdException : Exception
        {
            public MachineIdException(string message) : base(message) { }
            public MachineIdException(string message, Exception innerException) : base(message, innerException) { }
        }
        internal sealed class DeviceKeyException : Exception
        {
            public DeviceKeyException(string message) : base(message) { }
        }
        internal sealed class CryptoException : Exception
        {
            public CryptoException(string message) : base(message) { }
        }
    }
}
