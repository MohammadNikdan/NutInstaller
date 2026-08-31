using System;
using System.Security.Cryptography;
using System.Text;

namespace NutriculaInstaller
{
    internal static class CryptoService
    {
        public static string BuildPostData(
            string email,
            string purchaseKey,
            string machineId,
            string rndNumber,
            string transferKey = null,
            string localIp = null,
            string devicePublicKey = null,
            string platformProfile = null,
            string machineIdAlt = null,
            bool machineIdAltConfirmed = false)
        {
            if (string.IsNullOrEmpty(devicePublicKey))
                throw new InvalidOperationException("Required information is missing.");

            string postData =
                "v=3" +
                "&rnd_number=" + Uri.EscapeDataString(rndNumber ?? string.Empty) +
                "&email=" + Uri.EscapeDataString(email ?? string.Empty) +
                "&purchase_key=" + Uri.EscapeDataString(purchaseKey ?? string.Empty);

            if (!string.IsNullOrEmpty(transferKey))
                postData += "&transfer_key=" + Uri.EscapeDataString(transferKey);

            postData +=
                "&machine_id=" + Uri.EscapeDataString(machineId ?? string.Empty);

            // Secondary machine_id variant (2026 hardening) - see
            // NutriculaMachineId.cpp's Nutricula_GenerateMachineIdWithGuid
            // for the full reasoning. Omitted entirely for Free installs
            // and anything that doesn't need it - the server treats an
            // absent machine_id_alt as identical to machine_id.
            if (!string.IsNullOrEmpty(machineIdAlt))
                postData += "&machine_id_alt=" + Uri.EscapeDataString(machineIdAlt);
            if (machineIdAltConfirmed)
                postData += "&machine_id_alt_confirmed=1";

            if (!string.IsNullOrEmpty(localIp))
                postData += "&local_ip=" + Uri.EscapeDataString(localIp);

            // Replaces local_ip's old (and never actually reliable) role of
            // letting the server classify VM/VPS - platform_profile is a
            // generic category label ("WINDOWS", "WINDOWS_VM", "MACOS_WINE",
            // "LINUX_WINE") reported directly by the machine ID DLL's own
            // platform detection, not inferred from IP presence.
            if (!string.IsNullOrEmpty(platformProfile))
                postData += "&platform_profile=" + Uri.EscapeDataString(platformProfile);

            postData +=
                "&device_public_key=" + Uri.EscapeDataString(devicePublicKey);

            return MachineIdService.ProtectPayloadGcm(postData);
        }

        public static string EncryptResponseForTests(string plaintext)
        {
            return MachineIdService.ProtectPayloadGcm(plaintext);
        }

        public static string DecryptServerResponse(string rawResponse)
        {
            if (string.IsNullOrWhiteSpace(rawResponse))
                throw new InvalidOperationException("Server response is empty.");
            return MachineIdService.UnprotectPayloadGcm(rawResponse.Trim());
        }

        public static string Generate32DigitRandomNumber()
        {
            const int digitCount = 32;
            char[] result = new char[digitCount];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                byte[] buffer = new byte[1];
                for (int i = 0; i < result.Length; i++)
                {
                    do { rng.GetBytes(buffer); } while (buffer[0] >= 250);
                    result[i] = (char)('0' + (buffer[0] % 10));
                }
            }
            return new string(result);
        }
    }
}
