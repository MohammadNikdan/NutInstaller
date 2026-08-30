using System;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;

namespace NutriculaInstaller
{
    /// <summary>
    /// Anti-tamper check for the Installer binary itself (2026 hardening).
    ///
    /// HONEST SCOPE: this raises the bar against casual patching of the
    /// shipped .exe (e.g. hex-editing a jump instruction to skip the
    /// machine-id-required check, or a resource-editor changing an embedded
    /// string) - it does NOT defeat an attacker willing to also patch out
    /// or bypass this very check, since the check itself lives in the same
    /// binary it is protecting. No purely local, source-level technique can
    /// close that loop completely; this is defense-in-depth, not a
    /// guarantee. Combined with the DLLs' own anti-tamper (which is
    /// independent of the Installer and cannot be defeated by patching the
    /// Installer alone), the practical effort required to produce a
    /// tampered installer that still activates real licenses is
    /// meaningfully higher than editing one file with a hex editor.
    ///
    /// A separate signing step (mirroring NutriculaSignTool's manifest
    /// signing) must run AFTER the final Installer.exe is built, producing
    /// a ".sig" file (SHA-256 of the exe's bytes, signed with the vendor's
    /// P-256 private key) placed alongside the .exe. That .sig file is what
    /// this class verifies at startup - it is NOT embedded inside the exe
    /// itself (that would be circular: signing the exe would change its own
    /// bytes and invalidate the very hash being signed).
    /// </summary>
    internal static class SelfIntegrityCheck
    {
        /// <summary>
        /// Returns true if the currently-running executable's SHA-256 hash
        /// matches a valid, vendor-signed hash found in "<exe>.sig" next to
        /// it. Never throws - any failure (missing .sig file, corrupt data,
        /// I/O error) is treated as "not verified", never as a crash that
        /// could itself be a distinguishing signal for an attacker probing
        /// this check.
        /// </summary>
        public static bool Verify(out string failureReason)
        {
            failureReason = null;
            try
            {
                string exePath = Assembly.GetExecutingAssembly().Location;
                string sigPath = exePath + ".sig";

                if (!File.Exists(sigPath))
                {
                    failureReason = "No integrity signature file was found next to the installer.";
                    return false;
                }

                byte[] exeBytes = File.ReadAllBytes(exePath);
                byte[] actualHash;
                using (SHA256 sha256 = SHA256.Create())
                {
                    actualHash = sha256.ComputeHash(exeBytes);
                }

                string signatureB64 = File.ReadAllText(sigPath).Trim();
                byte[] signatureBytes = Convert.FromBase64String(signatureB64);
                // Raw (r||s) P-256 signature, 64 bytes - same convention
                // used everywhere else in this project (device key
                // signatures, server lease signatures).
                if (signatureBytes.Length != 64)
                {
                    failureReason = "The integrity signature file is malformed.";
                    return false;
                }

                using (ECDsaCng ecdsa = new ECDsaCng(CngKey.Import(
                    BuildP256PublicKeyBlob(VendorPublicKeyEmbedded.X, VendorPublicKeyEmbedded.Y),
                    CngKeyBlobFormat.EccPublicBlob)))
                {
                    ecdsa.HashAlgorithm = CngAlgorithm.Sha256;
                    bool valid = ecdsa.VerifyHash(actualHash, signatureBytes);
                    if (!valid)
                    {
                        failureReason = "The installer's integrity signature does not match this file's contents.";
                    }
                    return valid;
                }
            }
            catch (Exception)
            {
                failureReason = "The installer's integrity could not be verified.";
                return false;
            }
        }

        /// <summary>
        /// Builds a BCRYPT_ECCPUBLIC_BLOB-compatible byte array from raw
        /// X/Y coordinates, importable via CngKey.Import with
        /// CngKeyBlobFormat.EccPublicBlob.
        /// </summary>
        private static byte[] BuildP256PublicKeyBlob(byte[] x, byte[] y)
        {
            const int P256_MAGIC = 0x31534345; // "ECS1" - BCRYPT_ECDSA_PUBLIC_P256_MAGIC
            const int KEY_LENGTH = 32;

            byte[] blob = new byte[8 + KEY_LENGTH * 2];
            byte[] magicBytes = BitConverter.GetBytes(P256_MAGIC);
            byte[] lengthBytes = BitConverter.GetBytes(KEY_LENGTH);
            Array.Copy(magicBytes, 0, blob, 0, 4);
            Array.Copy(lengthBytes, 0, blob, 4, 4);
            Array.Copy(x, 0, blob, 8, KEY_LENGTH);
            Array.Copy(y, 0, blob, 8 + KEY_LENGTH, KEY_LENGTH);
            return blob;
        }
    }
}
