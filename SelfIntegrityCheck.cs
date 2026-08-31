using System;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

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
    /// A separate signing step (NutriculaSignInstaller.exe) must run AFTER
    /// the final Installer.exe is built. It signs the exe by APPENDING a
    /// small trailer directly onto the same file - there is no second file
    /// to distribute; the signed Installer.exe IS the one and only file
    /// customers ever download. See NutriculaSignInstaller.cpp's own header
    /// comment for the full trailer format and why appending is safe (the
    /// PE loader and .NET's own metadata reader never read past what their
    /// own size fields describe, so trailing bytes are simply invisible to
    /// them at runtime - this was verified empirically, not just assumed).
    /// </summary>
    internal static class SelfIntegrityCheck
    {
        private const int SignatureLen = 64;
        private const int MagicLen = 8;
        private const int TrailerLen = SignatureLen + MagicLen;
        private static readonly byte[] MagicBytes = Encoding.ASCII.GetBytes("NUTRSIG1");

        /// <summary>
        /// Returns true if this exe's own trailing signature trailer is
        /// present and validly signed over everything before it. Never
        /// throws - any failure (file too short, no magic marker, corrupt
        /// signature, I/O error) is treated as "not verified", never as a
        /// crash that could itself be a distinguishing signal for an
        /// attacker probing this check.
        /// </summary>
        public static bool Verify(out string failureReason)
        {
            failureReason = null;
            try
            {
                string exePath = Assembly.GetExecutingAssembly().Location;
                byte[] fileBytes = File.ReadAllBytes(exePath);

                if (fileBytes.Length < TrailerLen)
                {
                    failureReason = "This installer file is missing its integrity signature.";
                    return false;
                }

                int magicOffset = fileBytes.Length - MagicLen;
                for (int i = 0; i < MagicLen; i++)
                {
                    if (fileBytes[magicOffset + i] != MagicBytes[i])
                    {
                        failureReason = "This installer file is missing its integrity signature.";
                        return false;
                    }
                }

                int signatureOffset = fileBytes.Length - TrailerLen;
                byte[] signatureBytes = new byte[SignatureLen];
                Array.Copy(fileBytes, signatureOffset, signatureBytes, 0, SignatureLen);

                // Everything BEFORE the trailer is exactly what
                // NutriculaSignInstaller hashed and signed - never the
                // trailer itself (that would be circular).
                int cleanLength = fileBytes.Length - TrailerLen;
                byte[] cleanHash;
                using (SHA256 sha256 = SHA256.Create())
                {
                    cleanHash = sha256.ComputeHash(fileBytes, 0, cleanLength);
                }

                using (ECDsaCng ecdsa = new ECDsaCng(CngKey.Import(
                    BuildP256PublicKeyBlob(VendorPublicKeyEmbedded.X, VendorPublicKeyEmbedded.Y),
                    CngKeyBlobFormat.EccPublicBlob)))
                {
                    ecdsa.HashAlgorithm = CngAlgorithm.Sha256;
                    bool valid = ecdsa.VerifyHash(cleanHash, signatureBytes);
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
