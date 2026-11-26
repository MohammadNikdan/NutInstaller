using System;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
#if NET6_0_OR_GREATER
using System.Globalization;
using System.Numerics;
#endif

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
#if NET6_0_OR_GREATER
                // Single-file build (the Mac/Linux flavour, see
                // SelfContained\NutriculaInstaller.SelfContained.csproj):
                // there the assembly lives INSIDE the exe, so
                // Assembly.Location is an empty string. The path of the
                // running exe itself is what carries the signature trailer.
                string exePath = Environment.ProcessPath;
#else
                string exePath = Assembly.GetExecutingAssembly().Location;
#endif
                byte[] fileBytes = File.ReadAllBytes(exePath);

                if (fileBytes.Length < TrailerLen)
                {
                    failureReason = "This installer file appears to be corrupted or invalid.";
                    return false;
                }

                int magicOffset = fileBytes.Length - MagicLen;
                for (int i = 0; i < MagicLen; i++)
                {
                    if (fileBytes[magicOffset + i] != MagicBytes[i])
                    {
                        failureReason = "This installer file appears to be corrupted or invalid.";
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

#if NET6_0_OR_GREATER
                // Self-contained (Mac/Linux, runs under Wine): the signature
                // is checked by a small fully-managed ECDSA P-256 verifier
                // instead of ECDsaCng/CngKey.Import. CngKey.Import goes
                // through ncrypt.dll, and the ncrypt that ships in Wine
                // (the one bundled with MetaTrader 5 for Mac) does not
                // implement ECDSA public-key import at all ("Unhandled key
                // magic 0x31534345") - so under Wine the CNG route always
                // threw, was caught below, and a perfectly valid signature
                // was reported as "corrupted". The managed verifier needs
                // nothing from the OS except SHA-256 (already computed
                // above), so it behaves identically on Windows, Wine and
                // anywhere else. Same public key, same signature, same
                // standard ECDSA maths - only WHO does the maths changes.
                // The .NET Framework build (the Windows installer) does not
                // compile this branch and keeps the CNG route below.
                bool valid = ManagedEcdsaP256.Verify(
                    cleanHash, signatureBytes,
                    VendorPublicKeyEmbedded.X, VendorPublicKeyEmbedded.Y);
                if (!valid)
                {
                    failureReason = "This installer file appears to be corrupted or invalid.";
                }
                return valid;
#else
                using (ECDsaCng ecdsa = new ECDsaCng(CngKey.Import(
                    BuildP256PublicKeyBlob(VendorPublicKeyEmbedded.X, VendorPublicKeyEmbedded.Y),
                    CngKeyBlobFormat.EccPublicBlob)))
                {
                    ecdsa.HashAlgorithm = CngAlgorithm.Sha256;
                    bool valid = ecdsa.VerifyHash(cleanHash, signatureBytes);
                    if (!valid)
                    {
                        failureReason = "This installer file appears to be corrupted or invalid.";
                    }
                    return valid;
                }
#endif
            }
            catch (Exception)
            {
                failureReason = "This installer file appears to be corrupted or invalid.";
                return false;
            }
        }

#if !NET6_0_OR_GREATER
        /// <summary>
        /// Builds a BCRYPT_ECCPUBLIC_BLOB-compatible byte array from raw
        /// X/Y coordinates, importable via CngKey.Import with
        /// CngKeyBlobFormat.EccPublicBlob. (.NET Framework build only - the
        /// self-contained build verifies with ManagedEcdsaP256 instead.)
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
#endif
    }

#if NET6_0_OR_GREATER
    /// <summary>
    /// Minimal, dependency-free ECDSA P-256 (secp256r1) signature VERIFIER
    /// (verification only - it never signs and never touches a private key).
    /// Exists because ncrypt.dll under Wine cannot import an ECDSA public key
    /// (see SelfIntegrityCheck.Verify). Uses only System.Numerics.BigInteger,
    /// so it needs nothing from the operating system's crypto stack.
    ///
    /// Signature format: 64 bytes, r (32, big-endian) || s (32, big-endian) -
    /// exactly what NutriculaSignInstaller writes and what ECDsaCng.VerifyHash
    /// consumed before. Plain affine-coordinate textbook maths, chosen for
    /// being short enough to audit by eye; speed is irrelevant here (one
    /// verification at startup, a fraction of a second).
    /// </summary>
    internal static class ManagedEcdsaP256
    {
        // NIST P-256 domain parameters (FIPS 186-4, D.1.2.3 / SEC2 secp256r1).
        private static readonly BigInteger P  = Hex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");
        private static readonly BigInteger N  = Hex("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
        private static readonly BigInteger B  = Hex("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B");
        private static readonly BigInteger Gx = Hex("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296");
        private static readonly BigInteger Gy = Hex("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5");
        private static readonly BigInteger A  = P - 3;

        private sealed class Point
        {
            public readonly BigInteger X;
            public readonly BigInteger Y;
            public Point(BigInteger x, BigInteger y) { X = x; Y = y; }
        }

        // A null Point is the point at infinity (the group's identity).

        private static BigInteger Hex(string hex)
        {
            // Leading "0" keeps BigInteger from reading a high-bit-set value as negative.
            return BigInteger.Parse("0" + hex, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture);
        }

        private static BigInteger FromBigEndian(byte[] bytes)
        {
            return new BigInteger(bytes, true, true); // isUnsigned, isBigEndian
        }

        private static BigInteger Mod(BigInteger v, BigInteger m)
        {
            BigInteger r = v % m;
            return r.Sign < 0 ? r + m : r;
        }

        // Modular inverse for a PRIME modulus (both P and N are prime): Fermat.
        private static BigInteger Inv(BigInteger v, BigInteger m)
        {
            return BigInteger.ModPow(Mod(v, m), m - 2, m);
        }

        private static Point Double(Point p)
        {
            if (p == null || p.Y.IsZero) return null;
            BigInteger l = Mod((3 * p.X * p.X + A) * Inv(2 * p.Y, P), P);
            BigInteger x3 = Mod(l * l - 2 * p.X, P);
            BigInteger y3 = Mod(l * (p.X - x3) - p.Y, P);
            return new Point(x3, y3);
        }

        private static Point Add(Point p, Point q)
        {
            if (p == null) return q;
            if (q == null) return p;
            if (p.X == q.X)
            {
                // Same x: either the same point (double it) or inverses (infinity).
                return Mod(p.Y + q.Y, P).IsZero ? null : Double(p);
            }
            BigInteger l = Mod((q.Y - p.Y) * Inv(q.X - p.X, P), P);
            BigInteger x3 = Mod(l * l - p.X - q.X, P);
            BigInteger y3 = Mod(l * (p.X - x3) - p.Y, P);
            return new Point(x3, y3);
        }

        private static Point Multiply(BigInteger k, Point p)
        {
            Point result = null;
            for (int i = 255; i >= 0; i--)
            {
                result = Double(result);
                if (!((k >> i) & BigInteger.One).IsZero) result = Add(result, p);
            }
            return result;
        }

        private static bool IsOnCurve(BigInteger x, BigInteger y)
        {
            if (x.Sign < 0 || x >= P || y.Sign < 0 || y >= P) return false;
            return Mod(y * y, P) == Mod(x * x * x + A * x + B, P);
        }

        /// <summary>
        /// True only if <paramref name="signature"/> (r||s, 64 bytes) is a
        /// valid ECDSA signature of <paramref name="hash"/> (a 32-byte SHA-256
        /// digest) under the public key (<paramref name="qx"/>, <paramref name="qy"/>),
        /// each a 32-byte big-endian coordinate. Never throws on bad input -
        /// anything malformed is simply "not valid".
        /// </summary>
        public static bool Verify(byte[] hash, byte[] signature, byte[] qx, byte[] qy)
        {
            try
            {
                if (hash == null || hash.Length != 32) return false;
                if (signature == null || signature.Length != 64) return false;
                if (qx == null || qx.Length != 32 || qy == null || qy.Length != 32) return false;

                byte[] rBytes = new byte[32];
                byte[] sBytes = new byte[32];
                Array.Copy(signature, 0, rBytes, 0, 32);
                Array.Copy(signature, 32, sBytes, 0, 32);
                BigInteger r = FromBigEndian(rBytes);
                BigInteger s = FromBigEndian(sBytes);
                if (r.Sign <= 0 || r >= N || s.Sign <= 0 || s >= N) return false;

                BigInteger x = FromBigEndian(qx);
                BigInteger y = FromBigEndian(qy);
                if (!IsOnCurve(x, y)) return false;
                Point q = new Point(x, y);

                BigInteger e = FromBigEndian(hash); // 256-bit digest, 256-bit group order: no truncation
                BigInteger w = Inv(s, N);
                BigInteger u1 = Mod(e * w, N);
                BigInteger u2 = Mod(r * w, N);

                Point sum = Add(Multiply(u1, new Point(Gx, Gy)), Multiply(u2, q));
                if (sum == null) return false;
                return Mod(sum.X, N) == r;
            }
            catch (Exception)
            {
                return false;
            }
        }
    }
#endif
}
