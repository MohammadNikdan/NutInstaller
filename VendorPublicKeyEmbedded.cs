namespace NutriculaInstaller
{
    /// <summary>
    /// The vendor's P-256 public key, baked into the Installer at build time
    /// (mirrors the pattern already used for VendorSigningKey_Public in the
    /// Coordinator - see KeyBaker.exe / *_Generated.h). Used ONLY to verify
    /// the Installer's own self-integrity signature (see
    /// SelfIntegrityCheck.cs) - never used for anything license-related.
    ///
    /// THIS FILE MUST BE REGENERATED (by the same key-baking process used
    /// for the Coordinator) whenever VendorSigningKey_Public.pem changes -
    /// the X/Y bytes below are a placeholder pair generated for this
    /// specific delivery/test and must be replaced with the project's real
    /// vendor public key before this ships.
    /// </summary>
    internal static class VendorPublicKeyEmbedded
    {
        public static readonly byte[] X =
        {
            181,120,62,49,202,189,187,36,165,177,15,186,62,81,240,35,99,75,82,248,231,157,124,155,12,149,113,125,65,114,169,99
        };

        public static readonly byte[] Y =
        {
            156,61,171,156,50,153,233,197,82,172,137,24,99,160,163,247,44,54,216,15,199,37,31,38,29,215,67,60,163,244,158,131
        };
    }
}
