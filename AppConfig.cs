using System;
using System.IO;
using System.Reflection;

namespace NutriculaInstaller
{
    /// <summary>
    /// The installer-wide values the project owner changes most often - the
    /// displayed version number and every outward-facing link/URL - kept in
    /// one plain-text file (Config\AppConfig.txt) instead of scattered across
    /// source files, so updating any of them is just an edit-and-rebuild with
    /// nothing to hunt for in the code.
    ///
    /// Read once, lazily, from the embedded copy of that file (the same
    /// EmbeddedResource pattern this project already uses for its other
    /// bundled assets - see NutriculaInstaller.csproj). The hardcoded
    /// fallbacks below are only a safety net for the practically impossible
    /// case where the resource itself is missing from the build - they are
    /// not a second place anyone needs to remember to update.
    ///
    /// SECURITY NOTE: this file is an EmbeddedResource that also lives in the
    /// source tree and is committed to the repository, so ONLY non-secret,
    /// outward-facing values (version + public links) belong here. Real
    /// secrets (e.g. the Transport key, which is baked into the DLLs via the
    /// TransportKeyPrivate.h in the DO-NOT-UPLOAD folder, or the EDD API
    /// credentials, which live in the server-side license_config.php) must
    /// NEVER be moved here - putting a secret in a committed file would leak
    /// it to the repo even though the baked-in binary exposure is unchanged.
    /// </summary>
    internal static class AppConfig
    {
        private const string ResourceName = "NutriculaInstaller.Config.AppConfig.txt";

        private const string FallbackVersion = "3.1";
        private const string FallbackGuideUrl = "https://www.youtube.com/";
        private const string FallbackWebsiteUrl = "https://www.NutriculaExpert.com";
        private const string FallbackSupportUrl = "https://t.me/nutriculaexpertsupport";
        private const string FallbackPremiumPurchaseUrl = "https://www.NutriculaExpert.com";
        private const string FallbackSignupUrl = "https://nutriculaexpert.com/license_validator_phps/nutricula_computer_based_signup.php";
        private const string FallbackTransferUrl = "https://nutriculaexpert.com/license_validator_phps/nutricula_computer_based_signup_transfer.php";

        private static readonly Lazy<AppConfigValues> values = new Lazy<AppConfigValues>(Load);

        public static string Version => values.Value.Version;
        public static string InstallationGuideUrl => values.Value.InstallationGuideUrl;
        public static string WebsiteUrl => values.Value.WebsiteUrl;
        public static string SupportUrl => values.Value.SupportUrl;
        public static string PremiumPurchaseUrl => values.Value.PremiumPurchaseUrl;
        public static string SignupUrl => values.Value.SignupUrl;
        public static string TransferUrl => values.Value.TransferUrl;

        private sealed class AppConfigValues
        {
            public string Version = FallbackVersion;
            public string InstallationGuideUrl = FallbackGuideUrl;
            public string WebsiteUrl = FallbackWebsiteUrl;
            public string SupportUrl = FallbackSupportUrl;
            public string PremiumPurchaseUrl = FallbackPremiumPurchaseUrl;
            public string SignupUrl = FallbackSignupUrl;
            public string TransferUrl = FallbackTransferUrl;
        }

        private static AppConfigValues Load()
        {
            var result = new AppConfigValues();
            try
            {
                using (Stream stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(ResourceName))
                {
                    if (stream == null) return result;

                    using (var reader = new StreamReader(stream))
                    {
                        string line;
                        while ((line = reader.ReadLine()) != null)
                        {
                            string trimmed = line.Trim();
                            if (trimmed.Length == 0 || trimmed.StartsWith("#", StringComparison.Ordinal)) continue;

                            int eq = trimmed.IndexOf('=');
                            if (eq <= 0) continue;

                            string key = trimmed.Substring(0, eq).Trim();
                            string value = trimmed.Substring(eq + 1).Trim();
                            if (value.Length == 0) continue;

                            if (string.Equals(key, "VERSION", StringComparison.OrdinalIgnoreCase))
                                result.Version = value;
                            else if (string.Equals(key, "INSTALLATION_GUIDE_URL", StringComparison.OrdinalIgnoreCase))
                                result.InstallationGuideUrl = value;
                            else if (string.Equals(key, "WEBSITE_URL", StringComparison.OrdinalIgnoreCase))
                                result.WebsiteUrl = value;
                            else if (string.Equals(key, "SUPPORT_URL", StringComparison.OrdinalIgnoreCase))
                                result.SupportUrl = value;
                            else if (string.Equals(key, "PREMIUM_PURCHASE_URL", StringComparison.OrdinalIgnoreCase))
                                result.PremiumPurchaseUrl = value;
                            else if (string.Equals(key, "SIGNUP_URL", StringComparison.OrdinalIgnoreCase))
                                result.SignupUrl = value;
                            else if (string.Equals(key, "TRANSFER_URL", StringComparison.OrdinalIgnoreCase))
                                result.TransferUrl = value;
                        }
                    }
                }
            }
            catch
            {
                // Never worth crashing (or even just showing a wrong but
                // alarming value) over a malformed config file - fall back
                // to the hardcoded defaults above.
                return new AppConfigValues();
            }

            return result;
        }
    }
}
