using System;
using System.IO;
using System.Reflection;

namespace NutriculaInstaller
{
    /// <summary>
    /// The two installer-wide values the project owner changes most often -
    /// the displayed version number and the Installation Guide link - kept
    /// in one plain-text file (Config\AppConfig.txt) instead of scattered
    /// across source files, so updating either one is just an edit-and-
    /// rebuild with nothing to hunt for in the code.
    ///
    /// Read once, lazily, from the embedded copy of that file (the same
    /// EmbeddedResource pattern this project already uses for its other
    /// bundled assets - see NutriculaInstaller.csproj). The hardcoded
    /// fallbacks below are only a safety net for the practically impossible
    /// case where the resource itself is missing from the build - they are
    /// not a second place anyone needs to remember to update.
    /// </summary>
    internal static class AppConfig
    {
        private const string ResourceName = "NutriculaInstaller.Config.AppConfig.txt";

        private const string FallbackVersion = "3.1";
        private const string FallbackGuideUrl = "https://www.youtube.com/";

        private static readonly Lazy<AppConfigValues> values = new Lazy<AppConfigValues>(Load);

        public static string Version => values.Value.Version;
        public static string InstallationGuideUrl => values.Value.InstallationGuideUrl;

        private sealed class AppConfigValues
        {
            public string Version = FallbackVersion;
            public string InstallationGuideUrl = FallbackGuideUrl;
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
