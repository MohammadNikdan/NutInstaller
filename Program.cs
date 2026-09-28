using System;
using System.Windows.Forms;

namespace NutriculaInstaller
{
    internal static class Program
    {
        /// <summary>
        /// Result of the self-integrity check, computed once at startup -
        /// see SelfIntegrityCheck.cs for what this does and does not
        /// protect against. MainForm reads this to decide whether to warn
        /// the user before allowing Premium/Transfer (which consume a
        /// purchase key or transfer key) to proceed.
        /// </summary>
        public static bool SelfIntegrityVerified { get; private set; }
        public static string SelfIntegrityFailureReason { get; private set; }

        [STAThread]
        private static void Main()
        {
            string failureReason;
            SelfIntegrityVerified = SelfIntegrityCheck.Verify(out failureReason);
            SelfIntegrityFailureReason = failureReason;

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            // 2026 hardening: an unsigned or tampered installer.exe now
            // refuses to open at all, rather than opening normally and only
            // being blocked later at the Premium/Transfer activation step.
            // This does not weaken anything - SelfIntegrityCheck.Verify()'s
            // own header comment already explains that this check cannot be
            // made unbypassable purely from inside the binary it protects
            // (an attacker able to patch out this exact block could always
            // patch out any other gate too), so refusing to run at all is
            // strictly more restrictive than the previous "opens, but the
            // license step fails" behavior, never less secure. The
            // RequestLicenseAsync-side check in InstallerService.cs is left
            // in place as a harmless extra safety net; with this block, it
            // should never actually be reached in normal operation.
            if (!SelfIntegrityVerified)
            {
                MessageBox.Show(
                    (failureReason ?? "This installer file could not be verified.") +
                        " This installer cannot be used. Please download a fresh, unmodified copy of " +
                        "the Nutricula installer and try again.",
                    "Nutricula",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
                return;
            }

            Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
            Application.ThreadException += delegate(object sender, System.Threading.ThreadExceptionEventArgs e)
            {
                // Keep all failures inside the main UI instead of opening a separate dialog.
                MainForm.NotifyUnhandledException(e.Exception);
            };
            AppDomain.CurrentDomain.UnhandledException += delegate(object sender, UnhandledExceptionEventArgs e)
            {
                // Non-UI thread failures are handled by the service-level guards where possible.
            };

            Application.Run(new MainForm());
        }
    }
}
