using System;
using System.Diagnostics;
using System.Reflection;
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
        private static void Main(string[] args)
        {
            // The copy of this same .exe that RegisterUninstaller places at
            // <install dir>\Uninstall.exe (and that the "Apps & Features"
            // entry's UninstallString points to) is launched with this one
            // argument. Deliberately checked BEFORE the self-integrity gate
            // below - that gate exists to stop an unverifiable installer
            // from consuming a purchase/transfer key, which has no bearing
            // on whether someone should be allowed to remove files this
            // same program already installed.
            if (args != null && args.Length > 0 && string.Equals(args[0], "/uninstall", StringComparison.OrdinalIgnoreCase))
            {
                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);
                RunUninstallFlow();
                return;
            }

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

        /// <summary>
        /// The entire "/uninstall" flow: confirm, offer elevation if needed
        /// (Windows Service / %ProgramFiles% removal both require it - see
        /// UninstallService.WillNeedAdministrator), perform the removal, and
        /// report the result. Deliberately simple MessageBox-based UI - this
        /// is a short one-shot operation launched from Windows "Apps &amp;
        /// Features", not part of the normal multi-step install wizard.
        /// </summary>
        private static void RunUninstallFlow()
        {
            DialogResult confirm = MessageBox.Show(
                "This will remove Nutricula from MetaTrader on this computer, including the license " +
                "service/broker and all installed files. Continue?",
                "Uninstall Nutricula",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning);
            if (confirm != DialogResult.Yes) return;

            if (UninstallService.WillNeedAdministrator())
            {
                DialogResult elevate = MessageBox.Show(
                    "Administrator privileges are needed to fully remove Nutricula (a Windows Service or a " +
                    "Program Files installation was found). Restart this uninstaller as Administrator now?",
                    "Administrator Required",
                    MessageBoxButtons.YesNo,
                    MessageBoxIcon.Information);
                if (elevate == DialogResult.Yes)
                {
                    try
                    {
                        Process.Start(new ProcessStartInfo
                        {
                            FileName = Assembly.GetExecutingAssembly().Location,
                            Arguments = "/uninstall",
                            UseShellExecute = true,
                            Verb = "runas"
                        });
                        return;
                    }
                    catch (Exception)
                    {
                        // The user cancelled the UAC prompt, or elevation
                        // otherwise failed - fall through and continue with
                        // a best-effort, non-elevated removal rather than
                        // leaving them with nothing at all.
                    }
                }
            }

            UninstallService.UninstallOutcome outcome = UninstallService.PerformUninstall();

            string summary = "Nutricula has been uninstalled.";
            if (outcome.Warnings.Count > 0)
            {
                summary += "\n\nSome items could not be fully removed:\n- " + string.Join("\n- ", outcome.Warnings);
            }
            MessageBox.Show(
                summary,
                "Nutricula Uninstall",
                MessageBoxButtons.OK,
                outcome.Warnings.Count > 0 ? MessageBoxIcon.Warning : MessageBoxIcon.Information);
        }
    }
}
