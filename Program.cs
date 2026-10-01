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
                // "/skipconfirm" is passed only by this same process when it
                // relaunches itself elevated a few lines below (or by
                // MainForm's own "Uninstall Nutricula" button, which already
                // asked its own confirmation) - it exists purely so the
                // person is never asked "are you sure?" twice in a row.
                bool skipConfirm = args.Length > 1 && string.Equals(args[1], "/skipconfirm", StringComparison.OrdinalIgnoreCase);
                RunUninstallFlow(skipConfirm);
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
                // Deliberately generic wording, regardless of the specific
                // internal failureReason (missing trailer, bad magic bytes,
                // or a real signature mismatch - see SelfIntegrityCheck.cs)
                // - the person is never told anything about a "signature" at
                // all. From their side this must look and read exactly like
                // an ordinary corrupted/incomplete download, with one clear
                // fix: get a fresh copy from the official site.
                MessageBox.Show(
                    "This installer file appears to be corrupted or damaged and cannot be used.\n\n" +
                        "Please download a fresh copy of the Nutricula installer from the official " +
                        "Nutricula website: www.NutriculaExpert.com",
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
        /// The entire "/uninstall" flow: confirm once, elevate immediately
        /// if needed (no separate "a Windows Service was found, restart as
        /// Administrator?" question - this always elevates for an
        /// uninstall, since it is a short one-shot operation where asking
        /// twice only adds friction), perform the removal, finish the
        /// uninstaller's own self-delete if it was launched from inside the
        /// install directory (see UninstallService.ScheduleSelfDelete), and
        /// report the result. Deliberately simple MessageBox-based UI -
        /// this is launched from Windows "Apps &amp; Features" (or from
        /// MainForm's own "Uninstall Nutricula" button), not part of the
        /// normal multi-step install wizard.
        /// </summary>
        private static void RunUninstallFlow(bool skipConfirm)
        {
            if (!skipConfirm)
            {
                DialogResult confirm = MessageBox.Show(
                    "This will remove Nutricula EA from MetaTrader on this computer, including the " +
                    "license service/broker and all installed files. Continue?",
                    "Uninstall Nutricula EA",
                    MessageBoxButtons.YesNo,
                    MessageBoxIcon.Warning);
                if (confirm != DialogResult.Yes) return;
            }

            if (!UninstallService.IsRunningAsAdministrator())
            {
                try
                {
                    Process.Start(new ProcessStartInfo
                    {
                        FileName = Assembly.GetExecutingAssembly().Location,
                        Arguments = "/uninstall /skipconfirm",
                        UseShellExecute = true,
                        Verb = "runas"
                    });
                }
                catch (Exception)
                {
                    // The UAC prompt was cancelled, or elevation otherwise
                    // failed. Removal genuinely needs admin rights (the
                    // Windows Service and the Program Files installation
                    // both require it) - silently doing a partial,
                    // non-elevated removal the person never agreed to would
                    // be worse than clearly saying nothing happened yet.
                    MessageBox.Show(
                        "Administrator rights are required to remove Nutricula EA, and the elevation " +
                        "prompt was cancelled or failed. Nothing was changed - run Uninstall again and " +
                        "accept the prompt to continue.",
                        "Uninstall Nutricula EA",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Warning);
                }
                return;
            }

            UninstallService.UninstallOutcome outcome = UninstallService.PerformUninstall();

            // Must happen before the process exits (the MessageBox below
            // blocks on the user, which only adds extra margin) - finishes
            // deleting Uninstall.exe and its folder once this process has
            // actually released the lock on its own running .exe. A no-op
            // when PendingSelfDeleteDirectory is null (the common case - not
            // launched from inside the install directory).
            UninstallService.ScheduleSelfDelete(outcome.PendingSelfDeleteDirectory);

            string summary = "Nutricula EA has been uninstalled.";
            if (outcome.Warnings.Count > 0)
            {
                summary += "\n\nSome items could not be fully removed:\n- " + string.Join("\n- ", outcome.Warnings);
            }
            MessageBox.Show(
                summary,
                "Nutricula EA Uninstall",
                MessageBoxButtons.OK,
                outcome.Warnings.Count > 0 ? MessageBoxIcon.Warning : MessageBoxIcon.Information);
        }
    }
}
