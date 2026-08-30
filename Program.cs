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
