using System;
using System.Windows.Forms;

namespace NutriculaInstaller
{
    internal static class Program
    {
        [STAThread]
        private static void Main()
        {
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
