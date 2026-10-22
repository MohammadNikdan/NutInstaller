using System;
using System.Diagnostics;
using System.Threading;
using System.Windows.Forms;

namespace NutriculaInstaller
{
    internal static class Program
    {
        /// <summary>
        /// Result of the self-integrity check. Computed on MainForm's own
        /// startup background worker now (see MainForm.RunStartupChecks),
        /// behind its splash overlay, rather than before any window existed
        /// at all - so the setters are internal, not private: MainForm is
        /// what actually runs SelfIntegrityCheck.Verify() and reports the
        /// result back here. InstallerService reads the getters to decide
        /// whether to warn the user before allowing Premium/Transfer (which
        /// consume a purchase key or transfer key) to proceed.
        /// </summary>
        public static bool SelfIntegrityVerified { get; internal set; }
        public static string SelfIntegrityFailureReason { get; internal set; }

        // Single-instance guard for the main install wizard (2026 UX fix -
        // nothing stopped someone from double-clicking Installer.exe many
        // times and ending up with a dozen overlapping wizard windows, each
        // with its own InstallerService/CancellationTokenSource, all free to
        // race each other over the same install directory and license file).
        //
        // Deliberately a plain (session-local, no "Global\" prefix) named
        // Mutex rather than a machine-wide one: this product is a per-user,
        // non-elevated install (HKCU uninstall entry, %LocalAppData%
        // Broker - see InstallerService.GetCoordinatorInstallDir), so "one
        // instance" is scoped to one Windows login session, consistent with
        // everything else in this design. Two different users logged into
        // the same machine each still get their own single instance, which
        // is correct - they are installing into two different profiles.
        //
        // Deliberately NOT applied to the "/uninstall" launch path below:
        // that path is today a short-lived child process spawned by this
        // same MainForm's "Uninstall Nutricula" button (Process.Start,
        // immediately followed by this parent's own Close()). Guarding it
        // with the same mutex would race the parent's exit (mutex release)
        // against the child's acquire attempt, and could spuriously tell a
        // legitimate uninstall "already running". The one-instance guard
        // below exists to stop many WIZARD windows, which is what was asked
        // for; the uninstall child process has no window of its own at all
        // today, so it isn't the thing being guarded against here.
        private static Mutex singleInstanceMutex;

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
                // "/skipconfirm" is passed by MainForm's own "Uninstall
                // Nutricula" button (which already asked its own
                // confirmation) - it exists purely so the person is never
                // asked "are you sure?" twice in a row.
                bool skipConfirm = args.Length > 1 && string.Equals(args[1], "/skipconfirm", StringComparison.OrdinalIgnoreCase);
                RunUninstallFlow(skipConfirm);
                return;
            }

            // Only one copy of the install wizard may be open at a time -
            // see the field comment above for exactly why this is scoped
            // the way it is. createdNew=false means another instance (in
            // this same login session) already holds it; tell the person
            // and exit without touching anything. The mutex is deliberately
            // kept alive for the rest of the process (never Dispose()'d
            // here) - the OS releases it automatically when this process
            // exits, by any path, which is exactly the lifetime wanted.
            bool createdNew;
            singleInstanceMutex = new Mutex(true, @"Local\NutriculaInstaller_SingleInstance_8F2B7C1E-6A3D-4E2F-9C0B-1D5A7E9F3C21", out createdNew);
            if (!createdNew)
            {
                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);
                MessageBox.Show(
                    "The Nutricula installer is already open. Please use that window - only one copy can run at a time.",
                    "Nutricula",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
                return;
            }

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            // 2026 UX fix: the self-integrity signature check and the
            // MetaTrader-running scan used to both run here, silently,
            // before Application.Run ever created a window - so the person
            // saw nothing at all (not even an hourglass) for however long
            // that took. They now run on MainForm's own startup background
            // worker (MainForm.RunStartupChecks), behind a splash overlay
            // INSIDE that same window - one single window from the person's
            // side, shown immediately, with the real wizard underneath only
            // revealed once both checks pass. See MainForm's constructor and
            // RunStartupChecks/FinishStartupChecks for exactly how this
            // plays out, including the "corrupted installer" and
            // "MetaTrader is still open" cases, which now close that one
            // window instead of a window never existing at all - same end
            // result (nothing proceeds), just after a brief glimpse of the
            // splash rather than nothing.
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
        /// The entire "/uninstall" flow: confirm once, make sure MetaTrader
        /// is closed (its running terminal holds the EA's DLLs locked, so
        /// they cannot be deleted while it is open - the person is asked to
        /// close it and run Uninstall again), perform the removal, finish the
        /// uninstaller's own self-delete if it was launched from inside the
        /// install directory (see UninstallService.ScheduleSelfDelete), and
        /// report the result. No elevation step is needed any more - the
        /// whole product is a per-user, non-elevated install (the Coordinator
        /// is the user-session Broker under %LocalAppData%, with a per-user
        /// HKCU uninstall entry). Deliberately simple MessageBox-based UI -
        /// this is launched from Windows "Apps &amp; Features" (or from
        /// MainForm's own "Uninstall Nutricula" button), not part of the
        /// normal multi-step install wizard.
        /// </summary>
        private static void RunUninstallFlow(bool skipConfirm)
        {
            if (!skipConfirm)
            {
                DialogResult confirm = MessageBox.Show(
                    "This will completely remove Nutricula EA, including your license, from this computer. Continue?",
                    "Uninstall Nutricula EA",
                    MessageBoxButtons.YesNo,
                    MessageBoxIcon.Warning);
                if (confirm != DialogResult.Yes) return;
            }

            // MetaTrader must be closed first: while a terminal is running it
            // keeps the Nutricula DLLs (NutriculaLicenseCheck*.dll /
            // MachineId*.dll) loaded and locked in its MQL5/Libraries folder,
            // so they cannot be deleted and the uninstall would leave files
            // behind. Rather than do a partial removal, stop and tell the
            // person exactly what to do, then let them run Uninstall again.
            // Same gate as the install path, with a Retry button so the
            // person does not have to find and start Uninstall again.
            if (!EnsureMetaTraderClosed("be removed"))
            {
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

        /// <summary>
        /// Every MetaTrader process that would hold Nutricula's files open,
        /// by its process name (without ".exe", as
        /// Process.GetProcessesByName expects) and the name to show a person.
        ///
        /// MetaEditor and the Strategy Tester agents are included, not just
        /// the terminals: MetaEditor locks a compiled program it has open,
        /// and a tester agent runs its own copy of the EA out of
        /// &lt;data&gt;\Tester\Agent-*\MQL5\Experts. Either one left running
        /// can keep a stale file alive through an install, which is exactly
        /// what the integrity check would later refuse.
        /// </summary>
        private static readonly string[,] MetaTraderProcesses =
        {
            { "terminal", "MetaTrader 4" },
            { "terminal64", "MetaTrader 5" },
            { "metaeditor", "MetaEditor" },
            { "metaeditor64", "MetaEditor" },
            { "metatester", "a Strategy Tester agent" },
            { "metatester64", "a Strategy Tester agent" },
        };

        /// <summary>
        /// True if any of the processes above is running. Sets a
        /// human-readable list of which were found, with no duplicates, for
        /// the message shown to the person.
        /// </summary>
        private static bool AnyMetaTraderRunning(out string runningTerminals)
        {
            var found = new System.Collections.Generic.List<string>();
            for (int i = 0; i < MetaTraderProcesses.GetLength(0); i++)
            {
                string processName = MetaTraderProcesses[i, 0];
                string displayName = MetaTraderProcesses[i, 1];
                bool running = false;
                try { running = Process.GetProcessesByName(processName).Length > 0; }
                catch { /* best-effort: a process we cannot query is not a reason to block */ }
                if (running && !found.Contains(displayName)) found.Add(displayName);
            }

            runningTerminals = string.Join(", ", found.ToArray());
            return found.Count > 0;
        }

        /// <summary>
        /// Blocks until no MetaTrader process is running, or until the person
        /// gives up. Returns false if they chose to quit.
        ///
        /// Running this BEFORE the installer window opens is deliberate. The
        /// install now clears any existing Nutricula files out of a terminal
        /// before writing the fresh ones (see NutriculaSweeper.cs), and a
        /// running terminal holds those files open, so an install done around
        /// an open MetaTrader can leave a stale copy behind - which the
        /// Coordinator's integrity check would then refuse, leaving the
        /// customer unable to trade for a reason that looks like nothing they
        /// did. Stopping at the door, with a Retry button so they never have
        /// to find and start the installer again, is far kinder than letting
        /// them through and failing afterwards.
        /// </summary>
        // internal (not private): MainForm's in-process uninstall path (the
        // "Uninstall Nutricula" button - see MainForm.OnUninstallTapped)
        // calls this directly now, the same gate the install path and the
        // external "/uninstall" command-line path both already use.
        internal static bool EnsureMetaTraderClosed(string actionDescription)
        {
            for (;;)
            {
                string running;
                if (!AnyMetaTraderRunning(out running)) return true;

                DialogResult choice = MessageBox.Show(
                    "Nutricula cannot " + actionDescription + " while MetaTrader is open.\n\n" +
                        "Currently running: " + running + "\n\n" +
                        "MetaTrader keeps Nutricula's files in use while it is running, so they cannot be " +
                        "replaced or removed. Please close every MetaTrader window, including MetaEditor " +
                        "and any Strategy Tester agents, then click Retry.\n\n" +
                        "Nothing on your computer has been changed.",
                    "Close MetaTrader to Continue",
                    MessageBoxButtons.RetryCancel,
                    MessageBoxIcon.Warning);

                if (choice != DialogResult.Retry) return false;
            }
        }
    }
}
