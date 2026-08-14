using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace NutriculaInstaller
{
    public sealed class MainForm : Form
    {
        private readonly InstallerService installer = new InstallerService();
        private readonly CancellationTokenSource cts = new CancellationTokenSource();

        private OptionCard freeCard;
        private OptionCard premiumCard;
        private OptionCard transferCard;
        private TextBox emailBox;
        private TextBox purchaseKeyBox;
        private Label emailLabel;
        private Label purchaseLabel;
        private Label statusLabel;
        private Label resultLabel;
        private Label terminalCountLabel;
        private Label progressLabel;
        private ProgressBar progressBar;
        private Button prevButton;
        private Button nextButton;
        private Button finishButton;
        private Button guideButton;
        private Button buyButton;
        private Panel logPanel;
        private TextBox logBox;
        private bool running;
        private InstallMode selectedMode = InstallMode.Free;

        private static readonly Color Brand = UiHelpers.BrandColor;

        public MainForm()
        {
            InitializeForm();
            BuildUi();
            SelectMode(InstallMode.Free);
        }

        public static void NotifyUnhandledException(Exception ex)
        {
            // The main form handles its own exceptions. This hook intentionally does not open a second window.
        }

        protected override void OnFormClosed(FormClosedEventArgs e)
        {
            cts.Cancel();
            cts.Dispose();
            base.OnFormClosed(e);
        }

        private void InitializeForm()
        {
            Text = "Nutricula Expert Advisor Installer";
            StartPosition = FormStartPosition.CenterScreen;
            ClientSize = new Size(960, 680);
            MinimumSize = new Size(900, 620);
            BackColor = UiHelpers.Background;
            Font = new Font("Segoe UI", 9f);
            FormBorderStyle = FormBorderStyle.FixedSingle;
            MaximizeBox = false;
            DoubleBuffered = true;
            Icon = TryLoadIcon();
        }

        private Icon TryLoadIcon()
        {
            try
            {
                if (System.IO.File.Exists("icon.ico"))
                    return new Icon("icon.ico");
            }
            catch { }
            return SystemIcons.Application;
        }

        private void BuildUi()
        {
            Panel header = new Panel { Dock = DockStyle.Top, Height = 92, BackColor = Brand };
            Controls.Add(header);

            Label brand = new Label
            {
                AutoSize = true,
                Text = "NUTRICULA",
                Font = new Font("Segoe UI Semibold", 18f),
                ForeColor = Color.White,
                Location = new Point(34, 18)
            };
            header.Controls.Add(brand);

            Label title = new Label
            {
                AutoSize = true,
                Text = "Expert Advisor Installer",
                Font = new Font("Segoe UI", 11.5f),
                ForeColor = Color.FromArgb(222, 226, 239),
                Location = new Point(36, 52)
            };
            header.Controls.Add(title);

            Label company = new Label
            {
                AutoSize = true,
                Text = "(by Highflyers co.)",
                Font = new Font("Segoe UI", 8.5f),
                ForeColor = Color.FromArgb(211, 216, 232),
                Anchor = AnchorStyles.Top | AnchorStyles.Right,
                Location = new Point(794, 36)
            };
            header.Controls.Add(company);

            Panel body = new Panel { Dock = DockStyle.Fill, Padding = new Padding(28, 22, 28, 0), BackColor = UiHelpers.Background };
            Controls.Add(body);
            body.BringToFront();

            Label section = new Label
            {
                AutoSize = true,
                Text = "Choose an installation option",
                Font = new Font("Segoe UI Semibold", 12f),
                ForeColor = UiHelpers.TextDark,
                Location = new Point(2, 2)
            };
            body.Controls.Add(section);

            freeCard = new OptionCard(InstallMode.Free, "Install Free Version", "Install the free Nutricula files without license activation.") { Location = new Point(0, 34), Width = 560 };
            premiumCard = new OptionCard(InstallMode.Premium, "Install Premium Version", "Install Nutricula and activate a purchase license on this computer.") { Location = new Point(0, 116), Width = 560 };
            transferCard = new OptionCard(InstallMode.Transfer, "Transfer License to Another Computer", "Install Nutricula and move the existing license to this computer.") { Location = new Point(0, 198), Width = 560 };
            freeCard.CardClicked += delegate { SelectMode(InstallMode.Free); };
            premiumCard.CardClicked += delegate { SelectMode(InstallMode.Premium); };
            transferCard.CardClicked += delegate { SelectMode(InstallMode.Transfer); };
            body.Controls.Add(freeCard);
            body.Controls.Add(premiumCard);
            body.Controls.Add(transferCard);

            Panel credentials = new Panel { Location = new Point(594, 34), Width = 300, Height = 255, BackColor = Color.White };
            credentials.Paint += delegate(object sender, PaintEventArgs e)
            {
                e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
                UiHelpers.DrawRounded(e.Graphics, new Rectangle(0, 0, credentials.Width - 1, credentials.Height - 1), 14, Color.White, UiHelpers.Border);
            };
            body.Controls.Add(credentials);

            Label cTitle = new Label { AutoSize = true, Text = "License information", Font = new Font("Segoe UI Semibold", 10.5f), ForeColor = UiHelpers.TextDark, Location = new Point(18, 16) };
            credentials.Controls.Add(cTitle);

            emailLabel = new Label { AutoSize = true, Text = "Email", Font = new Font("Segoe UI Semibold", 8.5f), ForeColor = UiHelpers.TextDark, Location = new Point(18, 56) };
            emailBox = new TextBox { Location = new Point(18, 76), Width = 260, Height = 28, BorderStyle = BorderStyle.FixedSingle };
            credentials.Controls.Add(emailLabel);
            credentials.Controls.Add(emailBox);

            purchaseLabel = new Label { AutoSize = true, Text = "Purchase Key", Font = new Font("Segoe UI Semibold", 8.5f), ForeColor = UiHelpers.TextDark, Location = new Point(18, 124) };
            purchaseKeyBox = new TextBox { Location = new Point(18, 144), Width = 260, Height = 28, BorderStyle = BorderStyle.FixedSingle };
            credentials.Controls.Add(purchaseLabel);
            credentials.Controls.Add(purchaseKeyBox);

            Label note = new Label { AutoSize = false, Size = new Size(260, 44), Text = "Required only for Premium installation and license transfer.", Font = new Font("Segoe UI", 7.8f), ForeColor = UiHelpers.TextMuted, Location = new Point(18, 188) };
            credentials.Controls.Add(note);

            terminalCountLabel = new Label { AutoSize = false, Size = new Size(560, 32), Text = "MetaTrader terminals will be detected automatically.", Font = new Font("Segoe UI", 8.5f), ForeColor = UiHelpers.TextMuted, Location = new Point(0, 291) };
            body.Controls.Add(terminalCountLabel);

            resultLabel = new Label { AutoSize = false, Size = new Size(894, 44), Text = "", Font = new Font("Segoe UI Semibold", 10f), Location = new Point(0, 334) };
            body.Controls.Add(resultLabel);

            statusLabel = new Label { AutoSize = false, Size = new Size(650, 23), Text = "Ready", Font = new Font("Segoe UI", 8.5f), ForeColor = UiHelpers.TextMuted, Location = new Point(0, 381) };
            body.Controls.Add(statusLabel);

            progressBar = new ProgressBar { Minimum = 0, Maximum = 100, Value = 0, Location = new Point(0, 412), Size = new Size(894, 12), Style = ProgressBarStyle.Continuous };
            body.Controls.Add(progressBar);

            progressLabel = new Label { AutoSize = true, Text = "0%", Font = new Font("Segoe UI", 8f), ForeColor = UiHelpers.TextMuted, Location = new Point(850, 388) };
            body.Controls.Add(progressLabel);

            logPanel = new Panel { Location = new Point(0, 434), Size = new Size(894, 110), BackColor = Color.FromArgb(28, 31, 41), Visible = false };
            logPanel.Paint += delegate(object sender, PaintEventArgs e)
            {
                e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
                UiHelpers.DrawRounded(e.Graphics, new Rectangle(0, 0, logPanel.Width - 1, logPanel.Height - 1), 10, Color.FromArgb(28, 31, 41), Color.FromArgb(60, 65, 80));
            };
            body.Controls.Add(logPanel);
            logBox = new TextBox { Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, BackColor = Color.FromArgb(28, 31, 41), ForeColor = Color.FromArgb(226, 231, 242), BorderStyle = BorderStyle.None, Dock = DockStyle.Fill, Font = new Font("Consolas", 8.5f), Padding = new Padding(10) };
            logPanel.Controls.Add(logBox);

            Panel footer = new Panel { Dock = DockStyle.Bottom, Height = 76, BackColor = Color.White };
            Controls.Add(footer);
            footer.BringToFront();

            guideButton = CreateLinkButton("Installation Guide Video", 28, 18, 170);
            guideButton.Click += delegate { OpenUrl("https://www.youtube.com/"); };
            footer.Controls.Add(guideButton);

            buyButton = CreatePrimaryLinkButton("Buy Premium License", 205, 14, 170);
            buyButton.Click += delegate { OpenUrl("https://www.google.com/"); };
            footer.Controls.Add(buyButton);

            prevButton = CreateSecondaryButton("Prev", 610, 15, 80);
            prevButton.Enabled = false;
            footer.Controls.Add(prevButton);

            nextButton = CreateSecondaryButton("Next", 700, 15, 90);
            nextButton.Click += async delegate { await BeginInstallAsync(); };
            footer.Controls.Add(nextButton);

            finishButton = CreateMainButton("Finish", 800, 15, 120);
            finishButton.Enabled = false;
            finishButton.Click += delegate { Close(); };
            footer.Controls.Add(finishButton);
        }

        private Button CreateLinkButton(string text, int x, int y, int width)
        {
            return new Button
            {
                Text = text,
                Location = new Point(x, y),
                Size = new Size(width, 44),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.White,
                ForeColor = UiHelpers.TextDark,
                Font = new Font("Segoe UI Semibold", 8.5f),
                Cursor = Cursors.Hand,
                FlatAppearance = { BorderSize = 0 }
            };
        }

        private Button CreatePrimaryLinkButton(string text, int x, int y, int width)
        {
            Button b = CreateLinkButton(text, x, y, width);
            b.BackColor = Color.FromArgb(247, 240, 229);
            b.ForeColor = Color.FromArgb(131, 87, 25);
            return b;
        }

        private Button CreateSecondaryButton(string text, int x, int y, int width)
        {
            Button b = new Button
            {
                Text = text,
                Location = new Point(x, y),
                Size = new Size(width, 44),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.White,
                ForeColor = UiHelpers.TextDark,
                Font = new Font("Segoe UI Semibold", 9f),
                Cursor = Cursors.Hand
            };
            b.FlatAppearance.BorderColor = UiHelpers.Border;
            b.FlatAppearance.BorderSize = 1;
            return b;
        }

        private Button CreateMainButton(string text, int x, int y, int width)
        {
            Button b = new Button
            {
                Text = text,
                Location = new Point(x, y),
                Size = new Size(width, 44),
                FlatStyle = FlatStyle.Flat,
                BackColor = Brand,
                ForeColor = Color.White,
                Font = new Font("Segoe UI Semibold", 9f),
                Cursor = Cursors.Hand
            };
            b.FlatAppearance.BorderSize = 0;
            return b;
        }

        private void SelectMode(InstallMode mode)
        {
            selectedMode = mode;
            freeCard.Selected = mode == InstallMode.Free;
            premiumCard.Selected = mode == InstallMode.Premium;
            transferCard.Selected = mode == InstallMode.Transfer;
            bool needsCredentials = mode != InstallMode.Free;
            emailBox.Enabled = needsCredentials;
            purchaseKeyBox.Enabled = needsCredentials;
            emailLabel.Enabled = needsCredentials;
            purchaseLabel.Enabled = needsCredentials;
            statusLabel.Text = mode == InstallMode.Free ? "Ready to install the free version." : "Enter your Email and Purchase Key to continue.";
            resultLabel.Text = "";
            resultLabel.ForeColor = UiHelpers.TextDark;
        }

        private async Task BeginInstallAsync()
        {
            if (running)
                return;

            if (selectedMode != InstallMode.Free)
            {
                string email = emailBox.Text.Trim();
                string key = purchaseKeyBox.Text;
                string validationError;
                if (!ValidateCredentials(email, key, out validationError))
                {
                    resultLabel.ForeColor = UiHelpers.Error;
                    resultLabel.Text = validationError;
                    return;
                }
            }

            running = true;
            SetRunningState(true);
            logPanel.Visible = true;
            resultLabel.Text = "";
            resultLabel.ForeColor = UiHelpers.TextDark;
            progressBar.Value = 0;
            progressLabel.Text = "0%";
            AppendLog("Starting installer...");

            try
            {
                List<TerminalInfo> discovered = installer.DiscoverTerminals(AppendLog);
                terminalCountLabel.Text = discovered.Count + " MetaTrader terminal(s) found.";

                var progress = new Progress<ProgressUpdate>(p =>
                {
                    progressBar.Value = p.Percent;
                    progressLabel.Text = p.Percent + "%";
                    statusLabel.Text = "Installing files...";
                });

                InstallResult result = await installer.RunAsync(
                    selectedMode,
                    emailBox.Text.Trim(),
                    purchaseKeyBox.Text,
                    cts.Token,
                    progress,
                    AppendLog);

                progressBar.Value = result.OverallSuccess ? 100 : progressBar.Value;
                progressLabel.Text = result.OverallSuccess ? "100%" : progressLabel.Text;
                resultLabel.ForeColor = result.OverallSuccess ? UiHelpers.Success : UiHelpers.Error;
                resultLabel.Text = result.FinalMessage;
                statusLabel.Text = result.OverallSuccess ? "Completed" : "Completed with an error.";
                finishButton.Enabled = true;

                if (result.Errors.Count > 0)
                {
                    foreach (string err in result.Errors)
                        AppendLog("ERROR: " + err);
                }
            }
            catch (Exception ex)
            {
                resultLabel.ForeColor = UiHelpers.Error;
                resultLabel.Text = "The installation could not be completed: " + ex.Message;
                statusLabel.Text = "Completed with an error.";
                AppendLog("FATAL: " + ex);
                finishButton.Enabled = true;
            }
            finally
            {
                running = false;
                SetRunningState(false);
            }
        }

        private bool ValidateCredentials(string email, string key, out string error)
        {
            if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(key))
            {
                error = "Email and Purchase Key are both required.";
                return false;
            }

            try
            {
                var address = new System.Net.Mail.MailAddress(email);
                if (!string.Equals(address.Address, email, StringComparison.OrdinalIgnoreCase))
                {
                    error = "Please enter a valid email address.";
                    return false;
                }
            }
            catch
            {
                error = "Please enter a valid email address.";
                return false;
            }

            error = null;
            return true;
        }

        private void SetRunningState(bool isRunning)
        {
            nextButton.Visible = !isRunning;
            prevButton.Visible = !isRunning;
            finishButton.Visible = true;
            finishButton.Enabled = !isRunning && finishButton.Enabled;
            guideButton.Enabled = !isRunning;
            buyButton.Enabled = !isRunning;
            freeCard.Enabled = !isRunning;
            premiumCard.Enabled = !isRunning;
            transferCard.Enabled = !isRunning;
            emailBox.ReadOnly = isRunning;
            purchaseKeyBox.ReadOnly = isRunning;
        }

        private void AppendLog(string message)
        {
            if (IsDisposed)
                return;
            if (InvokeRequired)
            {
                BeginInvoke(new Action<string>(AppendLog), message);
                return;
            }

            logBox.AppendText(DateTime.Now.ToString("HH:mm:ss") + "  " + message + Environment.NewLine);
            logBox.SelectionStart = logBox.TextLength;
            logBox.ScrollToCaret();
        }

        private void OpenUrl(string url)
        {
            try
            {
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                {
                    FileName = url,
                    UseShellExecute = true
                });
            }
            catch (Exception ex)
            {
                AppendLog("Could not open browser: " + ex.Message);
            }
        }
    }
}
