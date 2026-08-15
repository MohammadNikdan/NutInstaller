using System;
using System.Collections.Generic;
using System.Drawing;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace NutriculaInstaller
{
    public sealed class MainForm : Form
    {
        private readonly InstallerService installer = new InstallerService();
        private readonly CancellationTokenSource cts = new CancellationTokenSource();

        // Panels for Android-like screen navigation
        private Panel pnlHome;
        private Panel pnlCredentials;
        private Panel pnlProgress;

        // Credentials Controls
        private TextBox emailBox;
        private TextBox purchaseKeyBox;
        private Label credErrorLabel;

        // Progress Controls
        private ProgressBar progressBar;
        private Label statusLabel;
        private Label resultLabel;
        private Button finishButton;

        private InstallMode selectedMode = InstallMode.Free;

        public MainForm()
        {
            InitializeForm();
            BuildUi();
            ShowPanel(pnlHome);
        }

        public static void NotifyUnhandledException(Exception ex)
        {
            // Handled silently to avoid breaking UI
        }

        protected override void OnFormClosed(FormClosedEventArgs e)
        {
            cts.Cancel();
            cts.Dispose();
            base.OnFormClosed(e);
        }

        private void InitializeForm()
        {
            Text = "Nutricula Installer";
            StartPosition = FormStartPosition.CenterScreen;
            ClientSize = new Size(480, 680); // Portrait Android-like aspect ratio
            FormBorderStyle = FormBorderStyle.FixedSingle;
            MaximizeBox = false;
            BackColor = Color.White;
            Font = new Font("Segoe UI", 10f);
            
            try
            {
                if (System.IO.File.Exists("icon.ico"))
                    Icon = new Icon("icon.ico");
            }
            catch { }
        }

        private void BuildUi()
        {
            // 1. HOME PANEL
            pnlHome = new Panel { Dock = DockStyle.Fill, BackColor = Color.White };
            Controls.Add(pnlHome);

            AddBrandHeader(pnlHome);

            Button btnFree = CreateMaterialButton("🎁  Install Free Version", UiHelpers.BrandColor, Color.White, 250);
            btnFree.Click += (s, e) => StartInstallFlow(InstallMode.Free);
            pnlHome.Controls.Add(btnFree);

            Button btnPremium = CreateMaterialButton("⭐  Install Premium Version", UiHelpers.BrandColor, Color.White, 320);
            btnPremium.Click += (s, e) => OpenCredentials(InstallMode.Premium);
            pnlHome.Controls.Add(btnPremium);

            Button btnTransfer = CreateMaterialButton("🔄  Transfer License", UiHelpers.BrandColor, Color.White, 390);
            btnTransfer.Click += (s, e) => OpenCredentials(InstallMode.Transfer);
            pnlHome.Controls.Add(btnTransfer);

            Button btnGuide = CreateMaterialButton("📖  Installation Guide", Color.FromArgb(240, 242, 248), UiHelpers.TextDark, 530);
            btnGuide.Click += (s, e) => OpenUrl("https://www.youtube.com/");
            pnlHome.Controls.Add(btnGuide);

            Button btnBuy = CreateMaterialButton("🛒  Buy Premium License", Color.FromArgb(240, 242, 248), UiHelpers.TextDark, 590);
            btnBuy.Click += (s, e) => OpenUrl("https://www.google.com/");
            pnlHome.Controls.Add(btnBuy);

            // 2. CREDENTIALS PANEL
            pnlCredentials = new Panel { Dock = DockStyle.Fill, BackColor = Color.White, Visible = false };
            Controls.Add(pnlCredentials);

            AddBrandHeader(pnlCredentials);

            Label lblCredTitle = new Label { Text = "License Information", Font = new Font("Segoe UI Semibold", 14f), ForeColor = UiHelpers.BrandColor, AutoSize = true, Location = new Point(40, 240) };
            pnlCredentials.Controls.Add(lblCredTitle);

            Label lblEmail = new Label { Text = "Email Address:", ForeColor = UiHelpers.TextMuted, AutoSize = true, Location = new Point(40, 290) };
            emailBox = new TextBox { Location = new Point(40, 315), Width = 400, Font = new Font("Segoe UI", 12f), BorderStyle = BorderStyle.FixedSingle };
            pnlCredentials.Controls.Add(lblEmail);
            pnlCredentials.Controls.Add(emailBox);

            Label lblKey = new Label { Text = "Purchase Key:", ForeColor = UiHelpers.TextMuted, AutoSize = true, Location = new Point(40, 370) };
            purchaseKeyBox = new TextBox { Location = new Point(40, 395), Width = 400, Font = new Font("Segoe UI", 12f), BorderStyle = BorderStyle.FixedSingle };
            pnlCredentials.Controls.Add(lblKey);
            pnlCredentials.Controls.Add(purchaseKeyBox);

            credErrorLabel = new Label { ForeColor = UiHelpers.Error, AutoSize = false, Width = 400, Height = 40, Location = new Point(40, 440), Font = new Font("Segoe UI", 9f) };
            pnlCredentials.Controls.Add(credErrorLabel);

            Button btnBack = CreateMaterialButton("🔙  Back", Color.FromArgb(230, 230, 230), UiHelpers.TextDark, 590);
            btnBack.Width = 190;
            btnBack.Location = new Point(40, 590);
            btnBack.Click += (s, e) => ShowPanel(pnlHome);
            pnlCredentials.Controls.Add(btnBack);

            Button btnInstall = CreateMaterialButton("✅  Install", UiHelpers.Success, Color.White, 590);
            btnInstall.Width = 190;
            btnInstall.Location = new Point(250, 590);
            btnInstall.Click += (s, e) => 
            {
                if (ValidateCredentials()) StartInstallFlow(selectedMode);
            };
            pnlCredentials.Controls.Add(btnInstall);

            // 3. PROGRESS PANEL
            pnlProgress = new Panel { Dock = DockStyle.Fill, BackColor = Color.White, Visible = false };
            Controls.Add(pnlProgress);

            AddBrandHeader(pnlProgress);

            statusLabel = new Label { Text = "Preparing installation...", Font = new Font("Segoe UI Semibold", 12f), ForeColor = UiHelpers.TextDark, AutoSize = false, TextAlign = ContentAlignment.MiddleCenter, Width = 480, Location = new Point(0, 280) };
            pnlProgress.Controls.Add(statusLabel);

            progressBar = new ProgressBar { Style = ProgressBarStyle.Marquee, MarqueeAnimationSpeed = 15, Width = 400, Height = 10, Location = new Point(40, 330) };
            pnlProgress.Controls.Add(progressBar);

            resultLabel = new Label { Text = "", Font = new Font("Segoe UI", 10.5f), AutoSize = false, TextAlign = ContentAlignment.TopCenter, Width = 400, Height = 100, Location = new Point(40, 380) };
            pnlProgress.Controls.Add(resultLabel);

            finishButton = CreateMaterialButton("🏁  Finish", UiHelpers.BrandColor, Color.White, 590);
            finishButton.Visible = false;
            finishButton.Click += (s, e) => Close();
            pnlProgress.Controls.Add(finishButton);
        }

        private void AddBrandHeader(Panel parent)
        {
            PictureBox pbLogo = new PictureBox
            {
                Size = new Size(110, 110),
                Location = new Point((this.ClientSize.Width - 110) / 2, 40),
                SizeMode = PictureBoxSizeMode.Zoom
            };

            try
            {
                if (System.IO.File.Exists("icon.ico"))
                    pbLogo.Image = Image.FromFile("icon.ico");
                else
                    pbLogo.Image = SystemIcons.Application.ToBitmap();
            }
            catch { }
            parent.Controls.Add(pbLogo);

            Label lblBrand = new Label
            {
                Text = "NUTRICULA",
                Font = new Font("Segoe UI", 18f, FontStyle.Bold),
                ForeColor = UiHelpers.BrandColor,
                AutoSize = false,
                TextAlign = ContentAlignment.MiddleCenter,
                Width = 480,
                Location = new Point(0, 160)
            };
            parent.Controls.Add(lblBrand);

            Label lblSub = new Label
            {
                Text = "Expert Advisor Installer",
                Font = new Font("Segoe UI", 10f),
                ForeColor = UiHelpers.TextMuted,
                AutoSize = false,
                TextAlign = ContentAlignment.MiddleCenter,
                Width = 480,
                Location = new Point(0, 195)
            };
            parent.Controls.Add(lblSub);
        }

        private Button CreateMaterialButton(string text, Color backColor, Color foreColor, int yPosition)
        {
            Button btn = new Button
            {
                Text = text,
                BackColor = backColor,
                ForeColor = foreColor,
                FlatStyle = FlatStyle.Flat,
                Size = new Size(400, 50),
                Location = new Point(40, yPosition),
                Font = new Font("Segoe UI Semibold", 11f),
                Cursor = Cursors.Hand
            };
            btn.FlatAppearance.BorderSize = 0;

            // Simple Hover Effect
            Color hoverColor = ControlPaint.Light(backColor, 0.15f);
            btn.MouseEnter += (s, e) => btn.BackColor = hoverColor;
            btn.MouseLeave += (s, e) => btn.BackColor = backColor;

            return btn;
        }

        private void ShowPanel(Panel panelToShow)
        {
            pnlHome.Visible = false;
            pnlCredentials.Visible = false;
            pnlProgress.Visible = false;
            panelToShow.Visible = true;
        }

        private void OpenCredentials(InstallMode mode)
        {
            selectedMode = mode;
            credErrorLabel.Text = "";
            ShowPanel(pnlCredentials);
        }

        private bool ValidateCredentials()
        {
            string email = emailBox.Text.Trim();
            string key = purchaseKeyBox.Text.Trim();

            if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(key))
            {
                credErrorLabel.Text = "❌ Email and Purchase Key are both required.";
                return false;
            }
            if (!email.Contains("@") || !email.Contains("."))
            {
                credErrorLabel.Text = "❌ Please enter a valid email address.";
                return false;
            }
            
            credErrorLabel.Text = "";
            return true;
        }

        private async void StartInstallFlow(InstallMode mode)
        {
            selectedMode = mode;
            ShowPanel(pnlProgress);

            progressBar.Style = ProgressBarStyle.Marquee;
            statusLabel.Text = "Installing... Please wait.";
            resultLabel.Text = "";
            finishButton.Visible = false;

            string email = emailBox.Text.Trim();
            string key = purchaseKeyBox.Text.Trim();

            try
            {
                // CRITICAL FIX: Run the heavy logic in a background Task to keep UI fluid and un-frozen
                InstallResult result = await Task.Run(async () =>
                {
                    // Empty delegate removes the need for logs
                    var dummyProgress = new Progress<ProgressUpdate>();
                    
                    // DiscoverTerminals was previously freezing the main thread!
                    var terminals = installer.DiscoverTerminals(_ => { });

                    return await installer.RunAsync(
                        mode,
                        email,
                        key,
                        cts.Token,
                        dummyProgress,
                        _ => { } // Suppress logs
                    );
                });

                // When Task completes, UI updates safely
                progressBar.Style = ProgressBarStyle.Continuous;
                progressBar.Value = result.OverallSuccess ? 100 : 0;

                resultLabel.ForeColor = result.OverallSuccess ? UiHelpers.Success : UiHelpers.Error;
                resultLabel.Text = result.FinalMessage;
                statusLabel.Text = result.OverallSuccess ? "Installation Successful" : "Installation Failed";
            }
            catch (Exception ex)
            {
                progressBar.Style = ProgressBarStyle.Continuous;
                progressBar.Value = 0;
                resultLabel.ForeColor = UiHelpers.Error;
                resultLabel.Text = "Fatal Error: " + ex.Message;
                statusLabel.Text = "Error Occurred";
            }
            finally
            {
                finishButton.Visible = true;
            }
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
            catch { }
        }
    }
}
