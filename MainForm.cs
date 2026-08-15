using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace NutriculaInstaller
{
    public sealed class MainForm : Form
    {
        private const int PageWidth = 696;

        private readonly InstallerService installer = new InstallerService();
        private readonly CancellationTokenSource cts = new CancellationTokenSource();

        // Pages
        private Panel contentHost;
        private Panel pageSelect;
        private Panel pageCredentials;
        private Panel pageProgress;
        private Panel footer;

        // Select page
        private OptionTile freeTile;
        private OptionTile premiumTile;
        private OptionTile transferTile;

        // Credentials page
        private Label credTitleLabel;
        private Label credSubtitleLabel;
        private TextBox emailBox;
        private TextBox purchaseKeyBox;
        private Label helperLabel;
        private MaterialButton backButton;
        private MaterialButton installButton;

        // Progress page
        private Panel runningPanel;
        private Panel resultPanel;
        private IndeterminateBar progressBar;
        private Label progressStatusLabel;
        private Label subStatusLabel;
        private ResultBadge resultBadge;
        private Label resultMessageLabel;
        private Label resultSummaryLabel;
        private MaterialButton finishButton;
        private MaterialButton tryAgainButton;

        // Footer links
        private MaterialButton guideButton;
        private MaterialButton buyButton;

        private bool running;
        private InstallMode selectedMode = InstallMode.Free;

        // Page fade-transition state
        private Panel lastShownPage;
        private Timer fadeTimer;
        private Panel fadeOverlay;
        private Bitmap fadeOldSnapshot;
        private Bitmap fadeNewSnapshot;
        private float fadeAlpha;

        private static readonly Color Brand = UiHelpers.BrandColor;

        public MainForm()
        {
            InitializeForm();
            BuildUi();
            ShowPage(pageSelect);
        }

        public static void NotifyUnhandledException(Exception ex)
        {
            // The main form handles its own exceptions. This hook intentionally does not open a second window.
        }

        protected override void OnFormClosed(FormClosedEventArgs e)
        {
            StopFadeTransition();
            cts.Cancel();
            cts.Dispose();
            base.OnFormClosed(e);
        }

        private void InitializeForm()
        {
            Text = "Nutricula Expert Advisor Installer";
            StartPosition = FormStartPosition.CenterScreen;
            ClientSize = new Size(760, 580);
            MinimumSize = new Size(760, 580);
            BackColor = UiHelpers.Background;
            Font = new Font("Segoe UI", 9f);
            FormBorderStyle = FormBorderStyle.FixedSingle;
            MaximizeBox = false;
            DoubleBuffered = true;
            Icon = TryLoadIcon();
        }

        private static Icon cachedAppIcon;

        private Icon TryLoadIcon()
        {
            if (cachedAppIcon != null)
                return cachedAppIcon;

            // Primary: extract the icon that is already embedded in this executable
            // (set via <ApplicationIcon>icon.ico</ApplicationIcon> in the .csproj).
            // This works no matter what the process's current working directory is,
            // unlike a relative File.Exists("icon.ico") check.
            try
            {
                Icon extracted = Icon.ExtractAssociatedIcon(Application.ExecutablePath);
                if (extracted != null)
                {
                    cachedAppIcon = extracted;
                    return cachedAppIcon;
                }
            }
            catch { }

            // Fallback: an icon.ico file sitting next to the executable.
            try
            {
                string besideExe = System.IO.Path.Combine(
                    System.IO.Path.GetDirectoryName(Application.ExecutablePath) ?? string.Empty, "icon.ico");
                if (System.IO.File.Exists(besideExe))
                {
                    cachedAppIcon = new Icon(besideExe);
                    return cachedAppIcon;
                }
                if (System.IO.File.Exists("icon.ico"))
                {
                    cachedAppIcon = new Icon("icon.ico");
                    return cachedAppIcon;
                }
            }
            catch { }

            cachedAppIcon = SystemIcons.Application;
            return cachedAppIcon;
        }

        // =====================================================================
        // UI construction
        // =====================================================================
        private void BuildUi()
        {
            BuildHeader();

            contentHost = new Panel { Dock = DockStyle.Fill, Padding = new Padding(32, 26, 32, 20), BackColor = UiHelpers.Background };
            Controls.Add(contentHost);
            contentHost.BringToFront();

            BuildFooter();

            pageSelect = BuildSelectPage();
            pageCredentials = BuildCredentialsPage();
            pageProgress = BuildProgressPage();

            contentHost.Controls.Add(pageProgress);
            contentHost.Controls.Add(pageCredentials);
            contentHost.Controls.Add(pageSelect);
        }

        private void BuildHeader()
        {
            Panel header = new Panel { Dock = DockStyle.Top, Height = 84, BackColor = Brand };
            Controls.Add(header);

            Icon appIcon = TryLoadIcon();
            PictureBox logo = new PictureBox
            {
                Size = new Size(40, 40),
                Location = new Point(28, 22),
                SizeMode = PictureBoxSizeMode.Zoom,
                BackColor = Brand
            };
            try { logo.Image = appIcon.ToBitmap(); } catch { }
            header.Controls.Add(logo);

            Label brand = new Label
            {
                AutoSize = true,
                Text = "NUTRICULA",
                Font = new Font("Segoe UI Semibold", 15f),
                ForeColor = Color.White,
                Location = new Point(80, 18)
            };
            header.Controls.Add(brand);

            Label title = new Label
            {
                AutoSize = true,
                Text = "Expert Advisor Installer",
                Font = new Font("Segoe UI", 9.5f),
                ForeColor = Color.FromArgb(206, 211, 228),
                Location = new Point(81, 46)
            };
            header.Controls.Add(title);
        }

        private void BuildFooter()
        {
            footer = new Panel { Dock = DockStyle.Bottom, Height = 68, BackColor = UiHelpers.Surface };
            Controls.Add(footer);
            footer.BringToFront();

            Panel divider = new Panel { Dock = DockStyle.Top, Height = 1, BackColor = UiHelpers.Border };
            footer.Controls.Add(divider);

            guideButton = new MaterialButton("Installation Guide", null, ButtonKind.Text) { Location = new Point(28, 14), Size = new Size(160, 40) };
            guideButton.Click += delegate { OpenUrl("https://www.youtube.com/"); };
            footer.Controls.Add(guideButton);

            buyButton = new MaterialButton("Buy Premium License", null, ButtonKind.Text) { Location = new Point(196, 14), Size = new Size(180, 40), TextColor = Color.FromArgb(131, 87, 25) };
            buyButton.Click += delegate { OpenUrl("https://www.google.com/"); };
            footer.Controls.Add(buyButton);
        }

        private Panel BuildSelectPage()
        {
            Panel page = new Panel { Dock = DockStyle.Fill, BackColor = UiHelpers.Background };

            Label sectionTitle = new Label
            {
                AutoSize = true,
                Text = "Choose an installation option",
                Font = new Font("Segoe UI Semibold", 13f),
                ForeColor = UiHelpers.TextDark,
                Location = new Point(0, 0)
            };
            page.Controls.Add(sectionTitle);

            Label sectionSubtitle = new Label
            {
                AutoSize = true,
                Text = "Tap an option to continue",
                Font = new Font("Segoe UI", 9f),
                ForeColor = UiHelpers.TextMuted,
                Location = new Point(0, 27)
            };
            page.Controls.Add(sectionSubtitle);

            freeTile = new OptionTile(InstallMode.Free, UiHelpers.GlyphDownload, "Install Free Version", "Install the free Nutricula files without license activation.")
            { Location = new Point(0, 62), Width = PageWidth };
            premiumTile = new OptionTile(InstallMode.Premium, UiHelpers.GlyphStar, "Install Premium Version", "Install Nutricula and activate a purchase license on this computer.")
            { Location = new Point(0, 160), Width = PageWidth };
            transferTile = new OptionTile(InstallMode.Transfer, UiHelpers.GlyphSync, "Transfer License to This Computer", "Install Nutricula and move the existing license to this computer.")
            { Location = new Point(0, 258), Width = PageWidth };

            freeTile.Click += delegate { OnOptionTapped(InstallMode.Free); };
            premiumTile.Click += delegate { OnOptionTapped(InstallMode.Premium); };
            transferTile.Click += delegate { OnOptionTapped(InstallMode.Transfer); };

            page.Controls.Add(freeTile);
            page.Controls.Add(premiumTile);
            page.Controls.Add(transferTile);

            return page;
        }

        private Panel BuildCredentialsPage()
        {
            Panel page = new Panel { Dock = DockStyle.Fill, BackColor = UiHelpers.Background };

            credTitleLabel = new Label
            {
                AutoSize = true,
                Font = new Font("Segoe UI Semibold", 13f),
                ForeColor = UiHelpers.TextDark,
                Location = new Point(0, 0)
            };
            page.Controls.Add(credTitleLabel);

            credSubtitleLabel = new Label
            {
                AutoSize = false,
                Size = new Size(PageWidth, 34),
                Font = new Font("Segoe UI", 9f),
                ForeColor = UiHelpers.TextMuted,
                Location = new Point(0, 27)
            };
            page.Controls.Add(credSubtitleLabel);

            Panel card = new Panel { Location = new Point(0, 78), Size = new Size(PageWidth, 210), BackColor = UiHelpers.Background };
            card.Paint += delegate (object sender, PaintEventArgs e)
            {
                e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
                // Paint the page background first so the corners outside the rounded
                // shape blend with the page instead of showing a square white patch.
                using (Brush pageBrush = new SolidBrush(UiHelpers.Background))
                    e.Graphics.FillRectangle(pageBrush, card.ClientRectangle);
                UiHelpers.DrawRounded(e.Graphics, new Rectangle(0, 0, card.Width - 1, card.Height - 1), 14, UiHelpers.Surface, UiHelpers.Border);
            };
            page.Controls.Add(card);

            Label emailCaption = new Label { AutoSize = true, Text = "Email", Font = new Font("Segoe UI Semibold", 8.5f), ForeColor = UiHelpers.TextDark, Location = new Point(18, 16) };
            card.Controls.Add(emailCaption);
            Panel emailWrap = BuildFieldWrap(UiHelpers.GlyphMail, new Point(18, 36), card.Width - 36, out emailBox);
            card.Controls.Add(emailWrap);

            Label purchaseCaption = new Label { AutoSize = true, Text = "Purchase Key", Font = new Font("Segoe UI Semibold", 8.5f), ForeColor = UiHelpers.TextDark, Location = new Point(18, 96) };
            card.Controls.Add(purchaseCaption);
            Panel purchaseWrap = BuildFieldWrap(UiHelpers.GlyphKey, new Point(18, 116), card.Width - 36, out purchaseKeyBox);
            card.Controls.Add(purchaseWrap);

            helperLabel = new Label
            {
                AutoSize = false,
                Size = new Size(card.Width - 36, 30),
                Text = "Required for Premium installation and license transfer.",
                Font = new Font("Segoe UI", 8f),
                ForeColor = UiHelpers.TextMuted,
                Location = new Point(18, 172)
            };
            card.Controls.Add(helperLabel);

            backButton = new MaterialButton("Back", UiHelpers.GlyphBack, ButtonKind.Outline) { Location = new Point(0, 308), Size = new Size(140, 46) };
            backButton.Click += delegate { ShowPage(pageSelect); };
            page.Controls.Add(backButton);

            installButton = new MaterialButton("Install", UiHelpers.GlyphCheck, ButtonKind.Filled)
            {
                Location = new Point(PageWidth - 170, 308),
                Size = new Size(170, 46),
                FillColor = UiHelpers.Success
            };
            installButton.Click += async delegate { await OnInstallTappedAsync(); };
            page.Controls.Add(installButton);

            return page;
        }

        private Panel BuildFieldWrap(string glyph, Point location, int width, out TextBox textBox)
        {
            Panel wrap = new Panel { Location = location, Size = new Size(width, 46), BackColor = UiHelpers.Surface };
            wrap.Paint += delegate (object sender, PaintEventArgs e)
            {
                e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
                UiHelpers.DrawRounded(e.Graphics, new Rectangle(0, 0, wrap.Width - 1, wrap.Height - 1), 10, UiHelpers.Surface, UiHelpers.Border);
            };

            Label icon = new Label
            {
                AutoSize = false,
                Size = new Size(28, 46),
                Text = glyph,
                Font = UiHelpers.IconFont(11f),
                ForeColor = UiHelpers.TextMuted,
                TextAlign = ContentAlignment.MiddleCenter,
                Location = new Point(10, 0),
                BackColor = Color.Transparent
            };
            wrap.Controls.Add(icon);

            TextBox box = new TextBox
            {
                BorderStyle = BorderStyle.None,
                Font = new Font("Segoe UI", 10f),
                Location = new Point(44, 14),
                Width = width - 58,
                BackColor = UiHelpers.Surface
            };
            wrap.Controls.Add(box);
            textBox = box;
            return wrap;
        }

        private Panel BuildProgressPage()
        {
            Panel page = new Panel { Dock = DockStyle.Fill, BackColor = UiHelpers.Background };
            int left = (PageWidth - 480) / 2;

            runningPanel = new Panel { Location = new Point(left, 110), Size = new Size(480, 120), BackColor = UiHelpers.Background };
            page.Controls.Add(runningPanel);

            progressStatusLabel = new Label
            {
                AutoSize = false,
                Size = new Size(480, 26),
                Text = "Installing Nutricula...",
                Font = new Font("Segoe UI Semibold", 11.5f),
                ForeColor = UiHelpers.TextDark,
                TextAlign = ContentAlignment.MiddleCenter,
                Location = new Point(0, 0)
            };
            runningPanel.Controls.Add(progressStatusLabel);

            progressBar = new IndeterminateBar { Location = new Point(0, 42), Size = new Size(480, 8) };
            runningPanel.Controls.Add(progressBar);

            subStatusLabel = new Label
            {
                AutoSize = false,
                Size = new Size(480, 40),
                Font = new Font("Segoe UI", 8.7f),
                ForeColor = UiHelpers.TextMuted,
                TextAlign = ContentAlignment.MiddleCenter,
                Location = new Point(0, 62)
            };
            runningPanel.Controls.Add(subStatusLabel);

            resultPanel = new Panel { Location = new Point(left, 90), Size = new Size(480, 250), BackColor = UiHelpers.Background, Visible = false };
            page.Controls.Add(resultPanel);

            resultBadge = new ResultBadge { Location = new Point((480 - 84) / 2, 0) };
            resultPanel.Controls.Add(resultBadge);

            resultMessageLabel = new Label
            {
                AutoSize = false,
                Size = new Size(480, 56),
                Font = new Font("Segoe UI Semibold", 11f),
                TextAlign = ContentAlignment.MiddleCenter,
                Location = new Point(0, 100)
            };
            resultPanel.Controls.Add(resultMessageLabel);

            finishButton = new MaterialButton("Finish", UiHelpers.GlyphCheck, ButtonKind.Filled)
            {
                Location = new Point((480 - 180) / 2, 164),
                Size = new Size(180, 46)
            };
            finishButton.Click += delegate { Close(); };
            resultPanel.Controls.Add(finishButton);

            tryAgainButton = new MaterialButton("Try Again", UiHelpers.GlyphSync, ButtonKind.Outline)
            {
                Size = new Size(170, 46),
                Visible = false
            };
            tryAgainButton.Click += delegate { OnTryAgainTapped(); };
            resultPanel.Controls.Add(tryAgainButton);

            resultSummaryLabel = new Label
            {
                AutoSize = false,
                Size = new Size(480, 18),
                Font = new Font("Segoe UI", 7.7f),
                ForeColor = UiHelpers.TextDark,
                TextAlign = ContentAlignment.MiddleCenter,
                Location = new Point(0, 216),
                Visible = false
            };
            resultPanel.Controls.Add(resultSummaryLabel);

            return page;
        }

        // =====================================================================
        // Navigation / flow
        // =====================================================================
        private void ShowPage(Panel page)
        {
            if (page == null || page == lastShownPage) return;

            // Only animate when there is something on screen already to fade from
            // (skip on the very first page shown from the constructor).
            bool animate = lastShownPage != null && lastShownPage.Visible;
            Bitmap oldSnapshot = animate ? CaptureContentHost() : null;

            pageSelect.Visible = page == pageSelect;
            pageCredentials.Visible = page == pageCredentials;
            pageProgress.Visible = page == pageProgress;
            page.BringToFront();
            footer.Visible = page != pageProgress;
            lastShownPage = page;

            if (animate)
            {
                contentHost.PerformLayout();
                page.Refresh();
                Bitmap newSnapshot = CaptureContentHost();
                StartFadeTransition(oldSnapshot, newSnapshot);
            }
        }

        // =====================================================================
        // Quick fade transition between pages
        // =====================================================================
        private Bitmap CaptureContentHost()
        {
            Bitmap bmp = new Bitmap(Math.Max(1, contentHost.Width), Math.Max(1, contentHost.Height));
            contentHost.DrawToBitmap(bmp, new Rectangle(Point.Empty, contentHost.Size));
            return bmp;
        }

        private void StartFadeTransition(Bitmap oldSnapshot, Bitmap newSnapshot)
        {
            StopFadeTransition();

            fadeOldSnapshot = oldSnapshot;
            fadeNewSnapshot = newSnapshot;
            fadeAlpha = 1f;

            fadeOverlay = new Panel { Location = Point.Empty, Size = contentHost.Size, BackColor = UiHelpers.Background };
            fadeOverlay.Paint += FadeOverlay_Paint;
            contentHost.Controls.Add(fadeOverlay);
            fadeOverlay.BringToFront();

            // Quick fade: a handful of 15ms steps, ~100-120ms total.
            fadeTimer = new Timer { Interval = 15 };
            fadeTimer.Tick += FadeTimer_Tick;
            fadeTimer.Start();
        }

        private void FadeTimer_Tick(object sender, EventArgs e)
        {
            fadeAlpha -= 0.16f;
            if (fadeAlpha <= 0f)
            {
                StopFadeTransition();
                return;
            }
            if (fadeOverlay != null) fadeOverlay.Invalidate();
        }

        private void FadeOverlay_Paint(object sender, PaintEventArgs e)
        {
            if (fadeNewSnapshot != null)
                e.Graphics.DrawImageUnscaled(fadeNewSnapshot, Point.Empty);
            if (fadeOldSnapshot != null && fadeAlpha > 0f)
                DrawWithAlpha(e.Graphics, fadeOldSnapshot, fadeAlpha);
        }

        private static void DrawWithAlpha(Graphics g, Image img, float alpha)
        {
            alpha = Math.Max(0f, Math.Min(1f, alpha));
            ColorMatrix matrix = new ColorMatrix { Matrix33 = alpha };
            using (ImageAttributes attributes = new ImageAttributes())
            {
                attributes.SetColorMatrix(matrix, ColorMatrixFlag.Default, ColorAdjustType.Bitmap);
                g.DrawImage(img, new Rectangle(0, 0, img.Width, img.Height), 0, 0, img.Width, img.Height, GraphicsUnit.Pixel, attributes);
            }
        }

        private void StopFadeTransition()
        {
            if (fadeTimer != null)
            {
                fadeTimer.Stop();
                fadeTimer.Tick -= FadeTimer_Tick;
                fadeTimer.Dispose();
                fadeTimer = null;
            }
            if (fadeOverlay != null)
            {
                fadeOverlay.Paint -= FadeOverlay_Paint;
                contentHost.Controls.Remove(fadeOverlay);
                fadeOverlay.Dispose();
                fadeOverlay = null;
            }
            if (fadeOldSnapshot != null)
            {
                fadeOldSnapshot.Dispose();
                fadeOldSnapshot = null;
            }
            if (fadeNewSnapshot != null)
            {
                fadeNewSnapshot.Dispose();
                fadeNewSnapshot = null;
            }
        }

        private void OnOptionTapped(InstallMode mode)
        {
            if (running) return;
            selectedMode = mode;

            if (mode == InstallMode.Free)
            {
                StartInstall();
                return;
            }

            credTitleLabel.Text = mode == InstallMode.Premium ? "Activate Premium License" : "Transfer License to This Computer";
            credSubtitleLabel.Text = mode == InstallMode.Premium
                ? "Enter your Email and Purchase Key to activate a license on this computer."
                : "Enter your Email and Purchase Key to move your existing license to this computer.";
            helperLabel.ForeColor = UiHelpers.TextMuted;
            helperLabel.Text = "Required for Premium installation and license transfer.";
            ShowPage(pageCredentials);
        }

        private async Task OnInstallTappedAsync()
        {
            if (running) return;

            string email = emailBox.Text.Trim();
            string key = purchaseKeyBox.Text;
            string validationError;
            if (!ValidateCredentials(email, key, out validationError))
            {
                helperLabel.ForeColor = UiHelpers.Error;
                helperLabel.Text = validationError;
                return;
            }

            StartInstall();
            await Task.CompletedTask;
        }

        private void StartInstall()
        {
            ShowPage(pageProgress);
            runningPanel.Visible = true;
            resultPanel.Visible = false;
            progressStatusLabel.Text = "Installing Nutricula...";
            // No status/log line is shown while installing - just the fixed title and the
            // indeterminate progress bar below it.
            subStatusLabel.Text = string.Empty;
            subStatusLabel.Visible = false;
            progressBar.StartAnimating();
            _ = RunInstallAsync();
        }

        private async Task RunInstallAsync()
        {
            running = true;

            try
            {
                // Run terminal discovery on a background thread so the window
                // never freezes while the disk/registry are being scanned. No status
                // text is surfaced from this - the caller only needs the final result.
                var progress = new Progress<ProgressUpdate>(delegate { });

                InstallResult result = await installer.RunAsync(
                    selectedMode,
                    emailBox != null ? emailBox.Text.Trim() : string.Empty,
                    purchaseKeyBox != null ? purchaseKeyBox.Text : string.Empty,
                    cts.Token,
                    progress,
                    AppendLog);

                ShowResult(result.OverallSuccess, result.FinalMessage, result.Mt4Count, result.Mt5Count);
            }
            catch (Exception ex)
            {
                ShowResult(false, "The installation could not be completed: " + ex.Message, 0, 0);
            }
            finally
            {
                running = false;
            }
        }

        private void ShowResult(bool success, string message, int mt4Count, int mt5Count)
        {
            progressBar.StopAnimating();
            runningPanel.Visible = false;
            resultBadge.SetSuccess(success);
            resultMessageLabel.ForeColor = success ? UiHelpers.Success : UiHelpers.Error;
            resultMessageLabel.Text = message;

            if (success)
            {
                resultSummaryLabel.Text = "Nutricula was installed on " + mt4Count + " MetaTrader 4 and " + mt5Count + " MetaTrader 5 terminal(s).";
            }

            LayoutResultButtons(success);
            resultPanel.Visible = true;
        }

        private void LayoutResultButtons(bool success)
        {
            const int buttonY = 164;
            if (success)
            {
                tryAgainButton.Visible = false;
                resultSummaryLabel.Visible = true;

                finishButton.Text2 = "Finish";
                finishButton.Size = new Size(180, 46);
                finishButton.Location = new Point((480 - finishButton.Width) / 2, buttonY);
            }
            else
            {
                resultSummaryLabel.Visible = false;

                finishButton.Text2 = "Close";
                finishButton.Size = new Size(170, 46);
                tryAgainButton.Size = new Size(170, 46);

                const int gap = 14;
                int totalWidth = tryAgainButton.Width + gap + finishButton.Width;
                int startX = (480 - totalWidth) / 2;

                tryAgainButton.Location = new Point(startX, buttonY);
                finishButton.Location = new Point(startX + tryAgainButton.Width + gap, buttonY);
                tryAgainButton.Visible = true;
            }
        }

        private void OnTryAgainTapped()
        {
            if (running) return;

            if (selectedMode == InstallMode.Free)
            {
                // Same window, same flow: the progress indicator starts moving again
                // and the install is simply re-attempted from scratch.
                StartInstall();
            }
            else
            {
                // Go back to the credentials page without clearing anything the user
                // already typed, so they can retry as-is or fix a mistake first.
                ShowPage(pageCredentials);
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

        private void AppendLog(string message)
        {
            // Intentionally a no-op: no log or status text is shown during installation.
            // The installer/discovery services still call this delegate internally, so
            // it is kept as a harmless sink rather than removing the parameter everywhere.
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
            catch
            {
                // Silently ignore - opening the browser is a convenience action only.
            }
        }
    }
}
