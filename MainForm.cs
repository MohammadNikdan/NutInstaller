using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace NutriculaInstaller
{
    public sealed class MainForm : Form
    {
        private const int PageWidth = 696; // ClientSize.Width (760) minus contentHost's left+right padding (32+32)

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
        private Panel credentialsCard;
        private TextBox emailBox;
        private TextBox purchaseKeyBox;
        private TextBox transferKeyBox;
        private Label transferCaption;
        private Panel transferFieldWrap;
        private Label helperLabel;
        private MaterialButton backButton;
        private MaterialButton installButton;

        private const int CredentialsCardHeightBase = 210;   // Free/Premium: unchanged from before
        private const int CredentialsCardHeightTransfer = 300; // Transfer: room for the extra field

        // Fixed position/size for the promo image (installerpic.jpg), shown on the select
        // page and the credentials page in Premium mode only (hidden during/after install,
        // and in Transfer mode where this space is used for the extra field instead).
        private const int PromoImageY = 366;
        private const int PromoImageHeight = 88;
        private PictureBox credentialsPromoImage;

        // Progress page
        private Panel runningPanel;
        private Panel resultPanel;
        private IndeterminateBar progressBar;
        private Label progressStatusLabel;
        private Label subStatusLabel;
        private ResultBadge resultBadge;
        private RichTextBox resultMessageLabel;
        private Label resultSummaryLabel;
        private MaterialButton finishButton;
        private MaterialButton tryAgainButton;

        // Footer links
        private MaterialButton guideButton;
        private MaterialButton buyButton;

        private bool running;
        private bool lastResultSuccess;
        private InstallMode selectedMode = InstallMode.Free;

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
            cts.Cancel();
            cts.Dispose();
            base.OnFormClosed(e);
        }

        private void InitializeForm()
        {
            // Must be set before anything else. This codebase positions every control with
            // hardcoded literal pixel values; without this, WinForms' default Font-based
            // auto-scaling silently rescales all of them at runtime based on the system's
            // font/DPI settings, which is what was causing controls to overflow past the
            // window edge regardless of the actual pixel math in this file.
            AutoScaleMode = AutoScaleMode.None;

            Text = "Nutricula Expert Advisor Installer";
            StartPosition = FormStartPosition.CenterScreen;
            ClientSize = new Size(760, 664);
            MinimumSize = new Size(760, 664);
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

        private readonly ToolTip headerToolTip = new ToolTip();

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
                Font = UiHelpers.UiFont(15f, FontStyle.Bold),
                ForeColor = Color.White,
                Location = new Point(80, 18)
            };
            header.Controls.Add(brand);

            Label title = new Label
            {
                AutoSize = true,
                Text = "Expert Advisor",
                Font = UiHelpers.UiFont(9.5f),
                ForeColor = Color.FromArgb(206, 211, 228),
                Location = new Point(81, 46)
            };
            header.Controls.Add(title);
            // Center the subtitle under the (larger) brand title above it.
            title.Location = new Point(brand.Left + (brand.Width - title.Width) / 2, 46);

            // Right side of the header: a small credit line plus quick links to the
            // website and Telegram support, so that space isn't left empty.
            Label byLabel = new Label
            {
                AutoSize = true,
                Text = "by Highflyers co.",
                Font = new Font("Segoe UI", 8f, FontStyle.Italic),
                ForeColor = Color.FromArgb(206, 211, 228),
                BackColor = Color.Transparent
            };
            header.Controls.Add(byLabel);
            byLabel.Location = new Point(ClientSize.Width - 20 - byLabel.Width, 16);

            HeaderIconButton webButton;
            HeaderIconButton chatButton;
            {
                // Center the two buttons as a group directly under the label above them,
                // with equal spacing before, between, and after (space-evenly), rather
                // than right-aligning them against the header edge.
                const int buttonSize = 34;
                float gap = (byLabel.Width - buttonSize * 2) / 3f;
                if (gap < 4f) gap = 4f;

                int rowLeft = byLabel.Left;
                int chatLeft = rowLeft + (int)Math.Round(gap);
                int webLeft = chatLeft + buttonSize + (int)Math.Round(gap);

                chatButton = new HeaderIconButton(UiHelpers.GlyphSendFill) { Location = new Point(chatLeft, 40) };
                webButton = new HeaderIconButton(UiHelpers.GlyphGlobe) { Location = new Point(webLeft, 40) };
            }

            chatButton.Click += delegate { OpenUrl("https://t.me/nutriculaexpertsupport"); };
            header.Controls.Add(chatButton);
            headerToolTip.SetToolTip(chatButton, "Chat with support on Telegram");

            webButton.Click += delegate { OpenUrl("https://www.NutriculaExpert.com"); };
            header.Controls.Add(webButton);
            headerToolTip.SetToolTip(webButton, "Visit our website");
        }

        private void BuildFooter()
        {
            footer = new Panel { Dock = DockStyle.Bottom, Height = 68, BackColor = UiHelpers.Surface };
            Controls.Add(footer);
            footer.BringToFront();

            Panel divider = new Panel { Dock = DockStyle.Top, Height = 1, BackColor = UiHelpers.Border };
            footer.Controls.Add(divider);

            guideButton = new MaterialButton("Installation Guide", UiHelpers.GlyphPlay, ButtonKind.Text)
            {
                Location = new Point(28, 14),
                Size = new Size(190, 40),
                UseCircularIcon = true,
                CustomIconDrawer = UiHelpers.DrawPlayGlyph
            };
            guideButton.Click += delegate { OpenUrl("https://www.youtube.com/"); };
            footer.Controls.Add(guideButton);

            buyButton = new MaterialButton("Buy Premium License", UiHelpers.GlyphShoppingCart, ButtonKind.Text)
            {
                Location = new Point(226, 14),
                Size = new Size(215, 40),
                UseCircularIcon = true,
                TextColor = UiHelpers.BrandColor,
                CustomIconDrawer = UiHelpers.DrawShoppingBagGlyph
            };
            buyButton.Click += delegate { OpenUrl("https://www.google.com/"); };
            footer.Controls.Add(buyButton);
        }

        private Panel BuildSelectPage()
        {
            Panel page = new Panel { Dock = DockStyle.Fill, BackColor = UiHelpers.Background };

            Label sectionTitle = new Label
            {
                AutoSize = true,
                Text = "Choose an installation option:",
                Font = new Font("Segoe UI Semibold", 13f),
                ForeColor = UiHelpers.TextDark,
                Location = new Point(0, 0)
            };
            page.Controls.Add(sectionTitle);

            Label sectionSubtitle = new Label
            {
                AutoSize = false,
                Size = new Size(PageWidth, 30),
                Text = "Nutricula will be automatically installed on every MetaTrader 4 and 5 version found on this computer.",
                Font = new Font("Segoe UI", 9f),
                ForeColor = UiHelpers.TextMuted,
                Location = new Point(0, 27)
            };
            page.Controls.Add(sectionSubtitle);

            freeTile = new OptionTile(InstallMode.Free, "FREE", "Install Free Version", "Install the free Nutricula files without license activation.")
            { Location = new Point(0, 62), Width = PageWidth };
            premiumTile = new OptionTile(InstallMode.Premium, "PRO", "Install Premium Version", "Install Nutricula and activate a purchase license on this computer.")
            { Location = new Point(0, 160), Width = PageWidth };
            transferTile = new OptionTile(InstallMode.Transfer, "SWITCH", "Transfer License to This Computer", "Install Nutricula and move the existing license to this computer.")
            { Location = new Point(0, 258), Width = PageWidth };

            freeTile.Click += delegate { OnOptionTapped(InstallMode.Free); };
            premiumTile.Click += delegate { OnOptionTapped(InstallMode.Premium); };
            transferTile.Click += delegate { OnOptionTapped(InstallMode.Transfer); };

            page.Controls.Add(freeTile);
            page.Controls.Add(premiumTile);
            page.Controls.Add(transferTile);

            page.Controls.Add(UiHelpers.CreatePromoImageBox(new Point(0, PromoImageY), new Size(PageWidth, PromoImageHeight)));

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

            credentialsCard = new Panel { Location = new Point(0, 78), Size = new Size(PageWidth, CredentialsCardHeightBase), BackColor = UiHelpers.Background };
            credentialsCard.Paint += delegate (object sender, PaintEventArgs e)
            {
                e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
                // Paint the page background first so the corners outside the rounded
                // shape blend with the page instead of showing a square white patch.
                using (Brush pageBrush = new SolidBrush(UiHelpers.Background))
                    e.Graphics.FillRectangle(pageBrush, credentialsCard.ClientRectangle);
                UiHelpers.DrawRounded(e.Graphics, new Rectangle(0, 0, credentialsCard.Width - 1, credentialsCard.Height - 1), 14, UiHelpers.Surface, UiHelpers.Border);
            };
            page.Controls.Add(credentialsCard);

            Label emailCaption = new Label { AutoSize = true, Text = "Email:", Font = UiHelpers.UiFont(9.5f, FontStyle.Bold), ForeColor = UiHelpers.TextDark, Location = new Point(18, 16), BackColor = Color.Transparent };
            credentialsCard.Controls.Add(emailCaption);
            Panel emailWrap = BuildFieldWrap(UiHelpers.GlyphMail, new Point(18, 36), credentialsCard.Width - 36, out emailBox);
            credentialsCard.Controls.Add(emailWrap);

            Label purchaseCaption = new Label { AutoSize = true, Text = "Purchase Key:", Font = UiHelpers.UiFont(9.5f, FontStyle.Bold), ForeColor = UiHelpers.TextDark, Location = new Point(18, 96), BackColor = Color.Transparent };
            credentialsCard.Controls.Add(purchaseCaption);
            Panel purchaseWrap = BuildFieldWrap(UiHelpers.GlyphKey, new Point(18, 116), credentialsCard.Width - 36, out purchaseKeyBox);
            credentialsCard.Controls.Add(purchaseWrap);

            // Transfer Key: only relevant (visible + required) in Transfer mode. Hidden by
            // default; LayoutCredentialsFields() toggles it and repositions everything
            // below it when the mode changes.
            transferCaption = new Label { AutoSize = true, Text = "Transfer Key:", Font = UiHelpers.UiFont(9.5f, FontStyle.Bold), ForeColor = UiHelpers.TextDark, Location = new Point(18, 176), BackColor = Color.Transparent, Visible = false };
            credentialsCard.Controls.Add(transferCaption);
            transferFieldWrap = BuildFieldWrap(UiHelpers.GlyphKey, new Point(18, 196), credentialsCard.Width - 36, out transferKeyBox);
            transferFieldWrap.Visible = false;
            credentialsCard.Controls.Add(transferFieldWrap);

            helperLabel = new Label
            {
                AutoSize = false,
                Size = new Size(credentialsCard.Width - 36, 30),
                Text = "Required for Premium installation.",
                Font = UiHelpers.UiFont(9f),
                ForeColor = UiHelpers.TextMuted,
                Location = new Point(18, 172),
                BackColor = Color.Transparent
            };
            credentialsCard.Controls.Add(helperLabel);

            backButton = new MaterialButton("Back", UiHelpers.GlyphBack, ButtonKind.Outline) { Location = new Point(0, 308), Size = new Size(140, 46) };
            backButton.Click += delegate { ShowPage(pageSelect); };
            page.Controls.Add(backButton);

            installButton = new MaterialButton("Install", UiHelpers.GlyphDownload, ButtonKind.Filled)
            {
                Location = new Point(PageWidth - 170, 308),
                Size = new Size(170, 46),
                FillColor = UiHelpers.Success
            };
            installButton.Click += async delegate { await OnInstallTappedAsync(); };
            page.Controls.Add(installButton);

            // Promo image: same fixed spot as the select/progress pages, but only relevant
            // in Premium mode - Transfer mode uses this space for the extra field instead.
            credentialsPromoImage = UiHelpers.CreatePromoImageBox(new Point(0, PromoImageY), new Size(PageWidth, PromoImageHeight));
            credentialsPromoImage.Visible = false;
            page.Controls.Add(credentialsPromoImage);

            return page;
        }

        /// <summary>
        /// Shows/hides and repositions the Transfer Key field and everything below it
        /// depending on mode. Premium mode is untouched (same card height, same button
        /// position as before); Transfer mode grows the card to fit the extra field and
        /// pushes the helper text and buttons down to match.
        /// </summary>
        private void LayoutCredentialsFields(InstallMode mode)
        {
            bool showTransfer = mode == InstallMode.Transfer;
            transferCaption.Visible = showTransfer;
            transferFieldWrap.Visible = showTransfer;
            credentialsPromoImage.Visible = !showTransfer;

            int cardHeight = showTransfer ? CredentialsCardHeightTransfer : CredentialsCardHeightBase;
            credentialsCard.Size = new Size(PageWidth, cardHeight);
            credentialsCard.Invalidate();

            helperLabel.Location = new Point(18, showTransfer ? 252 : 172);

            int buttonsY = credentialsCard.Top + cardHeight + 20;
            backButton.Location = new Point(0, buttonsY);
            installButton.Location = new Point(PageWidth - 170, buttonsY);
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
                Font = UiHelpers.UiFont(10f),
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

            runningPanel = new Panel { Location = new Point(0, 110), Size = new Size(PageWidth, 120), BackColor = UiHelpers.Background };
            page.Controls.Add(runningPanel);

            progressStatusLabel = new Label
            {
                AutoSize = false,
                Size = new Size(PageWidth, 26),
                Text = "Installing Nutricula...",
                Font = new Font("Segoe UI Semibold", 11.5f),
                ForeColor = UiHelpers.TextDark,
                TextAlign = ContentAlignment.MiddleCenter,
                Location = new Point(0, 0)
            };
            runningPanel.Controls.Add(progressStatusLabel);

            progressBar = new IndeterminateBar { Location = new Point(0, 50), Size = new Size(PageWidth, 8) };
            runningPanel.Controls.Add(progressBar);

            subStatusLabel = new Label
            {
                AutoSize = false,
                Size = new Size(PageWidth, 40),
                Font = new Font("Segoe UI", 8.7f),
                ForeColor = UiHelpers.TextMuted,
                TextAlign = ContentAlignment.MiddleCenter,
                Location = new Point(0, 62)
            };
            runningPanel.Controls.Add(subStatusLabel);

            resultPanel = new Panel
            {
                Location = new Point(0, 90),
                Size = new Size(PageWidth, 360),
                BackColor = UiHelpers.Background,
                Visible = false
            };
            page.Controls.Add(resultPanel);
            // Fixed-size children (badge, buttons) can't self-center via Anchor, so redo
            // their centering whenever this panel's width changes (including on window resize).
            resultPanel.Resize += delegate { LayoutResultButtons(lastResultSuccess); };

            resultBadge = new ResultBadge { Location = new Point((PageWidth - 84) / 2, 0) };
            resultPanel.Controls.Add(resultBadge);

            resultMessageLabel = new NonIBeamRichTextBox
            {
                DetectUrls = false,
                ReadOnly = true,
                BorderStyle = BorderStyle.None,
                BackColor = UiHelpers.Background,
                ForeColor = UiHelpers.TextDark,
                ScrollBars = RichTextBoxScrollBars.None,
                WordWrap = true,
                TabStop = false,
                Size = new Size(PageWidth, 56),
                Font = UiHelpers.UiFont(11f, FontStyle.Bold),
                Location = new Point(0, 100)
            };
            resultPanel.Controls.Add(resultMessageLabel);

            finishButton = new MaterialButton("Finish", UiHelpers.GlyphCheck, ButtonKind.Filled)
            {
                Location = new Point((PageWidth - 180) / 2, 164),
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

            // Small install summary, pinned to the very bottom of the window (a few px
            // of breathing room above the edge) rather than crowding the result card.
            resultSummaryLabel = new Label
            {
                Dock = DockStyle.Bottom,
                Height = 20,
                Font = new Font("Segoe UI", 7.2f),
                ForeColor = Color.Black,
                TextAlign = ContentAlignment.MiddleCenter,
                Visible = false
            };
            page.Controls.Add(resultSummaryLabel);

            return page;
        }

        private sealed class NonIBeamRichTextBox : RichTextBox
        {
            protected override void WndProc(ref Message m)
            {
                const int WM_SETCURSOR = 0x0020;
                const int WM_LBUTTONDOWN = 0x0201;
                const int WM_MOUSEMOVE = 0x0200;
                const int WM_LBUTTONUP = 0x0202;
        
                if (m.Msg == WM_SETCURSOR)
                {
                    Cursor.Current = Cursors.Default;
                    return;
                }
        
                if (m.Msg == WM_LBUTTONDOWN ||
                    m.Msg == WM_MOUSEMOVE ||
                    m.Msg == WM_LBUTTONUP)
                {
                    SelectionLength = 0;
                    SelectionStart = 0;
                    return;
                }
        
                base.WndProc(ref m);
            }
        
            protected override bool IsInputKey(Keys keyData)
            {
                if (keyData == Keys.Control ||
                    keyData == Keys.A ||
                    keyData == Keys.C)
                {
                    return false;
                }
        
                return base.IsInputKey(keyData);
            }
        }
        // =====================================================================
        // Navigation / flow
        // =====================================================================
        private void ShowPage(Panel page)
        {
            if (page == null) return;
            pageSelect.Visible = page == pageSelect;
            pageCredentials.Visible = page == pageCredentials;
            pageProgress.Visible = page == pageProgress;
            page.BringToFront();
            footer.Visible = page != pageProgress;
        }

        private void OnOptionTapped(InstallMode mode)
        {
            if (running) return;
            selectedMode = mode;

            if (mode == InstallMode.Free)
            {
                // The Free tier never needs the License Service (which
                // requires Administrator to register) - it always uses the
                // user-level Broker instead, so there is deliberately no
                // Administrator check on this path at all. Free installs
                // must work with a completely ordinary, non-elevated run.
                StartInstall();
                return;
            }

            // Premium activation and License Transfer both eventually need
            // InstallCoordinatorAsync to attempt a real Windows Service
            // registration, which requires this process to already be
            // elevated (Administrator) - see CreateServiceW's own
            // requirements. Checking here, before even opening the
            // credentials page, gives a clear, immediate reason rather than
            // letting the user fill out the whole form only to hit a
            // confusing failure at the very end.
            if (!IsRunningAsAdministrator())
            {
                helperLabel.ForeColor = UiHelpers.Error;
                helperLabel.Text = "Administrator privileges are required for this option. " +
                    "Please close this installer and run it again using \"Run as administrator\", then try again.";
                return;
            }

            credTitleLabel.Text = mode == InstallMode.Premium ? "Activate Premium License" : "Transfer License to This Computer";
            credSubtitleLabel.Text = mode == InstallMode.Premium
                ? "Enter your Email and Purchase Key to activate a license on this computer."
                : "Enter your Email, Purchase Key, and Transfer Key to move your existing license to this computer.";
            helperLabel.ForeColor = UiHelpers.TextMuted;
            helperLabel.Text = mode == InstallMode.Premium
                ? "Required for Premium installation."
                : "Required for license transfer.";
            LayoutCredentialsFields(mode);
            ShowPage(pageCredentials);
        }

        /// <summary>
        /// True if this process is already running elevated (Administrator).
        /// Used to gate Premium/Transfer (which need to register a real
        /// Windows Service) - never used to gate the Free tier, which must
        /// always work from a completely ordinary, non-elevated run.
        /// </summary>
        private static bool IsRunningAsAdministrator()
        {
            try
            {
                using (var identity = WindowsIdentity.GetCurrent())
                {
                    var principal = new WindowsPrincipal(identity);
                    return principal.IsInRole(WindowsBuiltInRole.Administrator);
                }
            }
            catch
            {
                // If we can't even determine elevation status, treat as
                // "not elevated" - the safer default, since proceeding
                // would just fail later with a less clear error anyway.
                return false;
            }
        }

        private async Task OnInstallTappedAsync()
        {
            if (running) return;

            string email = emailBox.Text.Trim();
            string key = purchaseKeyBox.Text;
            string transferKey = transferKeyBox != null ? transferKeyBox.Text : string.Empty;
            bool requireTransferKey = selectedMode == InstallMode.Transfer;

            string validationError;
            if (!ValidateCredentials(email, key, transferKey, requireTransferKey, out validationError))
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
                    transferKeyBox != null ? transferKeyBox.Text : string.Empty,
                    cts.Token,
                    progress,
                    AppendLog,
                    ShowConfirmationDialogAsync);

                ShowResult(result.OverallSuccess, result.FinalMessage, result.Mt4Count, result.Mt5Count);
            }
            catch (OperationCanceledException)
            {
                ShowResult(false, "The installation was cancelled.", 0, 0);
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

        /// <summary>
        /// Shows a modal confirmation dialog with custom button text and
        /// returns the user's choice - the delegate InstallerService.RunAsync
        /// calls for the 2026 identity-warning flow (see its own comments
        /// for exactly when this fires). A plain MessageBox cannot supply
        /// custom button text, so this builds a minimal custom Form instead.
        /// </summary>
        private Task<bool> ShowConfirmationDialogAsync(string message, string yesButtonText, string noButtonText)
        {
            var tcs = new TaskCompletionSource<bool>();

            using (var dialog = new Form())
            {
                dialog.Text = "Nutricula";
                dialog.FormBorderStyle = FormBorderStyle.FixedDialog;
                dialog.StartPosition = FormStartPosition.CenterParent;
                dialog.MinimizeBox = false;
                dialog.MaximizeBox = false;
                dialog.ClientSize = new Size(460, 220);

                var label = new Label
                {
                    Text = message,
                    AutoSize = false,
                    Location = new Point(20, 20),
                    Size = new Size(420, 120),
                    TextAlign = ContentAlignment.TopLeft
                };
                dialog.Controls.Add(label);

                var yesButton = new Button
                {
                    Text = yesButtonText,
                    Size = new Size(420, 32),
                    Location = new Point(20, 150),
                    DialogResult = DialogResult.Yes
                };
                dialog.Controls.Add(yesButton);

                var noButton = new Button
                {
                    Text = noButtonText,
                    Size = new Size(420, 32),
                    Location = new Point(20, 186),
                    DialogResult = DialogResult.No
                };
                dialog.Controls.Add(noButton);

                dialog.AcceptButton = null; // no default - the user must deliberately click one
                DialogResult chosen = dialog.ShowDialog(this);
                tcs.SetResult(chosen == DialogResult.Yes);
            }

            return tcs.Task;
        }

        private void ShowResult(bool success, string message, int mt4Count, int mt5Count)

        {
            progressBar.StopAnimating();
            runningPanel.Visible = false;
            resultBadge.SetSuccess(success);
            SetResultMessage(success, message);

            if (success)
            {
                resultSummaryLabel.Text = "MT4: " + mt4Count + "  |  MT5: " + mt5Count + "  case(s) found.";
            }

            lastResultSuccess = success;
            LayoutResultButtons(success);
            resultPanel.Visible = true;
        }

        private void SetResultMessage(bool success, string message)
        {
            resultMessageLabel.Clear();

            string text = message ?? string.Empty;
            resultMessageLabel.AppendText(text);

            resultMessageLabel.Select(0, resultMessageLabel.TextLength);
            resultMessageLabel.SelectionAlignment = HorizontalAlignment.Center;
            resultMessageLabel.SelectionFont = UiHelpers.UiFont(11f, FontStyle.Bold);
            resultMessageLabel.SelectionColor = success ? UiHelpers.Success : UiHelpers.Error;

            if (success)
            {
                string marker = "\n\nDon't forget that in MetaTrader";
                int reminderStart = text.IndexOf(marker, StringComparison.Ordinal);

                if (reminderStart >= 0)
                {
                    int reminderLength = text.Length - reminderStart;

                    resultMessageLabel.Select(reminderStart, reminderLength);
                    resultMessageLabel.SelectionFont = UiHelpers.UiFont(10f, FontStyle.Regular);
                    resultMessageLabel.SelectionColor = Color.FromArgb(110, 110, 110);
                    
                }
            }

            resultMessageLabel.Select(0, 0);
        }

        private void LayoutResultButtons(bool success)
        {
            if (resultPanel == null || finishButton == null || tryAgainButton == null) return;

            int w = resultPanel.Width;

            if (resultBadge != null)
                resultBadge.Left = (w - resultBadge.Width) / 2;

            int messageHeight = 0;
            
            if (resultMessageLabel != null)
            {
                string text = resultMessageLabel.Text ?? string.Empty;
            
                Size measured = TextRenderer.MeasureText(
                    text,
                    resultMessageLabel.Font,
                    new Size(w - 24, int.MaxValue),
                    TextFormatFlags.WordBreak |
                    TextFormatFlags.HorizontalCenter |
                    TextFormatFlags.NoPadding);
            
                messageHeight = measured.Height + 2;
            
                const int maxMessageHeight = 170;
                if (messageHeight > maxMessageHeight)
                    messageHeight = maxMessageHeight;
            
                resultMessageLabel.Size = new Size(w, messageHeight);
            }
            
            int buttonY = resultMessageLabel.Top + messageHeight + (success ? 12 : 23);

            if (success)
            {
                tryAgainButton.Visible = false;
                if (resultSummaryLabel != null) resultSummaryLabel.Visible = true;

                finishButton.Text2 = "Finish";
                finishButton.Size = new Size(180, 46);
                finishButton.Location = new Point((w - finishButton.Width) / 2, buttonY);
            }
            else
            {
                if (resultSummaryLabel != null) resultSummaryLabel.Visible = false;

                finishButton.Text2 = "Close";
                finishButton.Size = new Size(170, 46);
                tryAgainButton.Size = new Size(170, 46);

                const int gap = 14;
                int totalWidth = tryAgainButton.Width + gap + finishButton.Width;
                int startX = (w - totalWidth) / 2;

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

        private bool ValidateCredentials(string email, string key, string transferKey, bool requireTransferKey, out string error)
        {
            bool emailMissing = string.IsNullOrWhiteSpace(email);
            bool keyMissing = string.IsNullOrWhiteSpace(key);
            bool transferMissing = requireTransferKey && string.IsNullOrWhiteSpace(transferKey);

            if (emailMissing || keyMissing || transferMissing)
            {
                error = requireTransferKey
                    ? "Email, Purchase Key, and Transfer Key are all required."
                    : "Email and Purchase Key are both required.";
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
