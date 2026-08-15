using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Text;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace NutriculaInstaller
{
    /// <summary>
    /// Shared colors, icon-font glyphs and drawing helpers for the Material-style UI.
    /// The brand color below is unchanged from the original UI.
    /// </summary>
    internal static class UiHelpers
    {
        // ===== App-wide text font (embedded, no install needed on the user's machine) =====
        // The Outfit-Regular.ttf file only ships one weight, so "bold" text throughout
        // the app is GDI-synthesized bold (FontStyle.Bold) rather than a real semibold
        // weight file.
        //
        // Two separate registrations are needed for crisp text everywhere:
        //  - PrivateFontCollection.AddMemoryFont makes the font available to GDI+
        //    (our own custom-painted controls that call Graphics.DrawString directly).
        //  - AddFontMemResourceEx (a native GDI call) registers the font process-wide
        //    so plain WinForms controls (Label, TextBox, etc., which render through GDI,
        //    not GDI+) can resolve it by name too. Without this, GDI can't find the
        //    embedded font and silently substitutes an approximated font, which is what
        //    produces the blurry/low-quality look on ordinary Label/TextBox text.
        [DllImport("gdi32.dll", SetLastError = true)]
        private static extern IntPtr AddFontMemResourceEx(IntPtr pbFont, uint cbFont, IntPtr pdv, [In] ref uint pcFonts);

        private static IntPtr embeddedFontMemory = IntPtr.Zero;
        private static readonly FontFamily uiFontFamily = LoadEmbeddedFontFamily();

        private static FontFamily LoadEmbeddedFontFamily()
        {
            try
            {
                var assembly = typeof(UiHelpers).Assembly;
                using (Stream stream = assembly.GetManifestResourceStream("NutriculaInstaller.Fonts.Outfit-Regular.ttf"))
                {
                    if (stream == null) return FontFamily.GenericSansSerif;

                    byte[] fontData = new byte[stream.Length];
                    int total = 0;
                    while (total < fontData.Length)
                    {
                        int read = stream.Read(fontData, total, fontData.Length - total);
                        if (read <= 0) break;
                        total += read;
                    }

                    IntPtr fontPtr = Marshal.AllocCoTaskMem(fontData.Length);
                    Marshal.Copy(fontData, 0, fontPtr, fontData.Length);
                    embeddedFontMemory = fontPtr; // kept alive for the app's lifetime, per PrivateFontCollection docs

                    // Register with GDI (fixes Label/TextBox rendering quality).
                    uint fontCount = 0;
                    AddFontMemResourceEx(fontPtr, (uint)fontData.Length, IntPtr.Zero, ref fontCount);

                    // Register with GDI+ (used by our own custom OnPaint drawing).
                    PrivateFontCollection collection = new PrivateFontCollection();
                    collection.AddMemoryFont(fontPtr, fontData.Length);
                    if (collection.Families.Length > 0)
                        return collection.Families[0];
                }
            }
            catch { }
            return FontFamily.GenericSansSerif;
        }

        /// <summary>Creates a Font using the app's embedded Outfit font (falls back to a generic sans-serif if it failed to load).</summary>
        public static Font UiFont(float size, FontStyle style = FontStyle.Regular)
        {
            try
            {
                return new Font(uiFontFamily, size, style, GraphicsUnit.Point);
            }
            catch
            {
                return new Font(FontFamily.GenericSansSerif, size, style, GraphicsUnit.Point);
            }
        }

        // ===== Palette (brand color kept identical to the original UI) =====
        public static readonly Color BrandColor = Color.FromArgb(39, 47, 80);
        public static readonly Color BrandLighter = Color.FromArgb(62, 71, 108);
        public static readonly Color BrandSoft = Color.FromArgb(230, 232, 240);
        public static readonly Color Background = Color.FromArgb(246, 247, 250);
        public static readonly Color Surface = Color.White;
        public static readonly Color Border = Color.FromArgb(224, 227, 235);
        public static readonly Color TextDark = Color.FromArgb(32, 35, 44);
        public static readonly Color TextMuted = Color.FromArgb(112, 117, 130);
        public static readonly Color Success = Color.FromArgb(27, 138, 76);
        public static readonly Color SuccessSoft = Color.FromArgb(224, 246, 234);
        public static readonly Color Error = Color.FromArgb(198, 55, 55);
        public static readonly Color ErrorSoft = Color.FromArgb(252, 230, 230);

        // ===== Icon font (Segoe MDL2 Assets ships with Windows 10/11) =====
        public const string IconFontName = "Segoe MDL2 Assets";
        public const string GlyphDownload = "\uE896";
        public const string GlyphStar = "\uE734";
        public const string GlyphSync = "\uE895";
        public const string GlyphMail = "\uE715";
        public const string GlyphKey = "\uE192";
        public const string GlyphBack = "\uE72B";
        public const string GlyphChevronRight = "\uE76C";
        public const string GlyphCheck = "\uE73E";
        public const string GlyphCancel = "\uE711";
        public const string GlyphPackage = "\uE7B8";
        public const string GlyphShield = "\uEA18";
        public const string GlyphMoveToFolder = "\uE8DE";
        public const string GlyphGlobe = "\uE774";
        public const string GlyphMessage = "\uE8BD";
        public const string GlyphSendFill = "\uE725";
        public const string GlyphPlay = "\uE768";
        public const string GlyphShoppingCart = "\uE7BF";

        public static Font IconFont(float size)
        {
            return new Font(IconFontName, size, FontStyle.Regular, GraphicsUnit.Point);
        }

        public static Color Darken(Color c, float amount)
        {
            return Color.FromArgb(c.A,
                Math.Max(0, (int)(c.R * (1f - amount))),
                Math.Max(0, (int)(c.G * (1f - amount))),
                Math.Max(0, (int)(c.B * (1f - amount))));
        }

        public static Color Lighten(Color c, float amount)
        {
            return Color.FromArgb(c.A,
                Math.Min(255, (int)(c.R + (255 - c.R) * amount)),
                Math.Min(255, (int)(c.G + (255 - c.G) * amount)),
                Math.Min(255, (int)(c.B + (255 - c.B) * amount)));
        }

        public static void DrawRounded(Graphics g, Rectangle rect, int radius, Color fill, Color border)
        {
            using (GraphicsPath path = RoundedPath(rect, radius))
            {
                using (Brush brush = new SolidBrush(fill))
                    g.FillPath(brush, path);
                using (Pen pen = new Pen(border, 1f))
                    g.DrawPath(pen, path);
            }
        }

        public static GraphicsPath RoundedPath(Rectangle rect, int radius)
        {
            int r = Math.Min(radius, Math.Min(rect.Width, rect.Height) / 2);
            if (r < 1) r = 1;
            GraphicsPath p = new GraphicsPath();
            p.AddArc(rect.Left, rect.Top, r * 2, r * 2, 180, 90);
            p.AddArc(rect.Right - r * 2, rect.Top, r * 2, r * 2, 270, 90);
            p.AddArc(rect.Right - r * 2, rect.Bottom - r * 2, r * 2, r * 2, 0, 90);
            p.AddArc(rect.Left, rect.Bottom - r * 2, r * 2, r * 2, 90, 90);
            p.CloseFigure();
            return p;
        }

        public static void ApplyRoundedRegion(Control control, int radius)
        {
            control.Resize += delegate
            {
                if (control.Width <= 0 || control.Height <= 0) return;
                using (GraphicsPath path = RoundedPath(control.ClientRectangle, radius))
                {
                    control.Region = new Region(path);
                }
            };
            if (control.Width > 0 && control.Height > 0)
            {
                using (GraphicsPath path = RoundedPath(control.ClientRectangle, radius))
                {
                    control.Region = new Region(path);
                }
            }
        }

        /// <summary>Finds the largest font size (down to a 6pt floor) at which `text` fits within `maxWidth`.</summary>
        public static float ComputeFitFontSize(Graphics g, string text, float maxWidth, float maxFontSize)
        {
            float fontSize = maxFontSize;
            while (fontSize > 6f)
            {
                using (Font candidate = new Font("Segoe UI Semibold", fontSize, FontStyle.Bold, GraphicsUnit.Point))
                {
                    if (g.MeasureString(text, candidate).Width <= maxWidth)
                        return fontSize;
                }
                fontSize -= 0.5f;
            }
            return 6f;
        }

        private static float? sharedBadgeFontSize;

        /// <summary>
        /// Computes (once, then caches) the single font size that fits the longest of the
        /// given badge texts, so every option-tile badge renders at the same size instead
        /// of each shrinking independently based on its own word length.
        /// </summary>
        public static float GetSharedBadgeFontSize(Graphics g, float badgeDiameter, float maxFontSize, params string[] texts)
        {
            if (sharedBadgeFontSize.HasValue) return sharedBadgeFontSize.Value;

            float maxWidth = badgeDiameter * 0.72f;
            float smallest = maxFontSize;
            foreach (string text in texts)
            {
                float fit = ComputeFitFontSize(g, text, maxWidth, maxFontSize);
                if (fit < smallest) smallest = fit;
            }
            sharedBadgeFontSize = smallest;
            return smallest;
        }

        /// <summary>Draws a filled circular badge with short, bold, centered text at an explicit font size.</summary>
        public static void DrawTextBadge(Graphics g, Rectangle rect, string text, Color bg, Color fg, float fontSize)
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            using (Brush b = new SolidBrush(bg))
                g.FillEllipse(b, rect);
            if (string.IsNullOrEmpty(text)) return;

            using (Font f = new Font("Segoe UI Semibold", fontSize, FontStyle.Bold, GraphicsUnit.Point))
            using (Brush fb = new SolidBrush(fg))
            using (StringFormat sf = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center })
            {
                g.DrawString(text, f, fb, rect, sf);
            }
        }

        /// <summary>Draws a circular badge as just a colored outline (ring) with colored centered text - the resting state before hover, which then fills solid via DrawTextBadge.</summary>
        public static void DrawTextBadgeOutline(Graphics g, Rectangle rect, string text, Color accent, Color fill, float fontSize)
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            using (Brush b = new SolidBrush(fill))
                g.FillEllipse(b, rect);
            using (Pen p = new Pen(accent, 2f))
                g.DrawEllipse(p, Rectangle.Inflate(rect, -1, -1));
            if (string.IsNullOrEmpty(text)) return;

            using (Font f = new Font("Segoe UI Semibold", fontSize, FontStyle.Bold, GraphicsUnit.Point))
            using (Brush fb = new SolidBrush(accent))
            using (StringFormat sf = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center })
            {
                g.DrawString(text, f, fb, rect, sf);
            }
        }

        /// <summary>Draws a filled circular badge with a centered icon-font glyph.</summary>
        public static void DrawGlyphBadge(Graphics g, Rectangle rect, string glyph, Color bg, Color fg, float glyphSize)
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            using (Brush b = new SolidBrush(bg))
                g.FillEllipse(b, rect);
            if (string.IsNullOrEmpty(glyph)) return;
            using (Font f = IconFont(glyphSize))
            using (Brush fb = new SolidBrush(fg))
            using (StringFormat sf = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center })
            {
                g.DrawString(glyph, f, fb, rect, sf);
            }
        }

        /// <summary>A simple right-pointing play triangle, its bounding box exactly centered in `circle`.</summary>
        public static void DrawPlayGlyph(Graphics g, RectangleF circle, Color color)
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            float cx = circle.X + circle.Width / 2f;
            float cy = circle.Y + circle.Height / 2f;
            float r = circle.Width * 0.24f;
            PointF[] triangle =
            {
                new PointF(cx - r, cy - r),
                new PointF(cx - r, cy + r),
                new PointF(cx + r, cy)
            };
            using (Brush b = new SolidBrush(color))
                g.FillPolygon(b, triangle);
        }

        /// <summary>A simple shopping-bag silhouette (symmetric body + top handle arc), centered in `circle`.</summary>
        public static void DrawShoppingBagGlyph(Graphics g, RectangleF circle, Color color)
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            float cx = circle.X + circle.Width / 2f;
            float cy = circle.Y + circle.Height / 2f;
            float s = circle.Width * 0.30f;

            float bodyTop = cy - s * 0.10f;
            float bodyBottom = cy + s * 0.75f;
            float topHalfWidth = s * 0.55f;
            float bottomHalfWidth = s * 0.85f;

            PointF[] body =
            {
                new PointF(cx - topHalfWidth, bodyTop),
                new PointF(cx + topHalfWidth, bodyTop),
                new PointF(cx + bottomHalfWidth, bodyBottom),
                new PointF(cx - bottomHalfWidth, bodyBottom)
            };
            using (Brush b = new SolidBrush(color))
                g.FillPolygon(b, body);

            float handleWidth = topHalfWidth * 1.3f;
            float handleHeight = s * 0.85f;
            RectangleF handleRect = new RectangleF(cx - handleWidth / 2f, bodyTop - handleHeight * 0.65f, handleWidth, handleHeight);
            using (Pen p = new Pen(color, Math.Max(1.5f, circle.Width * 0.07f)))
            {
                g.DrawArc(p, handleRect, 180f, 180f);
            }
        }
    }

    // ======================================================================
    // Material-style clickable list row used on the "choose an option" page.
    // Tapping it fires Click immediately (no radio selection state).
    // ======================================================================
    internal sealed class OptionTile : Panel
    {
        public InstallMode Mode { get; private set; }
        private readonly string badgeText;
        private readonly string title;
        private readonly string subtitle;
        private bool hovering;
        private bool pressed;

        public OptionTile(InstallMode mode, string badgeText, string title, string subtitle)
        {
            Mode = mode;
            this.badgeText = badgeText;
            this.title = title;
            this.subtitle = subtitle;

            Height = 84;
            Cursor = Cursors.Hand;
            BackColor = UiHelpers.Background;
            SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);

            MouseEnter += delegate { hovering = true; Invalidate(); };
            MouseLeave += delegate { hovering = false; pressed = false; Invalidate(); };
            MouseDown += delegate { pressed = true; Invalidate(); };
            MouseUp += delegate { pressed = false; Invalidate(); };
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.TextRenderingHint = TextRenderingHint.ClearTypeGridFit;

            Color cardFill = pressed ? Color.FromArgb(247, 248, 251) : (hovering ? Color.FromArgb(250, 251, 253) : UiHelpers.Surface);
            Color cardBorder = hovering ? UiHelpers.BrandColor : UiHelpers.Border;

            // Paint the surrounding page background first. Without this, the control's own
            // opaque rectangular BackColor is left showing at the four corners outside the
            // rounded path (a "square white corner" behind the rounded card).
            Color pageBg = Parent != null ? Parent.BackColor : UiHelpers.Background;
            using (Brush pageBrush = new SolidBrush(pageBg))
                g.FillRectangle(pageBrush, ClientRectangle);

            Rectangle rect = new Rectangle(0, 0, Width - 1, Height - 1);
            UiHelpers.DrawRounded(g, rect, 14, cardFill, cardBorder);

            Rectangle badgeRect = new Rectangle(16, (Height - 52) / 2, 52, 52);
            // Fit against the longest of the three badge words ("SWITCH") so FREE/PRO/SWITCH
            // all render at the exact same font size instead of each shrinking independently.
            float badgeFontSize = UiHelpers.GetSharedBadgeFontSize(g, 52f, 11f, "FREE", "PRO", "SWITCH");
            if (hovering)
                UiHelpers.DrawTextBadge(g, badgeRect, badgeText, UiHelpers.BrandColor, Color.White, badgeFontSize);
            else
                UiHelpers.DrawTextBadgeOutline(g, badgeRect, badgeText, UiHelpers.BrandColor, UiHelpers.Surface, badgeFontSize);

            int textX = badgeRect.Right + 18;
            int textWidth = Width - textX - 46;

            using (Font tf = new Font("Segoe UI Semibold", 10.5f))
            using (Brush tb = new SolidBrush(UiHelpers.TextDark))
            {
                g.DrawString(title, tf, tb, new RectangleF(textX, 17, textWidth, 22));
            }
            using (Font sf = new Font("Segoe UI", 8.7f))
            using (Brush sb = new SolidBrush(UiHelpers.TextMuted))
            {
                g.DrawString(subtitle, sf, sb, new RectangleF(textX, 40, textWidth, 34));
            }

            Rectangle chevronRect = new Rectangle(Width - 40, (Height - 24) / 2, 24, 24);
            using (Font cf = UiHelpers.IconFont(11f))
            using (Brush cb = new SolidBrush(hovering ? UiHelpers.BrandColor : UiHelpers.TextMuted))
            using (StringFormat sfm = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center })
            {
                g.DrawString(UiHelpers.GlyphChevronRight, cf, cb, chevronRect, sfm);
            }
        }
    }

    internal enum ButtonKind { Filled, Outline, Text }

    // ======================================================================
    // Custom-painted Material-style button (used for every action button:
    // Install, Back, Finish, and the two footer link buttons).
    // ======================================================================
    internal sealed class MaterialButton : Panel
    {
        public string Text2 { get; set; }
        public string IconGlyph { get; set; }
        public ButtonKind Kind { get; set; }
        public Color FillColor { get; set; }
        public Color TextColor { get; set; }
        public bool UseCircularIcon { get; set; }
        /// <summary>
        /// When set (and UseCircularIcon is true), this draws the icon instead of IconGlyph.
        /// Segoe MDL2 Assets glyphs each carry their own inconsistent internal padding, so
        /// StringFormat centering only centers the character's bounding box, not necessarily
        /// how the shape visually reads - drawing the icon ourselves guarantees true centering.
        /// </summary>
        public Action<Graphics, RectangleF, Color> CustomIconDrawer { get; set; }

        private bool hovering;
        private bool pressed;

        public MaterialButton(string text, string iconGlyph, ButtonKind kind)
        {
            Text2 = text;
            IconGlyph = iconGlyph;
            Kind = kind;
            FillColor = UiHelpers.BrandColor;
            TextColor = kind == ButtonKind.Filled ? Color.White : UiHelpers.TextDark;
            Height = 44;
            Cursor = Cursors.Hand;
            Font = new Font("Segoe UI Semibold", 9.2f);
            SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);

            MouseEnter += delegate { hovering = true; Invalidate(); };
            MouseLeave += delegate { hovering = false; pressed = false; Invalidate(); };
            MouseDown += delegate { pressed = true; Invalidate(); };
            MouseUp += delegate { pressed = false; Invalidate(); };
        }

        protected override void OnEnabledChanged(EventArgs e)
        {
            base.OnEnabledChanged(e);
            Cursor = Enabled ? Cursors.Hand : Cursors.Default;
            Invalidate();
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.TextRenderingHint = TextRenderingHint.ClearTypeGridFit;

            Color bg = Parent != null ? Parent.BackColor : UiHelpers.Background;
            using (Brush bgb = new SolidBrush(bg))
                g.FillRectangle(bgb, ClientRectangle);

            Color fill;
            Color fg;
            Color border = Color.Transparent;
            bool disabled = !Enabled;

            if (Kind == ButtonKind.Filled)
            {
                Color baseColor = disabled ? Color.FromArgb(196, 199, 208) : FillColor;
                fill = pressed ? UiHelpers.Darken(baseColor, 0.12f) : (hovering ? UiHelpers.Lighten(baseColor, 0.08f) : baseColor);
                fg = disabled ? Color.FromArgb(240, 241, 244) : TextColor;
            }
            else if (Kind == ButtonKind.Outline)
            {
                fill = pressed ? UiHelpers.BrandSoft : (hovering ? Color.FromArgb(248, 249, 252) : UiHelpers.Surface);
                border = UiHelpers.Border;
                fg = disabled ? UiHelpers.TextMuted : UiHelpers.TextDark;
            }
            else
            {
                fill = pressed ? UiHelpers.BrandSoft : (hovering ? Color.FromArgb(240, 242, 247) : bg);
                fg = disabled ? UiHelpers.TextMuted : TextColor;
            }

            Rectangle rect = new Rectangle(0, 0, Width - 1, Height - 1);
            int radius = Kind == ButtonKind.Text ? 10 : Height / 2;
            using (GraphicsPath path = UiHelpers.RoundedPath(rect, radius))
            {
                using (Brush fb = new SolidBrush(fill)) g.FillPath(fb, path);
                if (border != Color.Transparent)
                    using (Pen p = new Pen(border, 1f)) g.DrawPath(p, path);
            }

            using (Font iconFont = UiHelpers.IconFont(10.5f))
            {
                SizeF textSize = string.IsNullOrEmpty(Text2) ? SizeF.Empty : g.MeasureString(Text2, Font);

                float iconBoxWidth = 0f;
                float circleDiameter = 0f;
                SizeF glyphSize = SizeF.Empty;

                if (!string.IsNullOrEmpty(IconGlyph))
                {
                    if (UseCircularIcon)
                    {
                        circleDiameter = Math.Max(16f, Height - 16f);
                        iconBoxWidth = circleDiameter;
                    }
                    else
                    {
                        glyphSize = g.MeasureString(IconGlyph, iconFont);
                        iconBoxWidth = glyphSize.Width;
                    }
                }

                float gap = (iconBoxWidth > 0f && !string.IsNullOrEmpty(Text2)) ? 8f : 0f;
                float totalWidth = iconBoxWidth + gap + textSize.Width;
                float startX = (Width - totalWidth) / 2f;
                float centerY = Height / 2f;

                using (Brush fgb = new SolidBrush(fg))
                {
                    if (!string.IsNullOrEmpty(IconGlyph))
                    {
                        if (UseCircularIcon)
                        {
                            RectangleF circleRect = new RectangleF(startX, centerY - circleDiameter / 2f, circleDiameter, circleDiameter);
                            using (Brush cb = new SolidBrush(UiHelpers.BrandColor))
                                g.FillEllipse(cb, circleRect);

                            if (CustomIconDrawer != null)
                            {
                                CustomIconDrawer(g, circleRect, Color.White);
                            }
                            else
                            {
                                using (Font smallIconFont = UiHelpers.IconFont(circleDiameter * 0.42f))
                                using (StringFormat sf = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center })
                                using (Brush whiteBrush = new SolidBrush(Color.White))
                                {
                                    g.DrawString(IconGlyph, smallIconFont, whiteBrush, circleRect, sf);
                                }
                            }
                        }
                        else
                        {
                            g.DrawString(IconGlyph, iconFont, fgb, startX, centerY - glyphSize.Height / 2f);
                        }
                    }
                    g.DrawString(Text2, Font, fgb, startX + iconBoxWidth + gap, centerY - textSize.Height / 2f);
                }
            }
        }
    }

    // ======================================================================
    // Linear "infinite" Material-style progress indicator (a moving segment
    // sliding across a light track). Purely a UI element - no install logic.
    // ======================================================================
    internal sealed class IndeterminateBar : Panel
    {
        private readonly Timer timer;
        private float phase;

        public Color TrackColor { get; set; }
        public Color BarColor { get; set; }

        public IndeterminateBar()
        {
            Height = 8;
            TrackColor = Color.FromArgb(228, 231, 240);
            BarColor = UiHelpers.BrandColor;
            SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);

            timer = new Timer { Interval = 16 };
            timer.Tick += delegate
            {
                phase += 0.02f;
                // Loop back to "segment already visible at the left edge" instead of a
                // fully off-screen negative phase - that off-screen pre-roll was what
                // produced a visible pause before any motion appeared, and it was
                // happening on every single lap, not just at startup.
                if (phase > 1f) phase = StartPhase;
                Invalidate();
            };
        }

        private float StartPhase
        {
            get
            {
                float segW = Math.Max(24f, Width * 0.30f);
                return Width > 0 ? segW / (Width + segW) : 0f;
            }
        }

        public void StartAnimating()
        {
            // Begin already visible at the left edge - no invisible pre-roll before
            // motion starts.
            phase = StartPhase;
            Visible = true;
            Invalidate();
            timer.Start();
        }

        public void StopAnimating()
        {
            timer.Stop();
            Visible = false;
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;

            Rectangle track = new Rectangle(0, 0, Width, Height);
            using (GraphicsPath trackPath = UiHelpers.RoundedPath(track, Height / 2))
            {
                using (Brush tb = new SolidBrush(TrackColor))
                    g.FillPath(tb, trackPath);

                float segW = Math.Max(24f, Width * 0.30f);
                float x = phase * (Width + segW) - segW;
                Rectangle bar = new Rectangle((int)x, 0, (int)segW, Height);

                Region oldClip = g.Clip;
                g.SetClip(trackPath, CombineMode.Replace);
                using (Brush bb = new SolidBrush(BarColor))
                    g.FillRectangle(bb, bar);
                g.Clip = oldClip;
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing) timer.Dispose();
            base.Dispose(disposing);
        }
    }

    // ======================================================================
    // Circular result badge (green check / red cross) shown after an
    // install finishes. Purely presentational.
    // ======================================================================
    internal sealed class ResultBadge : Panel
    {
        private string glyph = UiHelpers.GlyphCheck;
        private Color badgeColor = UiHelpers.Success;
        private Color softColor = UiHelpers.SuccessSoft;

        public ResultBadge()
        {
            Size = new Size(84, 84);
            SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
        }

        public void SetSuccess(bool success)
        {
            glyph = success ? UiHelpers.GlyphCheck : UiHelpers.GlyphCancel;
            badgeColor = success ? UiHelpers.Success : UiHelpers.Error;
            softColor = success ? UiHelpers.SuccessSoft : UiHelpers.ErrorSoft;
            Invalidate();
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.TextRenderingHint = TextRenderingHint.ClearTypeGridFit;
            Rectangle outer = new Rectangle(0, 0, Width, Height);
            using (Brush b = new SolidBrush(softColor))
                g.FillEllipse(b, outer);
            Rectangle inner = Rectangle.Inflate(outer, -14, -14);
            UiHelpers.DrawGlyphBadge(g, inner, glyph, badgeColor, Color.White, 24f);
        }
    }

    // ======================================================================
    // Small icon-only button designed for the dark brand-colored header
    // (website / support links). A plain MaterialButton's hover colors are
    // tuned for light backgrounds, so this uses a lighter-navy hover circle
    // instead of a near-white one.
    // ======================================================================
    internal sealed class HeaderIconButton : Panel
    {
        private readonly string glyph;
        private bool hovering;
        private bool pressed;

        public HeaderIconButton(string glyph)
        {
            this.glyph = glyph;
            Size = new Size(34, 34);
            Cursor = Cursors.Hand;
            SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);

            MouseEnter += delegate { hovering = true; Invalidate(); };
            MouseLeave += delegate { hovering = false; pressed = false; Invalidate(); };
            MouseDown += delegate { pressed = true; Invalidate(); };
            MouseUp += delegate { pressed = false; Invalidate(); };
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.TextRenderingHint = TextRenderingHint.ClearTypeGridFit;

            Color pageBg = Parent != null ? Parent.BackColor : UiHelpers.BrandColor;
            using (Brush pageBrush = new SolidBrush(pageBg))
                g.FillRectangle(pageBrush, ClientRectangle);

            if (pressed || hovering)
            {
                Color circleColor = pressed ? UiHelpers.Darken(UiHelpers.BrandLighter, 0.12f) : UiHelpers.BrandLighter;
                using (Brush cb = new SolidBrush(circleColor))
                    g.FillEllipse(cb, new Rectangle(0, 0, Width - 1, Height - 1));
            }

            using (Font f = UiHelpers.IconFont(12f))
            using (Brush fb = new SolidBrush(Color.White))
            using (StringFormat sf = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center })
            {
                g.DrawString(glyph, f, fb, new RectangleF(0, 0, Width, Height), sf);
            }
        }
    }
}
