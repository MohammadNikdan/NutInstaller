using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Text;
using System.Windows.Forms;

namespace NutriculaInstaller
{
    /// <summary>
    /// Shared colors, icon-font glyphs and drawing helpers for the Material-style UI.
    /// The brand color below is unchanged from the original UI.
    /// </summary>
    internal static class UiHelpers
    {
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
    }

    // ======================================================================
    // Material-style clickable list row used on the "choose an option" page.
    // Tapping it fires Click immediately (no radio selection state).
    // ======================================================================
    internal sealed class OptionTile : Panel
    {
        public InstallMode Mode { get; private set; }
        private readonly string glyph;
        private readonly string title;
        private readonly string subtitle;
        private bool hovering;
        private bool pressed;

        public OptionTile(InstallMode mode, string glyph, string title, string subtitle)
        {
            Mode = mode;
            this.glyph = glyph;
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
            Color badgeBg = hovering ? UiHelpers.BrandColor : UiHelpers.BrandSoft;
            Color badgeFg = hovering ? Color.White : UiHelpers.BrandColor;
            UiHelpers.DrawGlyphBadge(g, badgeRect, glyph, badgeBg, badgeFg, 16f);

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
                SizeF textSize = g.MeasureString(Text2, Font);
                SizeF iconSize = string.IsNullOrEmpty(IconGlyph) ? SizeF.Empty : g.MeasureString(IconGlyph, iconFont);
                float gap = string.IsNullOrEmpty(IconGlyph) ? 0f : 8f;
                float totalWidth = iconSize.Width + gap + textSize.Width;
                float startX = (Width - totalWidth) / 2f;
                float centerY = Height / 2f;

                using (Brush fgb = new SolidBrush(fg))
                {
                    if (!string.IsNullOrEmpty(IconGlyph))
                        g.DrawString(IconGlyph, iconFont, fgb, startX, centerY - iconSize.Height / 2f);
                    g.DrawString(Text2, Font, fgb, startX + iconSize.Width + gap, centerY - textSize.Height / 2f);
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
                phase += 0.014f;
                if (phase > 1.6f) phase = -0.6f;
                Invalidate();
            };
        }

        public void StartAnimating()
        {
            phase = -0.6f;
            Visible = true;
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
            Rectangle outer = new Rectangle(0, 0, Width, Height);
            using (Brush b = new SolidBrush(softColor))
                g.FillEllipse(b, outer);
            Rectangle inner = Rectangle.Inflate(outer, -14, -14);
            UiHelpers.DrawGlyphBadge(g, inner, glyph, badgeColor, Color.White, 24f);
        }
    }
}
