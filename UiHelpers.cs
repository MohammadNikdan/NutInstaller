using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Text;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace NutriculaInstaller
{
    /// <summary>
    /// Shared colors, icon-font glyphs and drawing helpers for the Material-style UI.
    /// The brand color below is unchanged from the original UI.
    /// </summary>
    // Same "ctrl flow" exclusion and reasoning as MainForm.cs: this class and
    // the Panel-derived controls below (OptionTile, MaterialButton,
    // IndeterminateBar, CircularSpinner, ResultBadge) are pure drawing/layout
    // code called from MainForm's constructor and from OnPaint on first
    // render, not security-sensitive logic.
    [Obfuscation(Exclude = false, Feature = "-ctrl flow", ApplyToMembers = true)]
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

        // ===== Embedded promo image (UIAssets/installerpic.jpg - deliberately
        //       kept OUT of Assets/, which is reserved for the critical
        //       license/security binaries; this is just decorative UI) =====
        private static readonly Image installerPromoImage = LoadEmbeddedInstallerPic();

        private static Image LoadEmbeddedInstallerPic()
        {
            try
            {
                var assembly = typeof(UiHelpers).Assembly;
                using (Stream stream = assembly.GetManifestResourceStream("NutriculaInstaller.UIAssets.installerpic.jpg"))
                {
                    if (stream == null) return null;
                    // Image.FromStream needs the stream to stay open for the lifetime of the
                    // Image in some GDI+ paths, so copy into a standalone MemoryStream first
                    // rather than wrapping the (about-to-be-disposed) resource stream directly.
                    using (MemoryStream ms = new MemoryStream())
                    {
                        stream.CopyTo(ms);
                        return Image.FromStream(ms);
                    }
                }
            }
            catch
            {
                return null;
            }
        }

        /// <summary>The embedded installer promo image, or null if it wasn't found/couldn't be loaded.</summary>
        public static Image InstallerPromoImage
        {
            get { return installerPromoImage; }
        }

        /// <summary>
        /// Creates a PictureBox showing the embedded promo image at a fixed size/position.
        /// Returns an empty (invisible) placeholder Panel-backed PictureBox if the image
        /// failed to load, so a missing asset never breaks the rest of the UI.
        /// </summary>
        public static PictureBox CreatePromoImageBox(Point location, Size size)
        {
            PictureBox box = new PictureBox
            {
                Location = location,
                Size = size,
                SizeMode = PictureBoxSizeMode.Zoom,
                BackColor = Color.Transparent
            };
            if (installerPromoImage != null)
                box.Image = installerPromoImage;
            return box;
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

        /// <summary>
        /// Draws a filled circular badge with a centered vector icon (see the
        /// Windows 8/8.1 compatibility note above DrawBackArrowGlyph) instead
        /// of an icon-font glyph.
        /// </summary>
        public static void DrawGlyphBadge(Graphics g, Rectangle rect, Action<Graphics, RectangleF, Color> iconDrawer, Color bg, Color fg)
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            using (Brush b = new SolidBrush(bg))
                g.FillEllipse(b, rect);
            if (iconDrawer == null) return;
            iconDrawer(g, rect, fg);
        }

        /// <summary>A simple right-pointing play triangle, its bounding box exactly centered in `circle`.</summary>
        public static void DrawPlayGlyph(Graphics g, RectangleF circle, Color color)
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            // Nudged right for optical centering: a geometrically-centered play triangle
            // reads as left-heavy since its visual mass sits toward the flat left edge.
            float cx = circle.X + circle.Width / 2f + circle.Width * 0.05f;
            float cy = circle.Y + circle.Height / 2f;
            float r = circle.Width * 0.17f;
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
            float cx = circle.X + circle.Width / 2f - circle.Width * 0.005f;
            float cy = circle.Y + circle.Height / 2f - circle.Height * 0.03f;
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

        // ==================================================================
        // 2026 hardening (Windows 8/8.1 compatibility fix): the icons below
        // replace the ones previously drawn with the "Segoe MDL2 Assets"
        // icon font (see IconFontName's own comment - that font only ships
        // starting with Windows 10, so every glyph drawn through it was
        // rendering as blank space on Windows 7/8/8.1, where GDI+ silently
        // substitutes a different font that has no mapping for those
        // private-use-area codepoints). These are plain vector shapes drawn
        // directly with GDI+ primitives (lines/arcs/polygons) instead of
        // text, so they render identically on every Windows version and
        // need no font, embedded or otherwise, to exist at all - the same
        // approach already used above for DrawPlayGlyph/DrawShoppingBagGlyph.
        // Each one follows that same signature convention: a bounding box
        // and a single fill/stroke color, so they drop straight into
        // MaterialButton.CustomIconDrawer, HeaderIconButton, DrawGlyphBadge
        // and the plain field-icon panels with no other change needed.
        // ==================================================================

        /// <summary>A left-pointing back arrow, centered in `box`.</summary>
        public static void DrawBackArrowGlyph(Graphics g, RectangleF box, Color color)
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            float cx = box.X + box.Width / 2f;
            float cy = box.Y + box.Height / 2f;
            float s = Math.Min(box.Width, box.Height) * 0.30f;
            using (Pen p = new Pen(color, Math.Max(1.6f, box.Width * 0.11f)) { StartCap = LineCap.Round, EndCap = LineCap.Round, LineJoin = LineJoin.Round })
            {
                g.DrawLine(p, cx + s, cy, cx - s, cy);
                g.DrawLine(p, cx - s * 0.30f, cy - s * 0.70f, cx - s, cy);
                g.DrawLine(p, cx - s * 0.30f, cy + s * 0.70f, cx - s, cy);
            }
        }

        /// <summary>A downward "download" arrow with a tray line beneath it, centered in `box`.</summary>
        public static void DrawDownloadGlyph(Graphics g, RectangleF box, Color color)
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            float cx = box.X + box.Width / 2f;
            float cy = box.Y + box.Height / 2f;
            float s = Math.Min(box.Width, box.Height) * 0.30f;
            using (Pen p = new Pen(color, Math.Max(1.6f, box.Width * 0.11f)) { StartCap = LineCap.Round, EndCap = LineCap.Round, LineJoin = LineJoin.Round })
            {
                g.DrawLine(p, cx, cy - s, cx, cy + s * 0.25f);
                g.DrawLine(p, cx - s * 0.55f, cy - s * 0.30f, cx, cy + s * 0.25f);
                g.DrawLine(p, cx + s * 0.55f, cy - s * 0.30f, cx, cy + s * 0.25f);
                g.DrawLine(p, cx - s, cy + s, cx + s, cy + s);
            }
        }

        /// <summary>A simple checkmark, centered in `box`.</summary>
        public static void DrawCheckGlyph(Graphics g, RectangleF box, Color color)
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            float cx = box.X + box.Width / 2f;
            float cy = box.Y + box.Height / 2f;
            float s = Math.Min(box.Width, box.Height) * 0.32f;
            using (Pen p = new Pen(color, Math.Max(1.8f, box.Width * 0.13f)) { StartCap = LineCap.Round, EndCap = LineCap.Round, LineJoin = LineJoin.Round })
            {
                g.DrawLines(p, new PointF[]
                {
                    new PointF(cx - s, cy + s * 0.05f),
                    new PointF(cx - s * 0.28f, cy + s * 0.78f),
                    new PointF(cx + s, cy - s * 0.62f)
                });
            }
        }

        /// <summary>A simple "X" cancel mark, centered in `box`.</summary>
        public static void DrawCancelGlyph(Graphics g, RectangleF box, Color color)
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            float cx = box.X + box.Width / 2f;
            float cy = box.Y + box.Height / 2f;
            float s = Math.Min(box.Width, box.Height) * 0.26f;
            using (Pen p = new Pen(color, Math.Max(1.6f, box.Width * 0.12f)) { StartCap = LineCap.Round, EndCap = LineCap.Round })
            {
                g.DrawLine(p, cx - s, cy - s, cx + s, cy + s);
                g.DrawLine(p, cx - s, cy + s, cx + s, cy - s);
            }
        }

        /// <summary>A right-pointing chevron ("&gt;"), centered in `box`.</summary>
        public static void DrawChevronRightGlyph(Graphics g, RectangleF box, Color color)
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            float cx = box.X + box.Width / 2f;
            float cy = box.Y + box.Height / 2f;
            float s = Math.Min(box.Width, box.Height) * 0.22f;
            using (Pen p = new Pen(color, Math.Max(1.6f, box.Width * 0.12f)) { StartCap = LineCap.Round, EndCap = LineCap.Round, LineJoin = LineJoin.Round })
            {
                g.DrawLines(p, new PointF[]
                {
                    new PointF(cx - s * 0.45f, cy - s),
                    new PointF(cx + s * 0.55f, cy),
                    new PointF(cx - s * 0.45f, cy + s)
                });
            }
        }

        /// <summary>A circular refresh/sync arrow, centered in `box`.</summary>
        public static void DrawSyncGlyph(Graphics g, RectangleF box, Color color)
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            float cx = box.X + box.Width / 2f;
            float cy = box.Y + box.Height / 2f;
            float r = Math.Min(box.Width, box.Height) * 0.30f;
            float penWidth = Math.Max(1.6f, box.Width * 0.11f);
            const float startAngle = -30f;
            const float sweepAngle = 260f;
            const float endAngle = startAngle + sweepAngle; // 230 degrees
            using (Pen p = new Pen(color, penWidth) { StartCap = LineCap.Round, EndCap = LineCap.Round })
            {
                g.DrawArc(p, cx - r, cy - r, r * 2f, r * 2f, startAngle, sweepAngle);
            }

            // Small filled arrowhead at the end of the arc. The arc is parametrized as
            // (cx + r*cos(theta), cy + r*sin(theta)); its tangent (the direction the arc
            // is travelling at that point, for increasing theta) is (-sin(theta), cos(theta)).
            double endRad = endAngle * Math.PI / 180.0;
            float ex = cx + r * (float)Math.Cos(endRad);
            float ey = cy + r * (float)Math.Sin(endRad);
            float dirX = -(float)Math.Sin(endRad);
            float dirY = (float)Math.Cos(endRad);
            float perpX = -dirY;
            float perpY = dirX;
            float headLen = r * 0.65f;
            PointF tip = new PointF(ex + dirX * headLen * 0.55f, ey + dirY * headLen * 0.55f);
            PointF baseA = new PointF(ex - dirX * headLen * 0.45f + perpX * headLen * 0.55f, ey - dirY * headLen * 0.45f + perpY * headLen * 0.55f);
            PointF baseB = new PointF(ex - dirX * headLen * 0.45f - perpX * headLen * 0.55f, ey - dirY * headLen * 0.45f - perpY * headLen * 0.55f);
            using (Brush b = new SolidBrush(color))
            {
                g.FillPolygon(b, new PointF[] { tip, baseA, baseB });
            }
        }

        /// <summary>A mail envelope (rectangle outline with a V-shaped flap), centered in `box`.</summary>
        public static void DrawMailGlyph(Graphics g, RectangleF box, Color color)
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            float cx = box.X + box.Width / 2f;
            float cy = box.Y + box.Height / 2f;
            float s = Math.Min(box.Width, box.Height) * 0.34f;
            RectangleF rect = new RectangleF(cx - s, cy - s * 0.68f, s * 2f, s * 1.36f);
            float penWidth = Math.Max(1.4f, box.Width * 0.08f);
            using (Pen p = new Pen(color, penWidth) { LineJoin = LineJoin.Round })
            {
                g.DrawRectangle(p, rect.X, rect.Y, rect.Width, rect.Height);
                g.DrawLine(p, rect.Left, rect.Top, cx, cy + s * 0.12f);
                g.DrawLine(p, rect.Right, rect.Top, cx, cy + s * 0.12f);
            }
        }

        /// <summary>A key (a ring plus a shaft with two teeth), centered in `box`.</summary>
        public static void DrawKeyGlyph(Graphics g, RectangleF box, Color color)
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            float cx = box.X + box.Width / 2f;
            float cy = box.Y + box.Height / 2f;
            float s = Math.Min(box.Width, box.Height) * 0.34f;
            float headR = s * 0.42f;
            float headCx = cx - s * 0.50f;
            float penWidth = Math.Max(1.4f, box.Width * 0.09f);
            using (Pen p = new Pen(color, penWidth) { StartCap = LineCap.Round, EndCap = LineCap.Round })
            {
                g.DrawEllipse(p, headCx - headR, cy - headR, headR * 2f, headR * 2f);
                float shaftStartX = headCx + headR * 0.60f;
                float shaftEndX = cx + s * 0.95f;
                g.DrawLine(p, shaftStartX, cy, shaftEndX, cy);
                g.DrawLine(p, shaftEndX, cy, shaftEndX, cy + s * 0.45f);
                g.DrawLine(p, shaftEndX - s * 0.30f, cy, shaftEndX - s * 0.30f, cy + s * 0.32f);
            }
        }

        /// <summary>A globe (outer circle, a narrow meridian ellipse and an equator line), centered in `box`.</summary>
        public static void DrawGlobeGlyph(Graphics g, RectangleF box, Color color)
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            float cx = box.X + box.Width / 2f;
            float cy = box.Y + box.Height / 2f;
            float r = Math.Min(box.Width, box.Height) * 0.36f;
            float penWidth = Math.Max(1.3f, box.Width * 0.07f);
            using (Pen p = new Pen(color, penWidth))
            {
                g.DrawEllipse(p, cx - r, cy - r, r * 2f, r * 2f);
                g.DrawEllipse(p, cx - r * 0.42f, cy - r, r * 0.84f, r * 2f);
                g.DrawLine(p, cx - r, cy, cx + r, cy);
            }
        }

        /// <summary>A paper-plane "send" icon (a dart-shaped silhouette with a fold crease), centered in `box`.</summary>
        public static void DrawSendGlyph(Graphics g, RectangleF box, Color color)
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            float cx = box.X + box.Width / 2f;
            float cy = box.Y + box.Height / 2f;
            float s = Math.Min(box.Width, box.Height) * 0.34f;

            PointF nose = new PointF(cx + s * 1.05f, cy);
            PointF topBack = new PointF(cx - s * 0.85f, cy - s * 0.78f);
            PointF notch = new PointF(cx - s * 0.30f, cy);
            PointF bottomBack = new PointF(cx - s * 0.85f, cy + s * 0.78f);

            using (Brush b = new SolidBrush(color))
            {
                g.FillPolygon(b, new PointF[] { nose, topBack, notch, bottomBack });
            }
            using (Pen p = new Pen(color, Math.Max(1f, box.Width * 0.05f)) { StartCap = LineCap.Round, EndCap = LineCap.Round })
            {
                g.DrawLine(p, notch, nose);
            }
        }
    }

    // ======================================================================
    // Material-style clickable list row used on the "choose an option" page.
    // Tapping it fires Click immediately (no radio selection state).
    // ======================================================================
    [Obfuscation(Exclude = false, Feature = "-ctrl flow", ApplyToMembers = true)]
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
            UiHelpers.DrawChevronRightGlyph(g, chevronRect, hovering ? UiHelpers.BrandColor : UiHelpers.TextMuted);
        }
    }

    internal enum ButtonKind { Filled, Outline, Text }

    // ======================================================================
    // Custom-painted Material-style button (used for every action button:
    // Install, Back, Finish, and the two footer link buttons).
    // ======================================================================
    [Obfuscation(Exclude = false, Feature = "-ctrl flow", ApplyToMembers = true)]
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
                            if (CustomIconDrawer != null)
                            {
                                RectangleF glyphRect = new RectangleF(startX, centerY - glyphSize.Height / 2f, glyphSize.Width, glyphSize.Height);
                                CustomIconDrawer(g, glyphRect, fg);
                            }
                            else
                            {
                                g.DrawString(IconGlyph, iconFont, fgb, startX, centerY - glyphSize.Height / 2f);
                            }
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
    [Obfuscation(Exclude = false, Feature = "-ctrl flow", ApplyToMembers = true)]
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
    // Faint, round "infinite" spinner (a short rotating arc) - used only by
    // MainForm's startup splash overlay (see MainForm.BuildSplashOverlay).
    // Deliberately a separate shape from IndeterminateBar above (the
    // horizontal sliding segment used for real install/uninstall progress):
    // the startup splash isn't reporting progress on anything specific, just
    // "please wait a moment", and a round spinner reads that way without
    // being confused for the linear progress bar shown a moment later.
    // ======================================================================
    [Obfuscation(Exclude = false, Feature = "-ctrl flow", ApplyToMembers = true)]
    internal sealed class CircularSpinner : Panel
    {
        private readonly Timer timer;
        private float angle;

        public CircularSpinner()
        {
            SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
            BackColor = Color.Transparent;

            timer = new Timer { Interval = 16 };
            timer.Tick += delegate
            {
                angle += 6f;
                if (angle >= 360f) angle -= 360f;
                Invalidate();
            };
        }

        public void StartSpinning()
        {
            Visible = true;
            timer.Start();
        }

        public void StopSpinning()
        {
            timer.Stop();
            Visible = false;
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;

            const int thickness = 4;
            Rectangle track = new Rectangle(thickness / 2, thickness / 2, Width - thickness, Height - thickness);

            // Faint full-circle track, deliberately much lighter than the brand
            // color - this is meant to feel quiet, not to draw attention to itself.
            using (Pen trackPen = new Pen(Color.FromArgb(235, 236, 240), thickness))
                g.DrawEllipse(trackPen, track);

            // One short rotating arc in the brand color, kept faint via alpha
            // rather than a fully saturated color, per the request for
            // something "کمرنگ" (muted) rather than a bold spinner.
            using (Pen arcPen = new Pen(Color.FromArgb(140, UiHelpers.BrandColor), thickness) { StartCap = LineCap.Round, EndCap = LineCap.Round })
            {
                g.DrawArc(arcPen, track, angle, 90f);
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
    [Obfuscation(Exclude = false, Feature = "-ctrl flow", ApplyToMembers = true)]
    internal sealed class ResultBadge : Panel
    {
        private Action<Graphics, RectangleF, Color> iconDrawer = UiHelpers.DrawCheckGlyph;
        private Color badgeColor = UiHelpers.Success;
        private Color softColor = UiHelpers.SuccessSoft;

        public ResultBadge()
        {
            Size = new Size(84, 84);
            SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
        }

        public void SetSuccess(bool success)
        {
            iconDrawer = success ? UiHelpers.DrawCheckGlyph : UiHelpers.DrawCancelGlyph;
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
            UiHelpers.DrawGlyphBadge(g, inner, iconDrawer, badgeColor, Color.White);
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
        /// <summary>
        /// When set, draws this vector icon instead of the "Segoe MDL2 Assets" glyph -
        /// see the Windows 8/8.1 compatibility note above DrawBackArrowGlyph in UiHelpers.
        /// </summary>
        public Action<Graphics, RectangleF, Color> CustomIconDrawer { get; set; }
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

            if (CustomIconDrawer != null)
            {
                CustomIconDrawer(g, new RectangleF(0, 0, Width, Height), Color.White);
            }
            else
            {
                using (Font f = UiHelpers.IconFont(12f))
                using (Brush fb = new SolidBrush(Color.White))
                using (StringFormat sf = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center })
                {
                    g.DrawString(glyph, f, fb, new RectangleF(0, 0, Width, Height), sf);
                }
            }
        }
    }
}
