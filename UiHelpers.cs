using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;

namespace NutriculaInstaller
{
    internal static class UiHelpers
    {
        public static readonly Color BrandColor = Color.FromArgb(39, 47, 80);
        public static readonly Color BrandLighter = Color.FromArgb(62, 71, 108);
        public static readonly Color Background = Color.FromArgb(245, 246, 249);
        public static readonly Color Border = Color.FromArgb(218, 221, 230);
        public static readonly Color TextDark = Color.FromArgb(32, 35, 44);
        public static readonly Color TextMuted = Color.FromArgb(105, 110, 123);
        public static readonly Color Success = Color.FromArgb(31, 137, 74);
        public static readonly Color Error = Color.FromArgb(180, 48, 48);

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
                using (GraphicsPath path = RoundedPath(control.ClientRectangle, radius))
                {
                    control.Region = new Region(path);
                }
            };
            using (GraphicsPath path = RoundedPath(control.ClientRectangle, radius))
            {
                control.Region = new Region(path);
            }
        }
    }

    internal sealed class OptionCard : Panel
    {
        private readonly Label titleLabel;
        private readonly Label descriptionLabel;
        private bool selected;

        public InstallMode Mode { get; private set; }
        public bool Selected
        {
            get { return selected; }
            set
            {
                selected = value;
                UpdateVisuals();
            }
        }

        public event EventHandler CardClicked;

        public OptionCard(InstallMode mode, string title, string description)
        {
            Mode = mode;
            Cursor = Cursors.Hand;
            Padding = new Padding(18, 14, 18, 14);
            BackColor = Color.White;
            Margin = new Padding(0, 0, 0, 10);
            Height = 72;

            titleLabel = new Label
            {
                AutoSize = true,
                Font = new Font("Segoe UI Semibold", 10.5f),
                ForeColor = UiHelpers.TextDark,
                Text = title,
                Location = new Point(18, 12),
                Cursor = Cursors.Hand
            };

            descriptionLabel = new Label
            {
                AutoSize = true,
                Font = new Font("Segoe UI", 8.5f),
                ForeColor = UiHelpers.TextMuted,
                Text = description,
                Location = new Point(18, 37),
                Cursor = Cursors.Hand
            };

            Controls.Add(titleLabel);
            Controls.Add(descriptionLabel);
            Paint += OnPaintCard;
            Click += OnCardClick;
            titleLabel.Click += OnCardClick;
            descriptionLabel.Click += OnCardClick;
            titleLabel.MouseEnter += delegate { Hover(true); };
            descriptionLabel.MouseEnter += delegate { Hover(true); };
            titleLabel.MouseLeave += delegate { Hover(false); };
            descriptionLabel.MouseLeave += delegate { Hover(false); };

            UiHelpers.ApplyRoundedRegion(this, 12);
            UpdateVisuals();
        }

        private void OnCardClick(object sender, EventArgs e)
        {
            if (CardClicked != null)
                CardClicked(this, EventArgs.Empty);
        }

        private void Hover(bool active)
        {
            if (!Selected)
                BackColor = active ? Color.FromArgb(250, 251, 253) : Color.White;
            Invalidate();
        }

        private void UpdateVisuals()
        {
            BackColor = selected ? Color.FromArgb(236, 239, 247) : Color.White;
            titleLabel.ForeColor = selected ? UiHelpers.BrandColor : UiHelpers.TextDark;
            Invalidate();
        }

        private void OnPaintCard(object sender, PaintEventArgs e)
        {
            e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
            Color border = Selected ? UiHelpers.BrandColor : UiHelpers.Border;
            UiHelpers.DrawRounded(e.Graphics, new Rectangle(0, 0, Width - 1, Height - 1), 12, BackColor, border);

            using (Brush b = new SolidBrush(Selected ? UiHelpers.BrandColor : Color.White))
                e.Graphics.FillEllipse(b, 8, 27, 16, 16);
            using (Pen p = new Pen(Selected ? UiHelpers.BrandColor : UiHelpers.Border, 2f))
                e.Graphics.DrawEllipse(p, 8, 27, 16, 16);
            if (Selected)
            {
                using (Brush b = new SolidBrush(Color.White))
                    e.Graphics.FillEllipse(b, 13, 32, 6, 6);
            }
        }
    }
}
