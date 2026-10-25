using System.Drawing;
using System.Windows.Forms;

namespace AppShield.Installer;

public class InstalledOptionsForm : Form
{
    public InstalledOptionsForm()
    {
        InitializeComponent();
    }

    private void InitializeComponent()
    {
        Text = "AppShield Setup — Endpoint Protection";
        Size = new Size(540, 440);
        StartPosition = FormStartPosition.CenterScreen;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        BackColor = Color.FromArgb(248, 249, 250);
        Font = new Font("Segoe UI", 9.5f, FontStyle.Regular);

        try
        {
            var icoStream = typeof(InstalledOptionsForm).Assembly.GetManifestResourceStream("AppShield.Installer.appshield.ico");
            if (icoStream != null) Icon = new Icon(icoStream);
        }
        catch { }

        var pnlHeader = new Panel
        {
            Dock = DockStyle.Top,
            Height = 85,
            BackColor = Color.FromArgb(24, 24, 37)
        };

        var lblTitle = new Label
        {
            Text = "AppShield is Already Installed",
            Font = new Font("Segoe UI", 13f, FontStyle.Bold),
            ForeColor = Color.White,
            Location = new Point(24, 18),
            AutoSize = true
        };

        var lblSubtitle = new Label
        {
            Text = "Endpoint Protection & Parental Shield Service is active on this PC",
            Font = new Font("Segoe UI", 9f, FontStyle.Regular),
            ForeColor = Color.FromArgb(166, 173, 200),
            Location = new Point(24, 46),
            AutoSize = true
        };

        pnlHeader.Controls.Add(lblTitle);
        pnlHeader.Controls.Add(lblSubtitle);
        Controls.Add(pnlHeader);

        int top = 110;

        // Button 1: Open Control Center
        var btnOpen = new Button
        {
            Text = "🛡️  Launch AppShield Control Center",
            Font = new Font("Segoe UI", 10f, FontStyle.Bold),
            Location = new Point(40, top),
            Size = new Size(440, 50),
            BackColor = Color.FromArgb(79, 70, 229),
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat,
            Cursor = Cursors.Hand
        };
        btnOpen.FlatAppearance.BorderSize = 0;
        btnOpen.Click += (s, e) =>
        {
            Hide();
            InstallEngine.LaunchControlCenter();
            Close();
        };
        Controls.Add(btnOpen);
        top += 66;

        // Button 2: Reinstall / Update Protection
        var btnReinstall = new Button
        {
            Text = "🔄  Update / Re-install Protection Engine",
            Font = new Font("Segoe UI", 10f, FontStyle.Bold),
            Location = new Point(40, top),
            Size = new Size(440, 50),
            BackColor = Color.FromArgb(16, 185, 129),
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat,
            Cursor = Cursors.Hand
        };
        btnReinstall.FlatAppearance.BorderSize = 0;
        btnReinstall.Click += (s, e) =>
        {
            Hide();
            using var installer = new InstallerForm();
            installer.ShowDialog();
            Close();
        };
        Controls.Add(btnReinstall);
        top += 66;

        // Button 3: Uninstall AppShield
        var btnUninstall = new Button
        {
            Text = "🗑️  Uninstall AppShield from this PC",
            Font = new Font("Segoe UI", 10f, FontStyle.Bold),
            Location = new Point(40, top),
            Size = new Size(440, 50),
            BackColor = Color.FromArgb(225, 29, 72),
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat,
            Cursor = Cursors.Hand
        };
        btnUninstall.FlatAppearance.BorderSize = 0;
        btnUninstall.Click += (s, e) =>
        {
            Hide();
            using var uninst = new UninstallForm();
            uninst.ShowDialog();
            Close();
        };
        Controls.Add(btnUninstall);
    }
}
