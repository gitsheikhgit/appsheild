using System.Diagnostics;
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
        Text = "AppShield Setup — Endpoint Protection v1.3.3";
        Size = new Size(540, 500);
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
            Text = "Endpoint Protection & Parental Shield Service v1.3.3 is active on this PC",
            Font = new Font("Segoe UI", 9f, FontStyle.Regular),
            ForeColor = Color.FromArgb(166, 173, 200),
            Location = new Point(24, 46),
            AutoSize = true
        };

        pnlHeader.Controls.Add(lblTitle);
        pnlHeader.Controls.Add(lblSubtitle);
        Controls.Add(pnlHeader);

        int top = 105;

        // Button 1: Open Control Center
        var btnOpen = new Button
        {
            Text = "🛡️  Launch AppShield Control Center (v1.3.3)",
            Font = new Font("Segoe UI", 10f, FontStyle.Bold),
            Location = new Point(40, top),
            Size = new Size(440, 48),
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
        top += 60;

        // Button 2: Open Web Control App
        var btnWeb = new Button
        {
            Text = "🌐  Open Web Control Dashboard (Browser)",
            Font = new Font("Segoe UI", 10f, FontStyle.Bold),
            Location = new Point(40, top),
            Size = new Size(440, 48),
            BackColor = Color.FromArgb(59, 130, 246),
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat,
            Cursor = Cursors.Hand
        };
        btnWeb.FlatAppearance.BorderSize = 0;
        btnWeb.Click += (s, e) =>
        {
            try
            {
                Process.Start(new ProcessStartInfo("http://127.0.0.1:54121") { UseShellExecute = true });
            }
            catch { }
            Close();
        };
        Controls.Add(btnWeb);
        top += 60;

        // Button 3: Reinstall / Update Protection
        var btnReinstall = new Button
        {
            Text = "🔄  Update / Re-install Protection Engine",
            Font = new Font("Segoe UI", 10f, FontStyle.Bold),
            Location = new Point(40, top),
            Size = new Size(440, 48),
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
        top += 60;

        // Button 4: Uninstall AppShield
        var btnUninstall = new Button
        {
            Text = "🗑️  Uninstall AppShield from this PC",
            Font = new Font("Segoe UI", 10f, FontStyle.Bold),
            Location = new Point(40, top),
            Size = new Size(440, 48),
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
