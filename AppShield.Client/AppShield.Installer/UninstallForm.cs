using System.Drawing;
using System.Windows.Forms;

namespace AppShield.Installer;

public class UninstallForm : Form
{
    private TextBox _txtPassword = null!;
    private CheckBox _chkShowPassword = null!;
    private Button _btnUninstall = null!;
    private Button _btnCancel = null!;
    private ProgressBar _progressBar = null!;
    private Label _lblStatus = null!;

    public UninstallForm()
    {
        InitializeComponent();
    }

    private void InitializeComponent()
    {
        Text = "AppShield Uninstaller";
        Size = new Size(520, 360);
        StartPosition = FormStartPosition.CenterScreen;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        BackColor = Color.FromArgb(248, 249, 250);
        Font = new Font("Segoe UI", 9.5f, FontStyle.Regular);

        try
        {
            var icoStream = typeof(UninstallForm).Assembly.GetManifestResourceStream("AppShield.Installer.appshield.ico");
            if (icoStream != null)
            {
                Icon = new Icon(icoStream);
            }
        }
        catch { }

        // Top Banner Panel
        var pnlHeader = new Panel
        {
            Dock = DockStyle.Top,
            Height = 75,
            BackColor = Color.FromArgb(30, 30, 40)
        };

        var lblTitle = new Label
        {
            Text = "Uninstall AppShield Protection",
            Font = new Font("Segoe UI", 13f, FontStyle.Bold),
            ForeColor = Color.White,
            Location = new Point(20, 16),
            AutoSize = true
        };

        var lblSubtitle = new Label
        {
            Text = "Restores all application access, system settings, and removes background service",
            Font = new Font("Segoe UI", 9f, FontStyle.Regular),
            ForeColor = Color.FromArgb(166, 173, 200),
            Location = new Point(20, 42),
            AutoSize = true
        };

        pnlHeader.Controls.Add(lblTitle);
        pnlHeader.Controls.Add(lblSubtitle);
        Controls.Add(pnlHeader);

        int top = 95;

        var lblPrompt = new Label
        {
            Text = "To prevent unauthorized removal, enter your Master Password to authorize uninstallation:",
            Location = new Point(25, top),
            Size = new Size(460, 40),
            ForeColor = Color.FromArgb(40, 40, 40)
        };
        Controls.Add(lblPrompt);
        top += 45;

        _txtPassword = new TextBox
        {
            UseSystemPasswordChar = true,
            Location = new Point(25, top),
            Size = new Size(360, 28),
            Font = new Font("Segoe UI", 10f)
        };
        Controls.Add(_txtPassword);

        _chkShowPassword = new CheckBox
        {
            Text = "Show",
            Location = new Point(400, top + 2),
            Size = new Size(80, 24),
            ForeColor = Color.FromArgb(70, 70, 70)
        };
        _chkShowPassword.CheckedChanged += (s, e) =>
        {
            _txtPassword.UseSystemPasswordChar = !_chkShowPassword.Checked;
        };
        Controls.Add(_chkShowPassword);
        top += 38;

        _progressBar = new ProgressBar
        {
            Location = new Point(25, top),
            Size = new Size(460, 20),
            Minimum = 0,
            Maximum = 100,
            Value = 0,
            Visible = false
        };
        Controls.Add(_progressBar);
        top += 24;

        _lblStatus = new Label
        {
            Text = "",
            Location = new Point(25, top),
            Size = new Size(460, 22),
            ForeColor = Color.FromArgb(100, 100, 100),
            Font = new Font("Segoe UI", 9f, FontStyle.Italic)
        };
        Controls.Add(_lblStatus);
        top += 26;

        _btnUninstall = new Button
        {
            Text = "⚠️  Uninstall AppShield",
            Location = new Point(25, top),
            Size = new Size(320, 42),
            BackColor = Color.FromArgb(198, 40, 40),
            ForeColor = Color.White,
            Font = new Font("Segoe UI", 10.5f, FontStyle.Bold),
            FlatStyle = FlatStyle.Flat,
            Cursor = Cursors.Hand
        };
        _btnUninstall.FlatAppearance.BorderSize = 0;
        _btnUninstall.Click += BtnUninstall_Click;
        Controls.Add(_btnUninstall);

        _btnCancel = new Button
        {
            Text = "Cancel",
            Location = new Point(360, top),
            Size = new Size(125, 42),
            Font = new Font("Segoe UI", 10f),
            Cursor = Cursors.Hand
        };
        _btnCancel.Click += (s, e) => Close();
        Controls.Add(_btnCancel);
    }

    private void BtnUninstall_Click(object? sender, EventArgs e)
    {
        string pass = _txtPassword.Text.Trim();
        if (string.IsNullOrEmpty(pass))
        {
            MessageBox.Show("Please enter the Master Password to confirm uninstallation.", "AppShield Uninstaller", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        _btnUninstall.Enabled = false;
        _btnCancel.Enabled = false;
        _txtPassword.Enabled = false;
        _progressBar.Visible = true;

        Task.Run(() =>
        {
            bool success = InstallEngine.RunUninstall(pass, (pct, msg) =>
            {
                Invoke(() =>
                {
                    _progressBar.Value = pct;
                    _lblStatus.Text = msg;
                });
            }, out string error);

            Invoke(() =>
            {
                if (success)
                {
                    MessageBox.Show(
                        "AppShield has been completely uninstalled.\n\nAll application restrictions have been lifted and all settings restored to defaults.",
                        "AppShield Uninstalled",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Information);
                    Close();
                }
                else
                {
                    _progressBar.Visible = false;
                    _btnUninstall.Enabled = true;
                    _btnCancel.Enabled = true;
                    _txtPassword.Enabled = true;
                    _lblStatus.Text = "Uninstall failed: " + error;
                    MessageBox.Show(error, "Authorization Failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            });
        });
    }
}
