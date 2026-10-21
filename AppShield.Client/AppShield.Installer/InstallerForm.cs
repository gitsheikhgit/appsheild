using System.Diagnostics;
using System.Drawing;
using System.Windows.Forms;

namespace AppShield.Installer;

public class InstallerForm : Form
{
    // Panels
    private Panel _pnlHeader = null!;
    private Panel _pnlStep1Privacy = null!;
    private Panel _pnlStep2Options = null!;
    private Panel _pnlStep3Success = null!;

    // Step 1: Privacy Policy
    private TextBox _txtPrivacyPolicy = null!;
    private CheckBox _chkAgreePrivacy = null!;
    private Button _btnStep1Next = null!;

    // Step 2: Options
    private TextBox _txtInstallDir = null!;
    private Button _btnBrowseDir = null!;
    private TextBox _txtPassword = null!;
    private CheckBox _chkShowPassword = null!;
    private TextBox _txtPsk = null!;
    private Button _btnRegenPsk = null!;
    private CheckBox _chkDesktopShortcut = null!;
    private Button _btnStep2Back = null!;
    private Button _btnInstall = null!;
    private ProgressBar _progressBar = null!;
    private Label _lblStatus = null!;

    // Step 3: Success
    private TextBox _txtSummary = null!;
    private Button _btnCopy = null!;
    private Button _btnClose = null!;

    public InstallerForm()
    {
        InitializeComponent();
    }

    private void InitializeComponent()
    {
        Text = "AppShield Endpoint Protection Setup";
        Size = new Size(680, 650);
        StartPosition = FormStartPosition.CenterScreen;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        BackColor = Color.FromArgb(248, 249, 250);
        Font = new Font("Segoe UI", 9.5f, FontStyle.Regular);

        try
        {
            var icoStream = typeof(InstallerForm).Assembly.GetManifestResourceStream("AppShield.Installer.appshield.ico");
            if (icoStream != null) Icon = new Icon(icoStream);
        }
        catch { }

        // Top Banner Panel
        _pnlHeader = new Panel
        {
            Dock = DockStyle.Top,
            Height = 85,
            BackColor = Color.FromArgb(24, 24, 37)
        };

        var lblTitle = new Label
        {
            Text = "AppShield Endpoint Protection Setup",
            Font = new Font("Segoe UI", 14f, FontStyle.Bold),
            ForeColor = Color.White,
            Location = new Point(24, 18),
            AutoSize = true
        };

        var lblSubtitle = new Label
        {
            Text = "Tamper-Resistant Windows Client Installer & Fleet Agent",
            Font = new Font("Segoe UI", 9.5f, FontStyle.Regular),
            ForeColor = Color.FromArgb(166, 173, 200),
            Location = new Point(24, 46),
            AutoSize = true
        };

        _pnlHeader.Controls.Add(lblTitle);
        _pnlHeader.Controls.Add(lblSubtitle);
        Controls.Add(_pnlHeader);

        BuildStep1Privacy();
        BuildStep2Options();
        BuildStep3Success();

        ShowStep(1);
    }

    private void ShowStep(int step)
    {
        _pnlStep1Privacy.Visible = (step == 1);
        _pnlStep2Options.Visible = (step == 2);
        _pnlStep3Success.Visible = (step == 3);
    }

    private void BuildStep1Privacy()
    {
        _pnlStep1Privacy = new Panel
        {
            Dock = DockStyle.Fill,
            Padding = new Padding(25, 15, 25, 20)
        };

        var lblHeading = new Label
        {
            Text = "Privacy Policy & System Modifications Disclosure",
            Font = new Font("Segoe UI", 11.5f, FontStyle.Bold),
            ForeColor = Color.FromArgb(30, 30, 30),
            Location = new Point(25, 15),
            AutoSize = true
        };
        _pnlStep1Privacy.Controls.Add(lblHeading);

        var lblNotice = new Label
        {
            Text = "Please review what AppShield monitors and the changes it makes to this computer before proceeding:",
            Location = new Point(25, 42),
            Size = new Size(610, 24),
            ForeColor = Color.FromArgb(70, 70, 70)
        };
        _pnlStep1Privacy.Controls.Add(lblNotice);

        string policyText =
            "APPSHIELD PRIVACY POLICY & OPERATIONAL DISCLOSURE\r\n" +
            "==================================================================\r\n\r\n" +
            "1. ZERO CLOUD TELEMETRY & 100% LOCAL PRIVACY\r\n" +
            "------------------------------------------------------------------\r\n" +
            "* AppShield DOES NOT transmit your keystrokes, personal files, web browsing\r\n" +
            "  history, or screen recordings to external cloud or third-party servers.\r\n" +
            "* All telemetry, logs, rules, and quotas remain strictly localized on this\r\n" +
            "  Windows PC and are accessible ONLY to your authorized parent macOS Admin\r\n" +
            "  dashboard over your encrypted local network (LAN) or peer-to-peer VPN.\r\n\r\n" +
            "2. WHAT APPSHIELD MONITORS & CONTROLS ON THIS DEVICE\r\n" +
            "------------------------------------------------------------------\r\n" +
            "* Process Execution Events: Evaluates application launches in real-time\r\n" +
            "  against parent-configured blocklists and daily time quotas.\r\n" +
            "* Anti-Rename Verification: Inspects PE Header metadata (OriginalFilename)\r\n" +
            "  and SHA-256 cryptographic hashes to prevent evasion via renaming games.\r\n" +
            "* Path Jail (User-Writable Directory Blocking): Prevents children from\r\n" +
            "  downloading and launching unapproved executables from Downloads, Desktop,\r\n" +
            "  and Temp directories when enabled.\r\n\r\n" +
            "3. SYSTEM MODIFICATIONS MADE DURING INSTALLATION\r\n" +
            "------------------------------------------------------------------\r\n" +
            "* Windows Service: Installs 'AppShieldService' under NT AUTHORITY\\SYSTEM\r\n" +
            "  with automatic 1-second restart recovery to prevent unauthorized termination.\r\n" +
            "* Access Control Lists (ACLs): Configures C:\\ProgramData\\AppShield with\r\n" +
            "  exclusive SYSTEM and Administrator permissions so standard accounts cannot\r\n" +
            "  tamper with or delete rules and databases.\r\n" +
            "* Windows Defender Firewall: Opens an inbound TCP rule for HTTPS port 54120\r\n" +
            "  exclusively for local network fleet management.\r\n" +
            "* Windows Settings Registration: Registers into 'Installed Apps' with an\r\n" +
            "  uninstaller that requires your Master Password for clean removal.\r\n\r\n" +
            "4. ADMINISTRATOR EXCLUSIVE ACCESS\r\n" +
            "------------------------------------------------------------------\r\n" +
            "* The AppShield Control Center interface and shortcuts are created solely\r\n" +
            "  for the Administrator account. Standard user (kid) accounts cannot access\r\n" +
            "  or open the management interface.\r\n" +
            "==================================================================";

        _txtPrivacyPolicy = new TextBox
        {
            Multiline = true,
            ReadOnly = true,
            ScrollBars = ScrollBars.Vertical,
            Font = new Font("Consolas", 9f),
            BackColor = Color.White,
            ForeColor = Color.FromArgb(40, 40, 40),
            Location = new Point(25, 70),
            Size = new Size(610, 360),
            Text = policyText
        };
        _pnlStep1Privacy.Controls.Add(_txtPrivacyPolicy);

        _chkAgreePrivacy = new CheckBox
        {
            Text = "I have read and agree to the Privacy Policy and system modifications above",
            Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
            ForeColor = Color.FromArgb(30, 30, 30),
            Location = new Point(25, 442),
            Size = new Size(610, 28),
            Cursor = Cursors.Hand
        };
        _chkAgreePrivacy.CheckedChanged += (s, e) =>
        {
            _btnStep1Next.Enabled = _chkAgreePrivacy.Checked;
        };
        _pnlStep1Privacy.Controls.Add(_chkAgreePrivacy);

        _btnStep1Next = new Button
        {
            Text = "Next >",
            Font = new Font("Segoe UI", 10.5f, FontStyle.Bold),
            BackColor = Color.FromArgb(37, 99, 235),
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat,
            Cursor = Cursors.Hand,
            Enabled = false,
            Location = new Point(485, 480),
            Size = new Size(150, 40)
        };
        _btnStep1Next.FlatAppearance.BorderSize = 0;
        _btnStep1Next.Click += (s, e) => ShowStep(2);
        _pnlStep1Privacy.Controls.Add(_btnStep1Next);

        Controls.Add(_pnlStep1Privacy);
    }

    private void BuildStep2Options()
    {
        _pnlStep2Options = new Panel
        {
            Dock = DockStyle.Fill,
            Padding = new Padding(25, 15, 25, 20),
            Visible = false
        };

        int top = 15;

        // 1. Install Location
        var lblDir = new Label
        {
            Text = "1. Installation Folder:",
            Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
            Location = new Point(25, top),
            Size = new Size(500, 22)
        };
        _pnlStep2Options.Controls.Add(lblDir);
        top += 24;

        _txtInstallDir = new TextBox
        {
            Text = InstallEngine.GetDefaultInstallDirectory(),
            Font = new Font("Segoe UI", 9.5f),
            Location = new Point(25, top),
            Size = new Size(475, 28)
        };
        _pnlStep2Options.Controls.Add(_txtInstallDir);

        _btnBrowseDir = new Button
        {
            Text = "📁 Browse...",
            Font = new Font("Segoe UI", 9f),
            Location = new Point(510, top - 2),
            Size = new Size(125, 30),
            Cursor = Cursors.Hand
        };
        _btnBrowseDir.Click += (s, e) =>
        {
            using var fbd = new FolderBrowserDialog
            {
                Description = "Select Destination Folder for AppShield",
                SelectedPath = _txtInstallDir.Text
            };
            if (fbd.ShowDialog() == DialogResult.OK)
            {
                _txtInstallDir.Text = fbd.SelectedPath;
            }
        };
        _pnlStep2Options.Controls.Add(_btnBrowseDir);
        top += 42;

        // 2. Master Password
        var lblPass = new Label
        {
            Text = "2. Master Password (for emergency offline unlock and uninstallation):",
            Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
            Location = new Point(25, top),
            Size = new Size(550, 22)
        };
        _pnlStep2Options.Controls.Add(lblPass);
        top += 24;

        _txtPassword = new TextBox
        {
            Text = "AdminPassword123!",
            UseSystemPasswordChar = true,
            Font = new Font("Segoe UI", 10f),
            Location = new Point(25, top),
            Size = new Size(475, 28)
        };
        _pnlStep2Options.Controls.Add(_txtPassword);

        _chkShowPassword = new CheckBox
        {
            Text = "Show",
            Location = new Point(515, top + 2),
            Size = new Size(80, 24),
            ForeColor = Color.FromArgb(70, 70, 70),
            Cursor = Cursors.Hand
        };
        _chkShowPassword.CheckedChanged += (s, e) =>
        {
            _txtPassword.UseSystemPasswordChar = !_chkShowPassword.Checked;
        };
        _pnlStep2Options.Controls.Add(_chkShowPassword);
        top += 42;

        // 3. PSK
        var lblPsk = new Label
        {
            Text = "3. Pre-Shared Key (PSK) - Authenticates with your macOS Admin Dashboard:",
            Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
            Location = new Point(25, top),
            Size = new Size(550, 22)
        };
        _pnlStep2Options.Controls.Add(lblPsk);
        top += 24;

        _txtPsk = new TextBox
        {
            Text = InstallEngine.GeneratePsk(),
            ReadOnly = true,
            Font = new Font("Consolas", 10f, FontStyle.Bold),
            BackColor = Color.White,
            Location = new Point(25, top),
            Size = new Size(475, 28)
        };
        _pnlStep2Options.Controls.Add(_txtPsk);

        _btnRegenPsk = new Button
        {
            Text = "🔄 New Key",
            Location = new Point(510, top - 2),
            Size = new Size(125, 30),
            Cursor = Cursors.Hand
        };
        _btnRegenPsk.Click += (s, e) =>
        {
            _txtPsk.Text = InstallEngine.GeneratePsk();
        };
        _pnlStep2Options.Controls.Add(_btnRegenPsk);
        top += 44;

        // 4. Desktop & Start Menu Shortcuts (Access Control)
        var grpShortcuts = new GroupBox
        {
            Text = "Shortcuts & Administrator Access Control",
            Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
            Location = new Point(25, top),
            Size = new Size(610, 95)
        };

        _chkDesktopShortcut = new CheckBox
        {
            Text = "Create a Desktop icon (Visible only in Administrator account)",
            Font = new Font("Segoe UI", 9.5f, FontStyle.Regular),
            Checked = true,
            Location = new Point(20, 26),
            Size = new Size(560, 26),
            Cursor = Cursors.Hand
        };
        grpShortcuts.Controls.Add(_chkDesktopShortcut);

        var lblShortcutNote = new Label
        {
            Text = "ℹ️ An Applications/Start Menu icon will always be installed for the Administrator. Interface will be invisible and inaccessible to standard (kid) accounts.",
            Font = new Font("Segoe UI", 8.5f, FontStyle.Italic),
            ForeColor = Color.FromArgb(100, 100, 100),
            Location = new Point(20, 56),
            Size = new Size(570, 32)
        };
        grpShortcuts.Controls.Add(lblShortcutNote);
        _pnlStep2Options.Controls.Add(grpShortcuts);
        top += 105;

        // Progress bar & Status label
        _progressBar = new ProgressBar
        {
            Location = new Point(25, top),
            Size = new Size(610, 20),
            Minimum = 0,
            Maximum = 100,
            Value = 0,
            Visible = false
        };
        _pnlStep2Options.Controls.Add(_progressBar);
        top += 24;

        _lblStatus = new Label
        {
            Text = "Ready to install. Click below to begin.",
            Location = new Point(25, top),
            Size = new Size(610, 22),
            ForeColor = Color.FromArgb(100, 100, 100),
            Font = new Font("Segoe UI", 9f, FontStyle.Italic)
        };
        _pnlStep2Options.Controls.Add(_lblStatus);
        top += 28;

        // Buttons
        _btnStep2Back = new Button
        {
            Text = "< Back",
            Font = new Font("Segoe UI", 10f),
            Location = new Point(25, top),
            Size = new Size(120, 42),
            Cursor = Cursors.Hand
        };
        _btnStep2Back.Click += (s, e) => ShowStep(1);
        _pnlStep2Options.Controls.Add(_btnStep2Back);

        _btnInstall = new Button
        {
            Text = "🛡️  Install AppShield Now",
            Font = new Font("Segoe UI", 11f, FontStyle.Bold),
            BackColor = Color.FromArgb(46, 125, 50),
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat,
            Cursor = Cursors.Hand,
            Location = new Point(160, top),
            Size = new Size(475, 42)
        };
        _btnInstall.FlatAppearance.BorderSize = 0;
        _btnInstall.Click += BtnInstall_Click;
        _pnlStep2Options.Controls.Add(_btnInstall);

        Controls.Add(_pnlStep2Options);
    }

    private void BuildStep3Success()
    {
        _pnlStep3Success = new Panel
        {
            Dock = DockStyle.Fill,
            Padding = new Padding(25, 20, 25, 20),
            Visible = false
        };

        var lblSuccessHeader = new Label
        {
            Text = "✅  AppShield Installed & Active!",
            Font = new Font("Segoe UI", 13f, FontStyle.Bold),
            ForeColor = Color.FromArgb(46, 125, 50),
            Location = new Point(25, 20),
            AutoSize = true
        };
        _pnlStep3Success.Controls.Add(lblSuccessHeader);

        var lblSuccessSub = new Label
        {
            Text = "AppShield is running as a protected Windows Service. Copy these credentials into your macOS Admin Dashboard:",
            Location = new Point(25, 52),
            Size = new Size(610, 35),
            ForeColor = Color.FromArgb(60, 60, 60)
        };
        _pnlStep3Success.Controls.Add(lblSuccessSub);

        _txtSummary = new TextBox
        {
            Multiline = true,
            ReadOnly = true,
            Location = new Point(25, 92),
            Size = new Size(610, 290),
            Font = new Font("Consolas", 10f),
            BackColor = Color.White,
            ScrollBars = ScrollBars.Vertical
        };
        _pnlStep3Success.Controls.Add(_txtSummary);

        _btnCopy = new Button
        {
            Text = "📋 Copy Setup Details",
            Location = new Point(25, 400),
            Size = new Size(405, 44),
            BackColor = Color.FromArgb(37, 99, 235),
            ForeColor = Color.White,
            Font = new Font("Segoe UI", 10f, FontStyle.Bold),
            FlatStyle = FlatStyle.Flat,
            Cursor = Cursors.Hand
        };
        _btnCopy.FlatAppearance.BorderSize = 0;
        _btnCopy.Click += (s, e) =>
        {
            Clipboard.SetText(_txtSummary.Text);
            _btnCopy.Text = "✅ Copied to Clipboard!";
        };
        _pnlStep3Success.Controls.Add(_btnCopy);

        _btnClose = new Button
        {
            Text = "🚀 Open Control Center",
            Location = new Point(445, 400),
            Size = new Size(190, 44),
            BackColor = Color.FromArgb(16, 185, 129),
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat,
            Font = new Font("Segoe UI", 10f, FontStyle.Bold),
            Cursor = Cursors.Hand
        };
        _btnClose.FlatAppearance.BorderSize = 0;
        _btnClose.Click += (s, e) =>
        {
            InstallEngine.LaunchControlCenter();
            Close();
        };
        _pnlStep3Success.Controls.Add(_btnClose);

        Controls.Add(_pnlStep3Success);
    }

    private void BtnInstall_Click(object? sender, EventArgs e)
    {
        string installDir = _txtInstallDir.Text.Trim();
        if (string.IsNullOrEmpty(installDir))
        {
            installDir = InstallEngine.GetDefaultInstallDirectory();
        }

        string password = _txtPassword.Text.Trim();
        if (password.Length < 6)
        {
            MessageBox.Show("Please enter a Master Password of at least 6 characters.", "AppShield Setup", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        string psk = _txtPsk.Text.Trim();
        if (string.IsNullOrEmpty(psk))
        {
            psk = InstallEngine.GeneratePsk();
        }

        bool createDesktopIcon = _chkDesktopShortcut.Checked;

        _btnInstall.Enabled = false;
        _btnStep2Back.Enabled = false;
        _txtInstallDir.Enabled = false;
        _btnBrowseDir.Enabled = false;
        _txtPassword.Enabled = false;
        _btnRegenPsk.Enabled = false;
        _chkDesktopShortcut.Enabled = false;
        _progressBar.Visible = true;

        Task.Run(() =>
        {
            try
            {
                var summary = InstallEngine.RunInstall(installDir, password, psk, createDesktopIcon, (pct, msg) =>
                {
                    Invoke(() =>
                    {
                        _progressBar.Value = pct;
                        _lblStatus.Text = msg;
                    });
                });

                Invoke(() =>
                {
                    ShowSuccessScreen(summary);
                });
            }
            catch (Exception ex)
            {
                Invoke(() =>
                {
                    _progressBar.Visible = false;
                    _btnInstall.Enabled = true;
                    _btnStep2Back.Enabled = true;
                    _txtInstallDir.Enabled = true;
                    _btnBrowseDir.Enabled = true;
                    _txtPassword.Enabled = true;
                    _btnRegenPsk.Enabled = true;
                    _chkDesktopShortcut.Enabled = true;
                    _lblStatus.Text = "Installation failed: " + ex.Message;
                    MessageBox.Show($"Installation failed:\n\n{ex.Message}\n\nPlease ensure you run as Administrator.", "AppShield Setup Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                });
            }
        });
    }

    private void ShowSuccessScreen(MachineSetupSummary summary)
    {
        string ipList = string.Join(", ", summary.IpAddresses);
        string text = $"AppShield Client Setup Summary\r\n" +
                      $"========================================\r\n" +
                      $"Installed To:      {summary.InstallDirectory}\r\n" +
                      $"Computer Name:     {summary.MachineName}\r\n" +
                      $"Local IP(s):       {ipList}\r\n" +
                      $"API Port:          {summary.Port} (HTTPS)\r\n" +
                      $"Pre-Shared Key:    {summary.PreSharedKey}\r\n" +
                      $"Master Password:   {summary.MasterPassword}\r\n" +
                      $"========================================\r\n" +
                      $"Desktop & Applications Icons:\r\n" +
                      $"* Installed in your Administrator account.\r\n" +
                      $"* Standard user (kid) accounts cannot view or open the interface.\r\n" +
                      $"* To configure locally: Double-click 'AppShield' on your Desktop or Start Menu.\r\n" +
                      $"========================================\r\n" +
                      $"Steps to connect from macOS Admin App:\r\n" +
                      $"1. Open 'AppShield Admin' on your Mac.\r\n" +
                      $"2. Click '+ Add PC'.\r\n" +
                      $"3. Enter Host/IP ({summary.IpAddresses.FirstOrDefault() ?? summary.MachineName}) and the PSK.\r\n" +
                      $"4. Click 'Save Machine'.";

        _txtSummary.Text = text;
        ShowStep(3);
    }
}
