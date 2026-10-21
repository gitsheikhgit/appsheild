using System.Diagnostics;
using System.Drawing;
using System.Windows.Forms;
using AppShield.Shared.Models;
using AppShield.Shared.Security;

namespace AppShield.Installer;

public class ControlCenterForm : Form
{
    private readonly string _dataDir;
    private bool _isUnlocked = false;

    // Controls
    private Panel _pnlLock = null!;
    private TextBox _txtMasterPassword = null!;
    private Button _btnUnlock = null!;
    private Label _lblLockError = null!;

    private TabControl _tabControl = null!;

    // Tab 1: Overview
    private Label _lblStatusBadge = null!;
    private TextBox _txtHostInfo = null!;
    private TextBox _txtPsk = null!;
    private Button _btnCopyPsk = null!;

    // Tab 2: Users
    private ListView _lvUsers = null!;
    private CheckBox _chkIsManaged = null!;
    private CheckBox _chkBlockUserWritable = null!;
    private Button _btnSaveUser = null!;
    private UserAccount? _selectedUser;

    // Tab 3: Rules
    private ListView _lvRules = null!;
    private TextBox _txtNewRuleExe = null!;
    private Button _btnBrowseExe = null!;
    private Button _btnAddRule = null!;
    private Button _btnDeleteRule = null!;

    // Tab 4: Logs
    private ListView _lvLogs = null!;
    private Button _btnRefreshLogs = null!;

    // Tab 5: Uninstall
    private Button _btnUninstallApp = null!;

    public ControlCenterForm()
    {
        _dataDir = InstallEngine.GetDataDirectory();
        InitializeComponent();
        LoadInitialData();
    }

    protected override void OnLoad(EventArgs e)
    {
        base.OnLoad(e);
        if (!InstallEngine.IsCurrentProcessElevatedAdmin())
        {
            MessageBox.Show(
                "Access Denied: The AppShield Control Center is restricted to Administrator accounts.\n\nStandard users cannot open or configure AppShield.",
                "AppShield Security",
                MessageBoxButtons.OK,
                MessageBoxIcon.Stop);
            Close();
        }
    }

    private void InitializeComponent()
    {
        Text = "AppShield Control Center";
        Size = new Size(840, 620);
        StartPosition = FormStartPosition.CenterScreen;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        BackColor = Color.FromArgb(248, 249, 250);
        Font = new Font("Segoe UI", 9.5f, FontStyle.Regular);

        try
        {
            var icoStream = typeof(ControlCenterForm).Assembly.GetManifestResourceStream("AppShield.Installer.appshield.ico");
            if (icoStream != null) Icon = new Icon(icoStream);
        }
        catch { }

        // Top Banner Panel
        var pnlHeader = new Panel
        {
            Dock = DockStyle.Top,
            Height = 80,
            BackColor = Color.FromArgb(24, 24, 37)
        };

        var lblTitle = new Label
        {
            Text = "AppShield Security Control Center",
            Font = new Font("Segoe UI", 14f, FontStyle.Bold),
            ForeColor = Color.White,
            Location = new Point(24, 16),
            AutoSize = true
        };

        var lblSubtitle = new Label
        {
            Text = "Tamper-Resistant Windows Endpoint Protection & Local Management",
            Font = new Font("Segoe UI", 9.5f, FontStyle.Regular),
            ForeColor = Color.FromArgb(166, 173, 200),
            Location = new Point(24, 44),
            AutoSize = true
        };

        _lblStatusBadge = new Label
        {
            Text = "🟢 Protection Active",
            Font = new Font("Segoe UI", 10f, FontStyle.Bold),
            ForeColor = Color.FromArgb(76, 175, 80),
            BackColor = Color.FromArgb(35, 45, 40),
            Location = new Point(620, 24),
            Size = new Size(180, 32),
            TextAlign = ContentAlignment.MiddleCenter
        };

        pnlHeader.Controls.Add(lblTitle);
        pnlHeader.Controls.Add(lblSubtitle);
        pnlHeader.Controls.Add(_lblStatusBadge);
        Controls.Add(pnlHeader);

        // Lock Overlay Panel (Requires Master Password)
        _pnlLock = new Panel
        {
            Dock = DockStyle.Fill,
            BackColor = Color.FromArgb(248, 249, 250),
            Padding = new Padding(40)
        };

        var pnlLockBox = new Panel
        {
            Size = new Size(460, 260),
            Location = new Point((840 - 460) / 2, 80),
            BackColor = Color.White,
            BorderStyle = BorderStyle.FixedSingle
        };

        var lblLockIcon = new Label
        {
            Text = "🔒",
            Font = new Font("Segoe UI", 26f),
            Location = new Point(20, 15),
            Size = new Size(50, 50)
        };
        pnlLockBox.Controls.Add(lblLockIcon);

        var lblLockTitle = new Label
        {
            Text = "Master Password Required",
            Font = new Font("Segoe UI", 13f, FontStyle.Bold),
            ForeColor = Color.FromArgb(30, 30, 30),
            Location = new Point(80, 18),
            AutoSize = true
        };
        pnlLockBox.Controls.Add(lblLockTitle);

        var lblLockSub = new Label
        {
            Text = "To prevent unauthorized changes by kids, please enter your Master Password to open the Control Center:",
            Font = new Font("Segoe UI", 9.5f),
            ForeColor = Color.FromArgb(80, 80, 80),
            Location = new Point(25, 75),
            Size = new Size(410, 40)
        };
        pnlLockBox.Controls.Add(lblLockSub);

        _txtMasterPassword = new TextBox
        {
            UseSystemPasswordChar = true,
            Font = new Font("Segoe UI", 11f),
            Location = new Point(25, 125),
            Size = new Size(410, 32)
        };
        _txtMasterPassword.KeyDown += (s, e) => { if (e.KeyCode == Keys.Enter) BtnUnlock_Click(s, e); };
        pnlLockBox.Controls.Add(_txtMasterPassword);

        _lblLockError = new Label
        {
            Text = "",
            Font = new Font("Segoe UI", 9f),
            ForeColor = Color.Red,
            Location = new Point(25, 162),
            Size = new Size(410, 20)
        };
        pnlLockBox.Controls.Add(_lblLockError);

        _btnUnlock = new Button
        {
            Text = "Unlock Control Center",
            Font = new Font("Segoe UI", 10.5f, FontStyle.Bold),
            BackColor = Color.FromArgb(37, 99, 235),
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat,
            Cursor = Cursors.Hand,
            Location = new Point(25, 190),
            Size = new Size(410, 42)
        };
        _btnUnlock.FlatAppearance.BorderSize = 0;
        _btnUnlock.Click += BtnUnlock_Click;
        pnlLockBox.Controls.Add(_btnUnlock);

        _pnlLock.Controls.Add(pnlLockBox);
        Controls.Add(_pnlLock);

        // Tab Control (Visible after Unlock)
        _tabControl = new TabControl
        {
            Dock = DockStyle.Fill,
            Font = new Font("Segoe UI", 10f),
            Visible = false
        };

        BuildTabOverview();
        BuildTabUsers();
        BuildTabRules();
        BuildTabLogs();
        BuildTabUninstall();

        Controls.Add(_tabControl);
    }

    private void BtnUnlock_Click(object? sender, EventArgs e)
    {
        string pass = _txtMasterPassword.Text.Trim();
        string storedHash = InstallEngine.GetStoredMasterPasswordHash(_dataDir);

        if (string.IsNullOrEmpty(storedHash) || CryptoHelper.VerifyPassword(pass, storedHash))
        {
            _isUnlocked = true;
            _pnlLock.Visible = false;
            _tabControl.Visible = true;
            RefreshAllTabs();
        }
        else
        {
            _lblLockError.Text = "Incorrect Master Password. Access denied.";
            _txtMasterPassword.SelectAll();
            _txtMasterPassword.Focus();
        }
    }

    private void BuildTabOverview()
    {
        var tab = new TabPage("🖥️  Overview & Connection");
        tab.BackColor = Color.FromArgb(248, 249, 250);
        tab.Padding = new Padding(25);

        int top = 20;

        var grpLocal = new GroupBox
        {
            Text = "Local Machine & Protection Engine",
            Location = new Point(25, top),
            Size = new Size(765, 175),
            Font = new Font("Segoe UI", 10f, FontStyle.Bold)
        };

        _txtHostInfo = new TextBox
        {
            Multiline = true,
            ReadOnly = true,
            BackColor = Color.White,
            Font = new Font("Consolas", 10f, FontStyle.Regular),
            Location = new Point(20, 30),
            Size = new Size(725, 125)
        };
        grpLocal.Controls.Add(_txtHostInfo);
        tab.Controls.Add(grpLocal);
        top += 195;

        var grpMac = new GroupBox
        {
            Text = "Remote Mac Connection (AppShield Admin.app)",
            Location = new Point(25, top),
            Size = new Size(765, 200),
            Font = new Font("Segoe UI", 10f, FontStyle.Bold)
        };

        var lblMacInfo = new Label
        {
            Text = "To manage this PC remotely from your Mac while your kid plays, open 'AppShield Admin.app' on your Mac, click '+ Add PC', and enter this PC's IP and Pre-Shared Key (PSK):",
            Font = new Font("Segoe UI", 9.5f, FontStyle.Regular),
            ForeColor = Color.FromArgb(60, 60, 60),
            Location = new Point(20, 30),
            Size = new Size(725, 40)
        };
        grpMac.Controls.Add(lblMacInfo);

        var lblPskTitle = new Label
        {
            Text = "Pre-Shared Key (PSK):",
            Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
            Location = new Point(20, 80),
            Size = new Size(200, 22)
        };
        grpMac.Controls.Add(lblPskTitle);

        _txtPsk = new TextBox
        {
            ReadOnly = true,
            Font = new Font("Consolas", 11f, FontStyle.Bold),
            BackColor = Color.White,
            Location = new Point(20, 105),
            Size = new Size(540, 30)
        };
        grpMac.Controls.Add(_txtPsk);

        _btnCopyPsk = new Button
        {
            Text = "📋 Copy Key",
            Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
            BackColor = Color.FromArgb(37, 99, 235),
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat,
            Cursor = Cursors.Hand,
            Location = new Point(575, 103),
            Size = new Size(170, 34)
        };
        _btnCopyPsk.FlatAppearance.BorderSize = 0;
        _btnCopyPsk.Click += (s, e) =>
        {
            if (!string.IsNullOrEmpty(_txtPsk.Text))
            {
                Clipboard.SetText(_txtPsk.Text);
                _btnCopyPsk.Text = "✅ Copied!";
            }
        };
        grpMac.Controls.Add(_btnCopyPsk);

        tab.Controls.Add(grpMac);
        _tabControl.TabPages.Add(tab);
    }

    private void BuildTabUsers()
    {
        var tab = new TabPage("👥  User Accounts & Path Jail");
        tab.BackColor = Color.FromArgb(248, 249, 250);
        tab.Padding = new Padding(20);

        var lblIntro = new Label
        {
            Text = "Select an account to configure protection. Managed accounts will have application restrictions and quotas enforced.",
            Location = new Point(20, 15),
            Size = new Size(770, 30),
            ForeColor = Color.FromArgb(60, 60, 60)
        };
        tab.Controls.Add(lblIntro);

        _lvUsers = new ListView
        {
            View = View.Details,
            FullRowSelect = true,
            GridLines = true,
            MultiSelect = false,
            Location = new Point(20, 50),
            Size = new Size(775, 260),
            Font = new Font("Segoe UI", 9.5f)
        };
        _lvUsers.Columns.Add("Username", 180);
        _lvUsers.Columns.Add("Administrator", 120);
        _lvUsers.Columns.Add("Protected (Managed)", 170);
        _lvUsers.Columns.Add("Path Jail Enabled", 160);
        _lvUsers.Columns.Add("SID", 120);

        _lvUsers.SelectedIndexChanged += LvUsers_SelectedIndexChanged;
        tab.Controls.Add(_lvUsers);

        // Edit Box
        var grpEdit = new GroupBox
        {
            Text = "Account Protection Settings",
            Location = new Point(20, 325),
            Size = new Size(775, 140),
            Font = new Font("Segoe UI", 9.5f, FontStyle.Bold)
        };

        _chkIsManaged = new CheckBox
        {
            Text = "Protect this user (Enforce application blocks & daily time quotas)",
            Font = new Font("Segoe UI", 9.5f, FontStyle.Regular),
            Location = new Point(20, 30),
            Size = new Size(600, 28)
        };
        grpEdit.Controls.Add(_chkIsManaged);

        _chkBlockUserWritable = new CheckBox
        {
            Text = "Path Jail: Block running unapproved .exe files from Downloads, Desktop, and Temp folders",
            Font = new Font("Segoe UI", 9.5f, FontStyle.Regular),
            Location = new Point(20, 65),
            Size = new Size(650, 28)
        };
        grpEdit.Controls.Add(_chkBlockUserWritable);

        _btnSaveUser = new Button
        {
            Text = "💾  Save Account Settings",
            Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
            BackColor = Color.FromArgb(46, 125, 50),
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat,
            Cursor = Cursors.Hand,
            Location = new Point(20, 100),
            Size = new Size(240, 34)
        };
        _btnSaveUser.FlatAppearance.BorderSize = 0;
        _btnSaveUser.Click += BtnSaveUser_Click;
        grpEdit.Controls.Add(_btnSaveUser);

        tab.Controls.Add(grpEdit);
        _tabControl.TabPages.Add(tab);
    }

    private void BuildTabRules()
    {
        var tab = new TabPage("🚫  Blocked Applications & Rules");
        tab.BackColor = Color.FromArgb(248, 249, 250);
        tab.Padding = new Padding(20);

        var lblIntro = new Label
        {
            Text = "Active block rules. Any restricted executable launched by a protected account is immediately terminated.",
            Location = new Point(20, 15),
            Size = new Size(770, 25),
            ForeColor = Color.FromArgb(60, 60, 60)
        };
        tab.Controls.Add(lblIntro);

        _lvRules = new ListView
        {
            View = View.Details,
            FullRowSelect = true,
            GridLines = true,
            Location = new Point(20, 45),
            Size = new Size(775, 270),
            Font = new Font("Segoe UI", 9.5f)
        };
        _lvRules.Columns.Add("Process Name", 220);
        _lvRules.Columns.Add("Rule Type", 140);
        _lvRules.Columns.Add("Description", 260);
        _lvRules.Columns.Add("Target User", 130);
        tab.Controls.Add(_lvRules);

        // Add Rule Group
        var grpAdd = new GroupBox
        {
            Text = "Block a New Application",
            Location = new Point(20, 325),
            Size = new Size(775, 140),
            Font = new Font("Segoe UI", 9.5f, FontStyle.Bold)
        };

        var lblExe = new Label
        {
            Text = "Executable Name (e.g. RobloxPlayerBeta.exe, Discord.exe, Steam.exe):",
            Font = new Font("Segoe UI", 9f, FontStyle.Regular),
            Location = new Point(20, 25),
            Size = new Size(500, 20)
        };
        grpAdd.Controls.Add(lblExe);

        _txtNewRuleExe = new TextBox
        {
            Font = new Font("Segoe UI", 10f),
            Location = new Point(20, 48),
            Size = new Size(420, 28)
        };
        grpAdd.Controls.Add(_txtNewRuleExe);

        _btnBrowseExe = new Button
        {
            Text = "📁 Browse .exe...",
            Font = new Font("Segoe UI", 9f),
            Location = new Point(450, 47),
            Size = new Size(130, 30),
            Cursor = Cursors.Hand
        };
        _btnBrowseExe.Click += (s, e) =>
        {
            using var ofd = new OpenFileDialog
            {
                Filter = "Executable Files (*.exe)|*.exe|All Files (*.*)|*.*",
                Title = "Select Application to Block"
            };
            if (ofd.ShowDialog() == DialogResult.OK)
            {
                _txtNewRuleExe.Text = Path.GetFileName(ofd.FileName);
            }
        };
        grpAdd.Controls.Add(_btnBrowseExe);

        _btnAddRule = new Button
        {
            Text = "🚫  Block This App",
            Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
            BackColor = Color.FromArgb(198, 40, 40),
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat,
            Cursor = Cursors.Hand,
            Location = new Point(20, 88),
            Size = new Size(180, 36)
        };
        _btnAddRule.FlatAppearance.BorderSize = 0;
        _btnAddRule.Click += BtnAddRule_Click;
        grpAdd.Controls.Add(_btnAddRule);

        _btnDeleteRule = new Button
        {
            Text = "❌  Remove Selected Block",
            Font = new Font("Segoe UI", 9.5f),
            Location = new Point(215, 88),
            Size = new Size(210, 36),
            Cursor = Cursors.Hand
        };
        _btnDeleteRule.Click += BtnDeleteRule_Click;
        grpAdd.Controls.Add(_btnDeleteRule);

        tab.Controls.Add(grpAdd);
        _tabControl.TabPages.Add(tab);
    }

    private void BuildTabLogs()
    {
        var tab = new TabPage("📜  Live Block Logs");
        tab.BackColor = Color.FromArgb(248, 249, 250);
        tab.Padding = new Padding(20);

        _lvLogs = new ListView
        {
            View = View.Details,
            FullRowSelect = true,
            GridLines = true,
            Location = new Point(20, 20),
            Size = new Size(775, 400),
            Font = new Font("Segoe UI", 9f)
        };
        _lvLogs.Columns.Add("Time (UTC)", 150);
        _lvLogs.Columns.Add("User", 120);
        _lvLogs.Columns.Add("Process Name", 180);
        _lvLogs.Columns.Add("Action", 100);
        _lvLogs.Columns.Add("Reason", 200);
        tab.Controls.Add(_lvLogs);

        _btnRefreshLogs = new Button
        {
            Text = "🔄  Refresh Logs",
            Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
            Location = new Point(20, 430),
            Size = new Size(160, 36),
            Cursor = Cursors.Hand
        };
        _btnRefreshLogs.Click += (s, e) => RefreshLogsTab();
        tab.Controls.Add(_btnRefreshLogs);

        _tabControl.TabPages.Add(tab);
    }

    private void BuildTabUninstall()
    {
        var tab = new TabPage("⚙️  Uninstaller");
        tab.BackColor = Color.FromArgb(248, 249, 250);
        tab.Padding = new Padding(30);

        var lblHeader = new Label
        {
            Text = "Uninstall AppShield Protection",
            Font = new Font("Segoe UI", 13f, FontStyle.Bold),
            ForeColor = Color.FromArgb(198, 40, 40),
            Location = new Point(30, 25),
            AutoSize = true
        };
        tab.Controls.Add(lblHeader);

        var lblDesc = new Label
        {
            Text = "Safely removes the background Windows Service, deletes firewall rules, removes the desktop icon, and restores all Windows settings to 100% normal behavior.\n\nYour Master Password will be verified before proceeding.",
            Font = new Font("Segoe UI", 10f),
            ForeColor = Color.FromArgb(60, 60, 60),
            Location = new Point(30, 65),
            Size = new Size(700, 60)
        };
        tab.Controls.Add(lblDesc);

        _btnUninstallApp = new Button
        {
            Text = "⚠️  Launch AppShield Uninstaller",
            Font = new Font("Segoe UI", 10.5f, FontStyle.Bold),
            BackColor = Color.FromArgb(198, 40, 40),
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat,
            Cursor = Cursors.Hand,
            Location = new Point(30, 140),
            Size = new Size(300, 44)
        };
        _btnUninstallApp.FlatAppearance.BorderSize = 0;
        _btnUninstallApp.Click += (s, e) =>
        {
            var uForm = new UninstallForm();
            uForm.ShowDialog(this);
            if (!InstallEngine.IsInstalled())
            {
                Close();
            }
        };
        tab.Controls.Add(_btnUninstallApp);

        _tabControl.TabPages.Add(tab);
    }

    private void LoadInitialData()
    {
        _txtMasterPassword.Focus();
    }

    private void RefreshAllTabs()
    {
        RefreshOverviewTab();
        RefreshUsersTab();
        RefreshRulesTab();
        RefreshLogsTab();
    }

    private void RefreshOverviewTab()
    {
        var ips = InstallEngine.GetLocalIpAddresses();
        string ipStr = string.Join(", ", ips);
        string host = Environment.MachineName;

        string summary = $"AppShield Service:   RUNNING (NT AUTHORITY\\SYSTEM)\r\n" +
                         $"Computer Name:       {host}\r\n" +
                         $"Local IP(s):         {ipStr}\r\n" +
                         $"Management Port:     {InstallEngine.DefaultPort} (HTTPS)\r\n" +
                         $"Status:              Protected & Monitoring active processes every 1.5 seconds";
        _txtHostInfo.Text = summary;

        string psk = InstallEngine.GetStoredPsk(_dataDir);
        _txtPsk.Text = psk;
    }

    private void RefreshUsersTab()
    {
        _lvUsers.Items.Clear();
        var users = InstallEngine.GetUsersFromDb(_dataDir);
        foreach (var u in users)
        {
            var lvi = new ListViewItem(u.Username);
            lvi.SubItems.Add(u.IsAdmin ? "Yes (Admin)" : "No (Standard)");
            lvi.SubItems.Add(u.IsManaged ? "✅ PROTECTED" : "No (Bypassed)");
            lvi.SubItems.Add(u.BlockUserWritableDirectories ? "✅ Enforced" : "Disabled");
            lvi.SubItems.Add(u.Sid);
            lvi.Tag = u;

            if (u.IsManaged)
            {
                lvi.BackColor = Color.FromArgb(235, 248, 235);
            }
            _lvUsers.Items.Add(lvi);
        }
    }

    private void LvUsers_SelectedIndexChanged(object? sender, EventArgs e)
    {
        if (_lvUsers.SelectedItems.Count > 0)
        {
            _selectedUser = _lvUsers.SelectedItems[0].Tag as UserAccount;
            if (_selectedUser != null)
            {
                _chkIsManaged.Checked = _selectedUser.IsManaged;
                _chkBlockUserWritable.Checked = _selectedUser.BlockUserWritableDirectories;
            }
        }
    }

    private void BtnSaveUser_Click(object? sender, EventArgs e)
    {
        if (_selectedUser == null)
        {
            MessageBox.Show("Please select a user account from the list above.", "AppShield", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        InstallEngine.UpdateUserInDb(_dataDir, _selectedUser.Sid, _chkIsManaged.Checked, _chkBlockUserWritable.Checked);
        MessageBox.Show($"Updated settings for '{_selectedUser.Username}'. Changes take effect immediately.", "Settings Saved", MessageBoxButtons.OK, MessageBoxIcon.Information);
        RefreshUsersTab();
    }

    private void RefreshRulesTab()
    {
        _lvRules.Items.Clear();
        var rules = InstallEngine.GetRulesFromDb(_dataDir);
        foreach (var r in rules)
        {
            var lvi = new ListViewItem(r.ProcessName ?? r.OriginalFilename ?? "App");
            lvi.SubItems.Add(r.RuleType.ToString());
            lvi.SubItems.Add(r.Description);
            lvi.SubItems.Add(r.TargetUserSid == "*" ? "All Protected Users" : r.TargetUserSid);
            lvi.Tag = r;
            _lvRules.Items.Add(lvi);
        }
    }

    private void BtnAddRule_Click(object? sender, EventArgs e)
    {
        string exe = _txtNewRuleExe.Text.Trim();
        if (string.IsNullOrEmpty(exe))
        {
            MessageBox.Show("Please enter an executable name to block (e.g. RobloxPlayerBeta.exe).", "AppShield", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        if (!exe.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
        {
            exe += ".exe";
        }

        InstallEngine.AddRuleToDb(_dataDir, exe, $"Blocked via Control Center: {exe}");
        _txtNewRuleExe.Clear();
        RefreshRulesTab();
        MessageBox.Show($"Rule added for '{exe}'. It is now blocked on all protected accounts.", "Rule Added", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    private void BtnDeleteRule_Click(object? sender, EventArgs e)
    {
        if (_lvRules.SelectedItems.Count == 0)
        {
            MessageBox.Show("Please select a rule to remove.", "AppShield", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        var rule = _lvRules.SelectedItems[0].Tag as Rule;
        if (rule != null)
        {
            InstallEngine.DeleteRuleFromDb(_dataDir, rule.Id);
            RefreshRulesTab();
            MessageBox.Show($"Rule for '{rule.ProcessName}' removed.", "Rule Removed", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
    }

    private void RefreshLogsTab()
    {
        _lvLogs.Items.Clear();
        var logs = InstallEngine.GetAuditLogsFromDb(_dataDir, 100);
        foreach (var log in logs)
        {
            var lvi = new ListViewItem(log.TimestampUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss"));
            lvi.SubItems.Add(log.Username);
            lvi.SubItems.Add(log.ProcessName);
            lvi.SubItems.Add(log.Action.ToString());
            lvi.SubItems.Add(log.Reason);
            _lvLogs.Items.Add(lvi);
        }
    }
}
