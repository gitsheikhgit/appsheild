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

    // Header & Lock controls
    private Panel _pnlHeader = null!;
    private Label _lblStatusBadge = null!;
    private Panel _pnlLock = null!;
    private TextBox _txtMasterPassword = null!;
    private Button _btnUnlock = null!;
    private Label _lblLockError = null!;

    // Modern Sidebar & Main Content
    private Panel _pnlMainContainer = null!;
    private Panel _pnlSidebar = null!;
    private Panel _pnlContent = null!;
    private Button[] _navButtons = Array.Empty<Button>();
    private Panel[] _tabPanels = Array.Empty<Panel>();
    private int _activeTabIndex = 0;

    // Tab 0: Overview
    private TextBox _txtHostInfo = null!;
    private TextBox _txtPsk = null!;
    private Button _btnCopyPsk = null!;
    private Button _btnRevealPsk = null!;
    private bool _pskRevealed = false;

    // Tab 1: Users
    private Panel _pnlNoStandardWarning = null!;
    private ListView _lvUsers = null!;
    private CheckBox _chkIsManaged = null!;
    private CheckBox _chkBlockUserWritable = null!;
    private Button _btnSaveUser = null!;
    private UserAccount? _selectedUser;

    // Tab 2: Rules & Schedules
    private ListView _lvRules = null!;
    private TextBox _txtNewRuleExe = null!;
    private ComboBox _cmbRuleType = null!;
    private TextBox _txtScheduleStart = null!;
    private TextBox _txtScheduleEnd = null!;
    private TextBox _txtQuotaMinutes = null!;
    private TextBox _txtRuleDescription = null!;
    private Button _btnAddRule = null!;
    private Button _btnDeleteRule = null!;

    // Tab 3: Installed Apps
    private ListView _lvInstalledApps = null!;
    private TextBox _txtAppFilter = null!;
    private Button _btnScanApps = null!;
    private List<(string Name, string Version, string ExeName, string Publisher)> _allInstalledApps = new();

    // Tab 4: Live Processes
    private ListView _lvProcesses = null!;
    private TextBox _txtProcFilter = null!;
    private Button _btnRefreshProcs = null!;

    // Tab 5: Logs
    private ListView _lvLogs = null!;
    private Button _btnRefreshLogs = null!;

    // Tab 6: Uninstall & Settings
    private TextBox _txtUninstallPassword = null!;
    private Button _btnUninstallApp = null!;

    // Colors matching modern dark palette
    private readonly Color _colBg = Color.FromArgb(17, 17, 27);
    private readonly Color _colSurface = Color.FromArgb(24, 24, 37);
    private readonly Color _colCard = Color.FromArgb(30, 30, 46);
    private readonly Color _colBorder = Color.FromArgb(69, 71, 90);
    private readonly Color _colAccent = Color.FromArgb(99, 102, 241);
    private readonly Color _colText = Color.FromArgb(205, 214, 244);
    private readonly Color _colSubtext = Color.FromArgb(166, 173, 200);

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
        Text = "AppShield Security Control Center v1.2.0";
        Size = new Size(1120, 750);
        MinimumSize = new Size(1000, 680);
        StartPosition = FormStartPosition.CenterScreen;
        FormBorderStyle = FormBorderStyle.Sizable;
        BackColor = _colBg;
        Font = new Font("Segoe UI", 9.5f, FontStyle.Regular);

        try
        {
            var icoStream = typeof(ControlCenterForm).Assembly.GetManifestResourceStream("AppShield.Installer.appshield.ico");
            if (icoStream != null) Icon = new Icon(icoStream);
        }
        catch { }

        // Top Header
        _pnlHeader = new Panel
        {
            Dock = DockStyle.Top,
            Height = 74,
            BackColor = _colSurface,
            Padding = new Padding(20, 0, 20, 0)
        };

        var lblTitle = new Label
        {
            Text = "AppShield Security Control Center",
            Font = new Font("Segoe UI", 13.5f, FontStyle.Bold),
            ForeColor = Color.White,
            Location = new Point(22, 12),
            AutoSize = true
        };

        var lblVersionBadge = new Label
        {
            Text = "v1.2.0",
            Font = new Font("Consolas", 8.5f, FontStyle.Bold),
            ForeColor = Color.FromArgb(165, 180, 252),
            BackColor = Color.FromArgb(49, 46, 129),
            Location = new Point(370, 15),
            Size = new Size(60, 22),
            TextAlign = ContentAlignment.MiddleCenter
        };

        var lblSubtitle = new Label
        {
            Text = "Tamper-Resistant Windows Endpoint Protection & Parental Shield",
            Font = new Font("Segoe UI", 9f),
            ForeColor = _colSubtext,
            Location = new Point(22, 42),
            AutoSize = true
        };

        _lblStatusBadge = new Label
        {
            Text = "🟢 Protection Active",
            Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
            ForeColor = Color.FromArgb(74, 222, 128),
            BackColor = Color.FromArgb(20, 45, 30),
            Location = new Point(740, 20),
            Size = new Size(160, 34),
            TextAlign = ContentAlignment.MiddleCenter
        };

        var btnOpenBrowser = new Button
        {
            Text = "🌐 Web Control App",
            Font = new Font("Segoe UI", 9f, FontStyle.Bold),
            BackColor = Color.FromArgb(40, 40, 60),
            ForeColor = Color.FromArgb(165, 180, 252),
            FlatStyle = FlatStyle.Flat,
            Cursor = Cursors.Hand,
            Location = new Point(915, 20),
            Size = new Size(160, 34)
        };
        btnOpenBrowser.FlatAppearance.BorderColor = _colBorder;
        btnOpenBrowser.Click += (s, e) => InstallEngine.LaunchControlCenter();

        _pnlHeader.Controls.Add(lblTitle);
        _pnlHeader.Controls.Add(lblVersionBadge);
        _pnlHeader.Controls.Add(lblSubtitle);
        _pnlHeader.Controls.Add(_lblStatusBadge);
        _pnlHeader.Controls.Add(btnOpenBrowser);
        Controls.Add(_pnlHeader);

        // Lock Overlay (Requires Master Password)
        _pnlLock = new Panel
        {
            Dock = DockStyle.Fill,
            BackColor = _colBg
        };

        var pnlLockBox = new Panel
        {
            Size = new Size(480, 280),
            BackColor = _colCard,
            BorderStyle = BorderStyle.FixedSingle
        };
        pnlLockBox.Location = new Point((1120 - 480) / 2, 140);
        pnlLockBox.Anchor = AnchorStyles.None;

        var lblLockIcon = new Label
        {
            Text = "🔒",
            Font = new Font("Segoe UI", 28f),
            Location = new Point(24, 20),
            Size = new Size(54, 54),
            ForeColor = Color.White
        };
        pnlLockBox.Controls.Add(lblLockIcon);

        var lblLockTitle = new Label
        {
            Text = "Master Password Required",
            Font = new Font("Segoe UI", 14f, FontStyle.Bold),
            ForeColor = Color.White,
            Location = new Point(88, 24),
            AutoSize = true
        };
        pnlLockBox.Controls.Add(lblLockTitle);

        var lblLockSub = new Label
        {
            Text = "To prevent unauthorized changes by kids, please enter your Administrator Master Password to open the Control Center:",
            Font = new Font("Segoe UI", 9.5f),
            ForeColor = _colSubtext,
            Location = new Point(28, 85),
            Size = new Size(420, 44)
        };
        pnlLockBox.Controls.Add(lblLockSub);

        _txtMasterPassword = new TextBox
        {
            UseSystemPasswordChar = true,
            Font = new Font("Segoe UI", 11f),
            BackColor = _colSurface,
            ForeColor = Color.White,
            Location = new Point(28, 140),
            Size = new Size(420, 32),
            BorderStyle = BorderStyle.FixedSingle
        };
        _txtMasterPassword.KeyDown += (s, e) => { if (e.KeyCode == Keys.Enter) BtnUnlock_Click(s, e); };
        pnlLockBox.Controls.Add(_txtMasterPassword);

        _lblLockError = new Label
        {
            Text = "",
            Font = new Font("Segoe UI", 9f),
            ForeColor = Color.FromArgb(248, 113, 113),
            Location = new Point(28, 178),
            Size = new Size(420, 20)
        };
        pnlLockBox.Controls.Add(_lblLockError);

        _btnUnlock = new Button
        {
            Text = "Unlock Control Center",
            Font = new Font("Segoe UI", 10.5f, FontStyle.Bold),
            BackColor = _colAccent,
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat,
            Cursor = Cursors.Hand,
            Location = new Point(28, 205),
            Size = new Size(420, 44)
        };
        _btnUnlock.FlatAppearance.BorderSize = 0;
        _btnUnlock.Click += BtnUnlock_Click;
        pnlLockBox.Controls.Add(_btnUnlock);

        _pnlLock.Controls.Add(pnlLockBox);
        Controls.Add(_pnlLock);

        // Main Navigation Layout Container (Visible after unlock)
        _pnlMainContainer = new Panel
        {
            Dock = DockStyle.Fill,
            BackColor = _colBg,
            Visible = false
        };

        // Left Sidebar Navigation
        _pnlSidebar = new Panel
        {
            Dock = DockStyle.Left,
            Width = 230,
            BackColor = _colSurface,
            Padding = new Padding(10, 15, 10, 15)
        };

        // Main Content Area
        _pnlContent = new Panel
        {
            Dock = DockStyle.Fill,
            BackColor = _colBg,
            Padding = new Padding(20)
        };

        BuildAllTabs();
        BuildSidebarNav();

        _pnlMainContainer.Controls.Add(_pnlContent);
        _pnlMainContainer.Controls.Add(_pnlSidebar);
        Controls.Add(_pnlMainContainer);
    }

    private void BuildSidebarNav()
    {
        string[] titles = {
            "🖥️  Overview & Fleet",
            "👥  User Accounts & Jail",
            "🛡️  Rules & Schedules",
            "📦  Installed Software",
            "⚡  Live Processes",
            "📋  Audit & Block Logs",
            "⚙️  Settings & Uninstaller"
        };

        _navButtons = new Button[titles.Length];
        int top = 15;

        for (int i = 0; i < titles.Length; i++)
        {
            int index = i;
            var btn = new Button
            {
                Text = titles[i],
                Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
                ForeColor = (i == 0) ? Color.White : _colSubtext,
                BackColor = (i == 0) ? Color.FromArgb(45, 45, 68) : Color.Transparent,
                FlatStyle = FlatStyle.Flat,
                TextAlign = ContentAlignment.MiddleLeft,
                Padding = new Padding(12, 0, 0, 0),
                Cursor = Cursors.Hand,
                Location = new Point(10, top),
                Size = new Size(210, 44)
            };
            btn.FlatAppearance.BorderSize = (i == 0) ? 1 : 0;
            btn.FlatAppearance.BorderColor = _colAccent;
            btn.Click += (s, e) => SwitchTab(index);

            _navButtons[i] = btn;
            _pnlSidebar.Controls.Add(btn);
            top += 50;
        }
    }

    private void SwitchTab(int index)
    {
        _activeTabIndex = index;
        for (int i = 0; i < _navButtons.Length; i++)
        {
            bool isActive = (i == index);
            _navButtons[i].ForeColor = isActive ? Color.White : _colSubtext;
            _navButtons[i].BackColor = isActive ? Color.FromArgb(45, 45, 68) : Color.Transparent;
            _navButtons[i].FlatAppearance.BorderSize = isActive ? 1 : 0;
        }

        for (int i = 0; i < _tabPanels.Length; i++)
        {
            _tabPanels[i].Visible = (i == index);
        }

        // Auto refresh tab data
        if (index == 1) RefreshUsersTab();
        else if (index == 2) RefreshRulesTab();
        else if (index == 3) RefreshInstalledAppsTab();
        else if (index == 4) RefreshProcessesTab();
        else if (index == 5) RefreshLogsTab();
    }

    private void BuildAllTabs()
    {
        _tabPanels = new Panel[7];
        for (int i = 0; i < 7; i++)
        {
            _tabPanels[i] = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = _colBg,
                Visible = (i == 0)
            };
            _pnlContent.Controls.Add(_tabPanels[i]);
        }

        BuildTabOverview(_tabPanels[0]);
        BuildTabUsers(_tabPanels[1]);
        BuildTabRules(_tabPanels[2]);
        BuildTabInstalledApps(_tabPanels[3]);
        BuildTabProcesses(_tabPanels[4]);
        BuildTabLogs(_tabPanels[5]);
        BuildTabSettings(_tabPanels[6]);
    }

    private void BtnUnlock_Click(object? sender, EventArgs e)
    {
        string pass = _txtMasterPassword.Text.Trim();
        string storedHash = InstallEngine.GetStoredMasterPasswordHash(_dataDir);

        if (string.IsNullOrEmpty(storedHash) || CryptoHelper.VerifyPassword(pass, storedHash))
        {
            _isUnlocked = true;
            _pnlLock.Visible = false;
            _pnlMainContainer.Visible = true;
            RefreshAllTabs();
        }
        else
        {
            _lblLockError.Text = "Incorrect Master Password. Access denied.";
            _txtMasterPassword.SelectAll();
            _txtMasterPassword.Focus();
        }
    }

    // ==========================================
    // TAB 0: OVERVIEW & FLEET
    // ==========================================
    private void BuildTabOverview(Panel panel)
    {
        var grpLocal = new GroupBox
        {
            Text = "Local Windows Machine Status",
            Location = new Point(10, 10),
            Size = new Size(820, 190),
            Font = new Font("Segoe UI", 10f, FontStyle.Bold),
            ForeColor = Color.White
        };

        _txtHostInfo = new TextBox
        {
            Multiline = true,
            ReadOnly = true,
            BackColor = _colCard,
            ForeColor = _colText,
            BorderStyle = BorderStyle.FixedSingle,
            Font = new Font("Consolas", 10f),
            Location = new Point(20, 30),
            Size = new Size(780, 140)
        };
        grpLocal.Controls.Add(_txtHostInfo);
        panel.Controls.Add(grpLocal);

        var grpRemote = new GroupBox
        {
            Text = "Remote Mac Connection & Pre-Shared Key (PSK)",
            Location = new Point(10, 215),
            Size = new Size(820, 220),
            Font = new Font("Segoe UI", 10f, FontStyle.Bold),
            ForeColor = Color.White
        };

        var lblMacInfo = new Label
        {
            Text = "To monitor and configure this PC remotely from your Mac while your child plays, open 'AppShield Admin.app' on macOS and enter this PC's IP and Pre-Shared Key:",
            Font = new Font("Segoe UI", 9.5f),
            ForeColor = _colSubtext,
            Location = new Point(20, 32),
            Size = new Size(780, 44)
        };
        grpRemote.Controls.Add(lblMacInfo);

        _txtPsk = new TextBox
        {
            ReadOnly = true,
            Font = new Font("Consolas", 11f, FontStyle.Bold),
            BackColor = _colCard,
            ForeColor = Color.FromArgb(165, 180, 252),
            BorderStyle = BorderStyle.FixedSingle,
            UseSystemPasswordChar = true,
            Location = new Point(20, 95),
            Size = new Size(540, 30)
        };
        grpRemote.Controls.Add(_txtPsk);

        _btnRevealPsk = new Button
        {
            Text = "👁️ Reveal",
            Font = new Font("Segoe UI", 9f, FontStyle.Bold),
            BackColor = Color.FromArgb(45, 45, 68),
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat,
            Cursor = Cursors.Hand,
            Location = new Point(570, 93),
            Size = new Size(100, 34)
        };
        _btnRevealPsk.FlatAppearance.BorderColor = _colBorder;
        _btnRevealPsk.Click += (s, e) =>
        {
            _pskRevealed = !_pskRevealed;
            _txtPsk.UseSystemPasswordChar = !_pskRevealed;
            _btnRevealPsk.Text = _pskRevealed ? "🙈 Hide" : "👁️ Reveal";
        };
        grpRemote.Controls.Add(_btnRevealPsk);

        _btnCopyPsk = new Button
        {
            Text = "📋 Copy Key",
            Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
            BackColor = _colAccent,
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat,
            Cursor = Cursors.Hand,
            Location = new Point(680, 93),
            Size = new Size(120, 34)
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
        grpRemote.Controls.Add(_btnCopyPsk);

        var btnAddRemote = new Button
        {
            Text = "🌐 Add a Remote Windows Computer to Manage",
            Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
            BackColor = Color.FromArgb(49, 46, 129),
            ForeColor = Color.FromArgb(199, 210, 254),
            FlatStyle = FlatStyle.Flat,
            Cursor = Cursors.Hand,
            Location = new Point(20, 150),
            Size = new Size(400, 38)
        };
        btnAddRemote.FlatAppearance.BorderColor = Color.FromArgb(99, 102, 241);
        btnAddRemote.Click += (s, e) => ShowAddRemoteDialog();
        grpRemote.Controls.Add(btnAddRemote);

        panel.Controls.Add(grpRemote);
    }

    // ==========================================
    // TAB 1: USER ACCOUNTS & CHILD JAIL
    // ==========================================
    private void BuildTabUsers(Panel panel)
    {
        // Warning Banner: Visible when NO Standard Account exists
        _pnlNoStandardWarning = new Panel
        {
            Location = new Point(10, 10),
            Size = new Size(820, 110),
            BackColor = Color.FromArgb(45, 30, 15),
            BorderStyle = BorderStyle.FixedSingle,
            Visible = false
        };

        var lblWarnIcon = new Label
        {
            Text = "⚠️",
            Font = new Font("Segoe UI", 24f),
            Location = new Point(12, 10),
            Size = new Size(50, 50),
            ForeColor = Color.FromArgb(245, 158, 11)
        };
        _pnlNoStandardWarning.Controls.Add(lblWarnIcon);

        var lblWarnTitle = new Label
        {
            Text = "No Child or Standard User Account Found",
            Font = new Font("Segoe UI", 11f, FontStyle.Bold),
            ForeColor = Color.FromArgb(253, 230, 138),
            Location = new Point(70, 12),
            AutoSize = true
        };
        _pnlNoStandardWarning.Controls.Add(lblWarnTitle);

        var lblWarnText = new Label
        {
            Text = "All accounts on this computer have Administrator privileges. AppShield restrictions require a Standard user account so children cannot disable services or bypass security.",
            Font = new Font("Segoe UI", 9f),
            ForeColor = Color.FromArgb(254, 243, 199),
            Location = new Point(70, 36),
            Size = new Size(730, 32)
        };
        _pnlNoStandardWarning.Controls.Add(lblWarnText);

        var btnCreateChild = new Button
        {
            Text = "➕ Create Standard Child Account",
            Font = new Font("Segoe UI", 9f, FontStyle.Bold),
            BackColor = Color.FromArgb(245, 158, 11),
            ForeColor = Color.Black,
            FlatStyle = FlatStyle.Flat,
            Cursor = Cursors.Hand,
            Location = new Point(70, 72),
            Size = new Size(240, 30)
        };
        btnCreateChild.FlatAppearance.BorderSize = 0;
        btnCreateChild.Click += (s, e) => PromptCreateChildAccount();
        _pnlNoStandardWarning.Controls.Add(btnCreateChild);

        var btnOpenSettings = new Button
        {
            Text = "⚙️ Open Windows Account Settings",
            Font = new Font("Segoe UI", 9f, FontStyle.Bold),
            BackColor = Color.FromArgb(45, 45, 68),
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat,
            Cursor = Cursors.Hand,
            Location = new Point(320, 72),
            Size = new Size(240, 30)
        };
        btnOpenSettings.FlatAppearance.BorderColor = _colBorder;
        btnOpenSettings.Click += (s, e) => InstallEngine.OpenWindowsAccountSettings();
        _pnlNoStandardWarning.Controls.Add(btnOpenSettings);

        var btnAddRemotePc = new Button
        {
            Text = "🌐 Add Remote Computer",
            Font = new Font("Segoe UI", 9f),
            BackColor = Color.FromArgb(45, 45, 68),
            ForeColor = Color.FromArgb(199, 210, 254),
            FlatStyle = FlatStyle.Flat,
            Cursor = Cursors.Hand,
            Location = new Point(570, 72),
            Size = new Size(200, 30)
        };
        btnAddRemotePc.FlatAppearance.BorderColor = _colBorder;
        btnAddRemotePc.Click += (s, e) => ShowAddRemoteDialog();
        _pnlNoStandardWarning.Controls.Add(btnAddRemotePc);

        panel.Controls.Add(_pnlNoStandardWarning);

        // Account List
        _lvUsers = new ListView
        {
            View = View.Details,
            FullRowSelect = true,
            GridLines = true,
            MultiSelect = false,
            Location = new Point(10, 130),
            Size = new Size(820, 240),
            BackColor = _colCard,
            ForeColor = Color.White,
            BorderStyle = BorderStyle.FixedSingle,
            Font = new Font("Segoe UI", 9.5f)
        };
        _lvUsers.Columns.Add("Username", 180);
        _lvUsers.Columns.Add("Account Type", 140);
        _lvUsers.Columns.Add("Protected (Managed)", 170);
        _lvUsers.Columns.Add("Path Jail Enabled", 160);
        _lvUsers.Columns.Add("SID", 150);
        _lvUsers.SelectedIndexChanged += LvUsers_SelectedIndexChanged;
        panel.Controls.Add(_lvUsers);

        // Edit Box
        var grpEdit = new GroupBox
        {
            Text = "Account Protection Configuration",
            Location = new Point(10, 380),
            Size = new Size(820, 170),
            Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
            ForeColor = Color.White
        };

        _chkIsManaged = new CheckBox
        {
            Text = "Protect this user (Enforce application blocklists, daily schedules, and time quotas)",
            Font = new Font("Segoe UI", 9.5f),
            ForeColor = Color.White,
            Location = new Point(20, 30),
            Size = new Size(680, 28)
        };
        grpEdit.Controls.Add(_chkIsManaged);

        _chkBlockUserWritable = new CheckBox
        {
            Text = "Path Jail: Block running unapproved .exe files from Downloads, Desktop, Temp, and USB drives",
            Font = new Font("Segoe UI", 9.5f),
            ForeColor = Color.White,
            Location = new Point(20, 65),
            Size = new Size(720, 28)
        };
        grpEdit.Controls.Add(_chkBlockUserWritable);

        _btnSaveUser = new Button
        {
            Text = "💾 Save Account Settings",
            Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
            BackColor = Color.FromArgb(34, 197, 94),
            ForeColor = Color.Black,
            FlatStyle = FlatStyle.Flat,
            Cursor = Cursors.Hand,
            Location = new Point(20, 110),
            Size = new Size(220, 36)
        };
        _btnSaveUser.FlatAppearance.BorderSize = 0;
        _btnSaveUser.Click += BtnSaveUser_Click;
        grpEdit.Controls.Add(_btnSaveUser);

        var btnNewAccount = new Button
        {
            Text = "➕ Create New Child Account",
            Font = new Font("Segoe UI", 9.5f),
            BackColor = Color.FromArgb(45, 45, 68),
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat,
            Cursor = Cursors.Hand,
            Location = new Point(260, 110),
            Size = new Size(230, 36)
        };
        btnNewAccount.FlatAppearance.BorderColor = _colBorder;
        btnNewAccount.Click += (s, e) => PromptCreateChildAccount();
        grpEdit.Controls.Add(btnNewAccount);

        panel.Controls.Add(grpEdit);
    }

    // ==========================================
    // TAB 2: RULES & ALLOWED SCHEDULES
    // ==========================================
    private void BuildTabRules(Panel panel)
    {
        _lvRules = new ListView
        {
            View = View.Details,
            FullRowSelect = true,
            GridLines = true,
            Location = new Point(10, 10),
            Size = new Size(820, 230),
            BackColor = _colCard,
            ForeColor = Color.White,
            BorderStyle = BorderStyle.FixedSingle,
            Font = new Font("Segoe UI", 9.5f)
        };
        _lvRules.Columns.Add("Process Name", 190);
        _lvRules.Columns.Add("Rule Type", 140);
        _lvRules.Columns.Add("Schedule / Quota", 160);
        _lvRules.Columns.Add("Description", 200);
        _lvRules.Columns.Add("Target User", 110);
        panel.Controls.Add(_lvRules);

        var grpAdd = new GroupBox
        {
            Text = "Create Application Rule or Usage Schedule",
            Location = new Point(10, 250),
            Size = new Size(820, 280),
            Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
            ForeColor = Color.White
        };

        var lblExe = new Label
        {
            Text = "Target Executable Name (e.g. RobloxPlayerBeta.exe, steam.exe, chrome.exe):",
            Font = new Font("Segoe UI", 9f),
            ForeColor = _colSubtext,
            Location = new Point(20, 26),
            Size = new Size(520, 20)
        };
        grpAdd.Controls.Add(lblExe);

        _txtNewRuleExe = new TextBox
        {
            Font = new Font("Segoe UI", 10f),
            BackColor = _colSurface,
            ForeColor = Color.White,
            BorderStyle = BorderStyle.FixedSingle,
            Location = new Point(20, 50),
            Size = new Size(400, 28)
        };
        grpAdd.Controls.Add(_txtNewRuleExe);

        var btnBrowse = new Button
        {
            Text = "📁 Browse .exe...",
            Font = new Font("Segoe UI", 9f),
            BackColor = Color.FromArgb(45, 45, 68),
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat,
            Cursor = Cursors.Hand,
            Location = new Point(430, 49),
            Size = new Size(130, 30)
        };
        btnBrowse.FlatAppearance.BorderColor = _colBorder;
        btnBrowse.Click += (s, e) =>
        {
            using var ofd = new OpenFileDialog
            {
                Filter = "Executable Files (*.exe)|*.exe|All Files (*.*)|*.*",
                Title = "Select Target Application"
            };
            if (ofd.ShowDialog() == DialogResult.OK)
            {
                _txtNewRuleExe.Text = Path.GetFileName(ofd.FileName);
            }
        };
        grpAdd.Controls.Add(btnBrowse);

        // Rule Type
        var lblType = new Label
        {
            Text = "Rule Type:",
            Font = new Font("Segoe UI", 9f),
            ForeColor = _colSubtext,
            Location = new Point(20, 90),
            Size = new Size(100, 20)
        };
        grpAdd.Controls.Add(lblType);

        _cmbRuleType = new ComboBox
        {
            DropDownStyle = ComboBoxStyle.DropDownList,
            BackColor = _colSurface,
            ForeColor = Color.White,
            Font = new Font("Segoe UI", 9.5f),
            Location = new Point(20, 112),
            Size = new Size(250, 30)
        };
        _cmbRuleType.Items.Add("AlwaysBlock (Always Forbidden)");
        _cmbRuleType.Items.Add("AllowedWindow (Allow Only 12pm-8pm)");
        _cmbRuleType.Items.Add("DailyQuota (Limit daily usage)");
        _cmbRuleType.SelectedIndex = 1;
        grpAdd.Controls.Add(_cmbRuleType);

        // Schedule times
        var lblSched = new Label
        {
            Text = "Allowed Window (Start / End):",
            Font = new Font("Segoe UI", 9f),
            ForeColor = _colSubtext,
            Location = new Point(290, 90),
            Size = new Size(200, 20)
        };
        grpAdd.Controls.Add(lblSched);

        _txtScheduleStart = new TextBox
        {
            Text = "12:00",
            Font = new Font("Segoe UI", 9.5f),
            BackColor = _colSurface,
            ForeColor = Color.White,
            BorderStyle = BorderStyle.FixedSingle,
            Location = new Point(290, 112),
            Size = new Size(80, 28)
        };
        grpAdd.Controls.Add(_txtScheduleStart);

        var lblTo = new Label
        {
            Text = "to",
            Font = new Font("Segoe UI", 9f),
            ForeColor = _colSubtext,
            Location = new Point(378, 115),
            Size = new Size(24, 20)
        };
        grpAdd.Controls.Add(lblTo);

        _txtScheduleEnd = new TextBox
        {
            Text = "20:00",
            Font = new Font("Segoe UI", 9.5f),
            BackColor = _colSurface,
            ForeColor = Color.White,
            BorderStyle = BorderStyle.FixedSingle,
            Location = new Point(408, 112),
            Size = new Size(80, 28)
        };
        grpAdd.Controls.Add(_txtScheduleEnd);

        // Daily Quota
        var lblQuota = new Label
        {
            Text = "Daily Quota (Minutes):",
            Font = new Font("Segoe UI", 9f),
            ForeColor = _colSubtext,
            Location = new Point(510, 90),
            Size = new Size(160, 20)
        };
        grpAdd.Controls.Add(lblQuota);

        _txtQuotaMinutes = new TextBox
        {
            Text = "60",
            Font = new Font("Segoe UI", 9.5f),
            BackColor = _colSurface,
            ForeColor = Color.White,
            BorderStyle = BorderStyle.FixedSingle,
            Location = new Point(510, 112),
            Size = new Size(100, 28)
        };
        grpAdd.Controls.Add(_txtQuotaMinutes);

        // Description
        var lblDesc = new Label
        {
            Text = "Description:",
            Font = new Font("Segoe UI", 9f),
            ForeColor = _colSubtext,
            Location = new Point(20, 150),
            Size = new Size(100, 20)
        };
        grpAdd.Controls.Add(lblDesc);

        _txtRuleDescription = new TextBox
        {
            Font = new Font("Segoe UI", 9.5f),
            BackColor = _colSurface,
            ForeColor = Color.White,
            BorderStyle = BorderStyle.FixedSingle,
            Location = new Point(20, 172),
            Size = new Size(468, 28)
        };
        grpAdd.Controls.Add(_txtRuleDescription);

        // Quick Presets
        var btnPreset12to8 = new Button
        {
            Text = "⚡ 12pm - 8pm Preset",
            Font = new Font("Segoe UI", 8.5f, FontStyle.Bold),
            BackColor = Color.FromArgb(49, 46, 129),
            ForeColor = Color.FromArgb(199, 210, 254),
            FlatStyle = FlatStyle.Flat,
            Cursor = Cursors.Hand,
            Location = new Point(510, 170),
            Size = new Size(150, 30)
        };
        btnPreset12to8.FlatAppearance.BorderColor = _colAccent;
        btnPreset12to8.Click += (s, e) =>
        {
            _cmbRuleType.SelectedIndex = 1;
            _txtScheduleStart.Text = "12:00";
            _txtScheduleEnd.Text = "20:00";
            _txtRuleDescription.Text = "Allowed Window: 12:00 PM to 8:00 PM only";
        };
        grpAdd.Controls.Add(btnPreset12to8);

        // Action Buttons
        _btnAddRule = new Button
        {
            Text = "🛡️ Save & Enforce Rule",
            Font = new Font("Segoe UI", 10f, FontStyle.Bold),
            BackColor = _colAccent,
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat,
            Cursor = Cursors.Hand,
            Location = new Point(20, 220),
            Size = new Size(200, 38)
        };
        _btnAddRule.FlatAppearance.BorderSize = 0;
        _btnAddRule.Click += BtnAddRule_Click;
        grpAdd.Controls.Add(_btnAddRule);

        _btnDeleteRule = new Button
        {
            Text = "❌ Remove Selected Rule",
            Font = new Font("Segoe UI", 9.5f),
            BackColor = Color.FromArgb(45, 45, 68),
            ForeColor = Color.FromArgb(248, 113, 113),
            FlatStyle = FlatStyle.Flat,
            Cursor = Cursors.Hand,
            Location = new Point(235, 220),
            Size = new Size(200, 38)
        };
        _btnDeleteRule.FlatAppearance.BorderColor = _colBorder;
        _btnDeleteRule.Click += BtnDeleteRule_Click;
        grpAdd.Controls.Add(_btnDeleteRule);

        panel.Controls.Add(grpAdd);
    }

    // ==========================================
    // TAB 3: INSTALLED APPLICATIONS
    // ==========================================
    private void BuildTabInstalledApps(Panel panel)
    {
        var pnlTop = new Panel
        {
            Location = new Point(10, 10),
            Size = new Size(820, 45)
        };

        _txtAppFilter = new TextBox
        {
            Font = new Font("Segoe UI", 10f),
            BackColor = _colCard,
            ForeColor = Color.White,
            BorderStyle = BorderStyle.FixedSingle,
            Location = new Point(0, 8),
            Size = new Size(340, 28)
        };
        _txtAppFilter.TextChanged += (s, e) => FilterInstalledApps();
        pnlTop.Controls.Add(_txtAppFilter);

        _btnScanApps = new Button
        {
            Text = "🔍 Scan Installed Windows Apps",
            Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
            BackColor = _colAccent,
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat,
            Cursor = Cursors.Hand,
            Location = new Point(360, 6),
            Size = new Size(240, 32)
        };
        _btnScanApps.FlatAppearance.BorderSize = 0;
        _btnScanApps.Click += (s, e) => RefreshInstalledAppsTab();
        pnlTop.Controls.Add(_btnScanApps);

        panel.Controls.Add(pnlTop);

        _lvInstalledApps = new ListView
        {
            View = View.Details,
            FullRowSelect = true,
            GridLines = true,
            Location = new Point(10, 65),
            Size = new Size(820, 400),
            BackColor = _colCard,
            ForeColor = Color.White,
            BorderStyle = BorderStyle.FixedSingle,
            Font = new Font("Segoe UI", 9.5f)
        };
        _lvInstalledApps.Columns.Add("Application Name", 260);
        _lvInstalledApps.Columns.Add("Version", 110);
        _lvInstalledApps.Columns.Add("Executable Name", 200);
        _lvInstalledApps.Columns.Add("Publisher", 220);
        panel.Controls.Add(_lvInstalledApps);

        var pnlActions = new Panel
        {
            Location = new Point(10, 480),
            Size = new Size(820, 50)
        };

        var btnBlockApp = new Button
        {
            Text = "🚫 Block Selected App",
            Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
            BackColor = Color.FromArgb(239, 68, 68),
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat,
            Cursor = Cursors.Hand,
            Location = new Point(0, 5),
            Size = new Size(190, 36)
        };
        btnBlockApp.FlatAppearance.BorderSize = 0;
        btnBlockApp.Click += (s, e) => BlockSelectedInstalledApp();
        pnlActions.Controls.Add(btnBlockApp);

        var btnScheduleApp = new Button
        {
            Text = "⚡ Allow 12pm - 8pm Only",
            Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
            BackColor = Color.FromArgb(49, 46, 129),
            ForeColor = Color.FromArgb(199, 210, 254),
            FlatStyle = FlatStyle.Flat,
            Cursor = Cursors.Hand,
            Location = new Point(205, 5),
            Size = new Size(210, 36)
        };
        btnScheduleApp.FlatAppearance.BorderColor = _colAccent;
        btnScheduleApp.Click += (s, e) => ScheduleSelectedInstalledApp();
        pnlActions.Controls.Add(btnScheduleApp);

        panel.Controls.Add(pnlActions);
    }

    // ==========================================
    // TAB 4: LIVE PROCESSES
    // ==========================================
    private void BuildTabProcesses(Panel panel)
    {
        var pnlTop = new Panel
        {
            Location = new Point(10, 10),
            Size = new Size(820, 45)
        };

        _btnRefreshProcs = new Button
        {
            Text = "🔄 Refresh Process List",
            Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
            BackColor = _colAccent,
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat,
            Cursor = Cursors.Hand,
            Location = new Point(0, 6),
            Size = new Size(200, 32)
        };
        _btnRefreshProcs.FlatAppearance.BorderSize = 0;
        _btnRefreshProcs.Click += (s, e) => RefreshProcessesTab();
        pnlTop.Controls.Add(_btnRefreshProcs);

        panel.Controls.Add(pnlTop);

        _lvProcesses = new ListView
        {
            View = View.Details,
            FullRowSelect = true,
            GridLines = true,
            Location = new Point(10, 65),
            Size = new Size(820, 400),
            BackColor = _colCard,
            ForeColor = Color.White,
            BorderStyle = BorderStyle.FixedSingle,
            Font = new Font("Segoe UI", 9.5f)
        };
        _lvProcesses.Columns.Add("PID", 80);
        _lvProcesses.Columns.Add("Process Name", 220);
        _lvProcesses.Columns.Add("Memory", 110);
        _lvProcesses.Columns.Add("Executable Path", 380);
        panel.Controls.Add(_lvProcesses);

        var pnlActions = new Panel
        {
            Location = new Point(10, 480),
            Size = new Size(820, 50)
        };

        var btnKill = new Button
        {
            Text = "🛑 Terminate Process Tree",
            Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
            BackColor = Color.FromArgb(239, 68, 68),
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat,
            Cursor = Cursors.Hand,
            Location = new Point(0, 5),
            Size = new Size(220, 36)
        };
        btnKill.FlatAppearance.BorderSize = 0;
        btnKill.Click += (s, e) => KillSelectedProcess();
        pnlActions.Controls.Add(btnKill);

        var btnBlockFromProc = new Button
        {
            Text = "🚫 Block This Process",
            Font = new Font("Segoe UI", 9.5f),
            BackColor = Color.FromArgb(45, 45, 68),
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat,
            Cursor = Cursors.Hand,
            Location = new Point(235, 5),
            Size = new Size(200, 36)
        };
        btnBlockFromProc.FlatAppearance.BorderColor = _colBorder;
        btnBlockFromProc.Click += (s, e) => BlockFromSelectedProcess();
        pnlActions.Controls.Add(btnBlockFromProc);

        panel.Controls.Add(pnlActions);
    }

    // ==========================================
    // TAB 5: AUDIT LOGS
    // ==========================================
    private void BuildTabLogs(Panel panel)
    {
        var pnlTop = new Panel
        {
            Location = new Point(10, 10),
            Size = new Size(820, 45)
        };

        _btnRefreshLogs = new Button
        {
            Text = "🔄 Refresh Block Logs",
            Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
            BackColor = _colAccent,
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat,
            Cursor = Cursors.Hand,
            Location = new Point(0, 6),
            Size = new Size(200, 32)
        };
        _btnRefreshLogs.FlatAppearance.BorderSize = 0;
        _btnRefreshLogs.Click += (s, e) => RefreshLogsTab();
        pnlTop.Controls.Add(_btnRefreshLogs);

        panel.Controls.Add(pnlTop);

        _lvLogs = new ListView
        {
            View = View.Details,
            FullRowSelect = true,
            GridLines = true,
            Location = new Point(10, 65),
            Size = new Size(820, 460),
            BackColor = _colCard,
            ForeColor = Color.White,
            BorderStyle = BorderStyle.FixedSingle,
            Font = new Font("Segoe UI", 9.5f)
        };
        _lvLogs.Columns.Add("Timestamp (Local)", 160);
        _lvLogs.Columns.Add("User", 140);
        _lvLogs.Columns.Add("Executable Blocked", 200);
        _lvLogs.Columns.Add("Action", 100);
        _lvLogs.Columns.Add("Reason / Policy", 200);
        panel.Controls.Add(_lvLogs);
    }

    // ==========================================
    // TAB 6: SETTINGS & UNINSTALLER
    // ==========================================
    private void BuildTabSettings(Panel panel)
    {
        var grpInfo = new GroupBox
        {
            Text = "Service & Protection Settings",
            Location = new Point(10, 10),
            Size = new Size(820, 150),
            Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
            ForeColor = Color.White
        };

        var lblStatus = new Label
        {
            Text = "Service Name: AppShieldService (LocalSystem)\nFirewall Port: 54120 (Encrypted HTTPS + Pre-Shared Key)\nLocal GUI Port: 54121 (HTTP Localhost Only)\nDatabase: C:\\ProgramData\\AppShield\\appshield.db",
            Font = new Font("Segoe UI", 9.5f),
            ForeColor = _colSubtext,
            Location = new Point(20, 30),
            Size = new Size(780, 100)
        };
        grpInfo.Controls.Add(lblStatus);
        panel.Controls.Add(grpInfo);

        var grpUninstall = new GroupBox
        {
            Text = "Self-Destruct Uninstallation",
            Location = new Point(10, 180),
            Size = new Size(820, 220),
            Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
            ForeColor = Color.FromArgb(248, 113, 113)
        };

        var lblWarn = new Label
        {
            Text = "WARNING: Uninstallation will completely remove the AppShield Windows Service, delete the SQLite rules database, clear firewall rules, and delete all desktop shortcuts.\n\nMaster Password confirmation is strictly required:",
            Font = new Font("Segoe UI", 9.5f),
            ForeColor = Color.White,
            Location = new Point(20, 30),
            Size = new Size(780, 60)
        };
        grpUninstall.Controls.Add(lblWarn);

        _txtUninstallPassword = new TextBox
        {
            UseSystemPasswordChar = true,
            Font = new Font("Segoe UI", 10.5f),
            BackColor = _colSurface,
            ForeColor = Color.White,
            BorderStyle = BorderStyle.FixedSingle,
            Location = new Point(20, 100),
            Size = new Size(360, 30)
        };
        grpUninstall.Controls.Add(_txtUninstallPassword);

        _btnUninstallApp = new Button
        {
            Text = "🗑️ Uninstall AppShield Completely",
            Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
            BackColor = Color.FromArgb(239, 68, 68),
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat,
            Cursor = Cursors.Hand,
            Location = new Point(20, 145),
            Size = new Size(260, 40)
        };
        _btnUninstallApp.FlatAppearance.BorderSize = 0;
        _btnUninstallApp.Click += BtnUninstallApp_Click;
        grpUninstall.Controls.Add(_btnUninstallApp);

        panel.Controls.Add(grpUninstall);
    }

    // ==========================================
    // DATA REFRESH LOGIC
    // ==========================================
    private void LoadInitialData()
    {
        string psk = InstallEngine.GetStoredPsk(_dataDir);
        _txtPsk.Text = psk;

        var ips = InstallEngine.GetLocalIpAddresses();
        string ipList = string.Join(", ", ips);

        _txtHostInfo.Text =
            $"Computer Name  : {Environment.MachineName}\r\n" +
            $"IP Addresses   : {ipList}\r\n" +
            $"Service Port   : 54120 (Remote Fleet HTTPS)\r\n" +
            $"Local GUI Port : 54121 (Edge Chromium App Mode)\r\n" +
            $"Version        : 1.2.0 (Tamper-Resistant Security)\r\n" +
            $"Operating Sys  : {Environment.OSVersion}";
    }

    private void RefreshAllTabs()
    {
        RefreshUsersTab();
        RefreshRulesTab();
    }

    private void RefreshUsersTab()
    {
        _lvUsers.Items.Clear();
        var users = InstallEngine.GetUsersFromDb(_dataDir);

        int standardCount = users.Count(u => !u.IsAdmin);
        _pnlNoStandardWarning.Visible = (users.Count > 0 && standardCount == 0);

        foreach (var u in users)
        {
            var lvi = new ListViewItem(u.Username);
            lvi.SubItems.Add(u.IsAdmin ? "Administrator" : "Standard User");
            lvi.SubItems.Add(u.IsManaged ? "✅ PROTECTED" : "Bypassed");
            lvi.SubItems.Add(u.BlockUserWritableDirectories ? "✅ Enforced" : "Disabled");
            lvi.SubItems.Add(u.Sid);
            lvi.Tag = u;

            if (u.IsManaged)
            {
                lvi.BackColor = Color.FromArgb(25, 45, 35);
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
            MessageBox.Show("Please select an account from the list above first.", "AppShield", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        InstallEngine.UpdateUserInDb(_dataDir, _selectedUser.Sid, _chkIsManaged.Checked, _chkBlockUserWritable.Checked);
        MessageBox.Show($"Updated settings for '{_selectedUser.Username}'. Restrictions are active immediately.", "Settings Saved", MessageBoxButtons.OK, MessageBoxIcon.Information);
        RefreshUsersTab();
    }

    private void PromptCreateChildAccount()
    {
        using var form = new Form
        {
            Text = "Create Standard Child Account",
            Size = new Size(420, 260),
            StartPosition = FormStartPosition.CenterParent,
            FormBorderStyle = FormBorderStyle.FixedDialog,
            MaximizeBox = false,
            MinimizeBox = false,
            BackColor = _colBg,
            Font = new Font("Segoe UI", 9.5f)
        };

        var lblUser = new Label { Text = "Child Account Name (e.g. Kid, Child):", Location = new Point(20, 15), Size = new Size(360, 20), ForeColor = _colSubtext };
        var txtUser = new TextBox { Location = new Point(20, 38), Size = new Size(360, 28), BackColor = _colCard, ForeColor = Color.White, BorderStyle = BorderStyle.FixedSingle };

        var lblPass = new Label { Text = "Password:", Location = new Point(20, 75), Size = new Size(360, 20), ForeColor = _colSubtext };
        var txtPass = new TextBox { UseSystemPasswordChar = true, Location = new Point(20, 98), Size = new Size(360, 28), BackColor = _colCard, ForeColor = Color.White, BorderStyle = BorderStyle.FixedSingle };

        var btnCreate = new Button
        {
            Text = "Create & Protect Account",
            Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
            BackColor = Color.FromArgb(245, 158, 11),
            ForeColor = Color.Black,
            FlatStyle = FlatStyle.Flat,
            Cursor = Cursors.Hand,
            Location = new Point(20, 150),
            Size = new Size(220, 36)
        };
        btnCreate.FlatAppearance.BorderSize = 0;
        btnCreate.Click += (s, e) =>
        {
            if (string.IsNullOrWhiteSpace(txtUser.Text) || string.IsNullOrWhiteSpace(txtPass.Text))
            {
                MessageBox.Show("Please enter both username and password.", "AppShield", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            if (InstallEngine.CreateStandardChildAccount(_dataDir, txtUser.Text, txtPass.Text, out string err))
            {
                MessageBox.Show($"Standard child account '{txtUser.Text}' created and protected successfully!", "Account Created", MessageBoxButtons.OK, MessageBoxIcon.Information);
                form.Close();
                RefreshUsersTab();
            }
            else
            {
                MessageBox.Show($"Failed to create account: {err}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        };

        var btnCancel = new Button
        {
            Text = "Cancel",
            Font = new Font("Segoe UI", 9.5f),
            BackColor = Color.FromArgb(45, 45, 68),
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat,
            Cursor = Cursors.Hand,
            Location = new Point(255, 150),
            Size = new Size(125, 36)
        };
        btnCancel.FlatAppearance.BorderColor = _colBorder;
        btnCancel.Click += (s, e) => form.Close();

        form.Controls.Add(lblUser);
        form.Controls.Add(txtUser);
        form.Controls.Add(lblPass);
        form.Controls.Add(txtPass);
        form.Controls.Add(btnCreate);
        form.Controls.Add(btnCancel);

        form.ShowDialog(this);
    }

    private void ShowAddRemoteDialog()
    {
        MessageBox.Show(
            "To manage a remote Windows computer:\n\n" +
            "1. Run AppShield-Setup.exe on the remote child PC.\n" +
            "2. Note the IP and Pre-Shared Key (PSK) displayed on that PC.\n" +
            "3. Open the AppShield Web Control App (or macOS Admin.app) and click '+ Add PC'.\n" +
            "4. Enter the remote PC's IP and PSK to begin managing it.",
            "Remote Fleet Management",
            MessageBoxButtons.OK,
            MessageBoxIcon.Information);
    }

    private void RefreshRulesTab()
    {
        _lvRules.Items.Clear();
        var rules = InstallEngine.GetRulesFromDb(_dataDir);
        foreach (var r in rules)
        {
            var lvi = new ListViewItem(r.ProcessName ?? r.OriginalFilename ?? "App");
            lvi.SubItems.Add(r.RuleType.ToString());

            string sched = "-";
            if (r.RuleType == RuleType.AllowedWindow && !string.IsNullOrEmpty(r.ScheduleStart))
            {
                sched = $"{r.ScheduleStart} - {r.ScheduleEnd}";
            }
            else if (r.RuleType == RuleType.DailyQuota && r.QuotaMinutes.HasValue)
            {
                sched = $"{r.QuotaMinutes.Value} min/day";
            }
            lvi.SubItems.Add(sched);
            lvi.SubItems.Add(r.Description);
            lvi.SubItems.Add(r.TargetUserSid == "*" ? "All Protected" : r.TargetUserSid);
            lvi.Tag = r;
            _lvRules.Items.Add(lvi);
        }
    }

    private void BtnAddRule_Click(object? sender, EventArgs e)
    {
        string exe = _txtNewRuleExe.Text.Trim();
        if (string.IsNullOrEmpty(exe))
        {
            MessageBox.Show("Please enter an executable name to control.", "AppShield", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        if (!exe.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) exe += ".exe";

        RuleType rt = RuleType.AllowedWindow;
        if (_cmbRuleType.SelectedIndex == 0) rt = RuleType.AlwaysBlock;
        else if (_cmbRuleType.SelectedIndex == 2) rt = RuleType.DailyQuota;

        string? start = rt == RuleType.AllowedWindow ? _txtScheduleStart.Text.Trim() : null;
        string? end = rt == RuleType.AllowedWindow ? _txtScheduleEnd.Text.Trim() : null;
        int quota = int.TryParse(_txtQuotaMinutes.Text.Trim(), out int q) ? q : 60;
        string desc = _txtRuleDescription.Text.Trim();

        InstallEngine.AddAdvancedRuleToDb(_dataDir, exe, rt, start, end, quota, desc);
        _txtNewRuleExe.Clear();
        _txtRuleDescription.Clear();
        RefreshRulesTab();
        MessageBox.Show($"Rule for '{exe}' added successfully. Restrictions are enforced immediately.", "Rule Saved", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    private void BtnDeleteRule_Click(object? sender, EventArgs e)
    {
        if (_lvRules.SelectedItems.Count == 0)
        {
            MessageBox.Show("Please select a rule from the list to remove.", "AppShield", MessageBoxButtons.OK, MessageBoxIcon.Information);
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

    private void RefreshInstalledAppsTab()
    {
        _allInstalledApps = InstallEngine.GetInstalledSoftwareList();
        FilterInstalledApps();
    }

    private void FilterInstalledApps()
    {
        _lvInstalledApps.Items.Clear();
        string filter = _txtAppFilter.Text.Trim().ToLowerInvariant();

        foreach (var app in _allInstalledApps)
        {
            if (!string.IsNullOrEmpty(filter) &&
                !app.Name.ToLowerInvariant().Contains(filter) &&
                !app.ExeName.ToLowerInvariant().Contains(filter))
            {
                continue;
            }

            var lvi = new ListViewItem(app.Name);
            lvi.SubItems.Add(app.Version);
            lvi.SubItems.Add(app.ExeName);
            lvi.SubItems.Add(app.Publisher);
            lvi.Tag = app;
            _lvInstalledApps.Items.Add(lvi);
        }
    }

    private void BlockSelectedInstalledApp()
    {
        if (_lvInstalledApps.SelectedItems.Count == 0)
        {
            MessageBox.Show("Select an application from the list to block.", "AppShield", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        var item = ((string Name, string Version, string ExeName, string Publisher))_lvInstalledApps.SelectedItems[0].Tag;
        InstallEngine.AddAdvancedRuleToDb(_dataDir, item.ExeName, RuleType.AlwaysBlock, null, null, 0, $"Block {item.Name}");
        MessageBox.Show($"Blocked '{item.Name}' ({item.ExeName}). It cannot be launched by protected accounts.", "Application Blocked", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    private void ScheduleSelectedInstalledApp()
    {
        if (_lvInstalledApps.SelectedItems.Count == 0)
        {
            MessageBox.Show("Select an application from the list to schedule.", "AppShield", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        var item = ((string Name, string Version, string ExeName, string Publisher))_lvInstalledApps.SelectedItems[0].Tag;
        InstallEngine.AddAdvancedRuleToDb(_dataDir, item.ExeName, RuleType.AllowedWindow, "12:00", "20:00", 0, $"Allowed 12pm-8pm: {item.Name}");
        MessageBox.Show($"Scheduled '{item.Name}' ({item.ExeName}). It is now allowed only between 12:00 PM and 8:00 PM.", "Schedule Enforced", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    private void RefreshProcessesTab()
    {
        _lvProcesses.Items.Clear();
        var procs = InstallEngine.GetRunningProcessesInfo();

        foreach (var p in procs)
        {
            var lvi = new ListViewItem(p.Pid.ToString());
            lvi.SubItems.Add(p.Name);
            lvi.SubItems.Add(p.MemoryMb);
            lvi.SubItems.Add(p.ExePath);
            lvi.Tag = p;
            _lvProcesses.Items.Add(lvi);
        }
    }

    private void KillSelectedProcess()
    {
        if (_lvProcesses.SelectedItems.Count == 0)
        {
            MessageBox.Show("Select a running process to terminate.", "AppShield", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        var p = ((int Pid, string Name, string MemoryMb, string ExePath))_lvProcesses.SelectedItems[0].Tag;
        try
        {
            var proc = Process.GetProcessById(p.Pid);
            proc.Kill(entireProcessTree: true);
            RefreshProcessesTab();
            MessageBox.Show($"Process '{p.Name}' (PID {p.Pid}) terminated.", "Process Terminated", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Failed to terminate process: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void BlockFromSelectedProcess()
    {
        if (_lvProcesses.SelectedItems.Count == 0)
        {
            MessageBox.Show("Select a process to block.", "AppShield", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        var p = ((int Pid, string Name, string MemoryMb, string ExePath))_lvProcesses.SelectedItems[0].Tag;
        InstallEngine.AddAdvancedRuleToDb(_dataDir, p.Name, RuleType.AlwaysBlock, null, null, 0, $"Blocked process {p.Name}");
        try
        {
            var proc = Process.GetProcessById(p.Pid);
            proc.Kill(entireProcessTree: true);
        }
        catch { }

        RefreshProcessesTab();
        MessageBox.Show($"Rule created and process '{p.Name}' killed. It is now blocked.", "Blocked", MessageBoxButtons.OK, MessageBoxIcon.Information);
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

    private void BtnUninstallApp_Click(object? sender, EventArgs e)
    {
        string pass = _txtUninstallPassword.Text.Trim();
        if (string.IsNullOrEmpty(pass))
        {
            MessageBox.Show("Master Password is required to uninstall AppShield.", "Security Warning", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        var confirm = MessageBox.Show(
            "Are you absolutely sure you want to permanently uninstall AppShield and delete all rules?\n\nThis cannot be undone.",
            "Confirm Permanent Uninstallation",
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Warning);

        if (confirm != DialogResult.Yes) return;

        bool success = InstallEngine.RunUninstall(pass, (pct, msg) => { }, out string err);
        if (success)
        {
            MessageBox.Show("AppShield has been completely uninstalled from this computer.", "Uninstalled", MessageBoxButtons.OK, MessageBoxIcon.Information);
            Application.Exit();
        }
        else
        {
            MessageBox.Show($"Uninstallation rejected: {err}", "Access Denied", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }
}
