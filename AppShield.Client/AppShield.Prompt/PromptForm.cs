using System.Drawing.Drawing2D;
using AppShield.Shared.NamedPipes;

namespace AppShield.Prompt;

public class PromptForm : Form
{
    private readonly string _appName;
    private readonly string _userSid;
    private readonly string _reason;

    private int _remainingSeconds = 60;
    private System.Windows.Forms.Timer? _countdownTimer;

    private Label _lblCountdown = null!;
    private TextBox _txtPassword = null!;
    private Button _btnUnlock = null!;
    private Button _btnDismiss = null!;
    private Label _lblStatus = null!;

    public PromptForm(string appName, string userSid, string reason)
    {
        _appName = string.IsNullOrWhiteSpace(appName) ? "Application" : appName;
        _userSid = userSid ?? string.Empty;
        _reason = string.IsNullOrWhiteSpace(reason) ? "Application usage restricted by administrator policy." : reason;

        InitializeComponent();
        StartCountdown();
    }

    private void InitializeComponent()
    {
        string version = typeof(PromptForm).Assembly.GetName().Version?.ToString(3) ?? "1.0.0";

        Text = $"AppShield Security Notice (v{version})";
        Size = new Size(480, 360);
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        StartPosition = FormStartPosition.CenterScreen;
        TopMost = true;
        BackColor = Color.FromArgb(24, 24, 27); // Zinc-900
        ForeColor = Color.FromArgb(244, 244, 245); // Zinc-100
        Font = new Font("Segoe UI", 9.5f, FontStyle.Regular);
        try
        {
            Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath);
        }
        catch
        {
        }

        // Header Shield Icon / Badge
        var pnlHeader = new Panel
        {
            Dock = DockStyle.Top,
            Height = 70,
            BackColor = Color.FromArgb(39, 39, 42) // Zinc-800
        };

        var lblShieldBadge = new Label
        {
            Text = $"🛡️ AppShield Control (v{version})",
            Font = new Font("Segoe UI", 12f, FontStyle.Bold),
            ForeColor = Color.FromArgb(129, 140, 248), // Indigo-400
            Location = new Point(20, 14),
            AutoSize = true
        };

        var lblHeaderSub = new Label
        {
            Text = "Tamper-Resistant Windows Endpoint Protection",
            Font = new Font("Segoe UI", 8.5f, FontStyle.Regular),
            ForeColor = Color.FromArgb(161, 161, 170), // Zinc-400
            Location = new Point(22, 40),
            AutoSize = true
        };

        pnlHeader.Controls.Add(lblShieldBadge);
        pnlHeader.Controls.Add(lblHeaderSub);

        // Main Container Panel
        var pnlBody = new Panel
        {
            Location = new Point(20, 80),
            Size = new Size(424, 230),
            BackColor = Color.Transparent
        };

        var lblAppTitle = new Label
        {
            Text = $"Restricted: {_appName}",
            Font = new Font("Segoe UI", 11.5f, FontStyle.Bold),
            ForeColor = Color.FromArgb(251, 113, 133), // Rose-400
            Location = new Point(0, 5),
            AutoSize = true
        };

        var lblReason = new Label
        {
            Text = _reason,
            Font = new Font("Segoe UI", 9f, FontStyle.Regular),
            ForeColor = Color.FromArgb(212, 212, 216), // Zinc-300
            Location = new Point(2, 32),
            Size = new Size(420, 36)
        };

        var lblPrompt = new Label
        {
            Text = "Enter Master Password to grant temporary offline access (60 min):",
            Font = new Font("Segoe UI", 8.5f, FontStyle.Regular),
            ForeColor = Color.FromArgb(161, 161, 170),
            Location = new Point(2, 75),
            AutoSize = true
        };

        _txtPassword = new TextBox
        {
            Location = new Point(2, 98),
            Size = new Size(420, 28),
            BackColor = Color.FromArgb(39, 39, 42),
            ForeColor = Color.White,
            BorderStyle = BorderStyle.FixedSingle,
            UseSystemPasswordChar = true,
            Font = new Font("Segoe UI", 10.5f)
        };
        _txtPassword.KeyDown += (s, e) =>
        {
            if (e.KeyCode == Keys.Enter)
            {
                e.SuppressKeyPress = true;
                _btnUnlock.PerformClick();
            }
        };

        _lblStatus = new Label
        {
            Location = new Point(2, 134),
            Size = new Size(420, 20),
            Font = new Font("Segoe UI", 8.5f, FontStyle.Bold),
            ForeColor = Color.Transparent,
            Text = string.Empty
        };

        _btnUnlock = new Button
        {
            Text = "Unlock (60 min)",
            Location = new Point(200, 160),
            Size = new Size(130, 36),
            BackColor = Color.FromArgb(99, 102, 241), // Indigo-500
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat,
            Cursor = Cursors.Hand,
            Font = new Font("Segoe UI", 9f, FontStyle.Bold)
        };
        _btnUnlock.FlatAppearance.BorderSize = 0;
        _btnUnlock.Click += async (s, e) => await OnUnlockClickedAsync();

        _btnDismiss = new Button
        {
            Text = "Dismiss",
            Location = new Point(340, 160),
            Size = new Size(82, 36),
            BackColor = Color.FromArgb(63, 63, 70), // Zinc-700
            ForeColor = Color.FromArgb(244, 244, 245),
            FlatStyle = FlatStyle.Flat,
            Cursor = Cursors.Hand
        };
        _btnDismiss.FlatAppearance.BorderSize = 0;
        _btnDismiss.Click += (s, e) => Close();

        _lblCountdown = new Label
        {
            Text = "Closing in 60s...",
            Location = new Point(2, 168),
            AutoSize = true,
            Font = new Font("Segoe UI", 8f),
            ForeColor = Color.FromArgb(113, 113, 122) // Zinc-500
        };

        var lblVerTag = new Label
        {
            Text = $"AppShield Engine v{version}",
            Location = new Point(2, 186),
            AutoSize = true,
            Font = new Font("Segoe UI", 7.5f),
            ForeColor = Color.FromArgb(82, 82, 91) // Zinc-600
        };

        pnlBody.Controls.Add(lblAppTitle);
        pnlBody.Controls.Add(lblReason);
        pnlBody.Controls.Add(lblPrompt);
        pnlBody.Controls.Add(_txtPassword);
        pnlBody.Controls.Add(_lblStatus);
        pnlBody.Controls.Add(_lblCountdown);
        pnlBody.Controls.Add(lblVerTag);
        pnlBody.Controls.Add(_btnUnlock);
        pnlBody.Controls.Add(_btnDismiss);

        Controls.Add(pnlHeader);
        Controls.Add(pnlBody);
    }

    private void StartCountdown()
    {
        _countdownTimer = new System.Windows.Forms.Timer { Interval = 1000 };
        _countdownTimer.Tick += (s, e) =>
        {
            _remainingSeconds--;
            if (_remainingSeconds <= 0)
            {
                _countdownTimer.Stop();
                Close();
            }
            else
            {
                _lblCountdown.Text = $"Closing in {_remainingSeconds}s...";
            }
        };
        _countdownTimer.Start();
    }

    private async Task OnUnlockClickedAsync()
    {
        string password = _txtPassword.Text;
        if (string.IsNullOrWhiteSpace(password))
        {
            ShowStatus("Please enter the Master Password.", Color.FromArgb(248, 113, 113));
            return;
        }

        _btnUnlock.Enabled = false;
        _btnDismiss.Enabled = false;
        _txtPassword.Enabled = false;
        ShowStatus("Validating with security engine...", Color.FromArgb(147, 197, 253));

        var response = await NamedPipeClient.SendOverrideRequestAsync(_appName, _userSid, password);

        if (response.Success)
        {
            _countdownTimer?.Stop();
            ShowStatus("✓ Access unlocked for 60 minutes!", Color.FromArgb(74, 222, 128));
            await Task.Delay(1200);
            Close();
        }
        else
        {
            ShowStatus($"✗ {response.Message}", Color.FromArgb(248, 113, 113));
            _txtPassword.Enabled = true;
            _btnUnlock.Enabled = true;
            _btnDismiss.Enabled = true;
            _txtPassword.Clear();
            _txtPassword.Focus();
        }
    }

    private void ShowStatus(string msg, Color color)
    {
        _lblStatus.Text = msg;
        _lblStatus.ForeColor = color;
    }

    protected override void OnFormClosed(FormClosedEventArgs e)
    {
        _countdownTimer?.Stop();
        _countdownTimer?.Dispose();
        base.OnFormClosed(e);
    }
}
