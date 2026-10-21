using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using AppShield.Service.Native;
using AppShield.Service.Storage;
using AppShield.Shared.DTOs;
using AppShield.Shared.Models;
using AppShield.Shared.Security;

namespace AppShield.Service.Engine;

public class EnforcementWorker : IDisposable
{
    private readonly StorageManager _storage;
    private readonly QuotaTracker _quotaTracker;
    private readonly ConcurrentDictionary<string, DateTime> _promptCooldowns = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<int, DateTime> _trackedProcessPids = new();

    private CancellationTokenSource? _cts;
    private Task? _pollingTask;
    private IDisposable? _wmiWatcher;

    public EnforcementWorker(StorageManager storage, QuotaTracker quotaTracker)
    {
        _storage = storage;
        _quotaTracker = quotaTracker;
    }

    public void Start()
    {
        _cts = new CancellationTokenSource();

        // 1. Start immediate WMI Process Creation Watcher on Windows
        StartWmiWatcher();

        // 2. Start fast 1,500ms safety polling loop
        _pollingTask = Task.Run(() => PollingLoopAsync(_cts.Token));
    }

    public void Stop()
    {
        _cts?.Cancel();
        _wmiWatcher?.Dispose();
        _wmiWatcher = null;
    }

    public void Dispose()
    {
        Stop();
        _cts?.Dispose();
    }

    private void StartWmiWatcher()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return;

        try
        {
            var watcher = new System.Management.ManagementEventWatcher("SELECT * FROM Win32_ProcessStartTrace");
            watcher.EventArrived += (sender, e) =>
            {
                try
                {
                    int pid = Convert.ToInt32(e.NewEvent.Properties["ProcessID"].Value);
                    string procName = e.NewEvent.Properties["ProcessName"]?.Value?.ToString() ?? string.Empty;
                    EvaluateProcessById(pid, procName);
                }
                catch
                {
                }
            };
            watcher.Start();
            _wmiWatcher = new DisposableAction(() =>
            {
                try { watcher.Stop(); } catch { }
                watcher.Dispose();
            });
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[EnforcementWorker] WMI Watcher initialization notice: {ex.Message}");
        }
    }

    private class DisposableAction : IDisposable
    {
        private readonly Action _action;
        public DisposableAction(Action action) => _action = action;
        public void Dispose() => _action();
    }

    private async Task PollingLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                ScanAllProcesses();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[EnforcementWorker] Polling error: {ex.Message}");
            }

            try
            {
                await Task.Delay(1500, ct);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }

    public void ScanAllProcesses()
    {
        var users = _storage.GetAllUsers().ToDictionary(u => u.Sid, u => u, StringComparer.OrdinalIgnoreCase);
        var rules = _storage.GetAllRules().Where(r => r.IsEnabled).ToList();
        var overrides = _storage.GetActiveOverrides();

        var processes = Process.GetProcesses();
        var currentPids = new HashSet<int>();

        foreach (var proc in processes)
        {
            currentPids.Add(proc.Id);
            EvaluateProcess(proc, users, rules, overrides);
        }

        // Clean stale tracked PIDs
        foreach (var pid in _trackedProcessPids.Keys)
        {
            if (!currentPids.Contains(pid))
            {
                _trackedProcessPids.TryRemove(pid, out _);
            }
        }
    }

    private void EvaluateProcessById(int pid, string fallbackProcName)
    {
        try
        {
            using var proc = Process.GetProcessById(pid);
            var users = _storage.GetAllUsers().ToDictionary(u => u.Sid, u => u, StringComparer.OrdinalIgnoreCase);
            var rules = _storage.GetAllRules().Where(r => r.IsEnabled).ToList();
            var overrides = _storage.GetActiveOverrides();
            EvaluateProcess(proc, users, rules, overrides);
        }
        catch
        {
        }
    }

    private void EvaluateProcess(Process proc, Dictionary<string, UserAccount> users, List<Rule> rules, List<TemporaryOverride> overrides)
    {
        int pid = proc.Id;
        if (pid <= 4) return; // System idle / System

        string procName = proc.ProcessName;
        string exeName = procName + ".exe";
        string exePath = string.Empty;

        try
        {
            exePath = proc.MainModule?.FileName ?? string.Empty;
        }
        catch
        {
            // Permission denied (e.g. system services)
        }

        // Win32 Token inspection
        var (username, domain, sid) = Win32ProcessHelper.GetProcessOwner(pid);
        if (string.IsNullOrEmpty(sid))
            return;

        // Exempt system accounts
        if (sid.Equals("S-1-5-18", StringComparison.OrdinalIgnoreCase) || // SYSTEM
            sid.Equals("S-1-5-19", StringComparison.OrdinalIgnoreCase) || // LOCAL SERVICE
            sid.Equals("S-1-5-20", StringComparison.OrdinalIgnoreCase))   // NETWORK SERVICE
        {
            return;
        }

        // Find user account
        if (!users.TryGetValue(sid, out var userAccount))
        {
            // Unregistered user, treat as unmanaged
            return;
        }

        // Unmanaged accounts or Admin accounts (unless explicitly managed) have zero restrictions
        if (!userAccount.IsManaged || (userAccount.IsAdmin && !userAccount.IsManaged))
        {
            return;
        }

        // Check if there is an active temporary override
        bool hasOverride = overrides.Any(o =>
            (o.UserSid == "*" || o.UserSid.Equals(sid, StringComparison.OrdinalIgnoreCase)) &&
            (o.ProcessName.Equals(procName, StringComparison.OrdinalIgnoreCase) ||
             o.ProcessName.Equals(exeName, StringComparison.OrdinalIgnoreCase)));

        if (hasOverride)
        {
            return;
        }

        string originalFilename = string.Empty;
        string sha256Hash = string.Empty;

        if (!string.IsNullOrEmpty(exePath))
        {
            originalFilename = Win32ProcessHelper.GetOriginalFilename(exePath);
            sha256Hash = CryptoHelper.ComputeFileSha256(exePath);
        }

        // 1. Check Path Jail (BlockUserWritableDirectories)
        if (userAccount.BlockUserWritableDirectories && !string.IsNullOrEmpty(exePath))
        {
            if (Win32ProcessHelper.IsUserWritablePath(exePath))
            {
                // Check if explicitly whitelisted by rule
                bool isWhitelisted = rules.Any(r =>
                    r.RuleType != RuleType.AlwaysBlock &&
                    IsRuleMatch(r, exeName, originalFilename, sha256Hash));

                if (!isWhitelisted)
                {
                    BlockProcess(proc, sid, username, procName, originalFilename, sha256Hash, exePath, "Path Jail: Launched from user-writable directory");
                    return;
                }
            }
        }

        // 2. Evaluate User Rules
        var applicableRules = rules.Where(r => r.TargetUserSid == "*" || r.TargetUserSid.Equals(sid, StringComparison.OrdinalIgnoreCase)).ToList();

        foreach (var rule in applicableRules)
        {
            if (!IsRuleMatch(rule, exeName, originalFilename, sha256Hash))
                continue;

            switch (rule.RuleType)
            {
                case RuleType.AlwaysBlock:
                    BlockProcess(proc, sid, username, procName, originalFilename, sha256Hash, exePath, $"AlwaysBlock rule triggered: {rule.Description}");
                    return;

                case RuleType.ScheduleBlock:
                    if (IsScheduleActive(rule.ScheduleStart, rule.ScheduleEnd))
                    {
                        BlockProcess(proc, sid, username, procName, originalFilename, sha256Hash, exePath, $"Schedule block window active ({rule.ScheduleStart} - {rule.ScheduleEnd})");
                        return;
                    }
                    break;

                case RuleType.DailyQuota:
                    if (rule.QuotaMinutes.HasValue && rule.QuotaMinutes.Value > 0)
                    {
                        // Track runtime
                        int activeSec = _quotaTracker.RecordActiveRuntime(sid, procName, 2 /* polling window roughly ~1.5 - 2s */);
                        if (_quotaTracker.IsQuotaExceeded(sid, procName, rule.QuotaMinutes.Value))
                        {
                            BlockProcess(proc, sid, username, procName, originalFilename, sha256Hash, exePath, $"Daily quota exceeded ({rule.QuotaMinutes.Value} minutes max)");
                            return;
                        }
                    }
                    break;

                case RuleType.AllowedWindow:
                    // Only allowed between ScheduleStart and ScheduleEnd. If NOT active, terminate!
                    if (!IsScheduleActive(rule.ScheduleStart, rule.ScheduleEnd))
                    {
                        BlockProcess(proc, sid, username, procName, originalFilename, sha256Hash, exePath, $"Outside allowed usage window (Allowed: {rule.ScheduleStart} - {rule.ScheduleEnd})");
                        return;
                    }
                    break;
            }
        }
    }

    private static bool IsRuleMatch(Rule rule, string exeName, string originalFilename, string sha256Hash)
    {
        // Layer 1: Executable name match
        if (!string.IsNullOrWhiteSpace(rule.ProcessName))
        {
            string target = rule.ProcessName.Trim();
            if (exeName.Equals(target, StringComparison.OrdinalIgnoreCase) ||
                Path.GetFileNameWithoutExtension(exeName).Equals(Path.GetFileNameWithoutExtension(target), StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        // Layer 2: PE Header OriginalFilename match
        if (!string.IsNullOrWhiteSpace(rule.OriginalFilename) && !string.IsNullOrWhiteSpace(originalFilename))
        {
            if (originalFilename.Equals(rule.OriginalFilename.Trim(), StringComparison.OrdinalIgnoreCase) ||
                Path.GetFileNameWithoutExtension(originalFilename).Equals(Path.GetFileNameWithoutExtension(rule.OriginalFilename.Trim()), StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        // Layer 3: SHA-256 hash match
        if (!string.IsNullOrWhiteSpace(rule.Sha256Hash) && !string.IsNullOrWhiteSpace(sha256Hash))
        {
            if (sha256Hash.Equals(rule.Sha256Hash.Trim(), StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsScheduleActive(string? startStr, string? endStr)
    {
        if (string.IsNullOrWhiteSpace(startStr) || string.IsNullOrWhiteSpace(endStr))
            return false;

        if (!TimeSpan.TryParse(startStr, out var startTime) || !TimeSpan.TryParse(endStr, out var endTime))
            return false;

        var now = DateTime.Now.TimeOfDay;

        if (startTime <= endTime)
        {
            // Standard daytime window, e.g. 09:00 to 17:00
            return now >= startTime && now <= endTime;
        }
        else
        {
            // Overnight window, e.g. 21:00 to 07:00
            return now >= startTime || now <= endTime;
        }
    }

    private void BlockProcess(Process proc, string userSid, string username, string procName, string origFile, string hash, string exePath, string reason)
    {
        int pid = proc.Id;
        int sessionId = 0;
        try { sessionId = proc.SessionId; } catch { }

        // Kill process tree immediately
        Win32ProcessHelper.KillProcessTree(pid);

        // Record audit log
        _storage.AddAuditLog(new AuditLog
        {
            UserSid = userSid,
            Username = username,
            ProcessName = procName + ".exe",
            OriginalFilename = origFile,
            Sha256Hash = hash,
            ExecutablePath = exePath,
            Action = EnforcementAction.Blocked,
            Reason = reason
        });

        // Prompt cooldown (30 seconds per app + user)
        string cooldownKey = $"{userSid}:{procName}";
        bool canPrompt = true;
        if (_promptCooldowns.TryGetValue(cooldownKey, out var lastPromptUtc))
        {
            if (DateTime.UtcNow - lastPromptUtc < TimeSpan.FromSeconds(30))
            {
                canPrompt = false;
            }
        }

        if (canPrompt)
        {
            _promptCooldowns[cooldownKey] = DateTime.UtcNow;
            SessionLauncher.LaunchPromptInSession(sessionId, procName + ".exe", userSid, reason);
        }
    }
}
