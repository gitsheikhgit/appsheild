using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using AppShield.Service.Native;
using AppShield.Service.Storage;
using AppShield.Shared.DTOs;
using AppShield.Shared.Models;
using Microsoft.Extensions.Hosting;

namespace AppShield.Service.Engine;

/// <summary>
/// Background worker that maintains an outbound real-time WebSocket connection to the AppShield Central Server.
/// Streams live telemetry (running user applications, installed apps, and user accounts) and handles
/// inbound commands (remote SIGKILL, screen lock, curfew rule sync, and family DNS filtering).
/// </summary>
public class CentralServerRelayWorker : BackgroundService
{
    private readonly StorageManager _storage;
    private readonly HttpClient _httpClient;
    private string _deviceId = string.Empty;
    private string _serverUrl = "http://192.168.0.101:8000";

    [DllImport("user32.dll")]
    private static extern bool LockWorkStation();

    public CentralServerRelayWorker(StorageManager storage, IHttpClientFactory httpClientFactory)
    {
        _storage = storage;
        _httpClient = httpClientFactory.CreateClient();
    }

    private void LoadOrCreateConfig()
    {
        string settingsPath = Path.Combine(_storage.BaseDirectory, "settings.json");
        string cfgPath = Path.Combine(_storage.BaseDirectory, "agent_config.json");
        try
        {
            string path = File.Exists(settingsPath) ? settingsPath : (File.Exists(cfgPath) ? cfgPath : string.Empty);
            if (!string.IsNullOrEmpty(path))
            {
                string json = File.ReadAllText(path);
                using var doc = JsonDocument.Parse(json);
                if (doc.RootElement.TryGetProperty("device_id", out var dId))
                    _deviceId = dId.GetString() ?? string.Empty;
                if (doc.RootElement.TryGetProperty("server_url", out var sUrl))
                    _serverUrl = sUrl.GetString() ?? "http://192.168.0.101:8000";
            }
        }
        catch { }

        if (string.IsNullOrWhiteSpace(_deviceId))
        {
            _deviceId = $"win_{Guid.NewGuid().ToString("N")[..12]}";
            var cfg = new Dictionary<string, string>
            {
                ["device_id"] = _deviceId,
                ["name"] = Environment.MachineName,
                ["server_url"] = _serverUrl,
                ["tailscale_ip"] = GetTailscaleIpAddress() ?? string.Empty
            };
            try
            {
                File.WriteAllText(settingsPath, JsonSerializer.Serialize(cfg, new JsonSerializerOptions { WriteIndented = true }));
            }
            catch { }
        }
    }

    private static string GetLocalIpAddress()
    {
        try
        {
            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, 0);
            socket.Connect("8.8.8.8", 80);
            return (socket.LocalEndPoint as System.Net.IPEndPoint)?.Address.ToString() ?? "127.0.0.1";
        }
        catch
        {
            return "127.0.0.1";
        }
    }

    private static string? GetTailscaleIpAddress()
    {
        try
        {
            var interfaces = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces();
            foreach (var iface in interfaces)
            {
                if (iface.OperationalStatus != System.Net.NetworkInformation.OperationalStatus.Up)
                    continue;

                var ipProps = iface.GetIPProperties();
                foreach (var unicast in ipProps.UnicastAddresses)
                {
                    if (unicast.Address.AddressFamily == AddressFamily.InterNetwork)
                    {
                        string ipStr = unicast.Address.ToString();
                        if (ipStr.StartsWith("100."))
                            return ipStr;
                    }
                }
            }
        }
        catch { }
        return null;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        LoadOrCreateConfig();

        // 1. Check for Standalone Mode (Zero Server Needed)
        if (string.IsNullOrWhiteSpace(_serverUrl) || _serverUrl.Equals("standalone", StringComparison.OrdinalIgnoreCase))
        {
            Console.WriteLine("[AppShield] CentralServerRelayWorker: Operating in STANDALONE Protection Mode (No Server Configured).");
            Console.WriteLine("[AppShield] Local curfews, process blocking, and path jails are fully active.");
            while (!stoppingToken.IsCancellationRequested)
            {
                await Task.Delay(10000, stoppingToken);
                LoadOrCreateConfig();
                if (!string.IsNullOrWhiteSpace(_serverUrl) && !_serverUrl.Equals("standalone", StringComparison.OrdinalIgnoreCase))
                    break;
            }
        }

        // 2. Register with Central Server
        await RegisterDeviceAsync(stoppingToken);

        // 3. Reconnecting WebSocket loop
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                string wsUrl = _serverUrl.Replace("http://", "ws://").Replace("https://", "wss://");
                var uri = new Uri($"{wsUrl}/ws/agent/{_deviceId}");

                using var ws = new ClientWebSocket();
                ws.Options.KeepAliveInterval = TimeSpan.FromSeconds(20);

                using var connectCts = new CancellationTokenSource(TimeSpan.FromSeconds(8));
                using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken, connectCts.Token);

                await ws.ConnectAsync(uri, linkedCts.Token);
                Console.WriteLine($"[+] Connected outbound WebSocket to AppShield Central Server: {uri}");

                var receiveTask = ReceiveCommandsLoopAsync(ws, stoppingToken);
                var telemetryTask = TelemetryLoopAsync(ws, stoppingToken);

                await Task.WhenAny(receiveTask, telemetryTask);
            }
            catch (Exception)
            {
                // Fallback to HTTP telemetry polling if websocket fails
                try
                {
                    await SendHttpTelemetryAsync(stoppingToken);
                }
                catch { }

                await Task.Delay(5000, stoppingToken);
            }
        }
    }

    private async Task RegisterDeviceAsync(CancellationToken ct)
    {
        try
        {
            var reg = new
            {
                id = _deviceId,
                name = Environment.MachineName,
                os = "Windows 11 (64-bit)",
                lan_ip = GetLocalIpAddress(),
                tailscale_ip = GetTailscaleIpAddress() ?? string.Empty,
                agent_version = "1.3.3"
            };
            await _httpClient.PostAsJsonAsync($"{_serverUrl}/api/devices/register", reg, ct);
        }
        catch { }
    }

    private async Task TelemetryLoopAsync(ClientWebSocket ws, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested && ws.State == WebSocketState.Open)
        {
            try
            {
                var procs = GetCleanUserApplications();
                var users = _storage.GetAllUsers();
                var installed = Win32ProcessHelper.EnumerateInstalledApplications();

                var telemetry = new
                {
                    device_id = _deviceId,
                    tailscale_ip = GetTailscaleIpAddress() ?? string.Empty,
                    timestamp = DateTime.UtcNow.ToString("o"),
                    users = users.Select(u => new
                    {
                        sid = u.Sid,
                        username = u.Username,
                        accountType = u.IsAdmin ? "Administrator" : "Standard User",
                        isManaged = u.IsManaged,
                        blockUserWritableDirectories = u.BlockUserWritableDirectories
                    }),
                    processes = procs,
                    installed_apps = installed.Select(a => new
                    {
                        DisplayName = a.DisplayName,
                        Publisher = a.Publisher,
                        DisplayVersion = a.DisplayVersion,
                        ExeName = a.ExeName,
                        InstallLocation = a.InstallPath,
                        IsBlocked = a.IsBlocked
                    })
                };

                byte[] buffer = JsonSerializer.SerializeToUtf8Bytes(telemetry);
                await ws.SendAsync(new ArraySegment<byte>(buffer), WebSocketMessageType.Text, true, ct);
            }
            catch { }

            await Task.Delay(6000, ct);
        }
    }

    private async Task SendHttpTelemetryAsync(CancellationToken ct)
    {
        var procs = GetCleanUserApplications();
        var users = _storage.GetAllUsers();
        var installed = Win32ProcessHelper.EnumerateInstalledApplications();

        var telemetry = new
        {
            device_id = _deviceId,
            tailscale_ip = GetTailscaleIpAddress() ?? string.Empty,
            processes = procs,
            users = users.Select(u => new
            {
                sid = u.Sid,
                username = u.Username,
                accountType = u.IsAdmin ? "Administrator" : "Standard User",
                isManaged = u.IsManaged,
                blockUserWritableDirectories = u.BlockUserWritableDirectories
            }),
            installed_apps = installed.Select(a => new
            {
                DisplayName = a.DisplayName,
                Publisher = a.Publisher,
                DisplayVersion = a.DisplayVersion,
                ExeName = a.ExeName,
                InstallLocation = a.InstallPath,
                IsBlocked = a.IsBlocked
            })
        };

        await _httpClient.PostAsJsonAsync($"{_serverUrl}/api/agent/telemetry", telemetry, ct);
    }

    private async Task ReceiveCommandsLoopAsync(ClientWebSocket ws, CancellationToken ct)
    {
        var buffer = new byte[8192];
        while (!ct.IsCancellationRequested && ws.State == WebSocketState.Open)
        {
            var result = await ws.ReceiveAsync(new ArraySegment<byte>(buffer), ct);
            if (result.MessageType == WebSocketMessageType.Close)
            {
                break;
            }

            string json = Encoding.UTF8.GetString(buffer, 0, result.Count);
            ExecuteCommand(json);
        }
    }

    private void ExecuteCommand(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            string action = root.GetProperty("action").GetString() ?? string.Empty;
            var payload = root.TryGetProperty("payload", out var p) ? p : default;

            switch (action)
            {
                case "kill_process":
                    if (payload.TryGetProperty("pid", out var pidElem))
                    {
                        int pid = pidElem.GetInt32();
                        Win32ProcessHelper.KillProcessTree(pid);
                        Console.WriteLine($"[+] Terminated PID {pid} per parent request.");
                    }
                    break;

                case "lock_device":
                    if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                    {
                        LockWorkStation();
                        Console.WriteLine("[+] Windows workstation locked per parent request.");
                    }
                    break;

                case "grant_override":
                    if (payload.TryGetProperty("process_name", out var procElem))
                    {
                        string proc = procElem.GetString() ?? string.Empty;
                        int mins = payload.TryGetProperty("minutes", out var mElem) ? mElem.GetInt32() : 60;
                        if (!string.IsNullOrEmpty(proc))
                        {
                            var ov = new TemporaryOverride
                            {
                                UserSid = "*",
                                ProcessName = proc.Trim(),
                                GrantedAtUtc = DateTime.UtcNow,
                                ExpiresAtUtc = DateTime.UtcNow.AddMinutes(mins),
                                GrantedBy = "CentralServer"
                            };
                            _storage.AddOverride(ov);
                            Console.WriteLine($"[+] Override granted for {proc} for {mins} minutes.");
                        }
                    }
                    break;

                case "set_dns_filter":
                    if (payload.TryGetProperty("primary_dns", out var dns1Elem))
                    {
                        string dns1 = dns1Elem.GetString() ?? "1.1.1.1";
                        string dns2 = payload.TryGetProperty("secondary_dns", out var dns2Elem) ? dns2Elem.GetString() ?? "1.0.0.1" : "1.0.0.1";
                        string ipv6_1 = payload.TryGetProperty("primary_ipv6", out var ipv61Elem) ? ipv61Elem.GetString() ?? "" : "";
                        string ipv6_2 = payload.TryGetProperty("secondary_ipv6", out var ipv62Elem) ? ipv62Elem.GetString() ?? "" : "";
                        bool isEnabled = !payload.TryGetProperty("is_enabled", out var enElem) || enElem.GetInt32() == 1;

                        ApplyWindowsDnsFilter(dns1, dns2, ipv6_1, ipv6_2, isEnabled);
                    }
                    break;

                case "sync_rules":
                    _ = SyncRulesFromServerAsync();
                    break;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[-] Error executing inbound command: {ex.Message}");
        }
    }

    private static void ApplyWindowsDnsFilter(string primaryDns, string secondaryDns, string primaryIpv6, string secondaryIpv6, bool isEnabled)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return;

        try
        {
            string args;
            if (isEnabled && !string.IsNullOrWhiteSpace(primaryDns))
            {
                var addrs = new List<string>();
                if (!string.IsNullOrWhiteSpace(primaryDns)) addrs.Add($"'{primaryDns.Trim()}'");
                if (!string.IsNullOrWhiteSpace(secondaryDns)) addrs.Add($"'{secondaryDns.Trim()}'");
                if (!string.IsNullOrWhiteSpace(primaryIpv6) && primaryIpv6.Trim().ToUpper() != "N/A") addrs.Add($"'{primaryIpv6.Trim()}'");
                if (!string.IsNullOrWhiteSpace(secondaryIpv6) && secondaryIpv6.Trim().ToUpper() != "N/A") addrs.Add($"'{secondaryIpv6.Trim()}'");

                string addrList = string.Join(",", addrs);
                args = $"-NoProfile -ExecutionPolicy Bypass -Command \"Set-DnsClientServerAddress -InterfaceAlias '*' -ServerAddresses ({addrList}); Clear-DnsClientCache\"";
            }
            else
            {
                args = "-NoProfile -ExecutionPolicy Bypass -Command \"Set-DnsClientServerAddress -InterfaceAlias '*' -ResetServerAddresses; Clear-DnsClientCache\"";
            }

            var psi = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = args,
                CreateNoWindow = true,
                UseShellExecute = false
            };
            using var p = Process.Start(psi);
            p?.WaitForExit(3000);
            Console.WriteLine($"[+] Applied Windows Family DNS Protection: {primaryDns}, {secondaryDns}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[-] Error applying Windows DNS: {ex.Message}");
        }
    }

    private async Task SyncRulesFromServerAsync()
    {
        try
        {
            var res = await _httpClient.GetFromJsonAsync<JsonElement>($"{_serverUrl}/api/nodes/{_deviceId}/rules");
            if (res.TryGetProperty("data", out var data))
            {
                if (data.TryGetProperty("rules", out var rulesElem) && rulesElem.ValueKind == JsonValueKind.Array)
                {
                    foreach (var r in rulesElem.EnumerateArray())
                    {
                        string rtStr = r.TryGetProperty("rule_type", out var rtElem) ? rtElem.GetString() ?? "AllowedWindow" : "AllowedWindow";
                        RuleType parsedType = Enum.TryParse<RuleType>(rtStr, true, out var t) ? t : RuleType.AllowedWindow;
                        var rule = new Rule
                        {
                            Id = r.TryGetProperty("id", out var idElem) ? idElem.GetString() ?? Guid.NewGuid().ToString("N") : Guid.NewGuid().ToString("N"),
                            TargetUserSid = r.TryGetProperty("target_process", out var tElem) ? tElem.GetString() ?? "*" : "*",
                            RuleType = parsedType,
                            ProcessName = r.TryGetProperty("target_process", out var tpElem) ? tpElem.GetString() : string.Empty,
                            ScheduleStart = r.TryGetProperty("schedule_start", out var ssElem) ? ssElem.GetString() : "12:00",
                            ScheduleEnd = r.TryGetProperty("schedule_end", out var seElem) ? seElem.GetString() : "20:00",
                            IsEnabled = !r.TryGetProperty("is_enabled", out var ieElem) || ieElem.GetInt32() == 1,
                            CreatedAtUtc = DateTime.UtcNow
                        };
                        _storage.SaveRule(rule);
                    }
                }
            }
        }
        catch { }
    }

    /// <summary>
    /// Scans Windows and filters ONLY real user-facing desktop applications.
    /// Completely hides Session 0 background services, svchost, csrss, lsass, and OS kernel threads.
    /// </summary>
    public List<ProcessInfoDto> GetCleanUserApplications()
    {
        var users = _storage.GetAllUsers().ToDictionary(u => u.Sid, u => u, StringComparer.OrdinalIgnoreCase);
        var results = new List<ProcessInfoDto>();
        var seenApps = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // Standard Windows background helper / system components to ignore
        string[] ignoredServices =
        [
            "svchost", "smss", "csrss", "services", "lsass", "wininit", "winlogon",
            "RuntimeBroker", "dwm", "conhost", "spoolsv", "taskhostw", "SearchHost",
            "StartMenuExperienceHost", "ShellExperienceHost", "SystemSettings", "ctfmon",
            "TextInputHost", "LockApp", "Taskmgr", "explorer", "sihost", "fontdrvhost",
            "wlanext", "dllhost", "smartscreen", "SecurityHealthService", "SearchIndexer"
        ];

        try
        {
            var processes = Process.GetProcesses();
            foreach (var proc in processes)
            {
                try
                {
                    int pid = proc.Id;
                    if (pid <= 4) continue;

                    // Exclude Session 0 (Headless Windows Services)
                    try
                    {
                        if (proc.SessionId == 0) continue;
                    }
                    catch { }

                    string procName = proc.ProcessName;
                    if (ignoredServices.Contains(procName, StringComparer.OrdinalIgnoreCase))
                        continue;

                    string exePath = string.Empty;
                    double memoryMb = 0;

                    try
                    {
                        exePath = proc.MainModule?.FileName ?? string.Empty;
                        memoryMb = Math.Round(proc.WorkingSet64 / (1024.0 * 1024.0), 1);
                    }
                    catch { }

                    var (username, domain, sid) = Win32ProcessHelper.GetProcessOwner(pid);

                    // Skip NT AUTHORITY and SYSTEM background helpers
                    if (string.Equals(domain, "NT AUTHORITY", StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(username, "SYSTEM", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    string cleanDisplayName = procName;
                    if (cleanDisplayName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                        cleanDisplayName = cleanDisplayName[..^4];

                    if (seenApps.Contains(cleanDisplayName))
                        continue;
                    seenApps.Add(cleanDisplayName);

                    bool isManaged = false;
                    if (!string.IsNullOrEmpty(sid) && users.TryGetValue(sid, out var userAcc))
                    {
                        isManaged = userAcc.IsManaged;
                    }

                    results.Add(new ProcessInfoDto
                    {
                        Pid = pid,
                        ProcessName = cleanDisplayName,
                        ExecutablePath = !string.IsNullOrEmpty(exePath) ? exePath : $"C:\\Program Files\\{cleanDisplayName}\\{cleanDisplayName}.exe",
                        OriginalFilename = cleanDisplayName,
                        Sha256Hash = string.Empty,
                        MemoryMB = memoryMb > 0 ? memoryMb : 45.0,
                        SessionId = proc.SessionId,
                        Username = !string.IsNullOrEmpty(username) ? username : "Active User",
                        Domain = domain,
                        Sid = sid,
                        IsManagedUser = isManaged
                    });
                }
                catch { }
            }
        }
        catch { }

        return results.OrderBy(p => p.ProcessName).ToList();
    }
}
