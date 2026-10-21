using System.Diagnostics;
using System.Runtime.InteropServices;
using AppShield.Service;
using AppShield.Service.Discovery;
using AppShield.Service.Engine;
using AppShield.Service.IPC;
using AppShield.Service.Maintenance;
using AppShield.Service.Middleware;
using AppShield.Service.Native;
using AppShield.Service.Storage;
using AppShield.Shared.DTOs;
using AppShield.Shared.Models;
using AppShield.Shared.Security;
using Microsoft.Extensions.Hosting.WindowsServices;

var startTimeUtc = DateTime.UtcNow;

var builder = WebApplication.CreateBuilder(args);

// Configure Windows Service Lifetime if running as a Windows Service
if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows) && WindowsServiceHelpers.IsWindowsService())
{
    builder.Services.AddSingleton<IHostLifetime, AppShieldWindowsServiceLifetime>();
}

// Singletons
builder.Services.AddSingleton<StorageManager>();
builder.Services.AddSingleton<FleetManager>();
builder.Services.AddSingleton<QuotaTracker>();
builder.Services.AddSingleton<EnforcementWorker>();
builder.Services.AddSingleton<OverridePipeServer>();
builder.Services.AddSingleton<MdnsAdvertiser>();
builder.Services.AddHttpClient();

// Initialize Storage and Certificate
var tempStorage = new StorageManager();
string certPath = Path.Combine(tempStorage.BaseDirectory, "cert.pfx");
var cert = CertificateGenerator.GetOrCreateCertificate(certPath);

// Configure Kestrel listeners
builder.WebHost.ConfigureKestrel(options =>
{
    // Port 54120: Remote HTTPS listener (Tailscale / LAN / macOS Admin)
    options.ListenAnyIP(54120, listenOptions =>
    {
        listenOptions.UseHttps(cert);
    });

    // Port 54121: Local HTTP listener strictly on localhost for Windows Admin Control Center GUI
    options.ListenLocalhost(54121);
});

var app = builder.Build();

// Enable Authentication Middleware
app.UseMiddleware<AuthMiddleware>();

// 1. GET /api/v1/health
app.MapGet("/api/v1/health", () =>
{
    long uptime = (long)(DateTime.UtcNow - startTimeUtc).TotalSeconds;
    string version = typeof(Program).Assembly.GetName().Version?.ToString(3) ?? "1.0.0";
    var status = new HealthResponseDto
    {
        Hostname = Environment.MachineName,
        OsVersion = Environment.OSVersion.ToString(),
        AgentVersion = version,
        UptimeSeconds = uptime,
        ServerTimeUtc = DateTime.UtcNow
    };
    return Results.Ok(ApiResponse<HealthResponseDto>.Ok(status));
});

// 2. GET /api/v1/users
app.MapGet("/api/v1/users", (StorageManager storage) =>
{
    // Enumerate current local accounts
    var localUsers = Win32ProcessHelper.EnumerateLocalUsers();
    // Sync with database
    storage.UpsertUsers(localUsers);
    var allUsers = storage.GetAllUsers();
    return Results.Ok(ApiResponse<List<UserAccount>>.Ok(allUsers));
});

// 3. POST /api/v1/users/manage
app.MapPost("/api/v1/users/manage", (ManageUserRequestDto req, StorageManager storage) =>
{
    if (string.IsNullOrWhiteSpace(req.Sid))
    {
        return Results.BadRequest(ApiResponse<string>.Fail("User SID is required."));
    }

    storage.UpdateUserManagement(req.Sid, req.IsManaged, req.BlockUserWritableDirectories);
    return Results.Ok(ApiResponse<string>.Ok("User management settings updated successfully."));
});

// 3b. POST /api/v1/users/create-standard (Creates Standard Child User and automatically protects it)
app.MapPost("/api/v1/users/create-standard", (CreateStandardUserRequestDto req, StorageManager storage) =>
{
    if (string.IsNullOrWhiteSpace(req.Username) || string.IsNullOrWhiteSpace(req.Password))
    {
        return Results.BadRequest(ApiResponse<string>.Fail("Username and password are required."));
    }

    string cleanUser = System.Text.RegularExpressions.Regex.Replace(req.Username.Trim(), @"[^a-zA-Z0-9_\-\.]", "");
    if (string.IsNullOrWhiteSpace(cleanUser))
    {
        return Results.BadRequest(ApiResponse<string>.Fail("Invalid username. Alphanumeric characters only."));
    }

    if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
    {
        try
        {
            // 1. Create Windows User
            var psiAdd = new ProcessStartInfo
            {
                FileName = "net.exe",
                Arguments = $"user \"{cleanUser}\" \"{req.Password}\" /add /comment:\"AppShield Managed Child Account\" /passwordchg:no",
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            using var pAdd = Process.Start(psiAdd);
            pAdd?.WaitForExit();
            string err = pAdd?.StandardError.ReadToEnd() ?? "";
            if (pAdd != null && pAdd.ExitCode != 0 && !err.Contains("already exists", StringComparison.OrdinalIgnoreCase))
            {
                return Results.BadRequest(ApiResponse<string>.Fail($"Failed to create Windows account: {err.Trim()}"));
            }

            // 2. Ensure added to standard Users group
            var psiGrp = new ProcessStartInfo
            {
                FileName = "net.exe",
                Arguments = $"localgroup Users \"{cleanUser}\" /add",
                CreateNoWindow = true,
                UseShellExecute = false
            };
            using var pGrp = Process.Start(psiGrp);
            pGrp?.WaitForExit();

            // 3. Ensure removed from Administrators group (Standard account only)
            var psiDelAdmin = new ProcessStartInfo
            {
                FileName = "net.exe",
                Arguments = $"localgroup Administrators \"{cleanUser}\" /delete",
                CreateNoWindow = true,
                UseShellExecute = false
            };
            using var pDel = Process.Start(psiDelAdmin);
            pDel?.WaitForExit();
        }
        catch (Exception ex)
        {
            return Results.StatusCode(500);
        }
    }

    // Refresh users and apply protection
    var localUsers = Win32ProcessHelper.EnumerateLocalUsers();
    storage.UpsertUsers(localUsers);

    var created = localUsers.FirstOrDefault(u => u.Username.Equals(cleanUser, StringComparison.OrdinalIgnoreCase));
    if (created != null)
    {
        storage.UpdateUserManagement(created.Sid, isManaged: true, blockUserWritableDirs: true);
    }

    return Results.Ok(ApiResponse<string>.Ok($"Standard child account '{cleanUser}' created and protected successfully."));
});

// 3c. POST /api/v1/system/open-account-settings (Launches Windows Settings to manage Family & other users)
app.MapPost("/api/v1/system/open-account-settings", () =>
{
    if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
    {
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = "/c start ms-settings:otherusers",
                CreateNoWindow = true,
                UseShellExecute = false
            });
            return Results.Ok(ApiResponse<string>.Ok("Windows Account Settings opened on host."));
        }
        catch (Exception ex)
        {
            return Results.BadRequest(ApiResponse<string>.Fail($"Unable to open Windows Settings: {ex.Message}"));
        }
    }

    return Results.Ok(ApiResponse<string>.Ok("Simulation: Opened Account Settings."));
});

// 4. GET /api/v1/processes
// 4. GET /api/v1/processes
app.MapGet("/api/v1/processes", (StorageManager storage) =>
{
    var results = GetRunningProcesses(storage);
    return Results.Ok(ApiResponse<List<ProcessInfoDto>>.Ok(results));
});

// 4b. DELETE /api/v1/processes/{pid}
app.MapDelete("/api/v1/processes/{pid:int}", (int pid) =>
{
    Win32ProcessHelper.KillProcessTree(pid);
    return Results.Ok(ApiResponse<string>.Ok($"Process {pid} terminated."));
});

// 5. GET /api/v1/rules
app.MapGet("/api/v1/rules", (StorageManager storage) =>
{
    var rules = storage.GetAllRules();
    var overrides = storage.GetActiveOverrides();
    var data = new RulesListResponseDto
    {
        Rules = rules,
        Overrides = overrides
    };
    return Results.Ok(ApiResponse<RulesListResponseDto>.Ok(data));
});

// 6. POST /api/v1/rules
app.MapPost("/api/v1/rules", (CreateRuleRequestDto req, StorageManager storage) =>
{
    if (string.IsNullOrWhiteSpace(req.ProcessName) &&
        string.IsNullOrWhiteSpace(req.OriginalFilename) &&
        string.IsNullOrWhiteSpace(req.Sha256Hash))
    {
        return Results.BadRequest(ApiResponse<string>.Fail("At least one identification layer (ProcessName, OriginalFilename, or Sha256Hash) must be provided."));
    }

    var rule = new Rule
    {
        TargetUserSid = string.IsNullOrWhiteSpace(req.TargetUserSid) ? "*" : req.TargetUserSid,
        RuleType = req.RuleType,
        ProcessName = req.ProcessName?.Trim(),
        OriginalFilename = req.OriginalFilename?.Trim(),
        Sha256Hash = req.Sha256Hash?.Trim(),
        ScheduleStart = req.ScheduleStart?.Trim(),
        ScheduleEnd = req.ScheduleEnd?.Trim(),
        QuotaMinutes = req.QuotaMinutes,
        IsEnabled = true,
        CreatedAtUtc = DateTime.UtcNow,
        Description = string.IsNullOrWhiteSpace(req.Description) ? $"Rule for {req.ProcessName ?? req.OriginalFilename ?? "App"}" : req.Description.Trim()
    };

    storage.SaveRule(rule);
    return Results.Ok(ApiResponse<Rule>.Ok(rule, "Rule created successfully."));
});

// 7. DELETE /api/v1/rules/{id}
app.MapDelete("/api/v1/rules/{id}", (string id, StorageManager storage) =>
{
    bool deleted = storage.DeleteRule(id);
    return deleted
        ? Results.Ok(ApiResponse<string>.Ok("Rule deleted successfully."))
        : Results.NotFound(ApiResponse<string>.Fail("Rule not found."));
});

// 8. POST /api/v1/override
app.MapPost("/api/v1/override", (OverrideRequestDto req, StorageManager storage) =>
{
    if (string.IsNullOrWhiteSpace(req.ProcessName))
    {
        return Results.BadRequest(ApiResponse<string>.Fail("Process name is required."));
    }

    int minutes = req.Minutes > 0 ? req.Minutes : 60;
    var ov = new TemporaryOverride
    {
        UserSid = string.IsNullOrWhiteSpace(req.UserSid) ? "*" : req.UserSid,
        ProcessName = req.ProcessName.Trim(),
        GrantedAtUtc = DateTime.UtcNow,
        ExpiresAtUtc = DateTime.UtcNow.AddMinutes(minutes),
        GrantedBy = "RemoteAdmin"
    };

    storage.AddOverride(ov);
    storage.AddAuditLog(new AuditLog
    {
        UserSid = ov.UserSid,
        Username = "RemoteAdmin",
        ProcessName = ov.ProcessName,
        OriginalFilename = string.Empty,
        Sha256Hash = string.Empty,
        ExecutablePath = string.Empty,
        Action = EnforcementAction.OverrideGranted,
        Reason = $"Remote Admin override granted for {minutes} minutes"
    });

    var response = new OverrideResponseDto
    {
        Success = true,
        Message = $"Temporary override granted for {minutes} minutes.",
        ExpiresAtUtc = ov.ExpiresAtUtc
    };

    return Results.Ok(ApiResponse<OverrideResponseDto>.Ok(response));
});

// 9. GET /api/v1/logs
app.MapGet("/api/v1/logs", (int? limit, int? offset, StorageManager storage) =>
{
    int lim = limit ?? 100;
    int off = offset ?? 0;
    var logs = storage.GetAuditLogs(lim, off);
    return Results.Ok(ApiResponse<List<AuditLog>>.Ok(logs));
});

// 10. GET /api/v1/installed-apps
app.MapGet("/api/v1/installed-apps", (StorageManager storage) =>
{
    var installed = Win32ProcessHelper.EnumerateInstalledApplications();
    var existingRules = storage.GetAllRules();
    var blockedExes = new HashSet<string>(existingRules.Where(r => !string.IsNullOrEmpty(r.ProcessName)).Select(r => r.ProcessName!), StringComparer.OrdinalIgnoreCase);

    foreach (var a in installed)
    {
        if (!string.IsNullOrEmpty(a.ExeName) && blockedExes.Contains(a.ExeName))
        {
            a.IsBlocked = true;
        }
    }

    return Results.Ok(ApiResponse<List<InstalledAppDto>>.Ok(installed));
});

// 11. POST /api/v1/system/uninstall
app.MapPost("/api/v1/system/uninstall", (UninstallRequestDto req, StorageManager storage) =>
{
    if (string.IsNullOrWhiteSpace(req.MasterPassword))
    {
        return Results.BadRequest(ApiResponse<string>.Fail("Master Password is required to authorize uninstallation."));
    }

    bool launched = UninstallRoutine.ExecuteRemoteUninstall(
        storage,
        req.MasterPassword,
        () => AppShieldWindowsServiceLifetime.AllowStop());

    if (!launched)
    {
        return Results.BadRequest(ApiResponse<string>.Fail("Uninstallation authorization rejected. Invalid Master Password."));
    }

    return Results.Ok(ApiResponse<string>.Ok("Remote self-destruct uninstaller initiated successfully."));
});

// ==============================================================================
// 12. Local Windows Control Center GUI & Fleet Manager Routes (Port 54121 / Local)
// ==============================================================================

// Dashboard HTML and Static Assets
app.MapGet("/", async (HttpContext ctx) =>
{
    ctx.Response.ContentType = "text/html; charset=utf-8";
    await ctx.Response.WriteAsync(GetDashboardHtml());
});

app.MapGet("/index.html", async (HttpContext ctx) =>
{
    ctx.Response.ContentType = "text/html; charset=utf-8";
    await ctx.Response.WriteAsync(GetDashboardHtml());
});

app.MapGet("/favicon.jpg", () =>
{
    var stream = typeof(Program).Assembly.GetManifestResourceStream("AppShield.Service.static.favicon.jpg");
    return stream != null ? Results.Stream(stream, "image/jpeg") : Results.NotFound();
});

app.MapGet("/appshield.ico", () =>
{
    string iconPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "appshield.ico");
    return File.Exists(iconPath) ? Results.File(iconPath, "image/x-icon") : Results.NotFound();
});

// Master Password Verification
app.MapPost("/api/auth/verify-master", (VerifyPasswordDto req, StorageManager storage) =>
{
    string storedHash = storage.GetSetting("MasterPasswordHash");
    if (string.IsNullOrEmpty(storedHash))
    {
        return Results.Ok(new { success = true, message = "Authorized" });
    }
    bool valid = CryptoHelper.VerifyPassword(req.Password ?? "", storedHash);
    return valid 
        ? Results.Ok(new { success = true, message = "Authorized" })
        : Results.BadRequest(new { success = false, message = "Invalid Master Password" });
});

// Fleet Management API
app.MapGet("/api/fleet", (FleetManager fm) =>
{
    return Results.Ok(new { success = true, data = fm.GetAll() });
});

app.MapPost("/api/fleet", (FleetNode node, FleetManager fm) =>
{
    var created = fm.Add(node);
    return Results.Ok(new { success = true, data = created });
});

app.MapPut("/api/fleet/{id}", (string id, Dictionary<string, object> updates, FleetManager fm) =>
{
    var updated = fm.Update(id, updates);
    return updated != null 
        ? Results.Ok(new { success = true, data = updated })
        : Results.NotFound(new { success = false, message = "Node not found" });
});

app.MapDelete("/api/fleet/{id}", (string id, FleetManager fm) =>
{
    bool deleted = fm.Delete(id);
    return deleted 
        ? Results.Ok(new { success = true, message = "Node removed" })
        : Results.BadRequest(new { success = false, message = "Cannot delete local node or node not found" });
});

app.MapPost("/api/fleet/{id}/ping", (string id, FleetManager fm) =>
{
    var node = fm.Get(id);
    if (node == null) return Results.NotFound(new { success = false, message = "Node not found" });
    long uptime = (long)(DateTime.UtcNow - startTimeUtc).TotalSeconds;
    return Results.Ok(new { 
        success = true, 
        data = new { 
            is_online = true, 
            hostname = Environment.MachineName, 
            os_version = Environment.OSVersion.ToString(),
            client_version = typeof(Program).Assembly.GetName().Version?.ToString(3) ?? "1.0.0",
            mode = "Local Endpoint",
            uptime_seconds = uptime
        } 
    });
});

app.MapGet("/api/discovery/scan", () =>
{
    return Results.Ok(new { success = true, data = new List<object>() });
});

// Node Process & User Management Endpoints
app.MapGet("/api/nodes/{nodeId}/processes", (string nodeId, StorageManager storage) =>
{
    return Results.Ok(new { success = true, data = GetRunningProcesses(storage) });
});

app.MapDelete("/api/nodes/{nodeId}/processes/{pid:int}", (string nodeId, int pid) =>
{
    Win32ProcessHelper.KillProcessTree(pid);
    return Results.Ok(new { success = true, message = "Process terminated" });
});

app.MapGet("/api/nodes/{nodeId}/users", (string nodeId, StorageManager storage) =>
{
    var localUsers = Win32ProcessHelper.EnumerateLocalUsers();
    storage.UpsertUsers(localUsers);
    return Results.Ok(new { success = true, data = storage.GetAllUsers() });
});

app.MapPost("/api/nodes/{nodeId}/users/manage", (string nodeId, ManageUserRequestDto req, StorageManager storage) =>
{
    storage.UpdateUserManagement(req.Sid, req.IsManaged, req.BlockUserWritableDirectories);
    return Results.Ok(new { success = true, message = "User settings updated" });
});

app.MapPost("/api/nodes/{nodeId}/users/create-standard", (string nodeId, CreateStandardUserRequestDto req, StorageManager storage) =>
{
    if (string.IsNullOrWhiteSpace(req.Username) || string.IsNullOrWhiteSpace(req.Password))
    {
        return Results.BadRequest(new { success = false, error = "Username and password are required." });
    }

    string cleanUser = System.Text.RegularExpressions.Regex.Replace(req.Username.Trim(), @"[^a-zA-Z0-9_\-\.]", "");
    if (string.IsNullOrWhiteSpace(cleanUser))
    {
        return Results.BadRequest(new { success = false, error = "Invalid username." });
    }

    if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
    {
        try
        {
            var psiAdd = new ProcessStartInfo
            {
                FileName = "net.exe",
                Arguments = $"user \"{cleanUser}\" \"{req.Password}\" /add /comment:\"AppShield Managed Child Account\" /passwordchg:no",
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            using var pAdd = Process.Start(psiAdd);
            pAdd?.WaitForExit();

            var psiGrp = new ProcessStartInfo
            {
                FileName = "net.exe",
                Arguments = $"localgroup Users \"{cleanUser}\" /add",
                CreateNoWindow = true,
                UseShellExecute = false
            };
            using var pGrp = Process.Start(psiGrp);
            pGrp?.WaitForExit();

            var psiDelAdmin = new ProcessStartInfo
            {
                FileName = "net.exe",
                Arguments = $"localgroup Administrators \"{cleanUser}\" /delete",
                CreateNoWindow = true,
                UseShellExecute = false
            };
            using var pDel = Process.Start(psiDelAdmin);
            pDel?.WaitForExit();
        }
        catch { }
    }

    var localUsers = Win32ProcessHelper.EnumerateLocalUsers();
    storage.UpsertUsers(localUsers);

    var created = localUsers.FirstOrDefault(u => u.Username.Equals(cleanUser, StringComparison.OrdinalIgnoreCase));
    if (created != null)
    {
        storage.UpdateUserManagement(created.Sid, isManaged: true, blockUserWritableDirs: true);
    }

    return Results.Ok(new { success = true, message = $"Standard child account '{cleanUser}' created and protected." });
});

app.MapPost("/api/nodes/{nodeId}/system/open-account-settings", () =>
{
    if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
    {
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = "/c start ms-settings:otherusers",
                CreateNoWindow = true,
                UseShellExecute = false
            });
            return Results.Ok(new { success = true, message = "Opened Windows Account Settings" });
        }
        catch (Exception ex)
        {
            return Results.BadRequest(new { success = false, error = ex.Message });
        }
    }
    return Results.Ok(new { success = true, message = "Simulation: Opened Account Settings" });
});

app.MapGet("/api/nodes/{nodeId}/rules", (string nodeId, StorageManager storage) =>
{
    return Results.Ok(new { 
        success = true, 
        data = new { 
            rules = storage.GetAllRules(), 
            overrides = storage.GetActiveOverrides() 
        } 
    });
});

app.MapPost("/api/nodes/{nodeId}/rules", (string nodeId, CreateRuleRequestDto req, StorageManager storage) =>
{
    var rule = new Rule
    {
        TargetUserSid = string.IsNullOrWhiteSpace(req.TargetUserSid) ? "*" : req.TargetUserSid,
        RuleType = req.RuleType,
        ProcessName = req.ProcessName?.Trim(),
        OriginalFilename = req.OriginalFilename?.Trim(),
        Sha256Hash = req.Sha256Hash?.Trim(),
        ScheduleStart = req.ScheduleStart?.Trim(),
        ScheduleEnd = req.ScheduleEnd?.Trim(),
        QuotaMinutes = req.QuotaMinutes,
        IsEnabled = true,
        CreatedAtUtc = DateTime.UtcNow,
        Description = string.IsNullOrWhiteSpace(req.Description) ? $"Rule for {req.ProcessName ?? req.OriginalFilename ?? "App"}" : req.Description.Trim()
    };
    storage.SaveRule(rule);
    return Results.Ok(new { success = true, data = rule, message = "Rule created" });
});

app.MapDelete("/api/nodes/{nodeId}/rules/{ruleId}", (string nodeId, string ruleId, StorageManager storage) =>
{
    bool deleted = storage.DeleteRule(ruleId);
    return deleted 
        ? Results.Ok(new { success = true, message = "Rule deleted" })
        : Results.NotFound(new { success = false, message = "Rule not found" });
});

app.MapPost("/api/nodes/{nodeId}/override", (string nodeId, OverrideRequestDto req, StorageManager storage) =>
{
    int minutes = req.Minutes > 0 ? req.Minutes : 60;
    var ov = new TemporaryOverride
    {
        UserSid = string.IsNullOrWhiteSpace(req.UserSid) ? "*" : req.UserSid,
        ProcessName = req.ProcessName.Trim(),
        GrantedAtUtc = DateTime.UtcNow,
        ExpiresAtUtc = DateTime.UtcNow.AddMinutes(minutes),
        GrantedBy = "LocalAdmin"
    };
    storage.AddOverride(ov);
    return Results.Ok(new { success = true, data = new { success = true, message = $"Override granted for {minutes} min.", expiresAtUtc = ov.ExpiresAtUtc } });
});

app.MapGet("/api/nodes/{nodeId}/logs", (string nodeId, int? limit, StorageManager storage) =>
{
    var logs = storage.GetAuditLogs(limit ?? 100, 0);
    return Results.Ok(new { success = true, data = logs });
});

app.MapGet("/api/nodes/{nodeId}/installed-apps", (string nodeId, StorageManager storage) =>
{
    var installed = Win32ProcessHelper.EnumerateInstalledApplications();
    var existingRules = storage.GetAllRules();
    var blockedExes = new HashSet<string>(existingRules.Where(r => !string.IsNullOrEmpty(r.ProcessName)).Select(r => r.ProcessName!), StringComparer.OrdinalIgnoreCase);
    foreach (var a in installed)
    {
        if (!string.IsNullOrEmpty(a.ExeName) && blockedExes.Contains(a.ExeName))
        {
            a.IsBlocked = true;
        }
    }
    return Results.Ok(new { success = true, data = installed });
});

app.MapPost("/api/nodes/{nodeId}/system/uninstall", (string nodeId, UninstallRequestDto req, StorageManager storage) =>
{
    if (string.IsNullOrWhiteSpace(req.MasterPassword))
    {
        return Results.BadRequest(new { success = false, message = "Master Password required" });
    }
    bool launched = UninstallRoutine.ExecuteRemoteUninstall(
        storage,
        req.MasterPassword,
        () => AppShieldWindowsServiceLifetime.AllowStop());
    return launched 
        ? Results.Ok(new { success = true, message = "Uninstallation started" })
        : Results.BadRequest(new { success = false, message = "Invalid Master Password" });
});

// Start Background Services
var lifetime = app.Services.GetRequiredService<IHostApplicationLifetime>();
var enforcementWorker = app.Services.GetRequiredService<EnforcementWorker>();
var overridePipeServer = app.Services.GetRequiredService<OverridePipeServer>();
var mdnsAdvertiser = app.Services.GetRequiredService<MdnsAdvertiser>();

lifetime.ApplicationStarted.Register(() =>
{
    string version = typeof(Program).Assembly.GetName().Version?.ToString(3) ?? "1.0.0";
    Console.WriteLine($"[AppShield.Service] AppShield Windows Service v{version} initialized.");
    Console.WriteLine("[AppShield.Service] Starting background process enforcement engine...");
    enforcementWorker.Start();
    Console.WriteLine("[AppShield.Service] Starting Named Pipe override server...");
    overridePipeServer.Start();
    Console.WriteLine("[AppShield.Service] Advertising via mDNS (_appshield._tcp.local)...");
    mdnsAdvertiser.Start();
    Console.WriteLine($"[AppShield.Service] Headless Service & Kestrel API ready on HTTPS port 54120 and Local Dashboard on HTTP port 54121 (v{version}).");
});

lifetime.ApplicationStopping.Register(() =>
{
    Console.WriteLine("[AppShield.Service] Shutting down services...");
    enforcementWorker.Stop();
    overridePipeServer.Stop();
    mdnsAdvertiser.Stop();
});

app.Run();

// ==============================================================================
// Helper Methods
// ==============================================================================

static string GetDashboardHtml()
{
    try
    {
        string diskPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "static", "index.html");
        if (File.Exists(diskPath))
        {
            return File.ReadAllText(diskPath);
        }
    }
    catch { }

    try
    {
        using var stream = typeof(Program).Assembly.GetManifestResourceStream("AppShield.Service.static.index.html");
        if (stream != null)
        {
            using var reader = new StreamReader(stream);
            return reader.ReadToEnd();
        }
    }
    catch { }

    return "<html><body><h2>AppShield Control Center</h2><p>Dashboard HTML loading...</p></body></html>";
}

static List<ProcessInfoDto> GetRunningProcesses(StorageManager storage)
{
    var users = storage.GetAllUsers().ToDictionary(u => u.Sid, u => u, StringComparer.OrdinalIgnoreCase);
    var results = new List<ProcessInfoDto>();
    var processes = Process.GetProcesses();

    foreach (var proc in processes)
    {
        try
        {
            int pid = proc.Id;
            if (pid <= 4) continue;

            string procName = proc.ProcessName;
            string exePath = string.Empty;
            double memoryMb = 0;

            try
            {
                exePath = proc.MainModule?.FileName ?? string.Empty;
                memoryMb = Math.Round(proc.WorkingSet64 / (1024.0 * 1024.0), 1);
            }
            catch { }

            var (username, domain, sid) = Win32ProcessHelper.GetProcessOwner(pid);

            bool isManaged = false;
            if (!string.IsNullOrEmpty(sid) && users.TryGetValue(sid, out var userAcc))
            {
                isManaged = userAcc.IsManaged;
            }

            string originalFilename = string.Empty;
            string sha256 = string.Empty;
            if (!string.IsNullOrEmpty(exePath))
            {
                originalFilename = Win32ProcessHelper.GetOriginalFilename(exePath);
                sha256 = CryptoHelper.ComputeFileSha256(exePath);
            }

            int sessionId = 0;
            try { sessionId = proc.SessionId; } catch { }

            results.Add(new ProcessInfoDto
            {
                Pid = pid,
                ProcessName = procName + ".exe",
                ExecutablePath = exePath,
                OriginalFilename = originalFilename,
                Sha256Hash = sha256,
                MemoryMB = memoryMb,
                SessionId = sessionId,
                Username = username,
                Domain = domain,
                Sid = sid,
                IsManagedUser = isManaged
            });
        }
        catch { }
    }

    return results;
}

public class VerifyPasswordDto
{
    public string? Password { get; set; }
}

public class CreateStandardUserRequestDto
{
    public string? Username { get; set; }
    public string? Password { get; set; }
}

