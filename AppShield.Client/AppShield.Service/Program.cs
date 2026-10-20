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
builder.Services.AddSingleton<QuotaTracker>();
builder.Services.AddSingleton<EnforcementWorker>();
builder.Services.AddSingleton<OverridePipeServer>();
builder.Services.AddSingleton<MdnsAdvertiser>();

// Initialize Storage and Certificate
var tempStorage = new StorageManager();
string certPath = Path.Combine(tempStorage.BaseDirectory, "cert.pfx");
var cert = CertificateGenerator.GetOrCreateCertificate(certPath);

// Configure Kestrel HTTPS listener on Port 54120
builder.WebHost.ConfigureKestrel(options =>
{
    options.ListenAnyIP(54120, listenOptions =>
    {
        listenOptions.UseHttps(cert);
    });
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

// 4. GET /api/v1/processes
app.MapGet("/api/v1/processes", (StorageManager storage) =>
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
            catch
            {
            }

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
        catch
        {
        }
    }

    return Results.Ok(ApiResponse<List<ProcessInfoDto>>.Ok(results));
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

// 10. POST /api/v1/system/uninstall
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

// Start Background Services
var lifetime = app.Services.GetRequiredService<IHostApplicationLifetime>();
var enforcementWorker = app.Services.GetRequiredService<EnforcementWorker>();
var overridePipeServer = app.Services.GetRequiredService<OverridePipeServer>();
var mdnsAdvertiser = app.Services.GetRequiredService<MdnsAdvertiser>();

lifetime.ApplicationStarted.Register(() =>
{
    Console.WriteLine("[AppShield.Service] Starting background process enforcement engine...");
    enforcementWorker.Start();
    Console.WriteLine("[AppShield.Service] Starting Named Pipe override server...");
    overridePipeServer.Start();
    Console.WriteLine("[AppShield.Service] Advertising via mDNS (_appshield._tcp.local)...");
    mdnsAdvertiser.Start();
    Console.WriteLine("[AppShield.Service] Headless Service & Kestrel API ready on HTTPS port 54120.");
});

lifetime.ApplicationStopping.Register(() =>
{
    Console.WriteLine("[AppShield.Service] Shutting down services...");
    enforcementWorker.Stop();
    overridePipeServer.Stop();
    mdnsAdvertiser.Stop();
});

app.Run();
