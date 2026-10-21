using System.Diagnostics;
using System.IO.Compression;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using AppShield.Shared.Models;
using AppShield.Shared.Security;
using Microsoft.Data.Sqlite;
using Microsoft.Win32;

namespace AppShield.Installer;

public record MachineSetupSummary(
    string MachineName,
    List<string> IpAddresses,
    int Port,
    string PreSharedKey,
    string MasterPassword,
    string InstallDirectory
);

public static class InstallEngine
{
    public const string ServiceName = "AppShieldService";
    public const string FirewallRuleName = "AppShield_API_Port";
    public const int DefaultPort = 54120;

    public static string GetDefaultInstallDirectory()
    {
        string progFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        return Path.Combine(progFiles, "AppShield");
    }

    public static string GetInstallDirectory()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
                using var key = baseKey.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\AppShield");
                string? loc = key?.GetValue("InstallLocation")?.ToString();
                if (!string.IsNullOrEmpty(loc) && Directory.Exists(loc))
                {
                    return loc;
                }
            }
            catch { }
        }

        return GetDefaultInstallDirectory();
    }

    public static string GetDataDirectory()
    {
        string progData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        return Path.Combine(progData, "AppShield");
    }

    public static bool IsInstalled()
    {
        string installDir = GetInstallDirectory();
        string dataDir = GetDataDirectory();
        string svcExe = Path.Combine(installDir, "AppShield.Service.exe");
        string db = Path.Combine(dataDir, "appshield.db");
        return File.Exists(svcExe) && File.Exists(db);
    }

    public static void LaunchControlCenter()
    {
        string url = "http://127.0.0.1:54121";

        // Start service if stopped
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            try
            {
                RunCommand("net.exe", "start AppShieldService");
            }
            catch { }
        }

        // Look for Edge (Chromium) or Chrome to launch in dedicated app window mode
        string edge1 = @"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe";
        string edge2 = @"C:\Program Files\Microsoft\Edge\Application\msedge.exe";
        string chrome1 = @"C:\Program Files\Google\Chrome\Application\chrome.exe";
        string chrome2 = @"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe";

        string? browser = null;
        if (File.Exists(edge1)) browser = edge1;
        else if (File.Exists(edge2)) browser = edge2;
        else if (File.Exists(chrome1)) browser = chrome1;
        else if (File.Exists(chrome2)) browser = chrome2;

        try
        {
            if (!string.IsNullOrEmpty(browser))
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = browser,
                    Arguments = $"--app={url} --window-size=1380,880",
                    UseShellExecute = true
                });
            }
            else
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = url,
                    UseShellExecute = true
                });
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Unable to launch browser window: {ex.Message}\r\nPlease open http://127.0.0.1:54121 in your browser.", "AppShield", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
    }

    public static bool IsCurrentProcessElevatedAdmin()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return true;

        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    public static string GeneratePsk()
    {
        byte[] bytes = RandomNumberGenerator.GetBytes(16);
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    public static MachineSetupSummary RunInstall(
        string installDir,
        string masterPassword,
        string psk,
        bool createDesktopShortcut,
        Action<int, string> progress)
    {
        if (string.IsNullOrWhiteSpace(installDir))
        {
            installDir = GetDefaultInstallDirectory();
        }

        string dataDir = GetDataDirectory();

        // 1. Stop and clean any existing service
        progress(10, "Stopping any existing AppShield service...");
        RunCommand("sc.exe", $"stop {ServiceName}");
        RunCommand("sc.exe", $"delete {ServiceName}");
        Thread.Sleep(1500);

        // 2. Prepare directories
        progress(25, $"Creating installation directory at {installDir}...");
        Directory.CreateDirectory(installDir);
        Directory.CreateDirectory(dataDir);

        // 3. Extract payload binaries
        progress(40, "Extracting AppShield engine and security binaries...");
        ExtractPayload(installDir);

        // Copy self to installDir as AppShield-Setup.exe and AppShield.exe
        string targetSetupExe = Path.Combine(installDir, "AppShield-Setup.exe");
        try
        {
            string currentExe = Environment.ProcessPath ?? "";
            if (File.Exists(currentExe))
            {
                if (!string.Equals(currentExe, targetSetupExe, StringComparison.OrdinalIgnoreCase))
                {
                    File.Copy(currentExe, targetSetupExe, true);
                }
            }
        }
        catch { }

        // 4. Secure Data Directory with strict NTFS ACLs
        progress(55, "Enforcing NTFS Access Control Lists (SYSTEM & Admins only)...");
        EnforceDirectorySecurity(dataDir);

        // 5. Initialize database & credentials
        progress(70, "Storing security credentials and encryption keys...");
        InitializeCredentials(dataDir, masterPassword, psk);

        // 6. Register Windows Service
        progress(80, "Registering Windows Service (NT AUTHORITY\\SYSTEM)...");
        string serviceExePath = Path.Combine(installDir, "AppShield.Service.exe");
        RunCommand("sc.exe", $"create {ServiceName} binPath= \"\\\"{serviceExePath}\\\"\" start= auto DisplayName= \"AppShield Security Service\"");
        RunCommand("sc.exe", $"description {ServiceName} \"Tamper-resistant application control and multi-user endpoint management service.\"");
        RunCommand("sc.exe", $"failure {ServiceName} reset= 0 actions= restart/1000/restart/1000/restart/1000");

        // 7. Configure Firewall Rule
        progress(88, "Opening Windows Defender Firewall port 54120...");
        RunCommand("netsh.exe", $"advfirewall firewall delete rule name=\"{FirewallRuleName}\"");
        RunCommand("netsh.exe", $"advfirewall firewall add rule name=\"{FirewallRuleName}\" dir=in action=allow protocol=TCP localport={DefaultPort}");

        // 8. Register in Windows Settings (Apps & features)
        progress(92, "Registering in Windows Settings (Installed Apps)...");
        RegisterInWindowsSettings(installDir);

        // 9. Create Desktop and Start Menu (Applications) Shortcuts for Administrator
        progress(95, "Creating Desktop and Applications icons for Administrator...");
        string iconPath = Path.Combine(installDir, "appshield.ico");
        CreateShortcuts(targetSetupExe, iconPath, createDesktopShortcut);

        // 10. Start Windows Service
        progress(98, "Starting AppShield Security Service...");
        RunCommand("sc.exe", $"start {ServiceName}");

        progress(100, "AppShield successfully installed and activated!");

        // Collect network summary
        var ips = GetLocalIpAddresses();
        return new MachineSetupSummary(
            Environment.MachineName,
            ips,
            DefaultPort,
            psk,
            masterPassword,
            installDir
        );
    }

    public static bool RunUninstall(string masterPassword, Action<int, string> progress, out string error)
    {
        error = string.Empty;
        string installDir = GetInstallDirectory();
        string dataDir = GetDataDirectory();

        // 1. Verify Master Password against database
        string storedHash = GetStoredMasterPasswordHash(dataDir);
        if (!string.IsNullOrEmpty(storedHash))
        {
            if (!CryptoHelper.VerifyPassword(masterPassword, storedHash))
            {
                error = "Incorrect Master Password. Uninstallation unauthorized and blocked.";
                return false;
            }
        }

        // 2. Stop and delete service
        progress(15, "Stopping AppShield Security Service...");
        RunCommand("sc.exe", $"stop {ServiceName}");
        Thread.Sleep(1000);

        progress(35, "Removing Windows Service registration...");
        RunCommand("sc.exe", $"delete {ServiceName}");

        // 3. Remove Firewall rule
        progress(50, "Removing Windows Firewall rules...");
        RunCommand("netsh.exe", $"advfirewall firewall delete rule name=\"{FirewallRuleName}\"");

        // 4. Remove Desktop and Applications shortcuts
        progress(65, "Removing Desktop and Applications shortcuts...");
        RemoveShortcuts();

        // 5. Unregister from Windows Settings
        progress(75, "Removing Windows Settings entry...");
        UnregisterFromWindowsSettings();

        // 6. Delete ProgramData
        progress(85, "Cleaning application data and database...");
        try
        {
            if (Directory.Exists(dataDir))
            {
                Directory.Delete(dataDir, true);
            }
        }
        catch { }

        // 7. Delete ProgramFiles (including AppShield-Setup.exe itself) via delayed background command
        progress(100, "AppShield has been completely uninstalled.");
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = $"/c timeout /t 2 /nobreak > NUL & for /l %i in (1,1,5) do (if exist \"{installDir}\" (rmdir /s /q \"{installDir}\" & timeout /t 1 > NUL))",
                CreateNoWindow = true,
                UseShellExecute = false
            };
            Process.Start(psi);
        }
        catch { }

        return true;
    }

    public static void CreateShortcuts(string targetExe, string iconPath, bool createDesktopShortcut)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return;

        try
        {
            // Administrator's user profile desktop & start menu
            string adminDesktopDir = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
            string adminProgramsDir = Environment.GetFolderPath(Environment.SpecialFolder.Programs);
            Directory.CreateDirectory(adminProgramsDir);

            string desktopShortcut = Path.Combine(adminDesktopDir, "AppShield.lnk");
            string startMenuShortcut = Path.Combine(adminProgramsDir, "AppShield.lnk");

            var sb = new StringBuilder();
            sb.AppendLine("$ws = New-Object -ComObject WScript.Shell");

            if (createDesktopShortcut)
            {
                sb.AppendLine($"$d = $ws.CreateShortcut('{desktopShortcut}')");
                sb.AppendLine($"$d.TargetPath = '{targetExe}'");
                sb.AppendLine($"$d.IconLocation = '{iconPath},0'");
                sb.AppendLine($"$d.Description = 'AppShield Security Control Center'");
                sb.AppendLine("$d.Save()");
            }

            // Applications / Start Menu icon is always installed for Admin
            sb.AppendLine($"$s = $ws.CreateShortcut('{startMenuShortcut}')");
            sb.AppendLine($"$s.TargetPath = '{targetExe}'");
            sb.AppendLine($"$s.IconLocation = '{iconPath},0'");
            sb.AppendLine($"$s.Description = 'AppShield Security Control Center'");
            sb.AppendLine("$s.Save()");

            RunCommand("powershell.exe", $"-NoProfile -ExecutionPolicy Bypass -Command \"{sb}\"");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Shortcut Warning] {ex.Message}");
        }
    }

    public static void RemoveShortcuts()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return;

        try
        {
            // Clean admin desktop and common desktop
            string adminDesktop = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), "AppShield.lnk");
            if (File.Exists(adminDesktop)) File.Delete(adminDesktop);

            string commonDesktop = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory), "AppShield.lnk");
            if (File.Exists(commonDesktop)) File.Delete(commonDesktop);

            // Clean admin programs and common programs
            string adminPrograms = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Programs), "AppShield.lnk");
            if (File.Exists(adminPrograms)) File.Delete(adminPrograms);

            string commonPrograms = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonStartMenu), "Programs", "AppShield.lnk");
            if (File.Exists(commonPrograms)) File.Delete(commonPrograms);
        }
        catch { }
    }

    private static void ExtractPayload(string installDir)
    {
        var assembly = Assembly.GetExecutingAssembly();
        using var stream = assembly.GetManifestResourceStream("AppShield.Installer.payload.zip");

        if (stream != null)
        {
            using var zip = new ZipArchive(stream, ZipArchiveMode.Read);
            foreach (var entry in zip.Entries)
            {
                if (string.IsNullOrEmpty(entry.Name)) continue;
                string destPath = Path.Combine(installDir, entry.FullName);
                entry.ExtractToFile(destPath, overwrite: true);
            }
            return;
        }

        // Fallback: Check if binaries exist in the current executable's folder (development mode)
        string baseDir = AppDomain.CurrentDomain.BaseDirectory;
        string svc = Path.Combine(baseDir, "AppShield.Service.exe");
        string pmt = Path.Combine(baseDir, "AppShield.Prompt.exe");
        if (File.Exists(svc) && File.Exists(pmt))
        {
            File.Copy(svc, Path.Combine(installDir, "AppShield.Service.exe"), true);
            File.Copy(pmt, Path.Combine(installDir, "AppShield.Prompt.exe"), true);
            string ico = Path.Combine(baseDir, "appshield.ico");
            if (File.Exists(ico)) File.Copy(ico, Path.Combine(installDir, "appshield.ico"), true);
            return;
        }

        throw new FileNotFoundException("Embedded payload.zip was not found in the installer assembly.");
    }

    public static void EnforceDirectorySecurity(string dirPath)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return;

        try
        {
            var dInfo = new DirectoryInfo(dirPath);
            var dSecurity = dInfo.GetAccessControl();

            dSecurity.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

            var currentRules = dSecurity.GetAccessRules(true, true, typeof(SecurityIdentifier));
            foreach (FileSystemAccessRule rule in currentRules)
            {
                dSecurity.RemoveAccessRuleSpecific(rule);
            }

            var systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            dSecurity.AddAccessRule(new FileSystemAccessRule(
                systemSid,
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));

            var adminSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            dSecurity.AddAccessRule(new FileSystemAccessRule(
                adminSid,
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));

            dInfo.SetAccessControl(dSecurity);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ACL Warning] {ex.Message}");
        }
    }

    public static void InitializeCredentials(string dataDir, string masterPassword, string psk)
    {
        string dbPath = Path.Combine(dataDir, "appshield.db");
        using var conn = new SqliteConnection($"Data Source={dbPath}");
        conn.Open();

        string createSql = @"
            CREATE TABLE IF NOT EXISTS Settings (
                Key TEXT PRIMARY KEY,
                Value TEXT NOT NULL,
                IsEncrypted INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS Users (
                Sid TEXT PRIMARY KEY,
                Username TEXT NOT NULL,
                Domain TEXT NOT NULL,
                IsAdmin INTEGER NOT NULL DEFAULT 0,
                IsManaged INTEGER NOT NULL DEFAULT 0,
                BlockUserWritableDirectories INTEGER NOT NULL DEFAULT 0,
                LastSeenUtc TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS Rules (
                Id TEXT PRIMARY KEY,
                TargetUserSid TEXT NOT NULL,
                RuleType TEXT NOT NULL,
                ProcessName TEXT,
                OriginalFilename TEXT,
                Sha256Hash TEXT,
                ScheduleStart TEXT,
                ScheduleEnd TEXT,
                QuotaMinutes INTEGER,
                IsEnabled INTEGER NOT NULL DEFAULT 1,
                CreatedAtUtc TEXT NOT NULL,
                Description TEXT
            );
            CREATE TABLE IF NOT EXISTS AuditLogs (
                Id TEXT PRIMARY KEY,
                TimestampUtc TEXT NOT NULL,
                UserSid TEXT NOT NULL,
                Username TEXT NOT NULL,
                ProcessName TEXT NOT NULL,
                OriginalFilename TEXT NOT NULL,
                Sha256Hash TEXT NOT NULL,
                ExecutablePath TEXT NOT NULL,
                Action TEXT NOT NULL,
                Reason TEXT NOT NULL
            );";
        using (var cmd = new SqliteCommand(createSql, conn))
        {
            cmd.ExecuteNonQuery();
        }

        string hash = CryptoHelper.HashPassword(masterPassword);
        using (var cmd = new SqliteCommand(@"
            INSERT INTO Settings (Key, Value, IsEncrypted) VALUES ('MasterPasswordHash', @val, 0)
            ON CONFLICT(Key) DO UPDATE SET Value = @val, IsEncrypted = 0", conn))
        {
            cmd.Parameters.AddWithValue("@val", hash);
            cmd.ExecuteNonQuery();
        }

        string storedPsk = psk;
        bool isEncrypted = false;
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            try
            {
                byte[] plainBytes = Encoding.UTF8.GetBytes(psk);
                byte[] protectedBytes = ProtectedData.Protect(plainBytes, null, DataProtectionScope.LocalMachine);
                storedPsk = Convert.ToBase64String(protectedBytes);
                isEncrypted = true;
            }
            catch { }
        }

        using (var cmd = new SqliteCommand(@"
            INSERT INTO Settings (Key, Value, IsEncrypted) VALUES ('PreSharedKey', @val, @enc)
            ON CONFLICT(Key) DO UPDATE SET Value = @val, IsEncrypted = @enc", conn))
        {
            cmd.Parameters.AddWithValue("@val", storedPsk);
            cmd.Parameters.AddWithValue("@enc", isEncrypted ? 1 : 0);
            cmd.ExecuteNonQuery();
        }
    }

    public static string GetStoredMasterPasswordHash(string dataDir)
    {
        string dbPath = Path.Combine(dataDir, "appshield.db");
        if (!File.Exists(dbPath)) return string.Empty;

        try
        {
            using var conn = new SqliteConnection($"Data Source={dbPath}");
            conn.Open();
            using var cmd = new SqliteCommand("SELECT Value FROM Settings WHERE Key = 'MasterPasswordHash'", conn);
            var res = cmd.ExecuteScalar();
            return res?.ToString() ?? string.Empty;
        }
        catch
        {
            return string.Empty;
        }
    }

    public static string GetStoredPsk(string dataDir)
    {
        string dbPath = Path.Combine(dataDir, "appshield.db");
        if (!File.Exists(dbPath)) return string.Empty;

        try
        {
            using var conn = new SqliteConnection($"Data Source={dbPath}");
            conn.Open();
            using var cmd = new SqliteCommand("SELECT Value, IsEncrypted FROM Settings WHERE Key = 'PreSharedKey'", conn);
            using var reader = cmd.ExecuteReader();
            if (reader.Read())
            {
                string val = reader.GetString(0);
                bool isEncrypted = reader.GetInt32(1) == 1;
                if (isEncrypted && RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    try
                    {
                        byte[] cipherBytes = Convert.FromBase64String(val);
                        byte[] plainBytes = ProtectedData.Unprotect(cipherBytes, null, DataProtectionScope.LocalMachine);
                        return Encoding.UTF8.GetString(plainBytes);
                    }
                    catch { }
                }
                return val;
            }
        }
        catch { }
        return string.Empty;
    }

    public static List<UserAccount> GetUsersFromDb(string dataDir)
    {
        var list = new List<UserAccount>();
        string dbPath = Path.Combine(dataDir, "appshield.db");
        if (!File.Exists(dbPath)) return list;

        try
        {
            using var conn = new SqliteConnection($"Data Source={dbPath}");
            conn.Open();
            using var cmd = new SqliteCommand("SELECT Sid, Username, Domain, IsAdmin, IsManaged, BlockUserWritableDirectories, LastSeenUtc FROM Users", conn);
            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                list.Add(new UserAccount
                {
                    Sid = reader.GetString(0),
                    Username = reader.GetString(1),
                    Domain = reader.GetString(2),
                    IsAdmin = reader.GetInt32(3) == 1,
                    IsManaged = reader.GetInt32(4) == 1,
                    BlockUserWritableDirectories = reader.GetInt32(5) == 1,
                    LastSeenUtc = DateTime.TryParse(reader.GetString(6), out var dt) ? dt : DateTime.UtcNow
                });
            }
        }
        catch { }
        return list;
    }

    public static void UpdateUserInDb(string dataDir, string sid, bool isManaged, bool blockUserWritable)
    {
        string dbPath = Path.Combine(dataDir, "appshield.db");
        if (!File.Exists(dbPath)) return;

        try
        {
            using var conn = new SqliteConnection($"Data Source={dbPath}");
            conn.Open();
            using var cmd = new SqliteCommand(@"
                UPDATE Users 
                SET IsManaged = @man, BlockUserWritableDirectories = @block 
                WHERE Sid = @sid", conn);
            cmd.Parameters.AddWithValue("@sid", sid);
            cmd.Parameters.AddWithValue("@man", isManaged ? 1 : 0);
            cmd.Parameters.AddWithValue("@block", blockUserWritable ? 1 : 0);
            cmd.ExecuteNonQuery();
        }
        catch { }
    }

    public static List<Rule> GetRulesFromDb(string dataDir)
    {
        var list = new List<Rule>();
        string dbPath = Path.Combine(dataDir, "appshield.db");
        if (!File.Exists(dbPath)) return list;

        try
        {
            using var conn = new SqliteConnection($"Data Source={dbPath}");
            conn.Open();
            using var cmd = new SqliteCommand("SELECT Id, TargetUserSid, RuleType, ProcessName, OriginalFilename, Sha256Hash, IsEnabled, CreatedAtUtc, Description FROM Rules", conn);
            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                list.Add(new Rule
                {
                    Id = reader.GetString(0),
                    TargetUserSid = reader.GetString(1),
                    RuleType = Enum.TryParse<RuleType>(reader.GetString(2), out var rt) ? rt : RuleType.AlwaysBlock,
                    ProcessName = reader.IsDBNull(3) ? null : reader.GetString(3),
                    OriginalFilename = reader.IsDBNull(4) ? null : reader.GetString(4),
                    Sha256Hash = reader.IsDBNull(5) ? null : reader.GetString(5),
                    IsEnabled = reader.GetInt32(6) == 1,
                    CreatedAtUtc = DateTime.TryParse(reader.GetString(7), out var dt) ? dt : DateTime.UtcNow,
                    Description = reader.IsDBNull(8) ? "" : reader.GetString(8)
                });
            }
        }
        catch { }
        return list;
    }

    public static void AddRuleToDb(string dataDir, string processName, string description)
    {
        string dbPath = Path.Combine(dataDir, "appshield.db");
        if (!File.Exists(dbPath)) return;

        try
        {
            using var conn = new SqliteConnection($"Data Source={dbPath}");
            conn.Open();
            using var cmd = new SqliteCommand(@"
                INSERT INTO Rules (Id, TargetUserSid, RuleType, ProcessName, IsEnabled, CreatedAtUtc, Description)
                VALUES (@id, '*', 'AlwaysBlock', @proc, 1, @now, @desc)", conn);
            cmd.Parameters.AddWithValue("@id", Guid.NewGuid().ToString("N"));
            cmd.Parameters.AddWithValue("@proc", processName.Trim());
            cmd.Parameters.AddWithValue("@now", DateTime.UtcNow.ToString("o"));
            cmd.Parameters.AddWithValue("@desc", string.IsNullOrEmpty(description) ? $"Blocked {processName}" : description);
            cmd.ExecuteNonQuery();
        }
        catch { }
    }

    public static void DeleteRuleFromDb(string dataDir, string ruleId)
    {
        string dbPath = Path.Combine(dataDir, "appshield.db");
        if (!File.Exists(dbPath)) return;

        try
        {
            using var conn = new SqliteConnection($"Data Source={dbPath}");
            conn.Open();
            using var cmd = new SqliteCommand("DELETE FROM Rules WHERE Id = @id", conn);
            cmd.Parameters.AddWithValue("@id", ruleId);
            cmd.ExecuteNonQuery();
        }
        catch { }
    }

    public static List<AuditLog> GetAuditLogsFromDb(string dataDir, int limit = 50)
    {
        var list = new List<AuditLog>();
        string dbPath = Path.Combine(dataDir, "appshield.db");
        if (!File.Exists(dbPath)) return list;

        try
        {
            using var conn = new SqliteConnection($"Data Source={dbPath}");
            conn.Open();
            using var cmd = new SqliteCommand(@"
                SELECT Id, TimestampUtc, Username, ProcessName, Action, Reason 
                FROM AuditLogs 
                ORDER BY TimestampUtc DESC 
                LIMIT @lim", conn);
            cmd.Parameters.AddWithValue("@lim", limit);
            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                list.Add(new AuditLog
                {
                    Id = reader.GetString(0),
                    TimestampUtc = DateTime.TryParse(reader.GetString(1), out var dt) ? dt : DateTime.UtcNow,
                    Username = reader.GetString(2),
                    ProcessName = reader.GetString(3),
                    Action = Enum.TryParse<EnforcementAction>(reader.GetString(4), out var act) ? act : EnforcementAction.Blocked,
                    Reason = reader.GetString(5)
                });
            }
        }
        catch { }
        return list;
    }

    public static void RegisterInWindowsSettings(string installDir)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return;

        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var key = baseKey.CreateSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\AppShield");
            if (key != null)
            {
                string iconPath = Path.Combine(installDir, "appshield.ico");
                string setupPath = Path.Combine(installDir, "AppShield-Setup.exe");

                key.SetValue("DisplayName", "AppShield Security Client");
                key.SetValue("DisplayVersion", "1.0.0");
                key.SetValue("Publisher", "AppShield Security Systems");
                key.SetValue("DisplayIcon", $"{iconPath},0");
                key.SetValue("InstallLocation", installDir);
                key.SetValue("UninstallString", $"\"{setupPath}\" --uninstall");
                key.SetValue("QuietUninstallString", $"\"{setupPath}\" --uninstall --silent");
                key.SetValue("NoModify", 1, RegistryValueKind.DWord);
                key.SetValue("NoRepair", 1, RegistryValueKind.DWord);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Registry Warning] {ex.Message}");
        }
    }

    public static void UnregisterFromWindowsSettings()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return;

        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            baseKey.DeleteSubKeyTree(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\AppShield", false);
        }
        catch { }
    }

    public static (int ExitCode, string Output) RunCommand(string fileName, string args)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = args,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var proc = Process.Start(psi);
            if (proc == null) return (-1, "Failed to start process");

            string stdout = proc.StandardOutput.ReadToEnd();
            string stderr = proc.StandardError.ReadToEnd();
            proc.WaitForExit();
            return (proc.ExitCode, stdout + "\n" + stderr);
        }
        catch (Exception ex)
        {
            return (-1, ex.Message);
        }
    }

    public static List<string> GetLocalIpAddresses()
    {
        var ips = new List<string>();
        try
        {
            var host = Dns.GetHostEntry(Dns.GetHostName());
            foreach (var ip in host.AddressList)
            {
                if (ip.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(ip))
                {
                    string ipStr = ip.ToString();
                    if (!ipStr.StartsWith("169.254")) // ignore APIPA
                    {
                        ips.Add(ipStr);
                    }
                }
            }
        }
        catch { }

        if (ips.Count == 0) ips.Add("127.0.0.1");
        return ips;
    }
}
