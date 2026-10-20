using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using AppShield.Shared.DTOs;
using AppShield.Shared.Models;
using AppShield.Shared.Security;
using Microsoft.Data.Sqlite;

namespace AppShield.Service.Storage;

public class StorageManager
{
    private readonly string _baseDir;
    private readonly string _dbPath;
    private readonly string _connectionString;
    private readonly object _lock = new();

    public StorageManager(string? baseDir = null)
    {
        if (!string.IsNullOrEmpty(baseDir))
        {
            _baseDir = baseDir;
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            _baseDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "AppShield");
        }
        else
        {
            _baseDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Data");
        }

        Directory.CreateDirectory(_baseDir);
        EnforceDirectorySecurity(_baseDir);

        _dbPath = Path.Combine(_baseDir, "appshield.db");
        _connectionString = $"Data Source={_dbPath}";

        InitializeDatabase();
    }

    public string BaseDirectory => _baseDir;
    public string DatabasePath => _dbPath;

    /// <summary>
    /// Programmatically enforces NTFS ACLs on C:\ProgramData\AppShield:
    /// - Disables inheritance (SetAccessRuleProtection(true, false))
    /// - Grants FileSystemRights.FullControl exclusively to SYSTEM and BUILTIN\Administrators.
    /// </summary>
    private void EnforceDirectorySecurity(string dirPath)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return;

        try
        {
            var dInfo = new DirectoryInfo(dirPath);
            var dSecurity = dInfo.GetAccessControl();

            // Disable inheritance and remove inherited rules
            dSecurity.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

            // Remove all existing explicit rules
            var currentRules = dSecurity.GetAccessRules(true, true, typeof(SecurityIdentifier));
            foreach (FileSystemAccessRule rule in currentRules)
            {
                dSecurity.RemoveAccessRuleSpecific(rule);
            }

            // Grant FullControl exclusively to NT AUTHORITY\SYSTEM
            var systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            dSecurity.AddAccessRule(new FileSystemAccessRule(
                systemSid,
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));

            // Grant FullControl exclusively to BUILTIN\Administrators
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
            Console.WriteLine($"[StorageManager] Warning: Failed to set NTFS ACLs: {ex.Message}");
        }
    }

    /// <summary>
    /// DPAPI encryption for local machine secrets.
    /// </summary>
    public string ProtectSecret(string plainText)
    {
        if (string.IsNullOrEmpty(plainText))
            return string.Empty;

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            try
            {
                byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
                byte[] protectedBytes = ProtectedData.Protect(plainBytes, null, DataProtectionScope.LocalMachine);
                return Convert.ToBase64String(protectedBytes);
            }
            catch
            {
            }
        }

        // Fallback for non-Windows dev host
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(plainText));
    }

    /// <summary>
    /// DPAPI decryption for local machine secrets.
    /// </summary>
    public string UnprotectSecret(string cipherText)
    {
        if (string.IsNullOrEmpty(cipherText))
            return string.Empty;

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            try
            {
                byte[] cipherBytes = Convert.FromBase64String(cipherText);
                byte[] plainBytes = ProtectedData.Unprotect(cipherBytes, null, DataProtectionScope.LocalMachine);
                return Encoding.UTF8.GetString(plainBytes);
            }
            catch
            {
            }
        }

        try
        {
            return Encoding.UTF8.GetString(Convert.FromBase64String(cipherText));
        }
        catch
        {
            return cipherText;
        }
    }

    private void InitializeDatabase()
    {
        lock (_lock)
        {
            using var conn = new SqliteConnection(_connectionString);
            conn.Open();

            string createTablesSql = @"
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

                CREATE TABLE IF NOT EXISTS DailyQuotas (
                    Id TEXT PRIMARY KEY,
                    UserSid TEXT NOT NULL,
                    ProcessName TEXT NOT NULL,
                    Date TEXT NOT NULL,
                    ActiveSeconds INTEGER NOT NULL DEFAULT 0,
                    LastActiveTimestampUtc TEXT NOT NULL,
                    UNIQUE(UserSid, ProcessName, Date)
                );

                CREATE TABLE IF NOT EXISTS Overrides (
                    Id TEXT PRIMARY KEY,
                    UserSid TEXT NOT NULL,
                    ProcessName TEXT NOT NULL,
                    GrantedAtUtc TEXT NOT NULL,
                    ExpiresAtUtc TEXT NOT NULL,
                    GrantedBy TEXT NOT NULL
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
                );

                CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON AuditLogs(TimestampUtc DESC);
                CREATE INDEX IF NOT EXISTS idx_rules_user ON Rules(TargetUserSid);
                CREATE INDEX IF NOT EXISTS idx_overrides_expiry ON Overrides(ExpiresAtUtc);
            ";

            using var cmd = new SqliteCommand(createTablesSql, conn);
            cmd.ExecuteNonQuery();

            // Seed default settings if missing
            SeedDefaultSettings(conn);
        }
    }

    private void SeedDefaultSettings(SqliteConnection conn)
    {
        // Check if MasterPassword exists
        using var checkCmd = new SqliteCommand("SELECT COUNT(*) FROM Settings WHERE Key = 'MasterPasswordHash'", conn);
        long count = (long)(checkCmd.ExecuteScalar() ?? 0L);
        if (count == 0)
        {
            // Default initial Master Password: "AdminPassword123!"
            string defaultHash = CryptoHelper.HashPassword("AdminPassword123!");
            using var insertCmd = new SqliteCommand("INSERT INTO Settings (Key, Value, IsEncrypted) VALUES ('MasterPasswordHash', @val, 0)", conn);
            insertCmd.Parameters.AddWithValue("@val", defaultHash);
            insertCmd.ExecuteNonQuery();
        }

        // Check if PSK exists
        using var checkPsk = new SqliteCommand("SELECT COUNT(*) FROM Settings WHERE Key = 'PreSharedKey'", conn);
        long pskCount = (long)(checkPsk.ExecuteScalar() ?? 0L);
        if (pskCount == 0)
        {
            // Default initial PSK
            string defaultPsk = "AppShield-Default-PSK-Key-2026-Secure";
            string encryptedPsk = ProtectSecret(defaultPsk);
            using var insertPsk = new SqliteCommand("INSERT INTO Settings (Key, Value, IsEncrypted) VALUES ('PreSharedKey', @val, 1)", conn);
            insertPsk.Parameters.AddWithValue("@val", encryptedPsk);
            insertPsk.ExecuteNonQuery();
        }
    }

    public string GetSetting(string key)
    {
        lock (_lock)
        {
            using var conn = new SqliteConnection(_connectionString);
            conn.Open();
            using var cmd = new SqliteCommand("SELECT Value, IsEncrypted FROM Settings WHERE Key = @key", conn);
            cmd.Parameters.AddWithValue("@key", key);

            using var reader = cmd.ExecuteReader();
            if (reader.Read())
            {
                string val = reader.GetString(0);
                bool isEncrypted = reader.GetInt32(1) == 1;
                return isEncrypted ? UnprotectSecret(val) : val;
            }
            return string.Empty;
        }
    }

    public void SetSetting(string key, string value, bool encrypt = false)
    {
        lock (_lock)
        {
            using var conn = new SqliteConnection(_connectionString);
            conn.Open();

            string storedValue = encrypt ? ProtectSecret(value) : value;

            using var cmd = new SqliteCommand(@"
                INSERT INTO Settings (Key, Value, IsEncrypted)
                VALUES (@key, @val, @enc)
                ON CONFLICT(Key) DO UPDATE SET Value = @val, IsEncrypted = @enc", conn);

            cmd.Parameters.AddWithValue("@key", key);
            cmd.Parameters.AddWithValue("@val", storedValue);
            cmd.Parameters.AddWithValue("@enc", encrypt ? 1 : 0);
            cmd.ExecuteNonQuery();
        }
    }

    public List<UserAccount> GetAllUsers()
    {
        lock (_lock)
        {
            var list = new List<UserAccount>();
            using var conn = new SqliteConnection(_connectionString);
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
                    LastSeenUtc = DateTime.Parse(reader.GetString(6))
                });
            }
            return list;
        }
    }

    public void UpsertUsers(IEnumerable<UserAccount> users)
    {
        lock (_lock)
        {
            using var conn = new SqliteConnection(_connectionString);
            conn.Open();
            using var tx = conn.BeginTransaction();

            foreach (var u in users)
            {
                using var cmd = new SqliteCommand(@"
                    INSERT INTO Users (Sid, Username, Domain, IsAdmin, IsManaged, BlockUserWritableDirectories, LastSeenUtc)
                    VALUES (@sid, @user, @dom, @adm, @man, @block, @seen)
                    ON CONFLICT(Sid) DO UPDATE SET
                        Username = @user,
                        Domain = @dom,
                        IsAdmin = @adm,
                        LastSeenUtc = @seen", conn, tx);

                cmd.Parameters.AddWithValue("@sid", u.Sid);
                cmd.Parameters.AddWithValue("@user", u.Username);
                cmd.Parameters.AddWithValue("@dom", u.Domain);
                cmd.Parameters.AddWithValue("@adm", u.IsAdmin ? 1 : 0);
                cmd.Parameters.AddWithValue("@man", u.IsManaged ? 1 : 0);
                cmd.Parameters.AddWithValue("@block", u.BlockUserWritableDirectories ? 1 : 0);
                cmd.Parameters.AddWithValue("@seen", u.LastSeenUtc.ToString("o"));
                cmd.ExecuteNonQuery();
            }

            tx.Commit();
        }
    }

    public void UpdateUserManagement(string sid, bool isManaged, bool blockUserWritableDirs)
    {
        lock (_lock)
        {
            using var conn = new SqliteConnection(_connectionString);
            conn.Open();
            using var cmd = new SqliteCommand(@"
                UPDATE Users 
                SET IsManaged = @man, BlockUserWritableDirectories = @block 
                WHERE Sid = @sid", conn);

            cmd.Parameters.AddWithValue("@sid", sid);
            cmd.Parameters.AddWithValue("@man", isManaged ? 1 : 0);
            cmd.Parameters.AddWithValue("@block", blockUserWritableDirs ? 1 : 0);
            cmd.ExecuteNonQuery();
        }
    }

    public List<Rule> GetAllRules()
    {
        lock (_lock)
        {
            var list = new List<Rule>();
            using var conn = new SqliteConnection(_connectionString);
            conn.Open();
            using var cmd = new SqliteCommand("SELECT Id, TargetUserSid, RuleType, ProcessName, OriginalFilename, Sha256Hash, ScheduleStart, ScheduleEnd, QuotaMinutes, IsEnabled, CreatedAtUtc, Description FROM Rules", conn);
            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                list.Add(new Rule
                {
                    Id = reader.GetString(0),
                    TargetUserSid = reader.GetString(1),
                    RuleType = Enum.Parse<RuleType>(reader.GetString(2)),
                    ProcessName = reader.IsDBNull(3) ? null : reader.GetString(3),
                    OriginalFilename = reader.IsDBNull(4) ? null : reader.GetString(4),
                    Sha256Hash = reader.IsDBNull(5) ? null : reader.GetString(5),
                    ScheduleStart = reader.IsDBNull(6) ? null : reader.GetString(6),
                    ScheduleEnd = reader.IsDBNull(7) ? null : reader.GetString(7),
                    QuotaMinutes = reader.IsDBNull(8) ? null : reader.GetInt32(8),
                    IsEnabled = reader.GetInt32(9) == 1,
                    CreatedAtUtc = DateTime.Parse(reader.GetString(10)),
                    Description = reader.IsDBNull(11) ? string.Empty : reader.GetString(11)
                });
            }
            return list;
        }
    }

    public void SaveRule(Rule rule)
    {
        lock (_lock)
        {
            using var conn = new SqliteConnection(_connectionString);
            conn.Open();
            using var cmd = new SqliteCommand(@"
                INSERT INTO Rules (Id, TargetUserSid, RuleType, ProcessName, OriginalFilename, Sha256Hash, ScheduleStart, ScheduleEnd, QuotaMinutes, IsEnabled, CreatedAtUtc, Description)
                VALUES (@id, @target, @type, @proc, @orig, @sha, @start, @end, @quota, @enabled, @created, @desc)
                ON CONFLICT(Id) DO UPDATE SET
                    TargetUserSid = @target,
                    RuleType = @type,
                    ProcessName = @proc,
                    OriginalFilename = @orig,
                    Sha256Hash = @sha,
                    ScheduleStart = @start,
                    ScheduleEnd = @end,
                    QuotaMinutes = @quota,
                    IsEnabled = @enabled,
                    Description = @desc", conn);

            cmd.Parameters.AddWithValue("@id", rule.Id);
            cmd.Parameters.AddWithValue("@target", rule.TargetUserSid);
            cmd.Parameters.AddWithValue("@type", rule.RuleType.ToString());
            cmd.Parameters.AddWithValue("@proc", (object?)rule.ProcessName ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@orig", (object?)rule.OriginalFilename ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@sha", (object?)rule.Sha256Hash ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@start", (object?)rule.ScheduleStart ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@end", (object?)rule.ScheduleEnd ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@quota", (object?)rule.QuotaMinutes ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@enabled", rule.IsEnabled ? 1 : 0);
            cmd.Parameters.AddWithValue("@created", rule.CreatedAtUtc.ToString("o"));
            cmd.Parameters.AddWithValue("@desc", rule.Description);

            cmd.ExecuteNonQuery();
        }
    }

    public bool DeleteRule(string ruleId)
    {
        lock (_lock)
        {
            using var conn = new SqliteConnection(_connectionString);
            conn.Open();
            using var cmd = new SqliteCommand("DELETE FROM Rules WHERE Id = @id", conn);
            cmd.Parameters.AddWithValue("@id", ruleId);
            return cmd.ExecuteNonQuery() > 0;
        }
    }

    public int GetDailyQuotaSeconds(string userSid, string processName, string date)
    {
        lock (_lock)
        {
            using var conn = new SqliteConnection(_connectionString);
            conn.Open();
            using var cmd = new SqliteCommand(@"
                SELECT ActiveSeconds FROM DailyQuotas 
                WHERE UserSid = @sid AND ProcessName = @proc AND Date = @date", conn);

            cmd.Parameters.AddWithValue("@sid", userSid);
            cmd.Parameters.AddWithValue("@proc", processName.ToLowerInvariant());
            cmd.Parameters.AddWithValue("@date", date);

            var res = cmd.ExecuteScalar();
            return res != null ? Convert.ToInt32(res) : 0;
        }
    }

    public void AddDailyQuotaSeconds(string userSid, string processName, string date, int secondsToAdd)
    {
        lock (_lock)
        {
            using var conn = new SqliteConnection(_connectionString);
            conn.Open();
            using var cmd = new SqliteCommand(@"
                INSERT INTO DailyQuotas (Id, UserSid, ProcessName, Date, ActiveSeconds, LastActiveTimestampUtc)
                VALUES (@id, @sid, @proc, @date, @sec, @ts)
                ON CONFLICT(UserSid, ProcessName, Date) DO UPDATE SET
                    ActiveSeconds = ActiveSeconds + @sec,
                    LastActiveTimestampUtc = @ts", conn);

            cmd.Parameters.AddWithValue("@id", Guid.NewGuid().ToString("N"));
            cmd.Parameters.AddWithValue("@sid", userSid);
            cmd.Parameters.AddWithValue("@proc", processName.ToLowerInvariant());
            cmd.Parameters.AddWithValue("@date", date);
            cmd.Parameters.AddWithValue("@sec", secondsToAdd);
            cmd.Parameters.AddWithValue("@ts", DateTime.UtcNow.ToString("o"));

            cmd.ExecuteNonQuery();
        }
    }

    public List<TemporaryOverride> GetActiveOverrides()
    {
        lock (_lock)
        {
            var list = new List<TemporaryOverride>();
            using var conn = new SqliteConnection(_connectionString);
            conn.Open();

            // Clean expired overrides
            using (var cleanCmd = new SqliteCommand("DELETE FROM Overrides WHERE ExpiresAtUtc <= @now", conn))
            {
                cleanCmd.Parameters.AddWithValue("@now", DateTime.UtcNow.ToString("o"));
                cleanCmd.ExecuteNonQuery();
            }

            using var cmd = new SqliteCommand("SELECT Id, UserSid, ProcessName, GrantedAtUtc, ExpiresAtUtc, GrantedBy FROM Overrides", conn);
            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                list.Add(new TemporaryOverride
                {
                    Id = reader.GetString(0),
                    UserSid = reader.GetString(1),
                    ProcessName = reader.GetString(2),
                    GrantedAtUtc = DateTime.Parse(reader.GetString(3)),
                    ExpiresAtUtc = DateTime.Parse(reader.GetString(4)),
                    GrantedBy = reader.GetString(5)
                });
            }
            return list;
        }
    }

    public void AddOverride(TemporaryOverride ov)
    {
        lock (_lock)
        {
            using var conn = new SqliteConnection(_connectionString);
            conn.Open();
            using var cmd = new SqliteCommand(@"
                INSERT INTO Overrides (Id, UserSid, ProcessName, GrantedAtUtc, ExpiresAtUtc, GrantedBy)
                VALUES (@id, @sid, @proc, @granted, @exp, @by)", conn);

            cmd.Parameters.AddWithValue("@id", ov.Id);
            cmd.Parameters.AddWithValue("@sid", ov.UserSid);
            cmd.Parameters.AddWithValue("@proc", ov.ProcessName.ToLowerInvariant());
            cmd.Parameters.AddWithValue("@granted", ov.GrantedAtUtc.ToString("o"));
            cmd.Parameters.AddWithValue("@exp", ov.ExpiresAtUtc.ToString("o"));
            cmd.Parameters.AddWithValue("@by", ov.GrantedBy);

            cmd.ExecuteNonQuery();
        }
    }

    public void AddAuditLog(AuditLog log)
    {
        lock (_lock)
        {
            using var conn = new SqliteConnection(_connectionString);
            conn.Open();
            using var cmd = new SqliteCommand(@"
                INSERT INTO AuditLogs (Id, TimestampUtc, UserSid, Username, ProcessName, OriginalFilename, Sha256Hash, ExecutablePath, Action, Reason)
                VALUES (@id, @ts, @sid, @user, @proc, @orig, @sha, @path, @action, @reason)", conn);

            cmd.Parameters.AddWithValue("@id", log.Id);
            cmd.Parameters.AddWithValue("@ts", log.TimestampUtc.ToString("o"));
            cmd.Parameters.AddWithValue("@sid", log.UserSid);
            cmd.Parameters.AddWithValue("@user", log.Username);
            cmd.Parameters.AddWithValue("@proc", log.ProcessName);
            cmd.Parameters.AddWithValue("@orig", log.OriginalFilename);
            cmd.Parameters.AddWithValue("@sha", log.Sha256Hash);
            cmd.Parameters.AddWithValue("@path", log.ExecutablePath);
            cmd.Parameters.AddWithValue("@action", log.Action.ToString());
            cmd.Parameters.AddWithValue("@reason", log.Reason);

            cmd.ExecuteNonQuery();
        }
    }

    public List<AuditLog> GetAuditLogs(int limit = 100, int offset = 0)
    {
        lock (_lock)
        {
            var list = new List<AuditLog>();
            using var conn = new SqliteConnection(_connectionString);
            conn.Open();
            using var cmd = new SqliteCommand(@"
                SELECT Id, TimestampUtc, UserSid, Username, ProcessName, OriginalFilename, Sha256Hash, ExecutablePath, Action, Reason 
                FROM AuditLogs 
                ORDER BY TimestampUtc DESC 
                LIMIT @lim OFFSET @off", conn);

            cmd.Parameters.AddWithValue("@lim", limit);
            cmd.Parameters.AddWithValue("@off", offset);

            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                list.Add(new AuditLog
                {
                    Id = reader.GetString(0),
                    TimestampUtc = DateTime.Parse(reader.GetString(1)),
                    UserSid = reader.GetString(2),
                    Username = reader.GetString(3),
                    ProcessName = reader.GetString(4),
                    OriginalFilename = reader.GetString(5),
                    Sha256Hash = reader.GetString(6),
                    ExecutablePath = reader.GetString(7),
                    Action = Enum.Parse<EnforcementAction>(reader.GetString(8)),
                    Reason = reader.GetString(9)
                });
            }
            return list;
        }
    }
}
