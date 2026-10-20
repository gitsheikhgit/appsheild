using AppShield.Service.Storage;

namespace AppShield.Service.Engine;

public class QuotaTracker
{
    private readonly StorageManager _storage;
    private readonly object _lock = new();

    public QuotaTracker(StorageManager storage)
    {
        _storage = storage;
    }

    /// <summary>
    /// Records elapsed active seconds for a process running under a user account.
    /// Returns the updated total active seconds for today.
    /// </summary>
    public int RecordActiveRuntime(string userSid, string processName, int elapsedSeconds)
    {
        lock (_lock)
        {
            string today = DateTime.UtcNow.ToString("yyyy-MM-dd");
            _storage.AddDailyQuotaSeconds(userSid, processName, today, elapsedSeconds);
            return _storage.GetDailyQuotaSeconds(userSid, processName, today);
        }
    }

    /// <summary>
    /// Checks whether a process has exceeded its daily quota (in minutes).
    /// </summary>
    public bool IsQuotaExceeded(string userSid, string processName, int quotaMinutes)
    {
        lock (_lock)
        {
            string today = DateTime.UtcNow.ToString("yyyy-MM-dd");
            int totalSeconds = _storage.GetDailyQuotaSeconds(userSid, processName, today);
            return totalSeconds >= (quotaMinutes * 60);
        }
    }
}
