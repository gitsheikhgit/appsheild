namespace AppShield.Shared.Models;

public class DailyQuotaUsage
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string UserSid { get; set; } = string.Empty;
    public string ProcessName { get; set; } = string.Empty;
    public string Date { get; set; } = DateTime.UtcNow.ToString("yyyy-MM-dd");
    public int ActiveSeconds { get; set; }
    public DateTime LastActiveTimestampUtc { get; set; } = DateTime.UtcNow;
}
