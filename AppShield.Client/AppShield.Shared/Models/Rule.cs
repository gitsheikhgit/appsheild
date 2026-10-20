namespace AppShield.Shared.Models;

public class Rule
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string TargetUserSid { get; set; } = "*"; // "*" for all managed users, or specific SID
    public RuleType RuleType { get; set; } = RuleType.AlwaysBlock;
    public string? ProcessName { get; set; }
    public string? OriginalFilename { get; set; }
    public string? Sha256Hash { get; set; }
    public string? ScheduleStart { get; set; } // Format: "HH:mm" e.g. "21:00"
    public string? ScheduleEnd { get; set; }   // Format: "HH:mm" e.g. "07:00"
    public int? QuotaMinutes { get; set; }
    public bool IsEnabled { get; set; } = true;
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public string Description { get; set; } = string.Empty;
}
