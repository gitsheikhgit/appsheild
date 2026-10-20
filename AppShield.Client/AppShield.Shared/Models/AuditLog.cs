namespace AppShield.Shared.Models;

public class AuditLog
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public DateTime TimestampUtc { get; set; } = DateTime.UtcNow;
    public string UserSid { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty;
    public string ProcessName { get; set; } = string.Empty;
    public string OriginalFilename { get; set; } = string.Empty;
    public string Sha256Hash { get; set; } = string.Empty;
    public string ExecutablePath { get; set; } = string.Empty;
    public EnforcementAction Action { get; set; } = EnforcementAction.Blocked;
    public string Reason { get; set; } = string.Empty;
}
