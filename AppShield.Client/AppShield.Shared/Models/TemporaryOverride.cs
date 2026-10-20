namespace AppShield.Shared.Models;

public class TemporaryOverride
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string UserSid { get; set; } = "*";
    public string ProcessName { get; set; } = string.Empty;
    public DateTime GrantedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime ExpiresAtUtc { get; set; } = DateTime.UtcNow.AddMinutes(60);
    public string GrantedBy { get; set; } = "MasterPassword"; // or "RemoteAdmin"
}
