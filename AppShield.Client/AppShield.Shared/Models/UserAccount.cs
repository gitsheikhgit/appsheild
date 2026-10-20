namespace AppShield.Shared.Models;

public class UserAccount
{
    public string Sid { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty;
    public string Domain { get; set; } = string.Empty;
    public bool IsAdmin { get; set; }
    public bool IsManaged { get; set; }
    public bool BlockUserWritableDirectories { get; set; }
    public DateTime LastSeenUtc { get; set; } = DateTime.UtcNow;
}
