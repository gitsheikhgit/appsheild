namespace AppShield.Shared.DTOs;

public class ProcessInfoDto
{
    public int Pid { get; set; }
    public string ProcessName { get; set; } = string.Empty;
    public string ExecutablePath { get; set; } = string.Empty;
    public string OriginalFilename { get; set; } = string.Empty;
    public string Sha256Hash { get; set; } = string.Empty;
    public double MemoryMB { get; set; }
    public int SessionId { get; set; }
    public string Username { get; set; } = string.Empty;
    public string Domain { get; set; } = string.Empty;
    public string Sid { get; set; } = string.Empty;
    public bool IsManagedUser { get; set; }
}

public class InstalledAppDto
{
    public string DisplayName { get; set; } = string.Empty;
    public string DisplayVersion { get; set; } = string.Empty;
    public string Publisher { get; set; } = string.Empty;
    public string ExeName { get; set; } = string.Empty;
    public string InstallPath { get; set; } = string.Empty;
    public string OriginalFilename { get; set; } = string.Empty;
    public bool IsBlocked { get; set; }
}
