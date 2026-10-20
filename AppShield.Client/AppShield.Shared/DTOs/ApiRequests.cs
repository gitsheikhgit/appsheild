using AppShield.Shared.Models;

namespace AppShield.Shared.DTOs;

public class ManageUserRequestDto
{
    public string Sid { get; set; } = string.Empty;
    public bool IsManaged { get; set; }
    public bool BlockUserWritableDirectories { get; set; }
}

public class CreateRuleRequestDto
{
    public string TargetUserSid { get; set; } = "*";
    public RuleType RuleType { get; set; } = RuleType.AlwaysBlock;
    public string? ProcessName { get; set; }
    public string? OriginalFilename { get; set; }
    public string? Sha256Hash { get; set; }
    public string? ScheduleStart { get; set; }
    public string? ScheduleEnd { get; set; }
    public int? QuotaMinutes { get; set; }
    public string Description { get; set; } = string.Empty;
}

public class OverrideRequestDto
{
    public string ProcessName { get; set; } = string.Empty;
    public string UserSid { get; set; } = "*";
    public int Minutes { get; set; } = 60;
}

public class UninstallRequestDto
{
    public string MasterPassword { get; set; } = string.Empty;
}
