using System.Text.Json.Serialization;

namespace AppShield.Shared.Models;

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum RuleType
{
    AlwaysBlock,
    ScheduleBlock,
    DailyQuota,
    AllowedWindow
}

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum EnforcementAction
{
    Allowed,
    Blocked,
    OverrideGranted
}
