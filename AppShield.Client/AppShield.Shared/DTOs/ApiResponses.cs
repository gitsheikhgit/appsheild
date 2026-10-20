using AppShield.Shared.Models;

namespace AppShield.Shared.DTOs;

public class ApiResponse<T>
{
    public bool Success { get; set; } = true;
    public string Message { get; set; } = string.Empty;
    public T? Data { get; set; }

    public static ApiResponse<T> Ok(T data, string message = "") =>
        new() { Success = true, Message = message, Data = data };

    public static ApiResponse<T> Fail(string message) =>
        new() { Success = false, Message = message, Data = default };
}

public class HealthResponseDto
{
    public string Hostname { get; set; } = Environment.MachineName;
    public string OsVersion { get; set; } = Environment.OSVersion.ToString();
    public string AgentVersion { get; set; } = "1.0.0";
    public long UptimeSeconds { get; set; }
    public DateTime ServerTimeUtc { get; set; } = DateTime.UtcNow;
}

public class RulesListResponseDto
{
    public List<Rule> Rules { get; set; } = new();
    public List<TemporaryOverride> Overrides { get; set; } = new();
}

public class OverrideResponseDto
{
    public bool Success { get; set; }
    public string Message { get; set; } = string.Empty;
    public DateTime? ExpiresAtUtc { get; set; }
}
