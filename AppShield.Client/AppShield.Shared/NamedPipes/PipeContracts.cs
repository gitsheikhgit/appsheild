namespace AppShield.Shared.NamedPipes;

public static class PipeConstants
{
    public const string PipeName = "AppShieldOverridePipe";
}

public class PipeRequest
{
    public string ProcessName { get; set; } = string.Empty;
    public string UserSid { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
}

public class PipeResponse
{
    public bool Success { get; set; }
    public string Message { get; set; } = string.Empty;
    public int GrantedMinutes { get; set; } = 60;
}
