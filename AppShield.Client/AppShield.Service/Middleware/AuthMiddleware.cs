using System.Text.Json;
using AppShield.Service.Storage;
using AppShield.Shared.DTOs;
using AppShield.Shared.Security;

namespace AppShield.Service.Middleware;

public class AuthMiddleware
{
    private readonly RequestDelegate _next;
    private const int MaxTimestampDriftSeconds = 60;

    public AuthMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context, StorageManager storage)
    {
        string path = context.Request.Path.Value ?? string.Empty;

        // Exempt /api/v1/health from authentication
        if (context.Request.Method.Equals("GET", StringComparison.OrdinalIgnoreCase) &&
            path.Equals("/api/v1/health", StringComparison.OrdinalIgnoreCase))
        {
            await _next(context);
            return;
        }

        // 1. Verify Timestamp header
        if (!context.Request.Headers.TryGetValue("X-AppShield-Timestamp", out var timestampHeader) ||
            !long.TryParse(timestampHeader.ToString(), out long clientTimestamp))
        {
            await ReturnUnauthorized(context, "Missing or invalid 'X-AppShield-Timestamp' header.");
            return;
        }

        long currentTimestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if (Math.Abs(currentTimestamp - clientTimestamp) > MaxTimestampDriftSeconds)
        {
            await ReturnUnauthorized(context, "Timestamp drift exceeded (+/- 60 seconds allowed). Potential replay attack.");
            return;
        }

        // 2. Verify Pre-Shared Key (PSK)
        if (!context.Request.Headers.TryGetValue("X-AppShield-PSK", out var pskHeader))
        {
            await ReturnUnauthorized(context, "Missing 'X-AppShield-PSK' header.");
            return;
        }

        string clientPsk = pskHeader.ToString();
        string storedPsk = storage.GetSetting("PreSharedKey");

        if (string.IsNullOrEmpty(storedPsk) || !CryptoHelper.FixedTimeEquals(clientPsk, storedPsk))
        {
            await ReturnUnauthorized(context, "Invalid Pre-Shared Key.");
            return;
        }

        await _next(context);
    }

    private static async Task ReturnUnauthorized(HttpContext context, string message)
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        context.Response.ContentType = "application/json";
        var payload = ApiResponse<object>.Fail(message);
        await context.Response.WriteAsync(JsonSerializer.Serialize(payload));
    }
}
