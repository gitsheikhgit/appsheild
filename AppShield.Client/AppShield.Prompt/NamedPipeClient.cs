using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using AppShield.Shared.NamedPipes;

namespace AppShield.Prompt;

public static class NamedPipeClient
{
    public static async Task<PipeResponse> SendOverrideRequestAsync(string appName, string userSid, string password, int timeoutMs = 5000)
    {
        try
        {
            using var pipe = new NamedPipeClientStream(".", PipeConstants.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
            using var cts = new CancellationTokenSource(timeoutMs);

            await pipe.ConnectAsync(cts.Token);

            using var writer = new StreamWriter(pipe, Encoding.UTF8, leaveOpen: true) { AutoFlush = true };
            using var reader = new StreamReader(pipe, Encoding.UTF8, leaveOpen: true);

            var req = new PipeRequest
            {
                ProcessName = appName,
                UserSid = userSid,
                Password = password
            };

            string jsonReq = JsonSerializer.Serialize(req);
            await writer.WriteLineAsync(jsonReq);

            string? line = await reader.ReadLineAsync(cts.Token);
            if (!string.IsNullOrWhiteSpace(line))
            {
                var resp = JsonSerializer.Deserialize<PipeResponse>(line);
                if (resp != null)
                {
                    return resp;
                }
            }

            return new PipeResponse { Success = false, Message = "Empty response from security service." };
        }
        catch (OperationCanceledException)
        {
            return new PipeResponse { Success = false, Message = "Request timed out. Security service did not respond." };
        }
        catch (Exception ex)
        {
            return new PipeResponse { Success = false, Message = $"Connection error: {ex.Message}" };
        }
    }
}
