using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using AppShield.Service.Storage;
using AppShield.Shared.Models;
using AppShield.Shared.NamedPipes;
using AppShield.Shared.Security;

namespace AppShield.Service.IPC;

public class OverridePipeServer : IDisposable
{
    private readonly StorageManager _storage;
    private CancellationTokenSource? _cts;
    private Task? _serverTask;

    public OverridePipeServer(StorageManager storage)
    {
        _storage = storage;
    }

    public void Start()
    {
        _cts = new CancellationTokenSource();
        _serverTask = Task.Run(() => ServerLoopAsync(_cts.Token));
    }

    public void Stop()
    {
        _cts?.Cancel();
    }

    public void Dispose()
    {
        Stop();
        _cts?.Dispose();
    }

    private async Task ServerLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            NamedPipeServerStream? pipeServer = null;
            try
            {
                pipeServer = CreatePipeServer();
                await pipeServer.WaitForConnectionAsync(ct);

                // Handle client in background task to avoid blocking the listener loop
                _ = HandleClientAsync(pipeServer, ct);
            }
            catch (OperationCanceledException)
            {
                pipeServer?.Dispose();
                break;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[OverridePipeServer] Listener error: {ex.Message}");
                pipeServer?.Dispose();
                await Task.Delay(1000, ct);
            }
        }
    }

    private NamedPipeServerStream CreatePipeServer()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            var pipeSecurity = new PipeSecurity();
            // Grant FullControl to SYSTEM
            pipeSecurity.AddAccessRule(new PipeAccessRule(
                new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                PipeAccessRights.FullControl,
                AccessControlType.Allow));

            // Grant FullControl to BUILTIN\Administrators
            pipeSecurity.AddAccessRule(new PipeAccessRule(
                new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                PipeAccessRights.FullControl,
                AccessControlType.Allow));

            // Grant ReadWrite to Authenticated Users (Interactive standard users)
            pipeSecurity.AddAccessRule(new PipeAccessRule(
                new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null),
                PipeAccessRights.ReadWrite | PipeAccessRights.CreateNewInstance,
                AccessControlType.Allow));

            return NamedPipeServerStreamAcl.Create(
                PipeConstants.PipeName,
                PipeDirection.InOut,
                NamedPipeServerStream.MaxAllowedServerInstances,
                PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous,
                4096,
                4096,
                pipeSecurity);
        }

        return new NamedPipeServerStream(
            PipeConstants.PipeName,
            PipeDirection.InOut,
            NamedPipeServerStream.MaxAllowedServerInstances,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous);
    }

    private async Task HandleClientAsync(NamedPipeServerStream pipe, CancellationToken ct)
    {
        using (pipe)
        {
            try
            {
                using var reader = new StreamReader(pipe, Encoding.UTF8, leaveOpen: true);
                using var writer = new StreamWriter(pipe, Encoding.UTF8, leaveOpen: true) { AutoFlush = true };

                string? line = await reader.ReadLineAsync(ct);
                if (string.IsNullOrWhiteSpace(line))
                    return;

                var req = JsonSerializer.Deserialize<PipeRequest>(line);
                if (req == null)
                    return;

                string storedHash = _storage.GetSetting("MasterPasswordHash");
                bool isValid = CryptoHelper.VerifyPassword(req.Password, storedHash);

                PipeResponse response;

                if (isValid)
                {
                    var ov = new TemporaryOverride
                    {
                        UserSid = string.IsNullOrWhiteSpace(req.UserSid) ? "*" : req.UserSid,
                        ProcessName = req.ProcessName,
                        GrantedAtUtc = DateTime.UtcNow,
                        ExpiresAtUtc = DateTime.UtcNow.AddMinutes(60),
                        GrantedBy = "MasterPassword"
                    };
                    _storage.AddOverride(ov);

                    _storage.AddAuditLog(new AuditLog
                    {
                        UserSid = req.UserSid,
                        Username = "PromptUser",
                        ProcessName = req.ProcessName,
                        OriginalFilename = string.Empty,
                        Sha256Hash = string.Empty,
                        ExecutablePath = string.Empty,
                        Action = EnforcementAction.OverrideGranted,
                        Reason = "Local Master Password entered in prompt"
                    });

                    response = new PipeResponse
                    {
                        Success = true,
                        Message = "Authorization accepted. Access granted for 60 minutes.",
                        GrantedMinutes = 60
                    };
                }
                else
                {
                    response = new PipeResponse
                    {
                        Success = false,
                        Message = "Incorrect Master Password."
                    };
                }

                string jsonResponse = JsonSerializer.Serialize(response);
                await writer.WriteLineAsync(jsonResponse);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[OverridePipeServer] Client processing error: {ex.Message}");
            }
        }
    }
}
