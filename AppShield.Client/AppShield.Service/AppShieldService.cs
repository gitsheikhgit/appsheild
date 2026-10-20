using System.ServiceProcess;
using Microsoft.Extensions.Hosting.WindowsServices;

namespace AppShield.Service;

public class AppShieldWindowsServiceLifetime : ServiceBase, IHostLifetime
{
    private readonly IHostEnvironment _environment;
    private readonly IHostApplicationLifetime _applicationLifetime;
    private readonly TaskCompletionSource<object?> _delayStart = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private static bool _allowStop = false;

    public AppShieldWindowsServiceLifetime(
        IHostEnvironment environment,
        IHostApplicationLifetime applicationLifetime)
    {
        _environment = environment;
        _applicationLifetime = applicationLifetime;

        ServiceName = "AppShieldService";
        // Tamper resistance: prevent stopping via services.msc or sc.exe during normal operations
        CanStop = false;
        CanPauseAndContinue = false;
        CanShutdown = true;
    }

    public static void AllowStop()
    {
        _allowStop = true;
    }

    public static bool IsStopAllowed => _allowStop;

    public Task WaitForStartAsync(CancellationToken cancellationToken)
    {
        cancellationToken.Register(() => _delayStart.TrySetCanceled());

        _applicationLifetime.ApplicationStarted.Register(() =>
        {
            // Register exit handler
        });

        // Run the service in background thread
        var thread = new Thread(Run);
        thread.IsBackground = true;
        thread.Name = "AppShieldServiceLifetime";
        thread.Start();

        return _delayStart.Task;
    }

    private void Run()
    {
        try
        {
            Run(this);
            _delayStart.TrySetException(new InvalidOperationException("Service stopped."));
        }
        catch (Exception ex)
        {
            _delayStart.TrySetException(ex);
        }
    }

    protected override void OnStart(string[] args)
    {
        _delayStart.TrySetResult(null);
        base.OnStart(args);
    }

    protected override void OnStop()
    {
        if (_allowStop)
        {
            _applicationLifetime.StopApplication();
            base.OnStop();
        }
        // If not allowed, ignore or throw
    }

    protected override void OnShutdown()
    {
        _applicationLifetime.StopApplication();
        base.OnShutdown();
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        if (_allowStop)
        {
            Stop();
        }
        return Task.CompletedTask;
    }
}
