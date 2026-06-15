using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System.Diagnostics;

namespace optiSCAN.Service;

public sealed class ProtectionWindowsService : BackgroundService
{
    private Process? _hostProcess;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var exe = Path.Combine(AppContext.BaseDirectory, "optiSCAN.exe");
        if (!File.Exists(exe))
        {
            if (OperatingSystem.IsWindows())
                EventLog.WriteEntry("optiSCAN.Service", "optiSCAN.exe introuvable", EventLogEntryType.Error);
            return;
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            if (_hostProcess is { HasExited: false })
            {
                await Task.Delay(TimeSpan.FromSeconds(15), stoppingToken).ConfigureAwait(false);
                continue;
            }

            var psi = new ProcessStartInfo
            {
                FileName = exe,
                WorkingDirectory = AppContext.BaseDirectory,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            psi.ArgumentList.Add("--service-host");
            _hostProcess = Process.Start(psi);

            await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken).ConfigureAwait(false);
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        try
        {
            using var client = new Platform.ProtectionPipeClient();
            await client.RequestShutdownAsync(cancellationToken).ConfigureAwait(false);
        }
        catch { /* ignore */ }

        try
        {
            if (_hostProcess is { HasExited: false })
                _hostProcess.Kill(entireProcessTree: true);
        }
        catch { /* ignore */ }

        await base.StopAsync(cancellationToken).ConfigureAwait(false);
    }
}
