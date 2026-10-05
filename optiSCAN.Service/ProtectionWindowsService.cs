using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using optiSCAN.Platform;
using System.Diagnostics;

namespace optiSCAN.Service;

public sealed class ProtectionWindowsService : BackgroundService
{
    private const string EventSourceName = ProtectionIdentifiers.EventSourceName;
    private const string EventLogName = "Application";

    private readonly ServiceHostRestartPolicy _restartPolicy = new();
    private Process? _hostProcess;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        RemoveLegacyEventSources();

        var exe = Path.Combine(AppContext.BaseDirectory, "optiSCAN.exe");
        if (!File.Exists(exe))
        {
            WriteEvent("optiSCAN.exe introuvable dans " + AppContext.BaseDirectory, EventLogEntryType.Error);
            return;
        }

        // L'hôte tourne en SYSTEM : un dossier modifiable par un utilisateur lui donnerait
        // une exécution SYSTEM en remplaçant optiSCAN.exe. Refus tant que le dossier n'est pas
        // réservé aux administrateurs (installation sous Program Files).
        if (!InstallLocationTrust.IsCurrentInstallTrusted(out var reason))
        {
            WriteEvent(
                "Hôte non démarré : le dossier d'installation n'est pas réservé aux administrateurs ("
                + reason + "). Réinstaller optiSCAN sous Program Files.",
                EventLogEntryType.Error);
            return;
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            if (_hostProcess is { HasExited: false })
            {
                _restartPolicy.OnHostHealthy();
                await Task.Delay(TimeSpan.FromSeconds(15), stoppingToken).ConfigureAwait(false);
                continue;
            }

            if (_hostProcess is { HasExited: true })
            {
                var code = _hostProcess.ExitCode;
                _restartPolicy.OnHostExit();
                WriteEvent(
                    $"Hôte --service-host terminé (exit={code}). Échecs consécutifs={_restartPolicy.ConsecutiveFailures}, relances/h={_restartPolicy.RestartsInWindow}",
                    EventLogEntryType.Warning);
            }

            if (!_restartPolicy.CanRestart())
            {
                WriteEvent(
                    $"Limite de relances atteinte ({ServiceHostRestartPolicy.MaxRestartsPerHour}/h). Pause 5 min.",
                    EventLogEntryType.Error);
                await Task.Delay(TimeSpan.FromMinutes(5), stoppingToken).ConfigureAwait(false);
                continue;
            }

            var delay = _restartPolicy.GetBackoffDelay();
            if (delay > TimeSpan.Zero)
                await Task.Delay(delay, stoppingToken).ConfigureAwait(false);

            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = exe,
                    WorkingDirectory = AppContext.BaseDirectory,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                };
                psi.ArgumentList.Add("--service-host");
                _hostProcess = Process.Start(psi);

                if (_hostProcess == null)
                {
                    _restartPolicy.OnHostExit();
                    WriteEvent("Process.Start a retourné null pour --service-host", EventLogEntryType.Error);
                }
                else
                {
                    WriteEvent($"Hôte --service-host démarré (PID {_hostProcess.Id})", EventLogEntryType.Information);
                }
            }
            catch (Exception ex)
            {
                _restartPolicy.OnHostExit();
                WriteEvent("Échec démarrage --service-host : " + ex.Message, EventLogEntryType.Error);
            }

            await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken).ConfigureAwait(false);
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        try
        {
            using var client = new ProtectionPipeClient();
            await client.RequestShutdownAsync(cancellationToken).ConfigureAwait(false);
        }
        catch { /* ignore */ }

        try
        {
            if (_hostProcess is { HasExited: false })
                _hostProcess.Kill(entireProcessTree: true);
        }
        catch { /* ignore */ }

        WriteEvent("Service Windows arrêté", EventLogEntryType.Information);
        await base.StopAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Supprime les anciennes sources du journal (y compris l'ancien libellé sans version), remplacées par la source v3.</summary>
    private static void RemoveLegacyEventSources()
    {
        if (!OperatingSystem.IsWindows())
            return;

        foreach (var legacy in ProtectionIdentifiers.LegacyEventSourceNames)
        {
            try
            {
                if (EventLog.SourceExists(legacy))
                    EventLog.DeleteEventSource(legacy);
            }
            catch { /* droits insuffisants : sans conséquence */ }
        }
    }

    private static void WriteEvent(string message, EventLogEntryType type)
    {
        if (!OperatingSystem.IsWindows())
            return;

        try
        {
            if (!EventLog.SourceExists(EventSourceName))
                EventLog.CreateEventSource(EventSourceName, EventLogName);

            EventLog.WriteEntry(EventSourceName, message, type);
        }
        catch
        {
            try { EventLog.WriteEntry("optiSCAN.Service", message, type); }
            catch { /* ignore */ }
        }
    }
}
