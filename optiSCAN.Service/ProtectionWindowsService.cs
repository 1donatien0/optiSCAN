// SPDX-License-Identifier: GPL-3.0-or-later
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using optiSCAN.Platform;
using System.Diagnostics;

namespace optiSCAN.Service;

public sealed class ProtectionWindowsService : BackgroundService
{
    private const string EventSourceName = ProtectionIdentifiers.EventSourceName;
    private const string EventLogName = "Application";

    /// <summary>Délai laissé à un hôte qui démarre avant de lui demander de répondre sur le pipe.</summary>
    internal static readonly TimeSpan LivenessGrace = TimeSpan.FromMinutes(2);

    /// <summary>Échecs de ping consécutifs (un toutes les 15 s) avant d'arrêter un hôte figé.</summary>
    internal const int MaxFailedPings = 4;

    /// <summary>Délai laissé à l'hôte pour s'arrêter proprement après la demande d'arrêt.</summary>
    internal static readonly TimeSpan HostShutdownGrace = TimeSpan.FromSeconds(10);

    private readonly ServiceHostRestartPolicy _restartPolicy = new();
    private readonly IHostApplicationLifetime _lifetime;
    private Process? _hostProcess;
    private DateTime _hostStartedUtc;
    private int _failedPings;

    public ProtectionWindowsService(IHostApplicationLifetime lifetime)
    {
        _lifetime = lifetime;
    }

    /// <summary>
    /// Arrête le service avec un code d'erreur : le gestionnaire de services l'affiche arrêté et
    /// applique ses actions de récupération, au lieu d'un service « en cours d'exécution » qui ne
    /// protège rien (audit V11).
    /// </summary>
    private void StopWithError(string message)
    {
        WriteEvent(message, EventLogEntryType.Error);
        Environment.ExitCode = 1;
        _lifetime.StopApplication();
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        RemoveLegacyEventSources();

        // Hôte console sans WPF (3.1) : l'interface optiSCAN.exe ne tourne plus sous SYSTEM.
        var exe = Path.Combine(AppContext.BaseDirectory, "optiSCAN.Host.exe");
        if (!File.Exists(exe))
        {
            StopWithError("optiSCAN.Host.exe introuvable dans " + AppContext.BaseDirectory);
            return;
        }

        // L'hôte tourne en SYSTEM : un dossier modifiable par un utilisateur lui donnerait
        // une exécution SYSTEM en remplaçant optiSCAN.Host.exe. Refus tant que le dossier n'est pas
        // réservé aux administrateurs (installation sous Program Files).
        if (!InstallLocationTrust.IsCurrentInstallTrusted(out var reason))
        {
            StopWithError(
                "Hôte non démarré : le dossier d'installation n'est pas réservé aux administrateurs ("
                + reason + "). Réinstaller optiSCAN sous Program Files.");
            return;
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            if (_hostProcess is { HasExited: false })
            {
                // Un processus vivant n'est pas forcément un hôte qui protège : il peut être figé.
                // Après le délai de démarrage, il doit répondre sur le pipe ; sinon il est arrêté
                // et la boucle le relance (audit V5).
                if (DateTime.UtcNow - _hostStartedUtc >= LivenessGrace)
                {
                    if (await PingHostAsync(stoppingToken).ConfigureAwait(false))
                    {
                        _failedPings = 0;
                        _restartPolicy.OnHostHealthy();
                    }
                    else if (++_failedPings >= MaxFailedPings)
                    {
                        WriteEvent(
                            $"Hôte --service-host sans réponse sur le pipe ({_failedPings} essais) : arrêt puis relance.",
                            EventLogEntryType.Warning);
                        _failedPings = 0;
                        try
                        {
                            _hostProcess.Kill(entireProcessTree: true);
                            _hostProcess.WaitForExit(5000);
                        }
                        catch (Exception ex) when (!ex.IsFatal()) { WriteEvent("Arrêt de l'hôte figé impossible : " + ex.Message, EventLogEntryType.Error); }
                        continue;
                    }
                }

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
                var previousHost = _hostProcess;
                _hostProcess = null;
                previousHost?.Dispose();
                _hostProcess = Process.Start(psi);
                _hostStartedUtc = DateTime.UtcNow;
                _failedPings = 0;

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
            catch (Exception ex) when (!ex.IsFatal())
            {
                _restartPolicy.OnHostExit();
                WriteEvent("Échec démarrage --service-host : " + ex.Message, EventLogEntryType.Error);
            }

            await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken).ConfigureAwait(false);
        }
    }

    private static async Task<bool> PingHostAsync(CancellationToken ct)
    {
        try
        {
            using var client = new ProtectionPipeClient(timeout: TimeSpan.FromSeconds(10));
            var response = await client.SendAsync(
                new ProtectionPipeRequest { Operation = ProtectionPipeOperations.Ping }, ct).ConfigureAwait(false);
            return response.Ok;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ignored) when (!ignored.IsFatal())
        {
            return false;
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        try
        {
            using var client = new ProtectionPipeClient();
            await client.RequestShutdownAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ignored) when (!ignored.IsFatal()) { /* ignore */ }

        try
        {
            // La demande d'arrêt est acquittée avant que l'hôte n'ait fini (temps réel, IPC,
            // clamd, journaux). Le tuer aussitôt rendait cet arrêt propre inopérant : il a
            // quelques secondes, dans la limite accordée par le gestionnaire de services.
            if (_hostProcess is { HasExited: false } host)
            {
                using var grace = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                grace.CancelAfter(HostShutdownGrace);
                try { await host.WaitForExitAsync(grace.Token).ConfigureAwait(false); }
                catch (OperationCanceledException) { /* délai écoulé : arrêt forcé ci-dessous */ }

                if (!host.HasExited)
                    host.Kill(entireProcessTree: true);
            }
        }
        catch (Exception ignored) when (!ignored.IsFatal()) { /* ignore */ }

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
            catch (Exception ignored) when (!ignored.IsFatal()) { /* droits insuffisants : sans conséquence */ }
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
        catch (Exception ignored) when (!ignored.IsFatal())
        {
            try { EventLog.WriteEntry("optiSCAN.Service", message, type); }
            catch (Exception inner) when (!inner.IsFatal()) { /* ignore */ }
        }
    }
}
