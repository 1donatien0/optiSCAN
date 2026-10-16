// SPDX-License-Identifier: GPL-3.0-or-later
using optiSCAN.Models;
using optiSCAN.Platform;

namespace optiSCAN.Services;

/// <summary>Hôte de protection système (RTP, processus, IPC) pour --service-host.</summary>
public sealed class ProtectionServiceHost : IDisposable
{
    private readonly IProtectionServiceHostDependencies _container;
    private readonly Action? _onShutdownRequested;
    private ProtectionPipeServer? _pipeServer;
    private ServiceHostThreatHandler? _threatHandler;
    private System.Threading.Timer? _retentionTimer;
    private bool _started;

    /// <summary>Premier passage de conservation peu après le démarrage, puis une fois par jour.</summary>
    private static readonly TimeSpan RetentionFirstRun = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan RetentionPeriod = TimeSpan.FromHours(24);

    /// <param name="onShutdownRequested">
    /// Appelé quand le service Windows demande l'arrêt par le pipe (jeton vérifié) : l'appelant
    /// arrête alors l'hôte proprement (<see cref="StopAsync"/>) puis quitte le processus.
    /// </param>
    public ProtectionServiceHost(IProtectionServiceHostDependencies container, Action? onShutdownRequested = null)
    {
        _container = container;
        _onShutdownRequested = onShutdownRequested;
    }

    public void Start()
    {
        if (_started)
            return;

        // Abonnement avant le démarrage du temps réel : une menace vue pendant le démarrage
        // est journalisée elle aussi.
        _threatHandler = new ServiceHostThreatHandler(_container, _container.ExclusionSettingsAccessor, _container.UserPreferencesAccessor);
        _container.RealTimeProtection.ThreatDetected += _threatHandler.OnThreatDetected;
        _container.ProcessStartMonitor.ThreatDetected += _threatHandler.OnThreatDetected;
        _container.RemovableDriveScan.ThreatDetected += _threatHandler.OnThreatDetected;

        // Copies d'analyse laissées par un arrêt brutal : supprimées avant toute nouvelle copie.
        ScanStaging.PurgeStale();
        _container.ApplyHostPreferences();
        SystemTweaksService.RemoveDefenderHistoryTask();
        DefenderLegacyCleanup.TryRunOnceInBackground();

        _pipeServer = new ProtectionPipeServer(
            _container.Orchestrator,
            onShutdown: _onShutdownRequested,
            serviceQuarantine: _container.Quarantine,
            realTimeDegradedFolders: () => _container.RealTimeProtection.IsEnabled
                ? _container.RealTimeProtection.DegradedFolderCount
                : null,
            // Client : le fournisseur AMSI, enregistré par l'installeur avec le service.
            enableScanBuffer: true);
        // Le service n'a personne à qui l'afficher : il journalise, les sessions le relèvent.
        _container.RealTimeProtection.HealthChanged += (_, _) =>
        {
            var issues = _container.RealTimeProtection.HealthIssues;
            if (issues.Count > 0)
                AppLogger.Warn("ProtectionServiceHost", "Temps réel dégradé : " + string.Join(" ; ", issues));
            else
                AppLogger.Info("ProtectionServiceHost", "Temps réel : surveillance complète rétablie");
        };
        _pipeServer.Start();

        _retentionTimer = new System.Threading.Timer(_ => ApplyQuarantineRetention(), null, RetentionFirstRun, RetentionPeriod);

        _started = true;
        AppLogger.Info("ProtectionServiceHost", "Hôte de protection système démarré");
    }

    public async Task StopAsync()
    {
        if (!_started)
            return;

        if (_retentionTimer != null)
        {
            await _retentionTimer.DisposeAsync().ConfigureAwait(false);
            _retentionTimer = null;
        }

        if (_threatHandler != null)
        {
            _container.RealTimeProtection.ThreatDetected -= _threatHandler.OnThreatDetected;
            _container.ProcessStartMonitor.ThreatDetected -= _threatHandler.OnThreatDetected;
            _container.RemovableDriveScan.ThreatDetected -= _threatHandler.OnThreatDetected;
        }

        MinifilterUserBridge.Stop();
        PlatformRegistration.TryUnregisterAmsiProvider();
        if (_pipeServer != null)
            await _pipeServer.StopAsync().ConfigureAwait(false);

        _container.Shutdown();
        _threatHandler = null;
        _started = false;
    }

    /// <summary>
    /// Conservation de la quarantaine du service : au-delà de
    /// <see cref="ServiceQuarantineStore.RetentionDays"/> jours, un élément est supprimé.
    /// </summary>
    internal int ApplyQuarantineRetention()
    {
        try
        {
            var removed = _container.Quarantine.PurgeOlderThan(DateTime.Now.AddDays(-ServiceQuarantineStore.RetentionDays));
            if (removed > 0)
                AppLogger.Info("ProtectionServiceHost",
                    $"Quarantaine du service : {removed} élément(s) de plus de {ServiceQuarantineStore.RetentionDays} jours supprimé(s).");
            return removed;
        }
        catch (Exception ex) when (!ex.IsFatal())
        {
            AppLogger.Warn("ProtectionServiceHost", "Conservation de la quarantaine", ex);
            return 0;
        }
    }

    public void Dispose() => _ = StopAsync();
}
