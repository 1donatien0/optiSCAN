using optiSCAN.Models;
using optiSCAN.Platform;

namespace optiSCAN.Services;

/// <summary>Hôte de protection système (RTP, processus, IPC) pour --service-host.</summary>
public sealed class ProtectionServiceHost : IDisposable
{
    private readonly IProtectionServiceHostDependencies _container;
    private ProtectionPipeServer? _pipeServer;
    private ServiceHostThreatHandler? _threatHandler;
    private System.Threading.Timer? _retentionTimer;
    private bool _started;

    /// <summary>Premier passage de conservation peu après le démarrage, puis une fois par jour.</summary>
    private static readonly TimeSpan RetentionFirstRun = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan RetentionPeriod = TimeSpan.FromHours(24);

    public ProtectionServiceHost(ServiceContainer container)
        : this((IProtectionServiceHostDependencies)container)
    {
    }

    public ProtectionServiceHost(IProtectionServiceHostDependencies container) =>
        _container = container;

    public void Start()
    {
        if (_started)
            return;

        _container.ApplyHostPreferences();
        SystemTweaksService.RemoveDefenderHistoryTask();
        DefenderLegacyCleanup.TryRunOnceInBackground();

        _threatHandler = new ServiceHostThreatHandler(_container, _container.ExclusionSettingsAccessor, _container.UserPreferencesAccessor);
        _container.RealTimeProtection.ThreatDetected += _threatHandler.OnThreatDetected;
        _container.ProcessStartMonitor.ThreatDetected += _threatHandler.OnThreatDetected;
        _container.RemovableDriveScan.ThreatDetected += _threatHandler.OnThreatDetected;

        _pipeServer = new ProtectionPipeServer(_container.Orchestrator, serviceQuarantine: _container.Quarantine);
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
        catch (Exception ex)
        {
            AppLogger.Warn("ProtectionServiceHost", "Conservation de la quarantaine", ex);
            return 0;
        }
    }

    public void Dispose() => _ = StopAsync();
}
