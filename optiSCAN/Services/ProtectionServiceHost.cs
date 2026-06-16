using optiSCAN.Models;
using optiSCAN.Platform;

namespace optiSCAN.Services;

/// <summary>Hôte de protection système (RTP, processus, IPC) pour --service-host.</summary>
public sealed class ProtectionServiceHost : IDisposable
{
    private readonly IProtectionServiceHostDependencies _container;
    private ProtectionPipeServer? _pipeServer;
    private ServiceHostThreatHandler? _threatHandler;
    private bool _started;

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

        _container.ApplyPreferencesOnStartup();

        _threatHandler = new ServiceHostThreatHandler(_container);
        _container.RealTimeProtection.ThreatDetected += _threatHandler.OnThreatDetected;
        _container.ProcessStartMonitor.ThreatDetected += _threatHandler.OnThreatDetected;
        _container.RemovableDriveScan.ThreatDetected += _threatHandler.OnThreatDetected;

        _pipeServer = new ProtectionPipeServer(_container.Orchestrator);
        _pipeServer.Start();

        MinifilterUserBridge.TryStart(_container.Orchestrator);
        PlatformRegistration.TryRegisterAmsiProvider();
        PlatformRegistration.TryLoadMinifilter();

        _started = true;
        AppLogger.Info("ProtectionServiceHost", "Hôte de protection système démarré");
    }

    public async Task StopAsync()
    {
        if (!_started)
            return;

        if (_threatHandler != null)
        {
            _container.RealTimeProtection.ThreatDetected -= _threatHandler.OnThreatDetected;
            _container.ProcessStartMonitor.ThreatDetected -= _threatHandler.OnThreatDetected;
            _container.RemovableDriveScan.ThreatDetected -= _threatHandler.OnThreatDetected;
        }

        MinifilterUserBridge.Stop();
        if (_pipeServer != null)
            await _pipeServer.StopAsync().ConfigureAwait(false);

        _container.Shutdown();
        _threatHandler = null;
        _started = false;
    }

    public void Dispose() => _ = StopAsync();
}
