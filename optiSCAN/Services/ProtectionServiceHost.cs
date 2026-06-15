using optiSCAN.Models;
using optiSCAN.Platform;

namespace optiSCAN.Services;

/// <summary>Hôte de protection système (RTP, processus, IPC) pour --service-host.</summary>
public sealed class ProtectionServiceHost : IDisposable
{
    private ProtectionPipeServer? _pipeServer;
    private bool _started;
    private ServiceContainer? _container;

    public void Start()
    {
        if (_started)
            return;

        _container = ServiceContainer.Default;
        _container.ApplyPreferencesOnStartup();

        _container.RealTimeProtection.ThreatDetected += ServiceHostThreatHandler.OnThreatDetected;
        _container.ProcessStartMonitor.ThreatDetected += ServiceHostThreatHandler.OnThreatDetected;
        _container.RemovableDriveScan.ThreatDetected += ServiceHostThreatHandler.OnThreatDetected;

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

        if (_container != null)
        {
            _container.RealTimeProtection.ThreatDetected -= ServiceHostThreatHandler.OnThreatDetected;
            _container.ProcessStartMonitor.ThreatDetected -= ServiceHostThreatHandler.OnThreatDetected;
            _container.RemovableDriveScan.ThreatDetected -= ServiceHostThreatHandler.OnThreatDetected;
        }

        MinifilterUserBridge.Stop();
        if (_pipeServer != null)
            await _pipeServer.StopAsync().ConfigureAwait(false);

        ServiceContainer.Default.Shutdown();
        _started = false;
        _container = null;
    }

    public void Dispose() => _ = StopAsync();
}
