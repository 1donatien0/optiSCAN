namespace optiSCAN.Services;

/// <summary>Dépendances de <see cref="ProtectionServiceHost"/> (testable par injection).</summary>
public interface IProtectionServiceHostDependencies : IServiceHostThreatContext
{
    RealTimeProtection RealTimeProtection { get; }

    ProcessStartMonitor ProcessStartMonitor { get; }

    RemovableDriveScanService RemovableDriveScan { get; }

    ScanOrchestrator Orchestrator { get; }

    void ApplyPreferencesOnStartup();

    void Shutdown();
}
