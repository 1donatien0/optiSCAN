// SPDX-License-Identifier: GPL-3.0-or-later
namespace optiSCAN.Services;

/// <summary>Dépendances de <see cref="ProtectionServiceHost"/> (testable par injection).</summary>
public interface IProtectionServiceHostDependencies : IServiceHostThreatContext
{
    RealTimeProtection RealTimeProtection { get; }

    ProcessStartMonitor ProcessStartMonitor { get; }

    RemovableDriveScanService RemovableDriveScan { get; }

    IExclusionSettingsAccessor ExclusionSettingsAccessor { get; }

    IUserPreferencesAccessor UserPreferencesAccessor { get; }

    ScanOrchestrator Orchestrator { get; }

    void ApplyPreferencesOnStartup();

    /// <summary>Démarrage de l'hôte SYSTEM : pas de relance du service ni d'un second processus.</summary>
    void ApplyHostPreferences();

    void Shutdown();
}
