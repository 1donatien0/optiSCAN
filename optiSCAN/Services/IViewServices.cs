using optiSCAN.Models;

namespace optiSCAN.Services;

/// <summary>
/// Services et bus UI exposés aux vues WPF (sans accès au singleton complet).
/// <see cref="ServiceContainer"/> l'implémente ; assigner via <c>Bind()</c> depuis <see cref="optiSCAN.MainWindow"/>.
/// </summary>
public interface IViewServices : IUiEventBus
{
    INavigationService? Navigation { get; }

    AntivirusActions Actions { get; }

    QuarantineManager Quarantine { get; }

    ScanLogManager Logger { get; }

    ThreatReputationService ThreatReputation { get; }

    IScheduledScanService ScheduledScan { get; }

    NotificationService Notifications { get; }

    ThreatInfo? FindKnownThreat(string filePath);
}
