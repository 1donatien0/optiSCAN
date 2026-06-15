using optiSCAN.Models;

namespace optiSCAN.Services;

/// <summary>Gestion des menaces détectées par le moteur --service-host (sans UI).</summary>
internal static class ServiceHostThreatHandler
{
    public static void OnThreatDetected(object? sender, ThreatInfo threat)
    {
        try
        {
            if (ExclusionSettings.Current.AutoQuarantineEnabled)
            {
                var repair = ThreatRepairService.TryRemediate(threat, ServiceContainer.Default.Quarantine);
                ServiceContainer.Default.Logger.WriteToLog(
                    $"[ServiceHost] Remédiation {threat.FilePath}: {repair.Message}");
            }
            else
            {
                ServiceContainer.Default.Logger.WriteToLog(
                    $"[ServiceHost] Menace {threat.VirusName} — {threat.FilePath}");
            }

            _ = EnrichCloudAsync(threat);
        }
        catch (Exception ex)
        {
            AppLogger.Warn("ServiceHostThreatHandler", "OnThreatDetected", ex);
        }
    }

    private static async Task EnrichCloudAsync(ThreatInfo threat)
    {
        try
        {
            var summary = await ServiceContainer.Default.CloudThreatIntel
                .EnrichThreatAsync(threat).ConfigureAwait(false);
            if (!string.IsNullOrWhiteSpace(summary))
            {
                ServiceContainer.Default.Logger.WriteToLog(
                    $"[ServiceHost] Réputation cloud — {threat.FilePath}: {summary}");
            }
        }
        catch (Exception ex)
        {
            AppLogger.Warn("ServiceHostThreatHandler", "EnrichCloudAsync", ex);
        }
    }
}
