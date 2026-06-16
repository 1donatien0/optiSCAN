using optiSCAN.Models;

namespace optiSCAN.Services;

/// <summary>Gestion des menaces détectées par le moteur --service-host (sans UI).</summary>
internal sealed class ServiceHostThreatHandler
{
    private readonly IServiceHostThreatContext _context;

    public ServiceHostThreatHandler(ServiceContainer container)
        : this((IServiceHostThreatContext)container)
    {
    }

    internal ServiceHostThreatHandler(IServiceHostThreatContext context) =>
        _context = context;

    public void OnThreatDetected(object? sender, ThreatInfo threat)
    {
        try
        {
            if (ExclusionSettings.Current.AutoQuarantineEnabled)
            {
                var repair = ThreatRepairService.TryRemediate(threat, _context.Quarantine);
                _context.Logger.WriteToLog(
                    $"[ServiceHost] Remédiation {threat.FilePath}: {repair.Message}");
            }
            else
            {
                _context.Logger.WriteToLog(
                    $"[ServiceHost] Menace {threat.VirusName} — {threat.FilePath}");
            }

            _ = EnrichCloudAsync(threat);
        }
        catch (Exception ex)
        {
            AppLogger.Warn("ServiceHostThreatHandler", "OnThreatDetected", ex);
        }
    }

    private async Task EnrichCloudAsync(ThreatInfo threat)
    {
        try
        {
            var summary = await _context.CloudThreatIntel
                .EnrichThreatAsync(threat).ConfigureAwait(false);
            if (!string.IsNullOrWhiteSpace(summary))
            {
                _context.Logger.WriteToLog(
                    $"[ServiceHost] Réputation cloud — {threat.FilePath}: {summary}");
            }
        }
        catch (Exception ex)
        {
            AppLogger.Warn("ServiceHostThreatHandler", "EnrichCloudAsync", ex);
        }
    }
}
