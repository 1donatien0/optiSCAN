using optiSCAN.Models;

namespace optiSCAN.Services;

/// <summary>Gestion des menaces détectées par le moteur --service-host (sans UI).</summary>
internal sealed class ServiceHostThreatHandler
{
    private readonly IServiceHostThreatContext _context;
    private readonly IExclusionSettingsAccessor _exclusions;

    public ServiceHostThreatHandler(IProtectionServiceHostDependencies container)
        : this(
            (IServiceHostThreatContext)container,
            container.ExclusionSettingsAccessor,
            container.UserPreferencesAccessor)
    {
    }

    internal ServiceHostThreatHandler(
        IServiceHostThreatContext context,
        IExclusionSettingsAccessor exclusions,
        IUserPreferencesAccessor preferences)
    {
        _context = context;
        _exclusions = exclusions;
        _ = preferences;
    }

    public void OnThreatDetected(object? sender, ThreatInfo threat)
    {
        try
        {
            // La quarantaine automatique est déjà faite par la source (temps réel, processus,
            // lecteur amovible), avec l'empreinte du contenu analysé. La refaire ici, sans
            // empreinte, mettait en quarantaine un contenu remplacé après l'analyse, justement
            // ce que l'empreinte refuse ; et un succès de la source s'affichait en « échec ».
            var outcome = threat.Status == ThreatStatus.Quarantined
                ? "mise en quarantaine"
                : _exclusions.Current.AutoQuarantineEnabled
                    ? "quarantaine automatique refusée ou impossible"
                    : "quarantaine automatique désactivée";
            _context.Logger.WriteToLog(
                $"[ServiceHost] Menace {threat.VirusName} — {PathRedaction.RedactPath(threat.FilePath)} ({outcome})");

            // Relevée par les sessions ouvertes (notification et historique de l'utilisateur).
            _context.Detections.Record(threat);

            if (threat.Status != ThreatStatus.Quarantined)
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
                    $"[ServiceHost] Réputation cloud — {PathRedaction.RedactPath(threat.FilePath)}: {summary}");
            }
        }
        catch (Exception ex)
        {
            AppLogger.Warn("ServiceHostThreatHandler", "EnrichCloudAsync", ex);
        }
    }
}
