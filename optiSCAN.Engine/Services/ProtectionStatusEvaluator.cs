using optiSCAN.Localization;

namespace optiSCAN.Services
{
    /// <summary>Niveau de protection affiché dans l'UI (badge Antivirus, etc.).</summary>
    public enum ProtectionBadgeLevel
    {
        Inactive = 0,
        Degraded = 1,
        Active = 2,
    }

    /// <summary>
    /// Évalue l'état global de protection (ClamAV + YARA + RTP) de façon cohérente
    /// entre Overview, sidebar et en-tête Antivirus.
    /// </summary>
    public static class ProtectionStatusEvaluator
    {
        public static ProtectionBadgeLevel Evaluate(
            bool clamAvInstalled,
            bool yaraAvailable,
            int yaraRulesCount,
            bool realTimeProtectionEnabled,
            bool realTimeProtectionRunning,
            bool realTimeProtectionHealthy = true)
        {
            if (!clamAvInstalled)
                return ProtectionBadgeLevel.Inactive;

            bool yaraOk = !yaraAvailable || yaraRulesCount > 0;
            if (!yaraOk)
                return ProtectionBadgeLevel.Degraded;

            if (!realTimeProtectionEnabled || !realTimeProtectionRunning || !realTimeProtectionHealthy)
                return ProtectionBadgeLevel.Degraded;

            return ProtectionBadgeLevel.Active;
        }

        public static string GetBadgeText(ProtectionBadgeLevel level) => level switch
        {
            ProtectionBadgeLevel.Active => LocalizationService.GetString("Protection_BadgeActive"),
            ProtectionBadgeLevel.Degraded => LocalizationService.GetString("Protection_BadgeDegraded"),
            _ => LocalizationService.GetString("Protection_BadgeInactive"),
        };
    }
}
