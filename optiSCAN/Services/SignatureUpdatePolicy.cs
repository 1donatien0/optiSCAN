namespace optiSCAN.Services
{
    /// <summary>Intervalles de mise à jour des signatures et contrôle au démarrage.</summary>
    public static class SignatureUpdatePolicy
    {
        private static readonly TimeSpan StandardClamInterval = TimeSpan.FromHours(4);
        private static readonly TimeSpan StandardYaraInterval = TimeSpan.FromHours(24);
        private static readonly TimeSpan AggressiveClamInterval = TimeSpan.FromHours(2);
        private static readonly TimeSpan AggressiveYaraInterval = TimeSpan.FromHours(12);

        public static void ApplyAutoUpdateTimers(
            ISignatureAutoUpdateTarget freshclam,
            ISignatureAutoUpdateTarget rules,
            bool enabled,
            IUserPreferencesAccessor preferences)
        {
            if (!enabled)
            {
                freshclam.DisableAutoUpdate();
                rules.DisableAutoUpdate();
                return;
            }

            var aggressive = preferences.Current.AggressiveSignatureUpdates;
            freshclam.EnableAutoUpdate(aggressive ? AggressiveClamInterval : StandardClamInterval);
            rules.EnableAutoUpdate(aggressive ? AggressiveYaraInterval : StandardYaraInterval);
        }

        public static void ScheduleStartupRefreshIfStale(ServiceContainer container, IUserPreferencesAccessor preferences)
        {
            if (!preferences.Current.SignatureAutoUpdateEnabled)
                return;

            var threshold = TimeSpan.FromDays(Math.Max(1, preferences.Current.SignatureStaleThresholdDays));
            _ = Task.Run(async () =>
            {
                try
                {
                    var fresh = container.FreshclamUpdater;
                    var rules = container.RulesUpdater;
                    var lastClam = fresh.GetLastSignatureUpdateTime();
                    var missingClam = lastClam == null;
                    var missingYara = !rules.HasLocalRulesFiles();
                    var clamStale = !missingClam
                        && DateTime.UtcNow - lastClam!.Value.ToUniversalTime() >= threshold;

                    if (!missingClam && !missingYara && !clamStale)
                        return;

                    string reason;
                    if (missingClam && missingYara)
                        reason = "Bases ClamAV et règles YARA absentes — téléchargement au démarrage";
                    else if (missingClam)
                        reason = "Bases ClamAV absentes — téléchargement freshclam au démarrage";
                    else if (missingYara)
                        reason = "Règles YARA absentes — téléchargement YARA-Forge au démarrage";
                    else
                        reason = "Signatures potentiellement obsolètes — MAJ au démarrage";

                    AppLogger.Info("SignatureUpdatePolicy", reason);
                    if (missingClam || clamStale)
                        await fresh.UpdateAsync().ConfigureAwait(false);
                    if (missingYara || clamStale || missingClam)
                        await rules.UpdateAsync().ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    AppLogger.Warn("SignatureUpdatePolicy", "ScheduleStartupRefreshIfStale", ex);
                }
            });
        }
    }
}
