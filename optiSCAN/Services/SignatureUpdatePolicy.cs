namespace optiSCAN.Services
{
    /// <summary>Résultat du contrôle signatures au démarrage (sans I/O réseau).</summary>
    public readonly struct SignatureStartupNeed
    {
        public bool Needed { get; init; }
        public bool MissingClam { get; init; }
        public bool MissingYara { get; init; }
        public bool ClamStale { get; init; }
        public string Reason { get; init; }
    }

    /// <summary>Intervalles de mise à jour des signatures et contrôle au démarrage.</summary>
    public static class SignatureUpdatePolicy
    {
        private static readonly TimeSpan StandardClamInterval = TimeSpan.FromHours(4);
        private static readonly TimeSpan StandardYaraInterval = TimeSpan.FromHours(24);
        private static readonly TimeSpan AggressiveClamInterval = TimeSpan.FromHours(2);
        private static readonly TimeSpan AggressiveYaraInterval = TimeSpan.FromHours(12);

        public static SignatureStartupNeed EvaluateStartupNeed(
            DateTime? lastClamUpdate,
            bool hasLocalYaraRules,
            int staleThresholdDays,
            DateTime? utcNow = null)
        {
            var now = utcNow ?? DateTime.UtcNow;
            var threshold = TimeSpan.FromDays(Math.Max(1, staleThresholdDays));
            var missingClam = lastClamUpdate == null;
            var missingYara = !hasLocalYaraRules;
            var clamStale = !missingClam
                && now - lastClamUpdate!.Value.ToUniversalTime() >= threshold;
            var needed = missingClam || missingYara || clamStale;

            string reason;
            if (!needed)
                reason = "Signatures à jour";
            else if (missingClam && missingYara)
                reason = "Bases ClamAV et règles YARA absentes — téléchargement au démarrage";
            else if (missingClam)
                reason = "Bases ClamAV absentes — téléchargement freshclam au démarrage";
            else if (missingYara)
                reason = "Règles YARA absentes — téléchargement YARA-Forge au démarrage";
            else
                reason = "Signatures potentiellement obsolètes — MAJ au démarrage";

            return new SignatureStartupNeed
            {
                Needed = needed,
                MissingClam = missingClam,
                MissingYara = missingYara,
                ClamStale = clamStale,
                Reason = reason,
            };
        }

        /// <summary>
        /// Informe l'utilisateur (toast, non bloquant) puis lance le téléchargement
        /// silencieux si la MAJ auto est activée.
        /// </summary>
        public static void NotifyAndScheduleStartupRefresh(
            ServiceContainer container,
            IUserPreferencesAccessor preferences)
        {
            var need = EvaluateStartupNeed(
                container.FreshclamUpdater.GetLastSignatureUpdateTime(),
                container.RulesUpdater.HasLocalRulesFiles(),
                preferences.Current.SignatureStaleThresholdDays);

            if (need.Needed)
            {
                if (preferences.Current.SignatureAutoUpdateEnabled)
                    container.Notifications.ShowSignatureDownloadStarted();
                else
                    container.Notifications.ShowSignatureUpdateNeeded();
            }

            ScheduleStartupRefreshIfStale(container, preferences);
        }

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

            _ = Task.Run(async () =>
            {
                try
                {
                    var fresh = container.FreshclamUpdater;
                    var rules = container.RulesUpdater;
                    var need = EvaluateStartupNeed(
                        fresh.GetLastSignatureUpdateTime(),
                        rules.HasLocalRulesFiles(),
                        preferences.Current.SignatureStaleThresholdDays);

                    if (!need.Needed)
                        return;

                    AppLogger.Info("SignatureUpdatePolicy", need.Reason);
                    if (need.MissingClam || need.ClamStale)
                        await fresh.UpdateAsync().ConfigureAwait(false);
                    if (need.MissingYara || need.ClamStale || need.MissingClam)
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
