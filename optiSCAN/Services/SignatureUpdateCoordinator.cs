namespace optiSCAN.Services
{
    /// <summary>
    /// Orchestre la mise à jour manuelle ClamAV (freshclam) puis les règles YARA (YaraForge).
    /// Logique extraite de <see cref="optiSCAN.MainWindow"/> pour isoler le flux métier du code-behind WPF.
    /// </summary>
    public static class SignatureUpdateCoordinator
    {
        private static readonly TimeSpan FullUpdateTimeout = TimeSpan.FromMinutes(5);

        /// <summary>
        /// Exécute freshclam puis la mise à jour des règles. Les logs passent par <paramref name="appendLog"/> (thread UI ou background).
        /// </summary>
        /// <returns><c>true</c> si les deux étapes ont réussi (ou ont été ignorées avec succès).</returns>
        public static async Task<bool> RunFullSignatureUpdateAsync(
            FreshclamUpdater? freshclam,
            YaraForgeUpdater? rules,
            Action<string> appendLog,
            CancellationToken cancellationToken = default)
        {
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(FullUpdateTimeout);
            var ct = timeoutCts.Token;

            appendLog("=== MISE À JOUR COMPLÈTE ===");
            appendLog("1. Mise à jour des signatures ClamAV…");

            var ok = true;

            if (freshclam != null)
            {
                var clam = await freshclam.UpdateAsync(ct).ConfigureAwait(false);
                appendLog(clam.Success
                    ? UiLogText.Ok($"ClamAV : {clam.Message}")
                    : UiLogText.Error($"ClamAV : {clam.Message}"));
                if (!clam.Success)
                    ok = false;
            }

            appendLog("");
            appendLog("2. Mise à jour des règles de détection…");

            if (rules != null)
            {
                var progress = new Progress<string>(appendLog);
                var rulesResult = await rules.UpdateAsync(progress, ct).ConfigureAwait(false);
                appendLog(rulesResult.Success
                    ? UiLogText.Ok($"Règles : {rulesResult.Message}")
                    : UiLogText.Error($"Règles : {rulesResult.Message}"));
                if (!rulesResult.Success)
                    ok = false;
            }

            appendLog("");
            appendLog("=== MISE À JOUR TERMINÉE ===");
            return ok;
        }
    }
}
