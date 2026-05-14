namespace optiSCAN.Services
{
    /// <summary>
    /// Orchestre la mise à jour manuelle ClamAV (freshclam) puis les règles YARA (YaraForge).
    /// Extrait de <see cref="optiSCAN.MainWindow"/> (audit A2) pour isoler le flux métier
    /// du code-behind WPF.
    /// </summary>
    public static class SignatureUpdateCoordinator
    {
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
            appendLog("=== MISE À JOUR COMPLÈTE ===");
            appendLog("1. Mise à jour des signatures ClamAV…");

            var ok = true;

            if (freshclam != null)
            {
                var clam = await freshclam.UpdateAsync(cancellationToken).ConfigureAwait(false);
                appendLog(clam.Success
                    ? $"✅ ClamAV : {clam.Message}"
                    : $"❌ ClamAV : {clam.Message}");
                if (!clam.Success)
                    ok = false;
            }

            appendLog("");
            appendLog("2. Mise à jour des règles de détection…");

            if (rules != null)
            {
                var progress = new Progress<string>(appendLog);
                var rulesResult = await rules.UpdateAsync(progress, cancellationToken).ConfigureAwait(false);
                appendLog(rulesResult.Success
                    ? $"✅ Règles : {rulesResult.Message}"
                    : $"❌ Règles : {rulesResult.Message}");
                if (!rulesResult.Success)
                    ok = false;
            }

            appendLog("");
            appendLog("=== MISE À JOUR TERMINÉE ===");
            return ok;
        }
    }
}
