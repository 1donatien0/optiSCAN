using System.IO;
using System.Runtime.Versioning;
using optiSCAN.Models;

namespace optiSCAN.Services
{
    /// <summary>
    /// Centralise les actions exécutables depuis l'UI antivirus.
    ///
    /// Avant ce service, AntivirusView déléguait 7 boutons vers MainWindow
    /// via un cast (Win?.BtnXxx_Click). Toute la logique métier était dans
    /// MainWindow.xaml.cs, et la vue ne compilait/testait que dans son contexte.
    ///
    /// Maintenant, AntivirusView peut appeler ces actions directement sans
    /// connaître MainWindow. La vue déclenche l'action, le service fait le
    /// travail, l'UI rafraîchit via les events du container.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public sealed class AntivirusActions
    {
        private readonly QuarantineManager _quarantine;
        private readonly FreshclamUpdater _freshclam;
        private readonly YaraForgeUpdater _rules;

        public AntivirusActions(ServiceContainer container)
        {
            _quarantine = container.Quarantine;
            _freshclam = container.FreshclamUpdater;
            _rules = container.RulesUpdater;
        }

        /// <summary>Événement déclenché après une action ayant modifié l'état de la quarantaine
        /// ou des menaces. Les vues s'y abonnent pour rafraîchir leurs DataGrids.</summary>
        public event EventHandler<ActionResult>? ActionCompleted;

        // ── Actions sur menaces détectées ────────────────────────────────────────

        public ActionResult QuarantineThreat(string filePath)
        {
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
                return Complete(false, $"Fichier introuvable : {Path.GetFileName(filePath)}");

            var threat = new ThreatInfo
            {
                FilePath = filePath,
                VirusName = "Détecté",
                DetectedAt = DateTime.Now,
                Status = ThreatStatus.Detected,
                FileSize = SafeFileSize(filePath),
            };

            bool ok = _quarantine.Quarantine(threat);
            return Complete(ok,
                ok ? $"✅ Fichier mis en quarantaine : {Path.GetFileName(filePath)}"
                   : $"❌ Échec quarantaine : {Path.GetFileName(filePath)}");
        }

        public ActionResult IgnoreThreat(string filePath)
        {
            // « Ignorer » = ne fait rien sur le filesystem, juste un signal UI.
            // Le fichier reste mais l'utilisateur a explicitement déclaré qu'il
            // n'est pas malveillant. On loggue pour traçabilité.
            AppLogger.Info("AntivirusActions", $"Menace ignorée par l'utilisateur : {filePath}");
            return Complete(true, $"⚠️ Fichier ignoré : {Path.GetFileName(filePath)}", isWarning: true);
        }

        public ActionResult DeleteThreatFile(string filePath)
        {
            try
            {
                if (File.Exists(filePath))
                {
                    File.Delete(filePath);
                    return Complete(true, $"🗑️ Fichier supprimé : {Path.GetFileName(filePath)}");
                }
                return Complete(false, $"Fichier déjà absent : {Path.GetFileName(filePath)}");
            }
            catch (Exception ex)
            {
                AppLogger.Error("AntivirusActions", $"DeleteThreatFile {filePath}", ex);
                return Complete(false, $"❌ Erreur suppression : {ex.Message}", isError: true);
            }
        }

        // ── Actions sur entrées de quarantaine ───────────────────────────────────

        public ActionResult RestoreFromQuarantine(string quarantineId)
        {
            bool ok = _quarantine.Restore(quarantineId);
            return Complete(ok,
                ok ? "✅ Fichier restauré depuis la quarantaine"
                   : "❌ Restauration impossible (chemin sensible, manifest invalide ou disque)",
                isError: !ok);
        }

        public ActionResult DeleteFromQuarantine(string quarantineId)
        {
            bool ok = _quarantine.DeletePermanently(quarantineId);
            return Complete(ok,
                ok ? "🗑️ Fichier supprimé définitivement de la quarantaine"
                   : "❌ Suppression impossible",
                isError: !ok);
        }

        // ── Actions sur mises à jour signatures ──────────────────────────────────

        public void StopAllUpdates()
        {
            try { _freshclam.CancelUpdate(); }
            catch (Exception ex) { AppLogger.Warn("AntivirusActions", "Cancel freshclam", ex); }

            try { _rules.CancelUpdate(); }
            catch (Exception ex) { AppLogger.Warn("AntivirusActions", "Cancel rules", ex); }

            Complete(true, "⏹️ Mise à jour interrompue par l'utilisateur");
        }

        // ── Helpers ──────────────────────────────────────────────────────────────

        private static long SafeFileSize(string path)
        {
            try { return new FileInfo(path).Length; }
            catch { return 0; }
        }

        private ActionResult Complete(bool success, string message, bool isError = false, bool isWarning = false)
        {
            var result = new ActionResult
            {
                Success = success,
                Message = message,
                IsError = isError,
                IsWarning = isWarning,
            };
            ActionCompleted?.Invoke(this, result);
            return result;
        }
    }

    /// <summary>Résultat synchrone d'une action UI antivirus.</summary>
    public sealed class ActionResult
    {
        public bool Success { get; init; }
        public string Message { get; init; } = string.Empty;
        public bool IsError { get; init; }
        public bool IsWarning { get; init; }
    }
}
