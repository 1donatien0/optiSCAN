using Microsoft.Toolkit.Uwp.Notifications;
using optiSCAN.Models;

namespace optiSCAN.Services
{
    /// <summary>
    /// Gère les notifications toast Windows natives.
    /// Nécessite le package Microsoft.Toolkit.Uwp.Notifications.
    /// </summary>
    public class NotificationService
    {
        private bool _toastsEnabled = true;

        public NotificationService()
        {
            // Callback d'activation des toasts — corps vide, nécessaire pour que
            // le Compat manager s'initialise correctement en WPF .NET 8.
            ToastNotificationManagerCompat.OnActivated += _ => { };
        }

        public bool IsEnabled
        {
            get => _toastsEnabled;
            set => _toastsEnabled = value;
        }

        /// <summary>
        /// Affiche une notification de menace détectée
        /// </summary>
        public void ShowThreatDetected(ThreatInfo threat)
        {
            if (!_toastsEnabled) return;

            try
            {
                var severity = RiskScoringService.GetSeverityLevel(threat);

                new ToastContentBuilder()
                    .AddArgument("action", "threat")
                    .AddArgument("file", threat.FilePath)
                    .AddArgument("virus", threat.VirusName)
                    .AddText("⚠️ Menace détectée !")
                    .AddText(threat.VirusName)
                    .AddText($"{threat.FileName} • {severity}")
                    .AddButton(new ToastButton()
                        .SetContent("Mettre en quarantaine")
                        .AddArgument("action", "quarantine"))
                    .AddButton(new ToastButton()
                        .SetContent("Ignorer")
                        .AddArgument("action", "ignore"))
                    .AddButton(new ToastButton()
                        .SetContent("Ouvrir optiSCAN")
                        .AddArgument("action", "open"))
                    .SetToastDuration(ToastDuration.Long)
                    .Show();
            }
            catch (Exception ex)
            {
                AppLogger.Error("NotificationService", "ShowThreatDetected", ex);
            }
        }

        /// <summary>
        /// Affiche une notification de mise en quarantaine
        /// </summary>
        public void ShowQuarantined(ThreatInfo threat)
        {
            if (!_toastsEnabled) return;

            try
            {
                new ToastContentBuilder()
                    .AddArgument("action", "quarantined")
                    .AddText("🔒 Fichier mis en quarantaine")
                    .AddText($"{threat.FileName} → {threat.VirusName}")
                    .AddButton(new ToastButton()
                        .SetContent("Voir quarantaine")
                        .AddArgument("action", "showquarantine"))
                    .Show();
            }
            catch (Exception ex)
            {
                AppLogger.Error("NotificationService", "ShowQuarantined", ex);
            }
        }

        /// <summary>
        /// Affiche une notification de scan terminé
        /// </summary>
        public void ShowScanCompleted(int threatsFound, int filesScanned)
        {
            if (!_toastsEnabled) return;

            try
            {
                if (threatsFound == 0)
                {
                    new ToastContentBuilder()
                        .AddText("✅ Scan terminé")
                        .AddText($"{filesScanned} fichiers analysés, aucune menace")
                        .Show();
                }
                else
                {
                    new ToastContentBuilder()
                        .AddText($"⚠️ Scan terminé — {threatsFound} menace(s)")
                        .AddText("Consultez l'historique pour plus de détails")
                        .AddButton(new ToastButton()
                            .SetContent("Ouvrir l'historique")
                            .AddArgument("action", "history"))
                        .Show();
                }
            }
            catch (Exception ex)
            {
                AppLogger.Error("NotificationService", "ShowScanCompleted", ex);
            }
        }

        /// <summary>
        /// Affiche une notification de mise à jour disponible
        /// </summary>
        public void ShowUpdateAvailable(string version)
        {
            if (!_toastsEnabled) return;

            try
            {
                new ToastContentBuilder()
                    .AddText("🔄 Mises à jour disponibles")
                    .AddText($"Nouvelles signatures ClamAV v{version}")
                    .AddButton(new ToastButton()
                        .SetContent("Mettre à jour")
                        .AddArgument("action", "update"))
                    .Show();
            }
            catch (Exception ex)
            {
                AppLogger.Error("NotificationService", "ShowUpdateAvailable", ex);
            }
        }

        /// <summary>
        /// Affiche une notification de démarrage de la protection temps réel
        /// </summary>
        public void ShowRealTimeProtectionStarted()
        {
            if (!_toastsEnabled) return;

            try
            {
                new ToastContentBuilder()
                    .AddText("🛡️ Protection temps réel activée")
                    .AddText("optiSCAN surveille les fichiers en arrière-plan")
                    .SetToastDuration(ToastDuration.Short)
                    .Show();
            }
            catch (Exception ex)
            {
                AppLogger.Error("NotificationService", "ShowRealTimeProtectionStarted", ex);
            }
        }

    }
}
