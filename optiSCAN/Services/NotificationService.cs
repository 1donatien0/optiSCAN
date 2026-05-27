using Microsoft.Toolkit.Uwp.Notifications;
using optiSCAN.Models;

namespace optiSCAN.Services
{
    /// <summary>
    /// Notifications toast Windows natives.
    /// Les actions (quarantaine, ignorer, navigation…) sont traitées via <see cref="ToastActivated"/>.
    /// </summary>
    public class NotificationService
    {
        private bool _toastsEnabled = true;
        private static bool _activationHooked;

        /// <summary>Émis sur le thread du callback toolkit — le handler doit marshaler vers l'UI WPF.</summary>
        public event EventHandler<ToastActivationEventArgs>? ToastActivated;

        public NotificationService()
        {
            EnsureActivationHook();
        }

        public bool IsEnabled
        {
            get => _toastsEnabled;
            set => _toastsEnabled = value;
        }

        /// <summary>Aligne l'état sur <see cref="UserPreferences.ActionNotificationsEnabled"/>.</summary>
        public void SyncFromUserPreferences()
        {
            _toastsEnabled = UserPreferences.Current.ActionNotificationsEnabled;
        }

        private static void EnsureActivationHook()
        {
            if (_activationHooked) return;
            _activationHooked = true;
            ToastNotificationManagerCompat.OnActivated += SurActivationToastStatic;
        }

        private static void SurActivationToastStatic(ToastNotificationActivatedEventArgsCompat e)
        {
            try
            {
                var parsed = ToastArguments.Parse(e.Argument);
                var action = parsed.Get("action") ?? string.Empty;
                var file = parsed.Get("file");
                var virus = parsed.Get("virus");

                var args = new ToastActivationEventArgs(action, file, virus);
                ServiceContainer.Default.Notifications.DispatchActivation(args);
            }
            catch (Exception ex)
            {
                AppLogger.Warn("NotificationService", "OnActivated", ex);
            }
        }

        internal void DispatchActivation(ToastActivationEventArgs args) =>
            ToastActivated?.Invoke(this, args);

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
                    .AddText("Menace détectée")
                    .AddText(threat.VirusName)
                    .AddText($"{threat.FileName} • {severity}")
                    .AddButton(new ToastButton()
                        .SetContent("Mettre en quarantaine")
                        .AddArgument("action", "quarantine")
                        .AddArgument("file", threat.FilePath)
                        .AddArgument("virus", threat.VirusName))
                    .AddButton(new ToastButton()
                        .SetContent("Ignorer")
                        .AddArgument("action", "ignore")
                        .AddArgument("file", threat.FilePath))
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

        public void ShowQuarantined(ThreatInfo threat)
        {
            if (!_toastsEnabled) return;

            try
            {
                new ToastContentBuilder()
                    .AddArgument("action", "quarantined")
                    .AddText("Fichier mis en quarantaine")
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

        public void ShowScanCompleted(int threatsFound, int filesScanned)
        {
            if (!_toastsEnabled) return;

            try
            {
                if (threatsFound == 0)
                {
                    new ToastContentBuilder()
                        .AddArgument("action", "scanok")
                        .AddText("Scan terminé")
                        .AddText($"{filesScanned} fichiers analysés, aucune menace")
                        .Show();
                }
                else
                {
                    new ToastContentBuilder()
                        .AddArgument("action", "scanthreats")
                        .AddArgument("threats", threatsFound.ToString())
                        .AddText($"Scan terminé — {threatsFound} menace(s)")
                        .AddText("Consultez l'historique pour plus de détails")
                        .AddButton(new ToastButton()
                            .SetContent("Ouvrir l'historique")
                            .AddArgument("action", "history"))
                        .AddButton(new ToastButton()
                            .SetContent("Ouvrir optiSCAN")
                            .AddArgument("action", "open"))
                        .Show();
                }
            }
            catch (Exception ex)
            {
                AppLogger.Error("NotificationService", "ShowScanCompleted", ex);
            }
        }

        public void ShowUpdateAvailable(string version)
        {
            if (!_toastsEnabled) return;

            try
            {
                new ToastContentBuilder()
                    .AddArgument("action", "update")
                    .AddText("Mises à jour disponibles")
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

        public void ShowRealTimeProtectionStarted()
        {
            if (!_toastsEnabled) return;

            try
            {
                new ToastContentBuilder()
                    .AddArgument("action", "rtpstarted")
                    .AddText("Protection temps réel activée")
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

    /// <summary>Action demandée depuis un toast Windows.</summary>
    public sealed class ToastActivationEventArgs : EventArgs
    {
        public ToastActivationEventArgs(string action, string? filePath, string? virusName)
        {
            Action = action ?? string.Empty;
            FilePath = filePath;
            VirusName = virusName;
        }

        public string Action { get; }
        public string? FilePath { get; }
        public string? VirusName { get; }
    }
}
