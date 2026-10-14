using Microsoft.Toolkit.Uwp.Notifications;
using optiSCAN.Localization;
using optiSCAN.Models;

namespace optiSCAN.Services
{
    /// <summary>
    /// Notifications toast Windows natives.
    /// Les actions (quarantaine, ignorer, navigation…) sont traitées via <see cref="ToastActivated"/>.
    /// </summary>
    public class NotificationService
    {
        private static NotificationService? _activationTarget;

        private bool _toastsEnabled = true;
        private static bool _activationHooked;

        /// <summary>Émis sur le thread du callback toolkit — le handler doit marshaler vers l'UI WPF.</summary>
        public event EventHandler<ToastActivationEventArgs>? ToastActivated;

        private readonly IUserPreferencesAccessor _prefs;

        public NotificationService(IUserPreferencesAccessor? preferences = null)
        {
            _prefs = preferences ?? new DefaultUserPreferencesAccessor();
            _activationTarget = this;
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
            _toastsEnabled = _prefs.Current.ActionNotificationsEnabled;
        }

        private static void EnsureActivationHook()
        {
            if (_activationHooked) return;
            _activationHooked = true;
            ToastNotificationManagerCompat.OnActivated += SurActivationToastStatic;
        }

        /// <summary>Réinitialise l'enregistrement du hook toast (tests unitaires uniquement).</summary>
        internal static void ResetActivationHookForTests()
        {
            _activationHooked = false;
            _activationTarget = null;
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
                _activationTarget?.DispatchActivation(args);
            }
            catch (Exception ex)
            {
                AppLogger.Warn("NotificationService", "OnActivated", ex);
            }
        }

        internal void DispatchActivation(ToastActivationEventArgs args) =>
            ToastActivated?.Invoke(this, args);

        /// <summary>
        /// Temps réel dégradé (dossiers non surveillés ou rattrapage en cours) : une alerte à
        /// l'entrée dans cet état, le détail reste sur le badge de protection.
        /// </summary>
        public void ShowRealTimeDegraded(int folderCount)
        {
            if (!ShouldShowToast())
                return;
            try
            {
                new ToastContentBuilder()
                    .AddArgument("action", "openav")
                    .AddText(LocalizationService.GetString("Notif_RtDegradedTitle"))
                    .AddText(LocalizationService.Format("Notif_RtDegradedBody", folderCount))
                    .Show();
            }
            catch (Exception ex)
            {
                AppLogger.Warn("NotificationService", "ShowRealTimeDegraded", ex);
            }
        }

        public void ShowThreatDetected(ThreatInfo threat)
        {
            if (!ShouldShowToast())
            {
                Defer(threat);
                return;
            }

            try
            {
                var severity = RiskScoringService.GetSeverityLevel(threat);

                new ToastContentBuilder()
                    .AddArgument("action", "threat")
                    .AddArgument("file", threat.FilePath)
                    .AddArgument("virus", threat.VirusName)
                    .AddText(LocalizationService.GetString("Notif_ThreatTitle"))
                    .AddText(threat.VirusName)
                    .AddText($"{threat.FileName} • {severity}")
                    .AddButton(new ToastButton()
                        .SetContent(LocalizationService.GetString("Notif_QuarantineBtn"))
                        .AddArgument("action", "quarantine")
                        .AddArgument("file", threat.FilePath)
                        .AddArgument("virus", threat.VirusName))
                    .AddButton(new ToastButton()
                        .SetContent(LocalizationService.GetString("Notif_IgnoreBtn"))
                        .AddArgument("action", "ignore")
                        .AddArgument("file", threat.FilePath)
                        .AddArgument("virus", threat.VirusName))
                    .AddButton(new ToastButton()
                        .SetContent(LocalizationService.GetString("Notif_OpenAntivirus"))
                        .AddArgument("action", "openav"))
                    .AddButton(new ToastButton()
                        .SetContent(LocalizationService.GetString("Notif_OpenApp"))
                        .AddArgument("action", "open"))
                    .SetToastDuration(ToastDuration.Long)
                    .Show();
            }
            catch (Exception ex)
            {
                AppLogger.Error("NotificationService", "ShowThreatDetected", ex);
            }
        }

        // ── Mode jeu / plein écran : alertes de menace différées ────────────────────
        // Une menace détectée pendant une partie n'était jamais signalée : la notification était
        // simplement abandonnée. Elle est gardée, puis résumée à la sortie du mode.

        internal const int MaxDeferredThreats = 50;
        private static readonly TimeSpan DeferredCheckInterval = TimeSpan.FromSeconds(20);
        private readonly object _deferGate = new();
        private readonly List<(ThreatInfo Threat, bool FromService)> _deferredThreats = new();
        private int _deferredCount;
        private System.Threading.Timer? _deferTimer;

        internal int DeferredCount
        {
            get { lock (_deferGate) return _deferredCount; }
        }

        private void Defer(ThreatInfo threat, bool fromService = false)
        {
            if (!_toastsEnabled)
                return;
            lock (_deferGate)
            {
                _deferredCount++;
                if (_deferredThreats.Count < MaxDeferredThreats)
                    _deferredThreats.Add((threat, fromService));
                _deferTimer ??= new System.Threading.Timer(_ => FlushDeferred(), null, DeferredCheckInterval, DeferredCheckInterval);
            }
        }

        private void DeferCount(int count)
        {
            if (!_toastsEnabled || count <= 0)
                return;
            lock (_deferGate)
            {
                _deferredCount += count;
                _deferTimer ??= new System.Threading.Timer(_ => FlushDeferred(), null, DeferredCheckInterval, DeferredCheckInterval);
            }
        }

        /// <summary>Hors mode jeu : montre ce qui a été retenu (une alerte, ou un résumé).</summary>
        internal void FlushDeferred()
        {
            if (!ShouldShowToast())
                return;

            List<(ThreatInfo Threat, bool FromService)> threats;
            int count;
            lock (_deferGate)
            {
                if (_deferredCount == 0)
                    return;
                threats = _deferredThreats.ToList();
                count = _deferredCount;
                _deferredThreats.Clear();
                _deferredCount = 0;
                _deferTimer?.Dispose();
                _deferTimer = null;
            }

            if (count == 1 && threats.Count == 1)
            {
                // Une détection du service garde sa notification propre (sans boutons d'action :
                // son chemin peut n'être qu'un nom de fichier).
                if (threats[0].FromService)
                    ShowServiceThreat(threats[0].Threat);
                else
                    ShowThreatDetected(threats[0].Threat);
                return;
            }

            try
            {
                new ToastContentBuilder()
                    .AddArgument("action", "history")
                    .AddText(LocalizationService.GetString("Notif_DeferredThreatsTitle"))
                    .AddText(LocalizationService.Format("Notif_DeferredThreatsBody", count))
                    .AddButton(new ToastButton()
                        .SetContent(LocalizationService.GetString("Notif_HistoryBtn"))
                        .AddArgument("action", "history"))
                    .SetToastDuration(ToastDuration.Long)
                    .Show();
            }
            catch (Exception ex)
            {
                AppLogger.Error("NotificationService", "FlushDeferred", ex);
            }
        }

        internal bool ShouldShowToast() =>
            _toastsEnabled && !DistractionFreeMonitor.ShouldSuppressNotifications();

        public void ShowQuarantined(ThreatInfo threat)
        {
            if (!ShouldShowToast()) return;

            try
            {
                new ToastContentBuilder()
                    .AddArgument("action", "quarantined")
                    .AddText(LocalizationService.GetString("Notif_QuarantinedTitle"))
                    .AddText($"{threat.FileName} → {threat.VirusName}")
                    .AddButton(new ToastButton()
                        .SetContent(LocalizationService.GetString("Notif_ViewQuarantine"))
                        .AddArgument("action", "showquarantine"))
                    .Show();
            }
            catch (Exception ex)
            {
                AppLogger.Error("NotificationService", "ShowQuarantined", ex);
            }
        }

        /// <summary>Menace trouvée par le service SYSTEM, relevée par la session.</summary>
        public void ShowServiceThreat(ThreatInfo threat)
        {
            if (!ShouldShowToast())
            {
                Defer(threat, fromService: true);
                return;
            }

            try
            {
                var body = threat.Status == ThreatStatus.Quarantined
                    ? LocalizationService.Format("Notif_ServiceThreatQuarantined", threat.FileName, threat.VirusName)
                    : LocalizationService.Format("Notif_ServiceThreatDetected", threat.FileName, threat.VirusName);
                new ToastContentBuilder()
                    .AddArgument("action", "history")
                    .AddText(LocalizationService.GetString("Notif_ServiceThreatTitle"))
                    .AddText(body)
                    .AddButton(new ToastButton()
                        .SetContent(LocalizationService.GetString("Notif_HistoryBtn"))
                        .AddArgument("action", "history"))
                    .Show();
            }
            catch (Exception ex)
            {
                AppLogger.Error("NotificationService", "ShowServiceThreat", ex);
            }
        }

        /// <summary>Plusieurs menaces du service relevées d'un coup : une seule notification.</summary>
        public void ShowServiceThreatsSummary(int count)
        {
            if (!ShouldShowToast())
            {
                DeferCount(count);
                return;
            }

            try
            {
                new ToastContentBuilder()
                    .AddArgument("action", "history")
                    .AddText(LocalizationService.GetString("Notif_ServiceThreatTitle"))
                    .AddText(LocalizationService.Format("Notif_ServiceThreatsSummary", count))
                    .AddButton(new ToastButton()
                        .SetContent(LocalizationService.GetString("Notif_HistoryBtn"))
                        .AddArgument("action", "history"))
                    .Show();
            }
            catch (Exception ex)
            {
                AppLogger.Error("NotificationService", "ShowServiceThreatsSummary", ex);
            }
        }

        public void ShowRemovableDriveScanStarted(string driveLabel)
        {
            if (!ShouldShowToast()) return;

            try
            {
                new ToastContentBuilder()
                    .AddArgument("action", "usbscanstart")
                    .AddArgument("drive", driveLabel)
                    .AddText(LocalizationService.GetString("Notif_UsbScanStartedTitle"))
                    .AddText(LocalizationService.Format("Notif_UsbScanStartedBody", driveLabel))
                    .SetToastDuration(ToastDuration.Short)
                    .Show();
            }
            catch (Exception ex)
            {
                AppLogger.Error("NotificationService", "ShowRemovableDriveScanStarted", ex);
            }
        }

        public void ShowRemovableDriveScanCompleted(string driveLabel, int threatsFound, int filesScanned)
        {
            if (!ShouldShowToast()) return;

            try
            {
                if (threatsFound == 0)
                {
                    new ToastContentBuilder()
                        .AddArgument("action", "usbscanok")
                        .AddArgument("drive", driveLabel)
                        .AddText(LocalizationService.Format("Notif_UsbScanOkTitle", driveLabel))
                        .AddText(LocalizationService.Format("Notif_UsbScanOkBody", driveLabel, filesScanned))
                        .AddButton(new ToastButton()
                            .SetContent(LocalizationService.GetString("Notif_OpenAntivirus"))
                            .AddArgument("action", "openav"))
                        .Show();
                }
                else
                {
                    new ToastContentBuilder()
                        .AddArgument("action", "usbscanthreats")
                        .AddArgument("drive", driveLabel)
                        .AddArgument("threats", threatsFound.ToString())
                        .AddText(LocalizationService.Format("Notif_UsbScanThreatsTitle", driveLabel, threatsFound))
                        .AddText(LocalizationService.Format("Notif_UsbScanThreatsBody", driveLabel, threatsFound, filesScanned))
                        .AddButton(new ToastButton()
                            .SetContent(LocalizationService.GetString("Notif_OpenAntivirus"))
                            .AddArgument("action", "openav"))
                        .AddButton(new ToastButton()
                            .SetContent(LocalizationService.GetString("Notif_HistoryBtn"))
                            .AddArgument("action", "history"))
                        .Show();
                }
            }
            catch (Exception ex)
            {
                AppLogger.Error("NotificationService", "ShowRemovableDriveScanCompleted", ex);
            }
        }

        public void ShowScanCompleted(int threatsFound, int filesScanned)
        {
            if (!ShouldShowToast()) return;

            try
            {
                if (threatsFound == 0)
                {
                    new ToastContentBuilder()
                        .AddArgument("action", "scanok")
                        .AddText(LocalizationService.GetString("Notif_ScanOkTitle"))
                        .AddText(LocalizationService.Format("Notif_ScanOkBody", filesScanned))
                        .AddButton(new ToastButton()
                            .SetContent(LocalizationService.GetString("Notif_OpenAntivirus"))
                            .AddArgument("action", "openav"))
                        .Show();
                }
                else
                {
                    new ToastContentBuilder()
                        .AddArgument("action", "scanthreats")
                        .AddArgument("threats", threatsFound.ToString())
                        .AddText(LocalizationService.Format("Notif_ScanThreatsTitle", threatsFound))
                        .AddText(LocalizationService.GetString("Notif_ScanThreatsBody"))
                        .AddButton(new ToastButton()
                            .SetContent(LocalizationService.GetString("Notif_OpenAntivirus"))
                            .AddArgument("action", "openav"))
                        .AddButton(new ToastButton()
                            .SetContent(LocalizationService.GetString("Notif_HistoryBtn"))
                            .AddArgument("action", "history"))
                        .AddButton(new ToastButton()
                            .SetContent(LocalizationService.GetString("Notif_OpenApp"))
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
            ShowSignatureUpdateNeeded();
            _ = version;
        }

        /// <summary>Téléchargement auto en cours — toast informatif, sans bouton.</summary>
        public void ShowSignatureDownloadStarted()
        {
            if (!ShouldShowToast()) return;

            try
            {
                new ToastContentBuilder()
                    .AddArgument("action", "openav")
                    .AddText(LocalizationService.GetString("Notif_SigDownloadTitle"))
                    .AddText(LocalizationService.GetString("Notif_SigDownloadBody"))
                    .SetToastDuration(ToastDuration.Short)
                    .Show();
            }
            catch (Exception ex)
            {
                AppLogger.Error("NotificationService", "ShowSignatureDownloadStarted", ex);
            }
        }

        /// <summary>MAJ auto désactivée et signatures manquantes/obsolètes — action « Mettre à jour ».</summary>
        public void ShowSignatureUpdateNeeded()
        {
            if (!ShouldShowToast()) return;

            try
            {
                new ToastContentBuilder()
                    .AddArgument("action", "update")
                    .AddText(LocalizationService.GetString("Notif_SigNeededTitle"))
                    .AddText(LocalizationService.GetString("Notif_SigNeededBody"))
                    .AddButton(new ToastButton()
                        .SetContent(LocalizationService.GetString("Notif_UpdateBtn"))
                        .AddArgument("action", "update"))
                    .Show();
            }
            catch (Exception ex)
            {
                AppLogger.Error("NotificationService", "ShowSignatureUpdateNeeded", ex);
            }
        }

        public void ShowRealTimeProtectionStarted()
        {
            if (!ShouldShowToast()) return;

            try
            {
                new ToastContentBuilder()
                    .AddArgument("action", "rtpstarted")
                    .AddText(LocalizationService.GetString("Notif_RtpStartedTitle"))
                    .AddText(LocalizationService.GetString("Notif_RtpStartedBody"))
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
