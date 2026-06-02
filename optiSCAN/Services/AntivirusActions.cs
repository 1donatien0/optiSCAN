using optiSCAN.Localization;
using optiSCAN.Models;
using System.IO;
using System.Runtime.Versioning;

namespace optiSCAN.Services
{
    /// <summary>
    /// Centralise les actions exécutables depuis l'UI antivirus.
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

        public event EventHandler<ActionResult>? ActionCompleted;

        public ActionResult QuarantineThreat(string filePath) =>
            QuarantineThreat(ResolveThreatForPath(filePath));

        public ActionResult QuarantineThreat(ThreatInfo threat)
        {
            if (string.IsNullOrEmpty(threat.FilePath) || !File.Exists(threat.FilePath))
                return Complete(false, LocalizationService.Format("Av_Action_FileNotFound", Path.GetFileName(threat.FilePath)));

            if (threat.FileSize < 0)
                threat.FileSize = SafeFileSize(threat.FilePath);
            if (string.IsNullOrWhiteSpace(threat.VirusName))
                threat.VirusName = LocalizationService.GetString("Av_Action_DetectedDefault");
            threat.Status = ThreatStatus.Detected;

            bool ok = _quarantine.Quarantine(threat);
            return Complete(ok,
                ok ? LocalizationService.Format("Av_Action_QuarantineOk", Path.GetFileName(threat.FilePath))
                   : LocalizationService.Format("Av_Action_QuarantineFail", Path.GetFileName(threat.FilePath)));
        }

        private static ThreatInfo ResolveThreatForPath(string filePath)
        {
            var known = ServiceContainer.Default.FindKnownThreat(filePath);
            if (known != null)
                return known.Clone();

            return new ThreatInfo
            {
                FilePath = filePath,
                VirusName = LocalizationService.GetString("Av_Action_DetectedDefault"),
                DetectedAt = DateTime.Now,
                Status = ThreatStatus.Detected,
                FileSize = SafeFileSize(filePath),
            };
        }

        public ActionResult IgnoreThreat(string filePath)
        {
            if (string.IsNullOrWhiteSpace(filePath))
                return Complete(false, LocalizationService.GetString("Av_Action_InvalidPath"), isError: true);

            if (!ExclusionSettings.Current.AddFile(filePath))
            {
                if (ExclusionSettings.Current.IsFileExcluded(filePath))
                    return Complete(true,
                        LocalizationService.Format("Av_Action_AlreadyExcluded", Path.GetFileName(filePath)),
                        isWarning: true);

                return Complete(false,
                    LocalizationService.Format("Av_Action_ExcludeFail", Path.GetFileName(filePath)),
                    isError: true);
            }

            AppLogger.Info("AntivirusActions", $"Fichier exclu des analyses : {filePath}");
            return Complete(true,
                LocalizationService.Format("Av_Action_ExcludedOk", Path.GetFileName(filePath)),
                isWarning: true);
        }

        public ActionResult DeleteThreatFile(string filePath)
        {
            try
            {
                // Refus identique à la restauration quarantaine : pas de suppression dans System32, Windows, etc.
                if (QuarantineManager.IsSensitivePath(filePath))
                    return Complete(false,
                        LocalizationService.Format("Av_Action_DeleteSensitive", Path.GetFileName(filePath)),
                        isError: true);

                if (File.Exists(filePath))
                {
                    File.Delete(filePath);
                    return Complete(true,
                        LocalizationService.Format("Av_Action_DeleteOk", Path.GetFileName(filePath)));
                }
                return Complete(false,
                    LocalizationService.Format("Av_Action_DeleteMissing", Path.GetFileName(filePath)));
            }
            catch (Exception ex)
            {
                AppLogger.Error("AntivirusActions", $"DeleteThreatFile {filePath}", ex);
                return Complete(false,
                    LocalizationService.Format("Av_Action_DeleteError", ex.Message),
                    isError: true);
            }
        }

        public ActionResult RestoreFromQuarantine(string quarantineId)
        {
            bool ok = _quarantine.Restore(quarantineId);
            return Complete(ok,
                ok ? LocalizationService.GetString("Ui_RestoreOk")
                   : LocalizationService.GetString("Ui_RestoreError"),
                isError: !ok);
        }

        public ActionResult DeleteFromQuarantine(string quarantineId)
        {
            bool ok = _quarantine.DeletePermanently(quarantineId);
            return Complete(ok,
                ok ? LocalizationService.GetString("Ui_DeleteOk")
                   : LocalizationService.GetString("Ui_DeleteError"),
                isError: !ok);
        }

        public void StopAllUpdates()
        {
            try { _freshclam.CancelUpdate(); }
            catch (Exception ex) { AppLogger.Warn("AntivirusActions", "Cancel freshclam", ex); }

            try { _rules.CancelUpdate(); }
            catch (Exception ex) { AppLogger.Warn("AntivirusActions", "Cancel rules", ex); }

            Complete(true, LocalizationService.GetString("Av_Action_UpdateStopped"));
        }

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

    public sealed class ActionResult
    {
        public bool Success { get; init; }
        public string Message { get; init; } = string.Empty;
        public bool IsError { get; init; }
        public bool IsWarning { get; init; }
    }
}
