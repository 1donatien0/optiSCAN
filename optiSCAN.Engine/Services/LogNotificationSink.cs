// SPDX-License-Identifier: GPL-3.0-or-later
using optiSCAN.Models;

namespace optiSCAN.Services
{
    /// <summary>
    /// Notifications de l'hôte SYSTEM : en session 0, aucun toast n'est visible. Les détections
    /// passent par <see cref="ServiceDetectionLog"/>, que la session relève et affiche ; ici, on
    /// ne fait que journaliser.
    /// </summary>
    public sealed class LogNotificationSink : INotificationSink
    {
        public void ShowThreatDetected(ThreatInfo threat) =>
            AppLogger.Info("HostNotify", "Menace détectée : " + threat.VirusName + " — " + PathRedaction.RedactPath(threat.FilePath));

        public void ShowQuarantined(ThreatInfo threat) =>
            AppLogger.Info("HostNotify", "Mise en quarantaine : " + threat.VirusName + " — " + PathRedaction.RedactPath(threat.FilePath));

        public void ShowServiceThreat(ThreatInfo threat) => ShowThreatDetected(threat);

        public void ShowServiceThreatsSummary(int count) =>
            AppLogger.Info("HostNotify", count + " menace(s) détectée(s) par le service.");

        public void ShowRealTimeDegraded(int folderCount) =>
            AppLogger.Warn("HostNotify", "Temps réel dégradé : " + folderCount + " dossier(s) non surveillé(s).");

        public void ShowRemovableDriveScanStarted(string driveLabel) =>
            AppLogger.Info("HostNotify", "Analyse du lecteur amovible " + driveLabel);

        public void ShowRemovableDriveScanCompleted(string driveLabel, int threatsFound, int filesScanned) =>
            AppLogger.Info("HostNotify", $"Lecteur {driveLabel} : {filesScanned} fichier(s), {threatsFound} menace(s).");
    }
}
