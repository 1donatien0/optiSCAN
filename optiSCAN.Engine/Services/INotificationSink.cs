// SPDX-License-Identifier: GPL-3.0-or-later
using optiSCAN.Models;

namespace optiSCAN.Services
{
    /// <summary>
    /// Notifications émises par le moteur (temps réel, clés USB, détections du service).
    /// L'interface WPF les affiche en toasts ; le moteur ne dépend d'aucune bibliothèque d'interface.
    /// </summary>
    public interface INotificationSink
    {
        void ShowThreatDetected(ThreatInfo threat);
        void ShowQuarantined(ThreatInfo threat);
        void ShowServiceThreat(ThreatInfo threat);
        void ShowServiceThreatsSummary(int count);
        void ShowRealTimeDegraded(int folderCount);
        void ShowRemovableDriveScanStarted(string driveLabel);
        void ShowRemovableDriveScanCompleted(string driveLabel, int threatsFound, int filesScanned);
    }
}
