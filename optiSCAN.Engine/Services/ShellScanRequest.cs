// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;

namespace optiSCAN.Services;

/// <summary>Transfert du chemin de scan entre instances (menu contextuel Explorateur).</summary>
public static class ShellScanRequest
{
    private static string PendingFilePath =>
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "optiSCAN",
            "shell_scan_pending.txt");

    private static readonly TimeSpan MaxPendingAge = TimeSpan.FromSeconds(60);

    public static void Publish(string path)
    {
        var dir = Path.GetDirectoryName(PendingFilePath)!;
        Directory.CreateDirectory(dir);
        File.WriteAllText(PendingFilePath, path);
    }

    public static string? TryConsume()
    {
        try
        {
            if (!File.Exists(PendingFilePath))
                return null;

            // Le message Windows qui déclenche cette lecture est diffusé sans authentification
            // dans la session : seule une demande récente (déposée par une seconde instance
            // juste avant) est prise en compte. L'appelant valide ensuite le chemin.
            var age = DateTime.UtcNow - File.GetLastWriteTimeUtc(PendingFilePath);
            var path = File.ReadAllText(PendingFilePath).Trim();
            File.Delete(PendingFilePath);
            if (age > MaxPendingAge || age < TimeSpan.FromSeconds(-5))
            {
                AppLogger.Warn("ShellScanRequest", "Demande de scan périmée ignorée");
                return null;
            }
            return string.IsNullOrWhiteSpace(path) ? null : path;
        }
        catch (Exception ex) when (!ex.IsFatal())
        {
            AppLogger.Warn("ShellScanRequest", "TryConsume", ex);
            return null;
        }
    }
}
