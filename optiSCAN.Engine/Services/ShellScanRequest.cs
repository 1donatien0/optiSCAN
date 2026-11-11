// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;

namespace optiSCAN.Services;

/// <summary>Transfert des chemins de scan entre instances (menu contextuel Explorateur).</summary>
/// <remarks>
/// Une demande = un fichier dans une file d'attente. L'Explorateur lance un processus par élément
/// d'une sélection multiple : avec un seul fichier partagé, chaque instance écrasait la demande
/// de la précédente et seul le dernier élément (ou celui qui gagnait la course) était analysé.
/// </remarks>
public static class ShellScanRequest
{
    private static string QueueDirectory =>
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "optiSCAN",
            "shell_scan_pending");

    /// <summary>Ancien fichier unique (versions précédentes) : lu une fois s'il existe encore.</summary>
    private static string LegacyPendingFilePath =>
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "optiSCAN",
            "shell_scan_pending.txt");

    private static readonly TimeSpan MaxPendingAge = TimeSpan.FromSeconds(60);
    private const int MaxRequestsPerDrain = 256;

    public static void Publish(string path)
    {
        var dir = QueueDirectory;
        Directory.CreateDirectory(dir);
        // Horodatage en tête du nom : l'ordre de lecture suit l'ordre de dépôt.
        var name = DateTime.UtcNow.Ticks.ToString("D19", System.Globalization.CultureInfo.InvariantCulture)
            + "_" + Guid.NewGuid().ToString("N") + ".txt";
        var final = Path.Combine(dir, name);
        var temp = final + ".tmp";
        File.WriteAllText(temp, path);
        // Renommage : le lecteur ne voit jamais une demande à moitié écrite.
        File.Move(temp, final);
    }

    /// <summary>Première demande en attente (compatibilité) ; les autres restent dans la file.</summary>
    public static string? TryConsume()
    {
        var all = TryConsumeAll(maxCount: 1);
        return all.Count > 0 ? all[0] : null;
    }

    /// <summary>
    /// Retire et renvoie les demandes récentes, dans l'ordre de dépôt, sans doublon.
    /// </summary>
    public static IReadOnlyList<string> TryConsumeAll(int maxCount = MaxRequestsPerDrain)
    {
        var result = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            if (File.Exists(LegacyPendingFilePath))
                TakeRequestFile(LegacyPendingFilePath, result, seen);

            var dir = QueueDirectory;
            if (!Directory.Exists(dir))
                return result;

            var files = Directory.GetFiles(dir, "*.txt");
            Array.Sort(files, StringComparer.Ordinal);
            foreach (var file in files)
            {
                if (result.Count >= maxCount)
                    break;
                TakeRequestFile(file, result, seen);
            }
        }
        catch (Exception ex) when (!ex.IsFatal())
        {
            AppLogger.Warn("ShellScanRequest", "TryConsumeAll", ex);
        }
        return result;
    }

    private static void TakeRequestFile(string file, List<string> result, HashSet<string> seen)
    {
        try
        {
            // Le message Windows qui déclenche cette lecture est diffusé sans authentification
            // dans la session : seule une demande récente (déposée par une seconde instance
            // juste avant) est prise en compte. L'appelant valide ensuite le chemin.
            var age = DateTime.UtcNow - File.GetLastWriteTimeUtc(file);
            var path = File.ReadAllText(file).Trim();
            File.Delete(file);
            if (age > MaxPendingAge || age < TimeSpan.FromSeconds(-5))
            {
                AppLogger.Warn("ShellScanRequest", "Demande de scan périmée ignorée");
                return;
            }
            if (!string.IsNullOrWhiteSpace(path) && seen.Add(path))
                result.Add(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Fichier pris par une autre lecture simultanée : ignoré.
            AppLogger.Debug("ShellScanRequest", "Lecture d'une demande : " + ex.Message);
        }
    }
}
