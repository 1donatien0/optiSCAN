using optiSCAN.Models;
using System.Diagnostics;
using System.IO;
using System.Runtime.Versioning;

namespace optiSCAN.Services;

/// <summary>
/// Remédiation avancée : sauvegarde, quarantaine, et recours Defender pour les cas non réparables par ClamAV.
/// </summary>
[SupportedOSPlatform("windows")]
public static class ThreatRepairService
{
    public sealed class RepairResult
    {
        public bool Success { get; init; }
        public string Message { get; init; } = string.Empty;
        public bool UsedDefenderFallback { get; init; }
    }

    public static RepairResult TryRemediate(
        ThreatInfo threat,
        QuarantineManager quarantine,
        IUserPreferencesAccessor? preferences = null)
    {
        if (quarantine.Quarantine(threat))
        {
            return new RepairResult
            {
                Success = true,
                Message = Localization.LocalizationService.GetString("Repair_Quarantined"),
            };
        }

        return new RepairResult
        {
            Success = false,
            Message = Localization.LocalizationService.GetString("Repair_QuarantineFailed"),
        };
    }

    private const int DefenderScanTimeoutMs = 120_000;

    /// <summary>Arguments de MpCmdRun pour l'analyse d'un fichier, un élément par argument.</summary>
    internal static IReadOnlyList<string> BuildDefenderScanArguments(string filePath) =>
        new[] { "-Scan", "-ScanType", "3", "-File", filePath, "-DisableRemediation" };

    /// <summary>
    /// Chemin absolu, sans guillemet ni caractère de contrôle (aucun chemin Windows valide n'en
    /// contient), et qui ne commence pas par un tiret (pris pour une option).
    /// </summary>
    internal static bool IsSafeScanTarget(string? filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath) || filePath.StartsWith('-'))
            return false;
        if (filePath.Any(c => c == '"' || char.IsControl(c)))
            return false;
        return Path.IsPathFullyQualified(filePath);
    }

    /// <summary>Lance une analyse Defender ciblée (MpCmdRun) si disponible — complément cloud Microsoft.</summary>
    public static RepairResult TryDefenderTargetedScan(string filePath)
    {
        try
        {
            var mp = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                "Windows Defender", "MpCmdRun.exe");

            if (!File.Exists(mp))
                return new RepairResult { Success = false, Message = "Defender indisponible" };

            if (!IsSafeScanTarget(filePath))
                return new RepairResult { Success = false, Message = "Chemin refusé" };

            // ArgumentList : chaque argument est échappé séparément. Un nom de fichier
            // contenant « " » ne peut plus ajouter d'options à MpCmdRun.
            var psi = new ProcessStartInfo
            {
                FileName = mp,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            foreach (var arg in BuildDefenderScanArguments(filePath))
                psi.ArgumentList.Add(arg);

            using var proc = Process.Start(psi);
            if (proc == null)
                return new RepairResult { Success = false, Message = "Defender indisponible" };

            if (!proc.WaitForExit(DefenderScanTimeoutMs))
            {
                try { proc.Kill(entireProcessTree: true); }
                catch (Exception killEx) { AppLogger.Debug("ThreatRepairService", "Arrêt MpCmdRun : " + killEx.Message); }
                return new RepairResult { Success = false, UsedDefenderFallback = true, Message = "Defender MpCmdRun : délai dépassé" };
            }

            return new RepairResult
            {
                Success = proc.ExitCode == 0,
                UsedDefenderFallback = true,
                Message = $"Defender MpCmdRun exit={proc.ExitCode}",
            };
        }
        catch (Exception ex)
        {
            AppLogger.Warn("ThreatRepairService", "TryDefenderTargetedScan", ex);
            return new RepairResult { Success = false, Message = ex.Message };
        }
    }
}
