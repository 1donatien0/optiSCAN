using System.Security.Principal;
using Microsoft.Win32;

namespace optiSCAN.Services;

/// <summary>
/// Retire les exclusions Defender posées par optiSCAN 3.0.0 (processus par simple nom,
/// dossiers AppData\Local\optiSCAN), celles d'un dossier d'installation modifiable par un
/// utilisateur, et la tâche d'effacement de l'historique Defender, une fois par version, dès qu'un processus optiSCAN
/// tourne avec les droits nécessaires : installeur, service SYSTEM, ou application élevée.
/// Une mise à jour faite en copiant les fichiers, sans l'installeur, est ainsi couverte
/// au premier démarrage du service ou à la première élévation.
/// </summary>
internal static class DefenderLegacyCleanup
{
    private const string MachineKey = @"SOFTWARE\optiSCAN";
    private const string MarkerValue = "LegacyDefenderCleanupVersion";
    private static int _started;

    /// <summary>Lance le nettoyage en arrière-plan s'il n'a pas déjà été fait pour cette version.</summary>
    internal static void TryRunOnceInBackground()
    {
        if (!CanModifyDefender() || Interlocked.Exchange(ref _started, 1) == 1)
            return;
        if (string.Equals(ReadMarker(), ProductVersionInfo.SemVer, StringComparison.Ordinal))
            return;

        _ = Task.Run(() =>
        {
            try { RunAndMark(); }
            catch (Exception ex) { AppLogger.Error("DefenderLegacyCleanup", "RunAndMark failed", ex); }
        });
    }

    /// <summary>Appel direct (installeur) : nettoie et enregistre la version.</summary>
    internal static void RunAndMark()
    {
        // Tâche de démarrage SYSTEM d'effacement de l'historique Defender (fonction retirée) :
        // elle ne dépend pas de Defender, elle est retirée à chaque passage.
        SystemTweaksService.RemoveDefenderHistoryTask();

        try
        {
            // Installation hors d'un dossier réservé aux administrateurs : une version
            // antérieure a pu y exclure le dossier et ses binaires de Defender.
            if (!optiSCAN.Platform.InstallLocationTrust.IsCurrentInstallTrusted(out _))
                WindowsDefenderExclusionService.RemoveOptiscanExclusions();

            var result = WindowsDefenderExclusionService.RemoveLegacyExclusions();
            // Defender absent ou désactivé (autre antivirus) : ses préférences, dont les
            // exclusions de la 3.0.0, subsistent et redeviendront actives s'il est réactivé.
            // Rien n'est marqué : le nettoyage sera retenté à la prochaine occasion.
            if (result.Status is not (DefenderExclusionStatus.AccessDenied
                    or DefenderExclusionStatus.PartialFailure
                    or DefenderExclusionStatus.DefenderUnavailable))
                WriteMarker(ProductVersionInfo.SemVer);
        }
        catch (Exception ex)
        {
            AppLogger.Warn("DefenderLegacyCleanup", "Nettoyage des exclusions 3.0.0", ex);
        }
    }

    private static bool CanModifyDefender()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return identity.IsSystem || ElevationHelper.IsRunningElevated();
        }
        catch
        {
            return false;
        }
    }

    private static string? ReadMarker()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(MachineKey);
            return key?.GetValue(MarkerValue) as string;
        }
        catch
        {
            return null;
        }
    }

    private static void WriteMarker(string version)
    {
        try
        {
            using var key = Registry.LocalMachine.CreateSubKey(MachineKey);
            key?.SetValue(MarkerValue, version, RegistryValueKind.String);
        }
        catch (Exception ex)
        {
            AppLogger.Debug("DefenderLegacyCleanup", "Marqueur non écrit : " + ex.Message);
        }
    }
}
