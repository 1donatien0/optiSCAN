using System.Runtime.Versioning;

namespace optiSCAN.Services;

/// <summary>
/// Mode complémentaire avec Windows Defender : Defender garde le temps réel,
/// optiSCAN se concentre sur les scans à la demande / planifiés (ClamAV + YARA).
/// </summary>
[SupportedOSPlatform("windows")]
public static class DefenderCoexistenceService
{
    /// <summary>Defender installé et service WinDefend actif.</summary>
    public static bool IsDefenderActive()
    {
        if (!OperatingSystem.IsWindows())
            return false;
        if (!WindowsDefenderExclusionService.IsWindowsDefenderPresent())
            return false;
        return IsWinDefendRunning();
    }

    /// <summary>
    /// Vrai si le temps réel est volontairement délégué à Defender (mode complémentaire actif
    /// et Defender en marche) : badge, accueil et posture ne doivent pas le compter comme « dégradé ».
    /// </summary>
    public static bool IsRealTimeDelegated(UserPreferences prefs) =>
        prefs.DefenderComplementModeEnabled && IsDefenderActive();

    /// <summary>Préférences par défaut pour une nouvelle installation avec Defender actif.</summary>
    public static void ApplyNewInstallDefaults(UserPreferences prefs)
    {
        if (!IsDefenderActive())
            return;

        prefs.DefenderCoexistenceConfigured = false;
        prefs.FirstLaunchDefenderPending = true;
        prefs.DefenderComplementModeEnabled = true;
        prefs.UsePlatformProtectionService = false;
        prefs.ProcessMonitorEnabled = false;
    }

    /// <summary>Applique le mode complémentaire (RTP optiSCAN désactivé).</summary>
    public static void ApplyComplementMode(
        IUserPreferencesAccessor preferences,
        IExclusionSettingsAccessor exclusions,
        Action<bool>? applyRealtimeProtection = null,
        Action<bool>? applyPlatformProtection = null,
        Action<bool>? applyProcessMonitor = null)
    {
        var prefs = preferences.Current;
        prefs.DefenderComplementModeEnabled = true;
        prefs.UsePlatformProtectionService = false;
        prefs.ProcessMonitorEnabled = false;
        prefs.Save();

        exclusions.Current.RealTimeEnabled = false;
        exclusions.Current.Save();

        applyPlatformProtection?.Invoke(false);
        applyProcessMonitor?.Invoke(false);
        applyRealtimeProtection?.Invoke(false);
    }

    /// <summary>L'utilisateur préfère la protection optiSCAN complète malgré Defender.</summary>
    public static void ApplyFullOptiscanMode(
        IUserPreferencesAccessor preferences,
        IExclusionSettingsAccessor exclusions,
        Action<bool>? applyRealtimeProtection = null,
        Action<bool>? applyPlatformProtection = null,
        Action<bool>? applyProcessMonitor = null)
    {
        var prefs = preferences.Current;
        prefs.DefenderComplementModeEnabled = false;
        prefs.UsePlatformProtectionService = false;
        prefs.ProcessMonitorEnabled = true;
        prefs.Save();

        exclusions.Current.RealTimeEnabled = true;
        exclusions.Current.Save();

        applyPlatformProtection?.Invoke(false);
        applyProcessMonitor?.Invoke(true);
        applyRealtimeProtection?.Invoke(true);
    }

    public static void MarkConfigured(IUserPreferencesAccessor preferences)
    {
        var prefs = preferences.Current;
        prefs.DefenderCoexistenceConfigured = true;
        prefs.FirstLaunchDefenderPending = false;
        prefs.Save();
    }

    /// <summary>RTP local désactivé tant que le premier lancement Defender n'est pas finalisé.</summary>
    public static void EnsureFirstLaunchExclusionSettings(IExclusionSettingsAccessor exclusions, IUserPreferencesAccessor preferences)
    {
        if (!preferences.Current.FirstLaunchDefenderPending || !IsDefenderActive())
            return;

        if (exclusions.Current.RealTimeEnabled)
        {
            exclusions.Current.RealTimeEnabled = false;
            exclusions.Current.Save();
        }
    }

        public static DefenderCoexistenceStatus BuildStatus(IUserPreferencesAccessor preferences) =>
            BuildStatus(preferences, WindowsDefenderExclusionService.LastExclusionResult);

    internal static DefenderCoexistenceStatus BuildStatus(
        IUserPreferencesAccessor preferences,
        DefenderExclusionResult? exclusionResult)
    {
        exclusionResult ??= WindowsDefenderExclusionService.LastExclusionResult;

        if (!IsDefenderActive())
        {
            return new DefenderCoexistenceStatus
            {
                IsDefenderActive = false,
                ComplementModeEnabled = preferences.Current.DefenderComplementModeEnabled,
                ExclusionStatus = DefenderExclusionStatus.NotApplicable,
                StatusMessageKey = "Defender_Opt_StatusInactive",
            };
        }

        var exclusionStatus = exclusionResult?.Status ?? DefenderExclusionStatus.DefenderUnavailable;
        var statusKey = preferences.Current.DefenderComplementModeEnabled
            ? "Defender_Opt_StatusComplement"
            : "Defender_Opt_StatusParallel";

        var exclusionKey = exclusionStatus switch
        {
            DefenderExclusionStatus.Added or DefenderExclusionStatus.AlreadyConfigured
                => "Defender_Opt_ExclusionsOk",
            DefenderExclusionStatus.AccessDenied
                => "Defender_Opt_ExclusionsTamper",
            DefenderExclusionStatus.PartialFailure
                => "Defender_Opt_ExclusionsPartial",
            _ => "Defender_Opt_ExclusionsPending",
        };

        return new DefenderCoexistenceStatus
        {
            IsDefenderActive = true,
            ComplementModeEnabled = preferences.Current.DefenderComplementModeEnabled,
            ExclusionStatus = exclusionStatus,
            StatusMessageKey = statusKey,
            ExclusionMessageKey = exclusionKey,
        };
    }

    private static bool IsWinDefendRunning()
    {
        try
        {
            using var sc = new System.ServiceProcess.ServiceController("WinDefend");
            return sc.Status == System.ServiceProcess.ServiceControllerStatus.Running;
        }
        catch
        {
            return false;
        }
    }
}

public sealed class DefenderCoexistenceStatus
{
    public bool IsDefenderActive { get; init; }
    public bool ComplementModeEnabled { get; init; }
    public DefenderExclusionStatus ExclusionStatus { get; init; }
    public string StatusMessageKey { get; init; } = string.Empty;
    public string ExclusionMessageKey { get; init; } = string.Empty;
}
