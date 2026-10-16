// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Security.Principal;
using System.Text.Json;
using optiSCAN.Platform;

namespace optiSCAN.Services;

/// <summary>Réglages de protection appliqués par l'hôte SYSTEM. Pas de chemins.</summary>
internal sealed class HostPolicy
{
    public bool RealTimeEnabled { get; set; } = true;
    public bool ProcessMonitorEnabled { get; set; }
    public bool AutoQuarantineEnabled { get; set; }
    public bool SignatureAutoUpdateEnabled { get; set; } = true;
    public bool RemovableDriveScanEnabled { get; set; }
}

/// <summary>Fichier de politique sous ProgramData, écrit par le service à la demande de l'interface.</summary>
internal static class HostPolicyStore
{
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };

#if OPTISCAN_TEST_HOOKS
    /// <summary>Tests seulement : contourne le contrôle d'ACL. Absent du binaire publié.</summary>
    internal static string? FilePathOverride { get; set; }
#else
    internal static string? FilePathOverride => null;
#endif

    internal static string FilePath =>
        FilePathOverride ?? Path.Combine(OptiScanProgramData.DirectoryPath, "host-policy.json");

    internal static event Action<HostPolicy>? Changed;

    internal static bool TryRead(out HostPolicy policy)
    {
        policy = new HostPolicy();
        try
        {
            if (!IsTrustedSource())
                return false;

            var read = JsonSerializer.Deserialize<HostPolicy>(File.ReadAllText(FilePath), JsonOptions);
            if (read == null)
                return false;
            policy = read;
            return true;
        }
        catch (Exception ignored) when (!ignored.IsFatal())
        {
            return false;
        }
    }

    /// <summary>
    /// Pour le fichier réel sous ProgramData : le dossier et le fichier doivent avoir un
    /// propriétaire et une ACL approuvés. Un fichier déposé avant la première reprise est ignoré :
    /// on applique alors la politique par défaut (temps réel actif, pas de quarantaine automatique).
    /// </summary>
    private static bool IsTrustedSource()
    {
        if (FilePathOverride != null)
            return File.Exists(FilePath) && (File.GetAttributes(FilePath) & FileAttributes.ReparsePoint) == 0;

        if (!OptiScanProgramData.IsTrustedEntry(OptiScanProgramData.DirectoryPath, isDirectory: true))
            return false;
        if (OptiScanProgramData.IsTrustedFile(FilePath))
            return true;

        if (File.Exists(FilePath))
            AppLogger.Warn("HostPolicy", "host-policy.json non fiable (propriétaire ou droits étrangers) : ignoré, politique par défaut.");
        return false;
    }

    internal static bool TryWrite(HostPolicy policy)
    {
        if (!OptiScanProgramData.EnsureTrusted())
            return false;
        if (File.Exists(FilePath) && (File.GetAttributes(FilePath) & FileAttributes.ReparsePoint) != 0)
            return false;

        // Écriture atomique : une coupure en cours d'écriture ne laisse pas un fichier tronqué
        // (qui ferait revenir à la politique par défaut).
        AtomicFile.WriteAllText(FilePath, JsonSerializer.Serialize(policy, JsonOptions));
        return true;
    }

    /// <summary>
    /// Vrai si la requête ne fait que renforcer la protection par rapport à la politique en place :
    /// activer, jamais désactiver, et ne pas toucher à la quarantaine automatique (qui supprime des
    /// fichiers en SYSTEM). Un compte standard peut l'envoyer ; tout le reste exige un administrateur.
    /// </summary>
    internal static bool IsStrengtheningOnly(ProtectionPipeRequest request)
    {
        if (request.RealTimeEnabled is not bool realtime
            || request.ProcessMonitorEnabled is not bool monitor
            || request.AutoQuarantineEnabled is not bool quarantine
            || request.SignatureAutoUpdateEnabled is not bool signatures
            || request.RemovableDriveScanEnabled is not bool removable)
            return false;

        TryRead(out var current);
        return (realtime || !current.RealTimeEnabled)
            && (monitor || !current.ProcessMonitorEnabled)
            && (signatures || !current.SignatureAutoUpdateEnabled)
            && (removable || !current.RemovableDriveScanEnabled)
            && quarantine == current.AutoQuarantineEnabled;
    }

    /// <summary>Forme texte pour la relance élevée : <c>rt=1,monitor=0,quarantine=0,signatures=1,removable=1</c>.</summary>
    internal static string ToArgument(ProtectionPipeRequest request) =>
        string.Join(',',
            "rt=" + Bit(request.RealTimeEnabled),
            "monitor=" + Bit(request.ProcessMonitorEnabled),
            "quarantine=" + Bit(request.AutoQuarantineEnabled),
            "signatures=" + Bit(request.SignatureAutoUpdateEnabled),
            "removable=" + Bit(request.RemovableDriveScanEnabled));

    internal static bool TryParseArgument(string? text, out ProtectionPipeRequest request)
    {
        request = new ProtectionPipeRequest { Operation = ProtectionPipeOperations.SetPolicy };
        if (string.IsNullOrWhiteSpace(text))
            return false;

        foreach (var part in text.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var pair = part.Split('=', 2);
            if (pair.Length != 2 || pair[1] is not ("0" or "1"))
                return false;
            var on = pair[1] == "1";
            switch (pair[0])
            {
                case "rt": request.RealTimeEnabled = on; break;
                case "monitor": request.ProcessMonitorEnabled = on; break;
                case "quarantine": request.AutoQuarantineEnabled = on; break;
                case "signatures": request.SignatureAutoUpdateEnabled = on; break;
                case "removable": request.RemovableDriveScanEnabled = on; break;
                default: return false;
            }
        }

        return request.RealTimeEnabled.HasValue
            && request.ProcessMonitorEnabled.HasValue
            && request.AutoQuarantineEnabled.HasValue
            && request.SignatureAutoUpdateEnabled.HasValue
            && request.RemovableDriveScanEnabled.HasValue;
    }

    private static string Bit(bool? value) => value == true ? "1" : "0";

    internal static ProtectionPipeResponse TryApply(ProtectionPipeRequest request)
    {
        if (request.RealTimeEnabled is not bool realtime
            || request.ProcessMonitorEnabled is not bool monitor
            || request.AutoQuarantineEnabled is not bool quarantine
            || request.SignatureAutoUpdateEnabled is not bool signatures
            || request.RemovableDriveScanEnabled is not bool removable)
            return ProtectionPipeResponse.Error("Politique incomplète");

        var policy = new HostPolicy
        {
            RealTimeEnabled = realtime,
            ProcessMonitorEnabled = monitor,
            AutoQuarantineEnabled = quarantine,
            SignatureAutoUpdateEnabled = signatures,
            RemovableDriveScanEnabled = removable,
        };
        if (!TryWrite(policy))
            return ProtectionPipeResponse.Error("Politique refusée");

        Changed?.Invoke(policy);
        return ProtectionPipeResponse.SuccessClean();
    }

    internal static void PushToService(IUserPreferencesAccessor preferences, IExclusionSettingsAccessor exclusions)
    {
        if (!preferences.Current.UsePlatformProtectionService)
            return;
        using (var identity = WindowsIdentity.GetCurrent())
        {
            if (identity.IsSystem)
                return;
        }
        if (!PlatformProtectionBootstrap.IsRemoteProtectionActive())
            return;

        var request = new ProtectionPipeRequest
        {
            Operation = ProtectionPipeOperations.SetPolicy,
            RealTimeEnabled = exclusions.Current.RealTimeEnabled,
            ProcessMonitorEnabled = preferences.Current.ProcessMonitorEnabled,
            AutoQuarantineEnabled = exclusions.Current.AutoQuarantineEnabled,
            SignatureAutoUpdateEnabled = preferences.Current.SignatureAutoUpdateEnabled,
            RemovableDriveScanEnabled = preferences.Current.RemovableDriveScanEnabled,
        };

        try
        {
            using var client = new ProtectionPipeClient(timeout: TimeSpan.FromSeconds(5));
            var response = client.SendAsync(request).GetAwaiter().GetResult();
            if (response.Ok)
                return;

            if (string.Equals(response.Message, "Non autorisé", StringComparison.Ordinal))
            {
                // Réduire la protection du service exige un administrateur : une invite UAC,
                // et c'est le processus élevé qui envoie la politique.
                RequestElevatedPush(request);
                return;
            }

            AppLogger.Warn("HostPolicy", "Le service a refusé la politique : " + response.Message);
        }
        catch (Exception ex) when (!ex.IsFatal())
        {
            AppLogger.Debug("HostPolicy", $"Service injoignable : {ex.Message}");
        }
    }

    private static void RequestElevatedPush(ProtectionPipeRequest request)
    {
        var argument = ToArgument(request);
        if (ElevationHelper.RelaunchElevated(HeadlessScanArguments.PushHostPolicy, argument, "--quiet"))
            AppLogger.Info("HostPolicy", "Instance élevée lancée pour envoyer la politique du service.");
        else
            AppLogger.Warn("HostPolicy", "Élévation refusée : le service garde sa politique précédente.");
    }

    /// <summary>Point d'entrée de <c>--push-host-policy</c> (processus élevé).</summary>
    internal static bool PushFromElevatedProcess(string? argument)
    {
        if (!TryParseArgument(argument, out var request))
        {
            AppLogger.Warn("HostPolicy", "Politique invalide : " + argument);
            return false;
        }

        try
        {
            using var client = new ProtectionPipeClient(timeout: TimeSpan.FromSeconds(10));
            var response = client.SendAsync(request).GetAwaiter().GetResult();
            if (!response.Ok)
                AppLogger.Warn("HostPolicy", "Politique refusée par le service : " + response.Message);
            return response.Ok;
        }
        catch (Exception ex) when (!ex.IsFatal())
        {
            AppLogger.Warn("HostPolicy", "Envoi de la politique", ex);
            return false;
        }
    }
}
