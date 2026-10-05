using System.IO;
using System.Security.Cryptography;
using System.Security.Principal;
using optiSCAN.Platform;

namespace optiSCAN.Services;

/// <summary>
/// Emplacement et politique de la quarantaine du service SYSTEM.
/// <para>
/// Avant : <c>%LOCALAPPDATA%</c> du processus, c'est-à-dire le profil <c>systemprofile</c>,
/// invisible de l'interface et laissé en place à la désinstallation.
/// Maintenant : <c>%ProgramData%\optiSCAN\Quarantine</c>, sous le dossier repris par
/// <see cref="OptiScanProgramData"/> (SYSTEM et Administrateurs uniquement), supprimé par le
/// désinstalleur. La clé reste protégée par DPAPI au nom de SYSTEM : seul le service déchiffre,
/// l'interface passe par le pipe (<see cref="ServiceQuarantineAdmin"/>).
/// </para>
/// </summary>
internal static class ServiceQuarantineStore
{
    /// <summary>Durée de conservation : au-delà, le service supprime l'élément définitivement.</summary>
    public const int RetentionDays = 90;

    public static string DirectoryPath => Path.Combine(OptiScanProgramData.DirectoryPath, "Quarantine");

    /// <summary>Ancien emplacement : <c>%LOCALAPPDATA%</c> du compte SYSTEM.</summary>
    public static string LegacyDirectoryPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "optiSCAN", "Quarantine");

    public static bool IsServiceIdentity()
    {
        if (!OperatingSystem.IsWindows())
            return false;
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return identity.IsSystem;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Dossier à utiliser par le service. Reprend <c>%ProgramData%\optiSCAN</c>, y déplace une
    /// quarantaine de l'ancien emplacement, puis rend le nouveau chemin. Si ProgramData n'est pas
    /// fiable, l'ancien emplacement (privé à SYSTEM) est gardé.
    /// </summary>
    public static string PrepareDirectory()
    {
        if (!OptiScanProgramData.EnsureTrusted())
        {
            AppLogger.Warn("ServiceQuarantine", "ProgramData non fiable : quarantaine du service laissée dans le profil SYSTEM.");
            return LegacyDirectoryPath;
        }

        MigrateLegacy(LegacyDirectoryPath, DirectoryPath);
        return DirectoryPath;
    }

    /// <summary>
    /// Déplace l'ancienne quarantaine si la nouvelle n'a pas encore de manifeste.
    /// Rend vrai si un déplacement a eu lieu.
    /// </summary>
    internal static bool MigrateLegacy(string legacyDirectory, string targetDirectory)
    {
        try
        {
            if (!File.Exists(Path.Combine(legacyDirectory, "manifest.json")))
                return false;
            if (File.Exists(Path.Combine(targetDirectory, "manifest.json")))
            {
                AppLogger.Warn("ServiceQuarantine",
                    "Deux quarantaines du service existent ; l'ancienne (profil SYSTEM) est laissée en place et sera supprimée à la désinstallation.");
                return false;
            }

            if (Directory.Exists(targetDirectory))
            {
                if (Directory.EnumerateFileSystemEntries(targetDirectory).Any())
                {
                    AppLogger.Warn("ServiceQuarantine", "Dossier de quarantaine du service non vide sans manifeste : migration ignorée.");
                    return false;
                }
                Directory.Delete(targetDirectory);
            }

            var parent = Path.GetDirectoryName(targetDirectory);
            if (!string.IsNullOrEmpty(parent))
                Directory.CreateDirectory(parent);

            Directory.Move(legacyDirectory, targetDirectory);
            AppLogger.Info("ServiceQuarantine", "Quarantaine du service déplacée du profil SYSTEM vers ProgramData.");
            return true;
        }
        catch (Exception ex)
        {
            AppLogger.Warn("ServiceQuarantine", "Migration de la quarantaine du service", ex);
            return false;
        }
    }
}

/// <summary>
/// Opérations du pipe sur la quarantaine du service. L'autorisation (administrateur élevé)
/// est vérifiée par <see cref="ProtectionPipeServer"/> avant l'appel.
/// </summary>
internal sealed class ServiceQuarantineAdmin
{
    /// <summary>Plafond de la liste renvoyée (les plus récents) : la réponse doit tenir dans 1 Mo.</summary>
    internal const int MaxListedEntries = 2000;

    /// <summary>Noms essayés quand le fichier d'origine existe déjà : jamais d'écrasement.</summary>
    private const int MaxRestoreNameAttempts = 5;

    private readonly QuarantineManager _quarantine;

    public ServiceQuarantineAdmin(QuarantineManager quarantine) => _quarantine = quarantine;

    public ProtectionPipeResponse Summary() => new()
    {
        Ok = true,
        Count = _quarantine.Count,
        TotalBytes = _quarantine.TotalSize,
        RetentionDays = ServiceQuarantineStore.RetentionDays,
    };

    public ProtectionPipeResponse List()
    {
        var items = _quarantine.GetNewestEntries(MaxListedEntries)
            .Select(e => new ServiceQuarantineItem
            {
                Id = e.Id,
                OriginalPath = e.OriginalPath,
                VirusName = e.VirusName,
                QuarantinedAt = e.QuarantinedAt,
                OriginalSize = e.OriginalSize,
            })
            .ToList();

        return new ProtectionPipeResponse
        {
            Ok = true,
            Count = _quarantine.Count,
            TotalBytes = _quarantine.TotalSize,
            RetentionDays = ServiceQuarantineStore.RetentionDays,
            Entries = items,
        };
    }

    public ProtectionPipeResponse Delete(string? id)
    {
        if (!IsValidId(id))
            return ProtectionPipeResponse.Error("Identifiant invalide");
        if (_quarantine.FindEntry(id!) == null)
            return ProtectionPipeResponse.Error("Élément introuvable");
        return _quarantine.DeletePermanently(id!)
            ? new ProtectionPipeResponse { Ok = true, Count = 1 }
            : ProtectionPipeResponse.Error("Suppression impossible");
    }

    public ProtectionPipeResponse Purge()
    {
        var removed = _quarantine.PurgeAll();
        return new ProtectionPipeResponse { Ok = true, Count = removed };
    }

    /// <summary>
    /// Restaure vers l'emplacement d'origine, ou vers <paramref name="destinationFolder"/>.
    /// Le fichier est créé par <paramref name="createTarget"/> (sous le jeton du client) ;
    /// le service n'y écrit que le contenu vérifié.
    /// </summary>
    public ProtectionPipeResponse Restore(string? id, string? destinationFolder, Func<string, IRestoreTarget?> createTarget)
    {
        if (!IsValidId(id))
            return ProtectionPipeResponse.Error("Identifiant invalide");
        var entry = _quarantine.FindEntry(id!);
        if (entry == null)
            return ProtectionPipeResponse.Error("Élément introuvable");

        string target;
        try
        {
            if (!string.IsNullOrWhiteSpace(destinationFolder))
            {
                if (!Path.IsPathFullyQualified(destinationFolder))
                    return ProtectionPipeResponse.Error("Dossier de restauration invalide");
                target = Path.Combine(Path.GetFullPath(destinationFolder), entry.FileName);
            }
            else
            {
                target = Path.GetFullPath(entry.OriginalPath);
            }
        }
        catch
        {
            return ProtectionPipeResponse.Error("Chemin de restauration invalide");
        }

        if (string.IsNullOrEmpty(Path.GetFileName(target)) || QuarantineManager.IsSensitivePath(target))
            return ProtectionPipeResponse.Error("Restauration refusée vers un dossier système");

        var plaintext = _quarantine.TryReadVerifiedPlaintext(entry);
        if (plaintext == null)
            return ProtectionPipeResponse.Error("Contenu illisible ou altéré");

        try
        {
            IRestoreTarget? file = null;
            foreach (var candidate in CandidateNames(target))
            {
                file = createTarget(candidate);
                if (file != null)
                    break;
            }

            if (file == null)
                return ProtectionPipeResponse.Error("Création du fichier refusée");

            using (file)
            {
                try
                {
                    file.Stream.Write(plaintext, 0, plaintext.Length);
                    file.Stream.Flush();
                }
                catch (Exception ex)
                {
                    AppLogger.Warn("ServiceQuarantine", $"Écriture de la restauration ({entry.Id})", ex);
                    file.Discard();
                    return ProtectionPipeResponse.Error("Écriture impossible");
                }
            }

            _quarantine.CompleteExternalRestore(entry);
            return new ProtectionPipeResponse { Ok = true, Message = file.FinalPath };
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    internal static IEnumerable<string> CandidateNames(string target)
    {
        yield return target;
        var dir = Path.GetDirectoryName(target) ?? string.Empty;
        var stem = Path.GetFileNameWithoutExtension(target);
        var ext = Path.GetExtension(target);
        yield return Path.Combine(dir, stem + "_restored" + ext);
        for (var i = 2; i < MaxRestoreNameAttempts; i++)
            yield return Path.Combine(dir, $"{stem}_restored_{i}{ext}");
    }

    internal static bool IsValidId(string? id) =>
        id is { Length: 32 } && id.All(Uri.IsHexDigit);
}
