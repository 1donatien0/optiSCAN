// SPDX-License-Identifier: GPL-3.0-or-later
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace optiSCAN.Platform;

/// <summary>
/// Dit si le dossier d'installation est réservé aux administrateurs.
/// <para>
/// Le service SYSTEM lance <c>optiSCAN.exe</c> depuis son propre dossier, et les exclusions
/// Defender visent ce dossier. Dans un dossier qu'un utilisateur peut modifier (installation
/// hors <c>Program Files</c>, build de développement, copie portable), remplacer un binaire
/// donnerait une exécution SYSTEM dans une zone que Defender ne regarde plus. Les opérations
/// privilégiées (enregistrer le service, démarrer l'hôte, exclure de Defender) sont donc
/// refusées tant que ce contrôle échoue.
/// </para>
/// </summary>
public static class InstallLocationTrust
{
    /// <summary>Droits qui permettent de modifier, remplacer ou réattribuer un dossier ou un fichier.</summary>
    internal const FileSystemRights ContentWriteRights =
        FileSystemRights.WriteData
        | FileSystemRights.AppendData
        | FileSystemRights.Delete
        | FileSystemRights.DeleteSubdirectoriesAndFiles
        | FileSystemRights.ChangePermissions
        | FileSystemRights.TakeOwnership;

    /// <summary>
    /// Sur un dossier parent, seuls comptent les droits qui permettent de renommer ou de
    /// supprimer ce qu'il contient, ou de changer ses droits. Créer un dossier à la racine
    /// d'un volume (droit accordé par défaut aux utilisateurs authentifiés) ne permet pas de
    /// remplacer un dossier existant.
    /// </summary>
    internal const FileSystemRights AncestorWriteRights =
        FileSystemRights.Delete
        | FileSystemRights.DeleteSubdirectoriesAndFiles
        | FileSystemRights.ChangePermissions
        | FileSystemRights.TakeOwnership;

    // GENERIC_ALL et GENERIC_WRITE peuvent apparaître tels quels dans une ACE explicite.
    private const int GenericAll = 0x10000000;
    private const int GenericWrite = 0x40000000;

    private const string TrustedInstallerSid = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

    private static readonly string[] Executables = { "optiSCAN.exe", "optiSCAN.Service.exe", "optiSCAN.Host.exe" };

    /// <summary>Vrai si le dossier de l'exécutable courant est réservé aux administrateurs.</summary>
    public static bool IsCurrentInstallTrusted(out string reason) =>
        IsAdminOnlyInstall(AppContext.BaseDirectory, out reason);

    /// <summary>
    /// Vrai si le dossier, ses parents et les exécutables optiSCAN qu'il contient ne peuvent
    /// être modifiés que par SYSTEM, les Administrateurs ou TrustedInstaller.
    /// </summary>
    public static bool IsAdminOnlyInstall(string? directory, out string reason)
    {
        reason = string.Empty;
        if (!OperatingSystem.IsWindows())
        {
            reason = "contrôle disponible sous Windows uniquement";
            return false;
        }

        if (string.IsNullOrWhiteSpace(directory))
        {
            reason = "dossier inconnu";
            return false;
        }

        try
        {
            var full = Path.GetFullPath(directory).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            var info = new DirectoryInfo(full);
            if (!info.Exists)
            {
                reason = "dossier absent";
                return false;
            }

            if (!IsAdminOnlyEntry(info, ContentWriteRights, out reason))
            {
                reason = "dossier d'installation : " + reason;
                return false;
            }

            foreach (var exe in Executables)
            {
                var file = new FileInfo(Path.Combine(full, exe));
                if (file.Exists && !IsAdminOnlyEntry(file, ContentWriteRights, out var fileReason))
                {
                    reason = exe + " : " + fileReason;
                    return false;
                }
            }

            for (var parent = info.Parent; parent != null; parent = parent.Parent)
            {
                if (!IsAdminOnlyEntry(parent, AncestorWriteRights, out var parentReason))
                {
                    reason = "dossier parent " + parent.FullName + " : " + parentReason;
                    return false;
                }
            }

            return true;
        }
        catch (Exception ex) when (!ex.IsFatal())
        {
            reason = "droits illisibles (" + ex.GetType().Name + ")";
            return false;
        }
    }

    [SupportedOSPlatform("windows")]
    private static bool IsAdminOnlyEntry(FileSystemInfo entry, FileSystemRights dangerous, out string reason)
    {
        reason = string.Empty;
        if ((entry.Attributes & FileAttributes.ReparsePoint) != 0)
        {
            reason = "point de réanalyse (jonction ou lien)";
            return false;
        }

        FileSystemSecurity security = entry is DirectoryInfo dir
            ? dir.GetAccessControl()
            : ((FileInfo)entry).GetAccessControl();
        return IsAdminOnlySecurity(security, dangerous, out reason);
    }

    /// <summary>
    /// Propriétaire de confiance, et aucune ACE d'autorisation effective qui donne à un autre
    /// compte l'un des droits <paramref name="dangerous"/>. Les ACE « héritage seulement »
    /// (modèles pour les enfants, comme CREATOR OWNER) ne s'appliquent pas à l'entrée elle-même.
    /// </summary>
    internal static bool IsAdminOnlySecurity(FileSystemSecurity security, FileSystemRights dangerous, out string reason)
    {
        reason = string.Empty;
        if (security.GetOwner(typeof(SecurityIdentifier)) is not SecurityIdentifier owner || !IsTrustedSid(owner))
        {
            reason = "propriétaire non administrateur";
            return false;
        }

        foreach (FileSystemAccessRule rule in security.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType != AccessControlType.Allow)
                continue;
            if ((rule.PropagationFlags & PropagationFlags.InheritOnly) != 0)
                continue;
            if (rule.IdentityReference is not SecurityIdentifier sid || IsTrustedSid(sid))
                continue;

            var mask = (int)rule.FileSystemRights;
            if ((mask & (int)dangerous) != 0 || (mask & (GenericAll | GenericWrite)) != 0)
            {
                reason = "droit d'écriture pour " + sid.Value;
                return false;
            }
        }

        return true;
    }

    internal static bool IsTrustedSid(SecurityIdentifier sid) =>
        sid.IsWellKnown(WellKnownSidType.LocalSystemSid)
        || sid.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid)
        || string.Equals(sid.Value, TrustedInstallerSid, StringComparison.OrdinalIgnoreCase);
}
