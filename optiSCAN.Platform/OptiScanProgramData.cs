// SPDX-License-Identifier: GPL-3.0-or-later
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;

namespace optiSCAN.Platform;

/// <summary>
/// Dossier %ProgramData%\optiSCAN réservé à SYSTEM et aux administrateurs.
/// Un dossier créé par un utilisateur, ou une jonction, est refusé ou repris.
/// </summary>
public static class OptiScanProgramData
{
    // SID du conteneur de clamd : lu à la demande (le nom n'existe qu'après le premier
    // démarrage de clamd), puis gardé une fois connu.
    private static SecurityIdentifier? _clamdSid;
    private static readonly Lazy<SecurityIdentifier?> LegacyClamdSid = new(() => DeriveContainerSid(ClamdContainerName.LegacyName));

    public static string DirectoryPath { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "optiSCAN");

    private static int _claimed;

    public static bool EnsureTrusted()
    {
        try
        {
            var path = DirectoryPath;
            if (IsReparse(path) && !TryDeleteReparse(path))
                return false;

            Directory.CreateDirectory(path);
            if (IsReparse(path))
                return false;

            if (!OperatingSystem.IsWindows())
                return false;

            // Déjà repris dans ce processus : ne pas réécrire la DACL à chaque appel,
            // chaque écriture repropage l'héritage à tout le contenu.
            if (Volatile.Read(ref _claimed) == 1 && IsTrustedEntry(path, isDirectory: true))
                return true;

            if (!TryClaim(path) && !IsTrustedEntry(path, isDirectory: true))
                return false;
            if (!IsTrustedEntry(path, isDirectory: true))
                return false;

            // Un fichier déposé avant la reprise garde son propriétaire, qui pourrait
            // en réécrire la DACL : propriétaire et droits sont remis à plat.
            if (!NormalizeChildren(path, depth: 0) || !IsTrustedEntry(path, isDirectory: true))
                return false;
            Volatile.Write(ref _claimed, 1);
            return true;
        }
        catch (Exception ignored) when (!ignored.IsFatal())
        {
            return false;
        }
    }

    public static bool IsTrustedOwner(string path)
    {
        try
        {
            var info = new DirectoryInfo(path);
            if (info.Attributes.HasFlag(FileAttributes.ReparsePoint))
                return false;

            var owner = info.GetAccessControl().GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
            if (owner == null)
                return false;

            var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            return owner.Equals(system) || owner.Equals(admins);
        }
        catch (Exception ignored) when (!ignored.IsFatal())
        {
            return false;
        }
    }

    /// <summary>Garde-fou contre un arbre anormalement grand ; jamais atteint en usage normal.</summary>
    private const int MaxNormalizedEntries = 200_000;

    /// <summary>Profondeur maximale parcourue ; au-delà, la reprise échoue (échec fermé).</summary>
    private const int MaxNormalizedDepth = 64;

    /// <summary>
    /// Parcourt tout le dossier, sans suivre de lien.
    /// Toute entrée dont le propriétaire ou l'une des autorisations ne vient pas de SYSTEM,
    /// des Administrateurs ou de l'AppContainer précis de clamd a été déposée par un autre compte
    /// avant la reprise : son <b>contenu</b> n'est pas fiable (une politique, un jeton, une base
    /// préparés à l'avance). Elle est donc supprimée, et non simplement remise à plat.
    /// Un dossier non fiable est vidé entièrement puis supprimé.
    /// <para>
    /// Chaque dossier en cours de parcours, de la racine à l'entrée traitée, reste ouvert sans
    /// partage de suppression : aucun ne peut être renommé ni remplacé par une jonction pendant
    /// qu'on agit sur son contenu par chemin. Chaque entrée est elle-même ouverte sans suivre de
    /// lien et gardée ouverte pendant la remise à plat de ses droits ; la suppression se fait
    /// par une poignée qui désigne l'entrée elle-même, jamais la cible d'un lien.
    /// </para>
    /// </summary>
    private static bool NormalizeChildren(string root, int depth)
    {
        _ = depth;
        EnablePrivilege("SeBackupPrivilege");
        using var rootPin = PinNoFollow(root, out var rootAttributes);
        if (rootPin == null || (rootAttributes & FileAttributes.ReparsePoint) != 0)
            return false;

        var visited = 0;
        return NormalizeDirectory(root, purge: false, level: 0, ref visited);
    }

    private static bool NormalizeDirectory(string directory, bool purge, int level, ref int visited)
    {
        if (level > MaxNormalizedDepth)
            return false;

        List<string> entries;
        try
        {
            entries = Directory.EnumerateFileSystemEntries(directory).ToList();
        }
        catch (Exception ignored) when (!ignored.IsFatal())
        {
            return false;
        }

        var complete = true;
        foreach (var entry in entries)
        {
            if (visited >= MaxNormalizedEntries)
                return false;
            visited++;

            try
            {
                if (!NormalizeEntry(entry, purge, level, ref visited))
                    complete = false;
            }
            catch (Exception ignored) when (!ignored.IsFatal())
            {
                complete = false;
            }
        }

        return complete;
    }

    private static bool NormalizeEntry(string entry, bool purge, int level, ref int visited)
    {
        if (!TryReadAttributesNoFollow(entry, out var attributes))
            return false;

        if ((attributes & FileAttributes.ReparsePoint) != 0)
        {
            // Jonction ou lien posé dans notre dossier : le lien lui-même est supprimé.
            return TryDeleteNoFollow(entry);
        }

        var isDirectory = (attributes & FileAttributes.Directory) != 0;
        var trusted = !purge && IsTrustedEntry(entry, isDirectory);

        // Un fichier fiable n'est ni modifié ni ouvert : rien à épingler. Un dossier l'est
        // toujours, pour que son chemin reste le sien pendant le parcours de son contenu.
        if (trusted && !isDirectory)
            return true;

        var pin = PinNoFollow(entry, out attributes);
        if (pin == null)
            return false;

        try
        {
            if ((attributes & FileAttributes.ReparsePoint) != 0)
            {
                // Remplacé par un lien entre les deux ouvertures.
                pin.Dispose();
                return TryDeleteNoFollow(entry);
            }

            if (!trusted && !purge && HasOnlyLegacyClamdAce(entry, isDirectory))
            {
                // Ancien conteneur clamd à nom fixe : on retire son ACE et on garde l'entrée
                // (bases ClamAV, configuration) au lieu de la supprimer.
                ResetEntry(entry, isDirectory);
                trusted = IsTrustedEntry(entry, isDirectory);
            }

            if (trusted)
                return !isDirectory || NormalizeDirectory(entry, purge: false, level + 1, ref visited);

            // Prendre la main d'abord : le dépositaire a pu retirer tout droit aux administrateurs.
            // L'entrée est épinglée : le chemin désigne encore l'objet vérifié.
            if (!IsTrustedEntry(entry, isDirectory))
                ResetEntry(entry, isDirectory);

            var emptied = !isDirectory || NormalizeDirectory(entry, purge: true, level + 1, ref visited);
            pin.Dispose();
            return TryDeleteNoFollow(entry) && emptied;
        }
        finally
        {
            pin.Dispose();
        }
    }

    /// <summary>
    /// Vrai si le fichier peut être lu comme donnée de confiance : pas un lien, propriétaire et
    /// autorisations limités à SYSTEM, aux Administrateurs (et à l'AppContainer de clamd).
    /// Hors Windows, toujours faux.
    /// </summary>
    public static bool IsTrustedFile(string path)
    {
        try
        {
            if (!OperatingSystem.IsWindows() || !File.Exists(path))
                return false;
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
                return false;
            return IsTrustedEntry(path, isDirectory: false);
        }
        catch (Exception ignored) when (!ignored.IsFatal())
        {
            return false;
        }
    }

    /// <summary>
    /// Propriétaire SYSTEM ou Administrateurs, et aucune autorisation pour un autre compte.
    /// Un fichier possédé par Administrateurs mais qui garde un droit pour un utilisateur
    /// est donc remis à plat lui aussi.
    /// </summary>
    public static bool IsTrustedEntry(string path, bool isDirectory)
    {
        FileSystemSecurity security = isDirectory
            ? new DirectoryInfo(path).GetAccessControl()
            : new FileInfo(path).GetAccessControl();
        return IsTrustedSecurity(security);
    }

    public static bool IsTrustedSecurity(FileSystemSecurity security) => IsTrustedSecurity(security, allowAppContainer: true);

    private static bool IsTrustedSecurity(FileSystemSecurity security, bool allowAppContainer)
    {
        if (security.GetOwner(typeof(SecurityIdentifier)) is not SecurityIdentifier owner || !IsTrustedPrincipal(owner, allowAppContainer: false))
            return false;

        foreach (FileSystemAccessRule rule in security.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType == AccessControlType.Deny)
                continue;
            if (rule.IdentityReference is not SecurityIdentifier sid || !IsTrustedPrincipal(sid, allowAppContainer))
                return false;
        }

        return true;
    }

    /// <summary>Comme <see cref="IsTrustedFile"/>, sans aucune ACE d'AppContainer admise.</summary>
    public static bool IsTrustedFileStrict(string path)
    {
        try
        {
            if (!OperatingSystem.IsWindows() || !File.Exists(path))
                return false;
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
                return false;
            return IsTrustedSecurity(new FileInfo(path).GetAccessControl(), allowAppContainer: false);
        }
        catch (Exception ignored) when (!ignored.IsFatal())
        {
            return false;
        }
    }

    /// <summary>
    /// Vrai si la seule autorisation étrangère est celle de l'ancien conteneur clamd à nom fixe :
    /// l'entrée a été créée par optiSCAN, il suffit d'en retirer cette ACE (pas de suppression).
    /// </summary>
    private static bool HasOnlyLegacyClamdAce(string path, bool isDirectory)
    {
        var legacy = LegacyClamdSid.Value;
        if (legacy == null)
            return false;

        FileSystemSecurity security = isDirectory
            ? new DirectoryInfo(path).GetAccessControl()
            : new FileInfo(path).GetAccessControl();
        if (security.GetOwner(typeof(SecurityIdentifier)) is not SecurityIdentifier owner || !IsTrustedPrincipal(owner, allowAppContainer: false))
            return false;

        var sawLegacy = false;
        foreach (FileSystemAccessRule rule in security.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType == AccessControlType.Deny || rule.IdentityReference is not SecurityIdentifier sid)
                continue;
            if (sid.Equals(legacy))
            {
                sawLegacy = true;
                continue;
            }
            if (!IsTrustedPrincipal(sid, allowAppContainer: true))
                return false;
        }

        return sawLegacy;
    }

    private static bool IsTrustedPrincipal(SecurityIdentifier sid, bool allowAppContainer)
    {
        if (sid.IsWellKnown(WellKnownSidType.LocalSystemSid) || sid.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid))
            return true;
        // Seul clamd reçoit une ACE sur sa configuration et ses bases. Accepter tout SID
        // S-1-15-2-* permettrait à un autre AppContainer créé par l'utilisateur de modifier
        // une entrée de ProgramData que le service considère ensuite fiable.
        return allowAppContainer && ClamdSid()?.Equals(sid) == true;
    }

    private static SecurityIdentifier? ClamdSid()
    {
        var known = Volatile.Read(ref _clamdSid);
        if (known != null)
            return known;
        var name = ClamdContainerName.TryReadServiceName();
        if (name == null)
            return null;
        known = DeriveContainerSid(name);
        if (known != null)
            Volatile.Write(ref _clamdSid, known);
        return known;
    }

    private static SecurityIdentifier? DeriveContainerSid(string containerName)
    {
        if (!OperatingSystem.IsWindows())
            return null;

        IntPtr sid = IntPtr.Zero;
        try
        {
            if (DeriveAppContainerSidFromAppContainerName(containerName, out sid) != 0 || sid == IntPtr.Zero)
                return null;
            return new SecurityIdentifier(sid);
        }
        catch (Exception ignored) when (!ignored.IsFatal())
        {
            return null;
        }
        finally
        {
            if (sid != IntPtr.Zero)
                FreeSid(sid);
        }
    }

    [DllImport("userenv.dll", CharSet = CharSet.Unicode)]
    private static extern int DeriveAppContainerSidFromAppContainerName(string appContainerName, out IntPtr appContainerSid);

    [DllImport("advapi32.dll")]
    private static extern IntPtr FreeSid(IntPtr sid);

    /// <summary>Propriétaire SYSTEM ou Administrateurs, DACL limitée à l'héritage du dossier repris.</summary>
    private static void ResetEntry(string path, bool isDirectory)
    {
        EnablePrivilege("SeTakeOwnershipPrivilege");
        EnablePrivilege("SeRestorePrivilege");
        var owner = new SecurityIdentifier(
            IsSystem() ? WellKnownSidType.LocalSystemSid : WellKnownSidType.BuiltinAdministratorsSid,
            null);

        if (isDirectory)
        {
            var info = new DirectoryInfo(path);
            var owned = new DirectorySecurity();
            owned.SetOwner(owner);
            info.SetAccessControl(owned);
            var inherit = new DirectorySecurity();
            inherit.SetAccessRuleProtection(isProtected: false, preserveInheritance: false);
            info.SetAccessControl(inherit);
        }
        else
        {
            var info = new FileInfo(path);
            var owned = new FileSecurity();
            owned.SetOwner(owner);
            info.SetAccessControl(owned);
            var inherit = new FileSecurity();
            inherit.SetAccessRuleProtection(isProtected: false, preserveInheritance: false);
            info.SetAccessControl(inherit);
        }
    }

    private static bool IsReparse(string path)
    {
        if (!File.Exists(path) && !Directory.Exists(path))
            return false;
        return (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0;
    }

    private static bool TryClaim(string path)
    {
        try
        {
            EnablePrivilege("SeTakeOwnershipPrivilege");
            EnablePrivilege("SeRestorePrivilege");

            var info = new DirectoryInfo(path);
            var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            var owned = info.GetAccessControl();
            owned.SetOwner(IsSystem() ? system : admins);
            info.SetAccessControl(owned);

            var security = new DirectorySecurity();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            security.AddAccessRule(new FileSystemAccessRule(
                system,
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));
            security.AddAccessRule(new FileSystemAccessRule(
                admins,
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));
            info.SetAccessControl(security);
            return true;
        }
        catch (Exception ignored) when (!ignored.IsFatal())
        {
            return false;
        }
    }

    private static bool IsSystem()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return identity.IsSystem;
    }

    private static bool TryDeleteReparse(string path) => TryDeleteNoFollow(path);

    private const uint FileReadData = 0x0001;
    private const uint FileReadAttributes = 0x0080;
    private const uint DeleteAccess = 0x00010000;
    private const uint ShareRead = 0x00000001;
    private const uint ShareWrite = 0x00000002;
    private const uint ShareDelete = 0x00000004;
    private const uint OpenExisting = 3;
    private const uint FlagOpenReparsePoint = 0x00200000;
    private const uint FlagBackupSemantics = 0x02000000;

    /// <summary>
    /// Ouvre l'entrée elle-même (jamais la cible d'un lien), en lecture et sans partage de
    /// suppression : tant que la poignée est ouverte, personne ne peut la renommer, la
    /// supprimer ni la remplacer. La lecture est demandée pour que le partage s'applique
    /// (une poignée limitée aux attributs n'empêche aucun renommage).
    /// </summary>
    private static Microsoft.Win32.SafeHandles.SafeFileHandle? PinNoFollow(string path, out FileAttributes attributes)
    {
        attributes = 0;
        var handle = CreateFile(
            path,
            FileReadData | FileReadAttributes,
            ShareRead | ShareWrite,
            IntPtr.Zero,
            OpenExisting,
            FlagOpenReparsePoint | FlagBackupSemantics,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            handle.Dispose();
            return null;
        }

        if (!GetFileInformationByHandle(handle, out var info))
        {
            handle.Dispose();
            return null;
        }

        attributes = (FileAttributes)info.FileAttributes;
        return handle;
    }

    /// <summary>Attributs de l'entrée elle-même (un lien n'est pas suivi), sans la garder ouverte.</summary>
    private static bool TryReadAttributesNoFollow(string path, out FileAttributes attributes)
    {
        attributes = 0;
        using var handle = CreateFile(
            path,
            FileReadAttributes,
            ShareRead | ShareWrite | ShareDelete,
            IntPtr.Zero,
            OpenExisting,
            FlagOpenReparsePoint | FlagBackupSemantics,
            IntPtr.Zero);
        if (handle.IsInvalid || !GetFileInformationByHandle(handle, out var info))
            return false;
        attributes = (FileAttributes)info.FileAttributes;
        return true;
    }

    /// <summary>
    /// Supprime l'entrée elle-même par sa poignée : un lien est supprimé, jamais sa cible.
    /// Un fichier en lecture seule est supprimé aussi (indicateur ignoré).
    /// </summary>
    private static bool TryDeleteNoFollow(string path)
    {
        using var handle = CreateFile(
            path,
            DeleteAccess | FileReadAttributes,
            ShareRead | ShareWrite | ShareDelete,
            IntPtr.Zero,
            OpenExisting,
            FlagOpenReparsePoint | FlagBackupSemantics,
            IntPtr.Zero);
        if (handle.IsInvalid)
            return false;

        // FILE_DISPOSITION_DELETE | FILE_DISPOSITION_POSIX_SEMANTICS | FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE
        var extended = new FileDispositionInfoExData { Flags = 0x1 | 0x2 | 0x10 };
        if (SetFileInformationByHandle(handle, FileDispositionInfoEx, ref extended, (uint)Marshal.SizeOf<FileDispositionInfoExData>()))
            return true;

        // Windows antérieur à 10 1809 : suppression classique (échoue sur un fichier en lecture seule).
        var info = new FileDispositionInfoData { DeleteFile = true };
        return SetFileInformationByHandle(handle, FileDispositionInfo, ref info, (uint)Marshal.SizeOf<FileDispositionInfoData>());
    }

    private const int FileDispositionInfo = 4;
    private const int FileDispositionInfoEx = 21;

    private static void EnablePrivilege(string name)
    {
        if (!OpenProcessToken(GetCurrentProcess(), 0x0020 | 0x0008, out var token))
            return;

        try
        {
            if (!LookupPrivilegeValue(null, name, out var luid))
                return;

            var privileges = new TokenPrivileges
            {
                PrivilegeCount = 1,
                Privileges = new LuidAndAttributes { Luid = luid, Attributes = 0x00000002 },
            };
            AdjustTokenPrivileges(token, false, ref privileges, 0, IntPtr.Zero, IntPtr.Zero);
        }
        finally
        {
            CloseHandle(token);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileDispositionInfoData
    {
        [MarshalAs(UnmanagedType.Bool)]
        public bool DeleteFile;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileDispositionInfoExData
    {
        public uint Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public long CreationTime;
        public long LastAccessTime;
        public long LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Luid
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LuidAndAttributes
    {
        public Luid Luid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TokenPrivileges
    {
        public uint PrivilegeCount;
        public LuidAndAttributes Privileges;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern Microsoft.Win32.SafeHandles.SafeFileHandle CreateFile(
        string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetFileInformationByHandle(
        Microsoft.Win32.SafeHandles.SafeFileHandle handle, int fileInformationClass, ref FileDispositionInfoData info, uint size);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetFileInformationByHandle(
        Microsoft.Win32.SafeHandles.SafeFileHandle handle, int fileInformationClass, ref FileDispositionInfoExData info, uint size);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandle(
        Microsoft.Win32.SafeHandles.SafeFileHandle handle, out ByHandleFileInformation information);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool LookupPrivilegeValue(string? system, string name, out Luid luid);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AdjustTokenPrivileges(
        IntPtr token, bool disableAll, ref TokenPrivileges privileges, uint length, IntPtr previous, IntPtr returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);
}
