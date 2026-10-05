using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace optiSCAN.Services;

/// <summary>
/// Supprime un fichier qui n'a qu'un seul nom, sans suivre une jonction dans un dossier parent.
/// Un lien physique (plusieurs noms pour le même fichier) est refusé : en supprimer un
/// laisserait le fichier en place sous l'autre nom, ou retirerait un nom qui n'est pas
/// celui d'origine.
/// </summary>
internal static class SafePathDelete
{
    private const uint FileReadAttributes = 0x00000080;
    private const uint FileListDirectory = 0x00000001;
    private const uint FileTraverse = 0x00000020;
    private const uint DeleteAccess = 0x00010000;
    private const uint Synchronize = 0x00100000;
    private const uint FileShareAll = 0x00000001 | 0x00000002 | 0x00000004;
    private const uint FileOpen = 1;
    private const uint FileDirectoryFile = 0x00000001;
    private const uint FileNonDirectoryFile = 0x00000040;
    private const uint FileSynchronousIoNonAlert = 0x00000020;
    private const uint FileOpenForBackupIntent = 0x00004000;
    private const uint FileOpenReparsePoint = 0x00200000;
    private const uint ObjCaseInsensitive = 0x00000040;
    private const uint FileAttributeReparsePoint = 0x00000400;
    private const int FileDispositionInfo = 4;

    private const uint GenericRead = 0x80000000;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareDelete = 0x00000004;

    internal static void Delete(string path)
    {
        if (!TryDelete(path))
            throw new IOException("Suppression du fichier refusée.");
    }

    private static bool TryDelete(string path)
    {
        var parent = OpenParent(path, out var name);
        if (parent == IntPtr.Zero)
            return false;

        var current = Open(parent, name, DeleteAccess | Synchronize | FileReadAttributes | FileWriteAttributes, FileShareAll, FileNonDirectoryFile | FileOpenReparsePoint);
        CloseHandle(parent);
        if (current == IntPtr.Zero)
            return false;

        using var handle = new SafeFileHandle(current, ownsHandle: true);
        if (!IsSoleName(handle))
            return false;
        // Un fichier en lecture seule (fréquent pour un malware) est supprimé par la même
        // poignée, sans retirer l'attribut par chemin.
        return SetDeleteDisposition(handle, true) || SetDeleteDispositionIgnoringReadOnly(handle);
    }

    private const uint FileWriteAttributes = 0x00000100;
    private const int FileDispositionInfoExClass = 21;
    private const uint FileDispositionFlagDelete = 0x00000001;
    private const uint FileDispositionFlagIgnoreReadOnly = 0x00000010;

    /// <summary>FileDispositionInfoEx (Windows 10 1809+) : supprime malgré l'attribut lecture seule.</summary>
    private static bool SetDeleteDispositionIgnoringReadOnly(SafeFileHandle handle)
    {
        var info = new FileDispositionInfoExData { Flags = FileDispositionFlagDelete | FileDispositionFlagIgnoreReadOnly };
        return SetFileInformationByHandleEx(handle, FileDispositionInfoExClass, ref info, (uint)Marshal.SizeOf<FileDispositionInfoExData>());
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileDispositionInfoExData
    {
        public uint Flags;
    }

    [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "SetFileInformationByHandle")]
    private static extern bool SetFileInformationByHandleEx(
        SafeFileHandle file,
        int fileInformationClass,
        ref FileDispositionInfoExData info,
        uint bufferSize);

    /// <summary>
    /// Descend du lecteur jusqu'au dossier parent, nom par nom, sans traverser de jonction ni
    /// de lien. Retourne le handle du parent et le dernier nom, ou <see cref="IntPtr.Zero"/>.
    /// </summary>
    private static IntPtr OpenParent(string path, out string lastName)
    {
        lastName = string.Empty;
        if (!OperatingSystem.IsWindows())
            return IntPtr.Zero;

        var full = Path.GetFullPath(path);
        if (full.StartsWith(@"\\", StringComparison.Ordinal))
            return IntPtr.Zero;

        var root = Path.GetPathRoot(full);
        if (string.IsNullOrEmpty(root))
            return IntPtr.Zero;

        var rest = full[root.Length..];
        var parts = rest.Split(new[] { Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar }, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 0)
            return IntPtr.Zero;

        var current = Open(IntPtr.Zero, ToNtPath(root), DirectoryAccess, FileShareAll, FileDirectoryFile | FileOpenReparsePoint);
        if (current == IntPtr.Zero)
            return IntPtr.Zero;

        for (var i = 0; i < parts.Length - 1; i++)
        {
            var next = Open(current, parts[i], DirectoryAccess, FileShareAll, FileDirectoryFile | FileOpenReparsePoint);
            CloseHandle(current);
            current = next;
            if (current == IntPtr.Zero)
                return IntPtr.Zero;

            if (IsRedirectingReparsePoint(current))
            {
                CloseHandle(current);
                return IntPtr.Zero;
            }
        }

        lastName = parts[^1];
        return current;
    }

    private const uint DirectoryAccess = FileListDirectory | FileTraverse | Synchronize | FileReadAttributes;

    /// <summary>
    /// Ouvre le fichier à mettre en quarantaine <b>une seule fois</b> : la lecture et la
    /// suppression passent par ce même accès. Le partage n'autorise que la lecture : tant
    /// qu'il est ouvert, personne ne peut renommer, remplacer, supprimer ni modifier ce nom.
    /// Le dernier nom n'est jamais suivi s'il s'agit d'un lien ; un fichier cloud (OneDrive)
    /// est relu par un second accès dont on vérifie qu'il désigne bien le même fichier.
    /// Retourne null si le chemin passe par une jonction, n'existe pas ou est verrouillé.
    /// </summary>
    internal static QuarantineHandle? OpenForQuarantine(string path)
    {
        var parent = OpenParent(path, out var name);
        if (parent == IntPtr.Zero)
            return null;

        try
        {
            var raw = Open(
                parent,
                name,
                GenericRead | DeleteAccess | Synchronize | FileReadAttributes,
                FileShareRead,
                FileNonDirectoryFile | FileOpenReparsePoint);
            if (raw == IntPtr.Zero)
                return null;

            var nameHandle = new SafeFileHandle(raw, ownsHandle: true);
            if (!GetFileInformationByHandleEx(raw, FileAttributeTagInfoClass, out var tag, (uint)Marshal.SizeOf<FileAttributeTagInfo>()))
            {
                nameHandle.Dispose();
                return null;
            }

            if (IsNameSurrogate(tag.ReparseTag))
            {
                // Lien symbolique ou jonction à la place du fichier : ni lu, ni supprimé.
                nameHandle.Dispose();
                return null;
            }

            if (!IsSoleName(nameHandle))
            {
                nameHandle.Dispose();
                return null;
            }

            if ((tag.FileAttributes & FileAttributeReparsePoint) == 0)
                return new QuarantineHandle(nameHandle, dataHandle: null);

            // Fichier cloud : les données passent par le filtre, donc un accès qui suit le
            // point de réanalyse. Le nom est verrouillé par le premier accès ; on vérifie
            // quand même que le second désigne le même fichier.
            var dataRaw = Open(
                parent,
                name,
                GenericRead | Synchronize | FileReadAttributes,
                FileShareRead | FileShareDelete,
                FileNonDirectoryFile);
            if (dataRaw == IntPtr.Zero || !SameFile(raw, dataRaw))
            {
                if (dataRaw != IntPtr.Zero)
                    CloseHandle(dataRaw);
                nameHandle.Dispose();
                return null;
            }

            return new QuarantineHandle(nameHandle, new SafeFileHandle(dataRaw, ownsHandle: true));
        }
        finally
        {
            CloseHandle(parent);
        }
    }

    /// <summary>
    /// Un seul lien de répertoire. Au-delà, ce chemin est un lien physique vers un fichier
    /// qui a déjà un autre nom : on ne le lit pas pour le supprimer.
    /// </summary>
    private static bool IsSoleName(SafeFileHandle handle)
    {
        if (handle.IsInvalid || handle.IsClosed)
            return false;
        if (!GetFileInformationByHandle(handle.DangerousGetHandle(), out var info))
            return false;
        return info.NumberOfLinks == 1;
    }

    private static bool SameFile(IntPtr a, IntPtr b) =>
        GetFileInformationByHandle(a, out var x)
        && GetFileInformationByHandle(b, out var y)
        && x.VolumeSerialNumber == y.VolumeSerialNumber
        && x.FileIndexHigh == y.FileIndexHigh
        && x.FileIndexLow == y.FileIndexLow;

    private const uint FileCreate = 2;
    private const uint GenericWrite = 0x40000000;

    /// <summary>
    /// Crée un fichier <b>neuf</b> (échec s'il existe, y compris sous forme de lien) en
    /// descendant du lecteur au dossier parent sans traverser de jonction ni de lien
    /// symbolique. Sert à la restauration : aucune écriture ne peut être redirigée ailleurs.
    /// Le dossier parent doit exister. Hors Windows : null.
    /// </summary>
    internal static SafeFileHandle? CreateNew(string path)
    {
        var parent = OpenParent(path, out var name);
        if (parent == IntPtr.Zero)
            return null;

        try
        {
            var raw = Open(
                parent,
                name,
                GenericWrite | DeleteAccess | Synchronize | FileReadAttributes,
                0,
                FileNonDirectoryFile,
                FileCreate);
            return raw == IntPtr.Zero ? null : new SafeFileHandle(raw, ownsHandle: true);
        }
        finally
        {
            CloseHandle(parent);
        }
    }

    internal static bool SetDeleteDisposition(SafeFileHandle handle, bool delete)
    {
        var info = new FileDispositionInfoData { DeleteFile = delete };
        return SetFileInformationByHandle(handle, FileDispositionInfo, ref info, (uint)Marshal.SizeOf<FileDispositionInfoData>());
    }

    /// <summary>Fichier ouvert pour la quarantaine : lecture puis suppression par le même accès.</summary>
    internal sealed class QuarantineHandle : IDisposable
    {
        private readonly SafeFileHandle _name;
        private readonly SafeFileHandle? _data;

        internal QuarantineHandle(SafeFileHandle name, SafeFileHandle? dataHandle)
        {
            _name = name;
            _data = dataHandle;
        }

        private SafeFileHandle Data => _data ?? _name;

        public long Length => RandomAccess.GetLength(Data);

        /// <summary>Lit tout le fichier ; false si sa taille change pendant la lecture.</summary>
        public bool TryReadAll(byte[] buffer)
        {
            long offset = 0;
            while (offset < buffer.Length)
            {
                var read = RandomAccess.Read(Data, buffer.AsSpan((int)offset), offset);
                if (read <= 0)
                    return false;
                offset += read;
            }

            return true;
        }

        /// <summary>
        /// Marque le fichier à supprimer : il disparaît à la fermeture de ce handle.
        /// <see cref="CancelDelete"/> l'annule tant que le handle est ouvert.
        /// </summary>
        public bool MarkForDelete() => SetDeleteDisposition(_name, true);

        public bool CancelDelete() => SetDeleteDisposition(_name, false);

        public void Dispose()
        {
            _data?.Dispose();
            _name.Dispose();
        }
    }

    private static string ToNtPath(string root)
    {
        var trimmed = root.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        return @"\??\" + trimmed + @"\";
    }

    private static IntPtr Open(IntPtr directory, string name, uint access, uint share, uint kindOptions, uint disposition = FileOpen)
    {
        if (name.Length == 0 || name.Length > 10000)
            return IntPtr.Zero;

        var buffer = Marshal.StringToHGlobalUni(name);
        var unicodePtr = Marshal.AllocHGlobal(Marshal.SizeOf<UnicodeString>());
        try
        {
            var unicode = new UnicodeString
            {
                Length = (ushort)(name.Length * 2),
                MaximumLength = (ushort)(name.Length * 2),
                Buffer = buffer,
            };
            Marshal.StructureToPtr(unicode, unicodePtr, false);
            var attributes = new ObjectAttributes
            {
                Length = Marshal.SizeOf<ObjectAttributes>(),
                RootDirectory = directory,
                ObjectName = unicodePtr,
                Attributes = ObjCaseInsensitive,
            };
            var options = kindOptions
                | FileOpenForBackupIntent
                | FileSynchronousIoNonAlert;
            var status = NtCreateFile(
                out var handle,
                access,
                ref attributes,
                out _,
                IntPtr.Zero,
                0,
                share,
                disposition,
                options,
                IntPtr.Zero,
                0);
            return status < 0 ? IntPtr.Zero : handle;
        }
        finally
        {
            Marshal.FreeHGlobal(unicodePtr);
            Marshal.FreeHGlobal(buffer);
        }
    }

    /// <summary>
    /// Vrai pour un dossier parent qui renvoie ailleurs : jonction, lien symbolique, et
    /// tout point de réanalyse « substitut de nom ». Les dossiers OneDrive et autres
    /// fichiers de stockage cloud portent aussi un point de réanalyse, mais ne redirigent
    /// pas : ils restent traversables, sinon la quarantaine échouerait sous OneDrive.
    /// </summary>
    private static bool IsRedirectingReparsePoint(IntPtr handle)
    {
        if (!GetFileInformationByHandleEx(handle, FileAttributeTagInfoClass, out var tag, (uint)Marshal.SizeOf<FileAttributeTagInfo>()))
            return true;
        if ((tag.FileAttributes & FileAttributeReparsePoint) == 0)
            return false;
        return IsNameSurrogate(tag.ReparseTag);
    }

    /// <summary>Bit « substitut de nom » des étiquettes de réanalyse (IsReparseTagNameSurrogate).</summary>
    internal static bool IsNameSurrogate(uint reparseTag) => (reparseTag & 0x20000000) != 0;

    private const int FileAttributeTagInfoClass = 9;

    [StructLayout(LayoutKind.Sequential)]
    private struct FileAttributeTagInfo
    {
        public uint FileAttributes;
        public uint ReparseTag;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandleEx(
        IntPtr handle,
        int fileInformationClass,
        out FileAttributeTagInfo info,
        uint bufferSize);

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public uint CreationTimeLow;
        public uint CreationTimeHigh;
        public uint LastAccessTimeLow;
        public uint LastAccessTimeHigh;
        public uint LastWriteTimeLow;
        public uint LastWriteTimeHigh;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandle(IntPtr handle, out ByHandleFileInformation info);

    [StructLayout(LayoutKind.Sequential)]
    private struct UnicodeString
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ObjectAttributes
    {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoStatusBlock
    {
        public IntPtr Status;
        public IntPtr Information;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileDispositionInfoData
    {
        [MarshalAs(UnmanagedType.U1)]
        public bool DeleteFile;
    }

    [DllImport("ntdll.dll")]
    private static extern int NtCreateFile(
        out IntPtr handle,
        uint access,
        ref ObjectAttributes attributes,
        out IoStatusBlock io,
        IntPtr allocationSize,
        uint fileAttributes,
        uint share,
        uint disposition,
        uint options,
        IntPtr eaBuffer,
        uint eaLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetFileInformationByHandle(
        SafeFileHandle file,
        int fileInformationClass,
        ref FileDispositionInfoData info,
        uint bufferSize);
}
