using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace optiSCAN.Services;

/// <summary>
/// Le temps réel tourne en SYSTEM et surveille des dossiers que l'utilisateur contrôle
/// (Téléchargements, Bureau, Temp, Démarrage). Une jonction créée dans l'un d'eux ferait
/// analyser par SYSTEM des fichiers situés ailleurs. Ce garde :
/// <list type="bullet">
/// <item>refuse un dossier à surveiller dont le chemin passe par une jonction ou un lien ;</item>
/// <item>avant chaque analyse, ouvre le fichier et vérifie que son chemin réel (résolu par le
/// système) reste sous le chemin réel du dossier surveillé ;</item>
/// <item>garde ce fichier ouvert, sans partage d'écriture ni de suppression : le fichier lui-même
/// ne peut être ni modifié, ni renommé, ni remplacé. Un dossier <b>parent</b>, lui, peut encore
/// être renommé ; c'est pourquoi la protection temps réel analyse une copie faite depuis cette
/// poignée, et non le chemin (<c>RealTimeProtection.ScanPinnedAsync</c>).</item>
/// </list>
/// </summary>
internal static class RealTimePathGuard
{
    /// <summary>
    /// Vrai si aucun élément du chemin (du lecteur jusqu'au dossier lui-même) n'est une jonction,
    /// un lien symbolique ou un autre point de réanalyse « substitut de nom ».
    /// Les dossiers OneDrive (réanalyse cloud) restent acceptés.
    /// </summary>
    internal static bool IsDirectPath(string folder)
    {
        if (!OperatingSystem.IsWindows())
            return true;

        try
        {
            var full = Path.GetFullPath(folder);
            var root = Path.GetPathRoot(full);
            if (string.IsNullOrEmpty(root) || full.StartsWith(@"\\", StringComparison.Ordinal))
                return false;

            var current = root;
            foreach (var part in full[root.Length..].Split(
                         new[] { Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar },
                         StringSplitOptions.RemoveEmptyEntries))
            {
                current = Path.Combine(current, part);
                if (IsNameSurrogateReparse(current))
                    return false;
            }

            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Ouvre <paramref name="file"/> et vérifie qu'il se trouve réellement sous
    /// <paramref name="watchRoot"/>. Retourne le handle à garder ouvert pendant l'analyse,
    /// ou null si le fichier est ailleurs (jonction), est un lien, ou ne peut pas être ouvert.
    /// Hors Windows : un handle factice (pas de vérification possible).
    /// </summary>
    internal static IDisposable? PinWithinRoot(string watchRoot, string file, out string? refusal)
    {
        refusal = null;
        if (!OperatingSystem.IsWindows())
            return new NoPin();

        var rootFinal = FinalPathOf(watchRoot, directory: true);
        if (rootFinal == null)
        {
            refusal = "dossier surveillé introuvable ou redirigé";
            return null;
        }

        var handle = CreateFile(
            file,
            GenericRead,
            // Autorise les lecteurs concurrents (dont ClamAV), mais bloque les écritures
            // et remplacements jusqu'à la fin du scan.
            FileShareRead,
            IntPtr.Zero,
            OpenExisting,
            FileFlagOpenReparsePoint,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            handle.Dispose();
            refusal = "fichier inaccessible";
            return null;
        }

        if (IsNameSurrogate(handle))
        {
            handle.Dispose();
            refusal = "lien symbolique";
            return null;
        }

        var fileFinal = FinalPath(handle);
        if (fileFinal == null || !IsUnder(fileFinal, rootFinal))
        {
            handle.Dispose();
            refusal = "hors du dossier surveillé (jonction)";
            return null;
        }

        return handle;
    }

    /// <summary>Comparaison de chemins réels, insensible à la casse, sur une frontière de dossier.</summary>
    internal static bool IsUnder(string path, string root)
    {
        var r = root.TrimEnd('\\', '/');
        return path.Length > r.Length + 1
            && path.StartsWith(r, StringComparison.OrdinalIgnoreCase)
            && (path[r.Length] == '\\' || path[r.Length] == '/');
    }

    private static string? FinalPathOf(string path, bool directory)
    {
        using var handle = CreateFile(
            path,
            FileReadAttributes,
            FileShareRead | FileShareWrite | FileShareDelete,
            IntPtr.Zero,
            OpenExisting,
            FileFlagOpenReparsePoint | (directory ? FileFlagBackupSemantics : 0),
            IntPtr.Zero);
        if (handle.IsInvalid || IsNameSurrogate(handle))
            return null;
        return FinalPath(handle);
    }

    private static bool IsNameSurrogateReparse(string path)
    {
        var attributes = File.GetAttributes(path);
        if ((attributes & FileAttributes.ReparsePoint) == 0)
            return false;

        using var handle = CreateFile(
            path,
            FileReadAttributes,
            FileShareRead | FileShareWrite | FileShareDelete,
            IntPtr.Zero,
            OpenExisting,
            FileFlagOpenReparsePoint | FileFlagBackupSemantics,
            IntPtr.Zero);
        return handle.IsInvalid || IsNameSurrogate(handle);
    }

    private static bool IsNameSurrogate(SafeFileHandle handle)
    {
        if (!GetFileInformationByHandleEx(handle, FileAttributeTagInfoClass, out var tag, (uint)Marshal.SizeOf<FileAttributeTagInfo>()))
            return true;
        return (tag.FileAttributes & 0x400) != 0 && SafePathDelete.IsNameSurrogate(tag.ReparseTag);
    }

    internal static string? FinalPath(SafeFileHandle handle)
    {
        var buffer = new char[1024];
        var length = GetFinalPathNameByHandle(handle, buffer, (uint)buffer.Length, 0);
        if (length == 0)
            return null;
        if (length >= buffer.Length)
        {
            buffer = new char[length + 1];
            length = GetFinalPathNameByHandle(handle, buffer, (uint)buffer.Length, 0);
            if (length == 0 || length >= buffer.Length)
                return null;
        }

        return new string(buffer, 0, (int)length);
    }

    /// <summary>
    /// Retire le préfixe <c>\\?\</c> (ou <c>\\?\UNC\</c>) d'un chemin rendu par
    /// <see cref="FinalPath"/>, pour le comparer aux dossiers système.
    /// </summary>
    internal static string NormalizeFinalPath(string finalPath)
    {
        if (finalPath.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
            return @"\\" + finalPath[8..];
        if (finalPath.StartsWith(@"\\?\", StringComparison.Ordinal))
            return finalPath[4..];
        return finalPath;
    }

    private sealed class NoPin : IDisposable
    {
        public void Dispose()
        {
        }
    }

    private const uint GenericRead = 0x80000000;
    private const uint FileReadAttributes = 0x00000080;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint FileShareDelete = 0x00000004;
    private const uint OpenExisting = 3;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const int FileAttributeTagInfoClass = 9;

    [StructLayout(LayoutKind.Sequential)]
    private struct FileAttributeTagInfo
    {
        public uint FileAttributes;
        public uint ReparseTag;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "CreateFileW")]
    private static extern SafeFileHandle CreateFile(
        string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandleEx(
        SafeFileHandle handle, int fileInformationClass, out FileAttributeTagInfo info, uint bufferSize);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "GetFinalPathNameByHandleW")]
    private static extern uint GetFinalPathNameByHandle(SafeFileHandle handle, [Out] char[] path, uint length, uint flags);
}
