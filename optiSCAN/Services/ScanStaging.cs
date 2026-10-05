using System.Collections.Concurrent;
using System.IO;
using System.Security.Cryptography;
using System.Security.Principal;
using optiSCAN.Platform;

namespace optiSCAN.Services;

/// <summary>
/// Copies privées des contenus scannés depuis une poignée épinglée (IPC ou RTP).
/// Remplacer le fichier par son chemin après le contrôle ne change donc pas ce qui est analysé.
/// </summary>
internal static class ScanStaging
{
    /// <summary>Reserve de l'espace pour le système pendant la copie temporaire.</summary>
    private const long ReservedFreeSpaceBytes = 128L * 1024 * 1024;

    /// <summary>Plafond propre aux scans IPC synchrones (distinct du staging RTP).</summary>
    internal const long MaxIpcStagedBytes = 256L * 1024 * 1024;

    private const string FolderName = "scan-staging";

    /// <summary>
    /// Sous SYSTEM : %ProgramData%\optiSCAN\scan-staging (SYSTEM et Administrateurs seulement).
    /// Ailleurs (tests, hôte local) : dossier temporaire de l'utilisateur.
    /// </summary>
    internal static string Root
    {
        get
        {
            if (IsSystem())
            {
                if (!OptiScanProgramData.EnsureTrusted())
                    throw new InvalidOperationException("Le stockage sécurisé du scan SYSTEM est indisponible.");
                return Path.Combine(OptiScanProgramData.DirectoryPath, FolderName);
            }
            return Path.Combine(Path.GetTempPath(), "optiscan_" + FolderName);
        }
    }

    // Dossiers de copie en cours d'analyse, et ceux supprimés récemment (date de suppression).
    private static readonly ConcurrentDictionary<string, byte> ActiveDirectories = new(StringComparer.OrdinalIgnoreCase);
    private static readonly ConcurrentDictionary<string, DateTime> RecentlyDisposed = new(StringComparer.OrdinalIgnoreCase);
    private static readonly TimeSpan RecentlyDisposedWindow = TimeSpan.FromMinutes(2);
    private const int RecentlyDisposedPruneThreshold = 256;

    /// <summary>
    /// La protection temps réel ignore les copies faites par optiSCAN : celles en cours
    /// d'analyse, et les événements tardifs d'une copie déjà supprimée. Rien d'autre :
    /// le dossier de staging de l'utilisateur est dans %TEMP%, que la session peut écrire,
    /// et un préfixe ignoré y deviendrait une cachette pour un malware.
    /// </summary>
    internal static bool IsStagingPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return false;
        try
        {
            var full = Path.GetFullPath(path);
            var directory = Path.GetDirectoryName(full);
            if (string.IsNullOrEmpty(directory))
                return false;
            if (ActiveDirectories.ContainsKey(directory))
                return true;

            // Copie déjà analysée puis supprimée : seul un événement en retard peut encore la
            // désigner. Si un fichier existe de nouveau à cet endroit, il est analysé.
            return RecentlyDisposed.TryGetValue(directory, out var disposedAt)
                && DateTime.UtcNow - disposedAt < RecentlyDisposedWindow
                && !File.Exists(full)
                && !Directory.Exists(directory);
        }
        catch
        {
            /* chemin invalide */
        }

        return false;
    }

    private static void Register(string directory) =>
        ActiveDirectories[Path.GetFullPath(directory)] = 0;

    private static void Unregister(string directory)
    {
        var full = Path.GetFullPath(directory);
        ActiveDirectories.TryRemove(full, out _);
        var now = DateTime.UtcNow;
        RecentlyDisposed[full] = now;
        if (RecentlyDisposed.Count > RecentlyDisposedPruneThreshold)
        {
            foreach (var entry in RecentlyDisposed)
            {
                if (now - entry.Value >= RecentlyDisposedWindow)
                    RecentlyDisposed.TryRemove(entry.Key, out _);
            }
        }
    }

    /// <summary>
    /// Copie <paramref name="source"/> dans un dossier propre au scan et rend son chemin.
    /// Le nom d'origine (extension comprise) est conservé : certaines signatures en dépendent.
    /// </summary>
    internal static StagedFile Stage(Stream source, string? originalName, long? expectedLength = null)
    {
        var directory = Path.Combine(Root, Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        Register(directory);
        var name = Path.GetFileName(originalName ?? string.Empty);
        if (string.IsNullOrWhiteSpace(name))
            name = "content.bin";
        var path = Path.Combine(directory, name);

        try
        {
            if (expectedLength is null && source.CanSeek)
                expectedLength = source.Length - source.Position;
            if (expectedLength is < 0)
                throw new IOException("Taille source invalide pour le scan.");

            var volumeRoot = Path.GetPathRoot(directory);
            if (string.IsNullOrEmpty(volumeRoot))
                throw new IOException("Volume de staging introuvable.");

            var availableForStagingBytes = Math.Max(
                0, new DriveInfo(volumeRoot).AvailableFreeSpace - ReservedFreeSpaceBytes);
            if (expectedLength.HasValue && expectedLength.Value > availableForStagingBytes)
                throw new IOException("Espace disque insuffisant pour créer la copie d'analyse.");

            using var target = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read);
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            var buffer = new byte[81920];
            long total = 0;
            int read;
            while ((read = source.Read(buffer, 0, buffer.Length)) > 0)
            {
                total += read;
                if (total > availableForStagingBytes)
                    throw new IOException("La copie d'analyse dépasserait l'espace disponible réservé.");
                if (expectedLength.HasValue && total > expectedLength.Value)
                    throw new IOException("Le contenu source a grandi pendant sa copie de staging.");
                hash.AppendData(buffer, 0, read);
                target.Write(buffer, 0, read);
            }

            if (expectedLength.HasValue && total != expectedLength.Value)
                throw new IOException("Le contenu source a changé ou a été tronqué pendant sa copie de staging.");

            return new StagedFile(path, directory, Convert.ToHexString(hash.GetHashAndReset()));
        }
        catch
        {
            TryDeleteDirectory(directory);
            throw;
        }

    }

    private static void TryDeleteDirectory(string directory)
    {
        try { Directory.Delete(directory, recursive: true); }
        catch (Exception ex) { AppLogger.Debug("ScanStaging", "Nettoyage : " + ex.Message); }
        finally { Unregister(directory); }
    }

    private static bool IsSystem()
    {
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

    internal sealed class StagedFile : IDisposable
    {
        private readonly string _directory;

        internal StagedFile(string path, string directory, string sha256)
        {
            Path = path;
            _directory = directory;
            Sha256 = sha256;
        }

        public string Path { get; }
        public string Sha256 { get; }

        public void Dispose() => TryDeleteDirectory(_directory);
    }
}
