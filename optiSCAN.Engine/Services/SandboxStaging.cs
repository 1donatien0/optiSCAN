using System.IO;

namespace optiSCAN.Services;

/// <summary>
/// Copies d'analyse pour les analyseurs confinés. Sous SYSTEM, <c>yara</c> et <c>clamscan</c>
/// ne lisent que le dossier des copies (<see cref="ScanStaging"/>) : une cible ailleurs (clé USB,
/// dossier d'un compte) est d'abord copiée par le service, puis la copie est analysée et les
/// résultats rapportés au chemin d'origine.
/// </summary>
internal static class SandboxStaging
{
    /// <summary>Taille maximale d'un fichier copié pour l'analyse confinée.</summary>
    internal const long MaxFileBytes = ScanStaging.MaxIpcStagedBytes;

    /// <summary>Nombre de fichiers copiés puis analysés par un même lancement.</summary>
    internal const int BatchSize = 64;

    /// <summary>Vrai si l'analyseur confiné ne peut pas lire <paramref name="path"/> directement.</summary>
    internal static bool NeedsStaging(string path)
    {
        if (!ScannerSandbox.IsRequired)
            return false;
        try
        {
            var root = Path.GetFullPath(ScanStaging.Root).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            return !Path.GetFullPath(path).StartsWith(root, StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or IOException or InvalidOperationException)
        {
            return true;
        }
    }

    /// <summary>Fichiers d'un dossier, sans suivre les liens ni les dossiers illisibles.</summary>
    internal static IEnumerable<string> EnumerateFolder(string folder) =>
        Directory.EnumerateFiles(folder, "*", SafeDirectoryCleaner.WithoutLinks);

    /// <summary>Découpe <paramref name="files"/> en lots de <see cref="BatchSize"/>.</summary>
    internal static IEnumerable<List<string>> Batches(IEnumerable<string> files)
    {
        var batch = new List<string>(BatchSize);
        foreach (var file in files)
        {
            batch.Add(file);
            if (batch.Count == BatchSize)
            {
                yield return batch;
                batch = new List<string>(BatchSize);
            }
        }
        if (batch.Count > 0)
            yield return batch;
    }

    /// <summary>
    /// Copie chaque fichier lisible du lot. Les fichiers illisibles sont rendus dans
    /// <see cref="Batch.Skipped"/>, les trop gros dans <see cref="Batch.TooLarge"/>.
    /// </summary>
    internal static Batch Stage(IEnumerable<string> files, CancellationToken ct)
    {
        var batch = new Batch();
        try
        {
            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using var source = new FileStream(
                        file,
                        FileMode.Open,
                        FileAccess.Read,
                        FileShare.ReadWrite | FileShare.Delete,
                        bufferSize: 1,
                        FileOptions.SequentialScan);
                    if (source.Length > MaxFileBytes)
                    {
                        batch.TooLarge.Add(file);
                        continue;
                    }
                    var staged = ScanStaging.Stage(source, Path.GetFileName(file), source.Length);
                    batch.Add(staged, file);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    AppLogger.Debug("SandboxStaging", "Copie d'analyse impossible : " + ex.Message);
                    batch.Skipped.Add(file);
                }
            }
            return batch;
        }
        catch
        {
            batch.Dispose();
            throw;
        }
    }

    internal sealed class Batch : IDisposable
    {
        private readonly List<ScanStaging.StagedFile> _staged = new();
        private readonly Dictionary<string, string> _originals = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>Fichiers illisibles : non analysés.</summary>
        public List<string> Skipped { get; } = new();

        /// <summary>Fichiers au-delà de <see cref="MaxFileBytes"/> : non analysés par cet analyseur.</summary>
        public List<string> TooLarge { get; } = new();

        public IReadOnlyList<string> StagedPaths => _staged.Select(s => s.Path).ToList();

        internal void Add(ScanStaging.StagedFile staged, string original)
        {
            _staged.Add(staged);
            _originals[Path.GetFullPath(staged.Path)] = original;
        }

        /// <summary>Chemin d'origine d'une copie ; le chemin tel quel s'il n'en est pas une.</summary>
        public string OriginalOf(string path)
        {
            try
            {
                return _originals.TryGetValue(Path.GetFullPath(path), out var original) ? original : path;
            }
            catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
            {
                return path;
            }
        }

        public void Dispose()
        {
            foreach (var staged in _staged)
                staged.Dispose();
            _staged.Clear();
        }
    }
}
