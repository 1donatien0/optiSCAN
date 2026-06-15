using System.IO;

namespace optiSCAN.Services
{
    /// <summary>
    /// Dossiers surveillés par la protection temps réel — alignés sur le scan rapide Defender-like.
    /// </summary>
    internal static class RealTimeWatchPaths
    {
        private static readonly string[] SystemFolders =
        {
            @"C:\ProgramData",
            @"C:\Windows\Downloaded Program Files",
        };

        public static IReadOnlyList<string> GetWatchFolders()
        {
            var folders = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var path in SystemFolders)
                TryAdd(folders, path);

            foreach (var path in ScanTargets.QuickScanTargets())
                TryAdd(folders, path);

            var exclusions = ExclusionSettings.Current;
            return folders
                .Where(p => !exclusions.IsFolderExcluded(p))
                .OrderBy(p => p, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }

        private static void TryAdd(HashSet<string> folders, string? path)
        {
            if (string.IsNullOrWhiteSpace(path))
                return;
            try
            {
                if (Directory.Exists(path))
                    folders.Add(Path.GetFullPath(path));
            }
            catch
            {
                /* chemin invalide */
            }
        }
    }
}
