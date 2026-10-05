using System.IO;
using System.Security.Principal;

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

        public static IReadOnlyList<string> GetWatchFolders(IExclusionSettingsAccessor? exclusions = null)
        {
            var folders = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var path in SystemFolders)
                TryAdd(folders, path);

            foreach (var path in ScanTargets.QuickScanTargets())
                TryAdd(folders, path);

            if (IsSystemProcess())
                AddInteractiveUserFolders(folders);

            var excl = (exclusions ?? new DefaultExclusionSettingsAccessor()).Current;
            return folders
                .Where(p => !excl.IsFolderExcluded(p))
                .OrderBy(p => p, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }

        private static bool IsSystemProcess()
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

        /// <summary>
        /// Sous SYSTEM, SpecialFolder pointe vers systemprofile. On surveille
        /// les dossiers des comptes interactifs, sans suivre les jonctions.
        /// </summary>
        private static void AddInteractiveUserFolders(HashSet<string> folders)
        {
            var root = Path.GetPathRoot(Environment.SystemDirectory);
            if (string.IsNullOrWhiteSpace(root))
                return;

            var users = Path.Combine(root, "Users");
            if (!Directory.Exists(users))
                return;

            foreach (var userDir in Directory.EnumerateDirectories(users))
            {
                try
                {
                    if ((File.GetAttributes(userDir) & FileAttributes.ReparsePoint) != 0)
                        continue;
                }
                catch
                {
                    continue;
                }

                var name = Path.GetFileName(userDir);
                if (name.Equals("Public", StringComparison.OrdinalIgnoreCase)
                    || name.Equals("Default", StringComparison.OrdinalIgnoreCase)
                    || name.Equals("Default User", StringComparison.OrdinalIgnoreCase)
                    || name.Equals("All Users", StringComparison.OrdinalIgnoreCase))
                    continue;

                TryAdd(folders, Path.Combine(userDir, "Downloads"));
                TryAdd(folders, Path.Combine(userDir, "Desktop"));
                TryAdd(folders, Path.Combine(userDir, "AppData", "Local", "Temp"));
                TryAdd(folders, Path.Combine(userDir, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup"));
            }
        }

        private static void TryAdd(HashSet<string> folders, string? path)
        {
            if (string.IsNullOrWhiteSpace(path))
                return;
            try
            {
                if (Directory.Exists(path) && RealTimePathGuard.IsDirectPath(path))
                    folders.Add(Path.GetFullPath(path));
            }
            catch
            {
                /* chemin invalide */
            }
        }
    }
}
