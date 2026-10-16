// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Security.Principal;

namespace optiSCAN.Services
{
    /// <summary>
    /// Dossiers surveillés par la protection temps réel — alignés sur le scan rapide Defender-like.
    /// </summary>
    internal static class RealTimeWatchPaths
    {
        /// <summary>
        /// Résolus par l'API et non codés en dur : Windows n'est pas toujours sur C: (audit A9).
        /// </summary>
        private static IEnumerable<string> SystemFolders()
        {
            var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            if (!string.IsNullOrWhiteSpace(programData))
                yield return programData;

            var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            if (!string.IsNullOrWhiteSpace(windows))
                yield return Path.Combine(windows, "Downloaded Program Files");
        }

        public static IReadOnlyList<string> GetWatchFolders(IExclusionSettingsAccessor? exclusions = null)
        {
            var folders = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var path in SystemFolders())
                TryAdd(folders, path);

            foreach (var path in ScanTargets.QuickScanTargets())
                TryAdd(folders, path);

            if (IsSystemProcess())
                AddInteractiveUserFolders(folders);

            var excl = (exclusions ?? new DefaultExclusionSettingsAccessor()).Current;
            // Un dossier contenu dans un autre n'est pas surveillé deux fois (événements doublés).
            return ScanTargets.RemoveNested(folders.Where(p => !excl.IsFolderExcluded(p)))
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
            catch (Exception ignored) when (!ignored.IsFatal())
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
                catch (Exception ignored) when (!ignored.IsFatal())
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
                // Roaming entier (contient le dossier Démarrage), comme le scan rapide.
                TryAdd(folders, Path.Combine(userDir, "AppData", "Roaming"));
            }

            TryAdd(folders, Path.Combine(users, "Public"));
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
            catch (Exception ignored) when (!ignored.IsFatal())
            {
                /* chemin invalide */
            }
        }
    }
}
