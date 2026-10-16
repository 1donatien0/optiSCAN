// SPDX-License-Identifier: GPL-3.0-or-later
using Microsoft.Win32;
using System.IO;
using System.Text.RegularExpressions;

namespace optiSCAN.Services
{
    /// <summary>
    /// Périmètres optiSCAN jamais analysés (scans, RTP, quarantaine auto) pour éviter
    /// l'auto-détection sur binaires, règles YARA, bases ClamAV et artefacts de MAJ.
    /// </summary>
    internal static class OptiscanProtectedPaths
    {
        private const string InnoUninstallGuid = @"F3A2C1D0-5B6E-4F7A-8C9D-0E1F2A3B4C5D";

        private static readonly Lazy<IReadOnlyList<string>> CachedRoots = new(
            ResolveDistinctRoots,
            LazyThreadSafetyMode.ExecutionAndPublication);

        /// <summary>Racines entièrement exclues (tout leur contenu).</summary>
        private static readonly Lazy<IReadOnlyList<string>> CachedWholeRoots = new(
            () => CachedRoots.Value.Where(r => !IsLocalDataRoot(r)).ToList(),
            LazyThreadSafetyMode.ExecutionAndPublication);

        /// <summary>Racines modifiables par la session : seuls leurs fichiers de données sont exclus.</summary>
        private static readonly Lazy<IReadOnlyList<string>> CachedDataRoots = new(
            () => CachedRoots.Value.Where(IsLocalDataRoot).ToList(),
            LazyThreadSafetyMode.ExecutionAndPublication);

        private static bool IsLocalDataRoot(string root)
        {
            var local = GetLocalAppDataRoot();
            return LocalAppDataProtectedSubfolders.Any(sub =>
                string.Equals(root, Path.GetFullPath(Path.Combine(local, sub)), StringComparison.OrdinalIgnoreCase));
        }

        /// <summary>%LOCALAPPDATA%\optiSCAN (seuls certains sous-dossiers sont protégés, voir <see cref="LocalAppDataProtectedSubfolders"/>).</summary>
        public static string GetLocalAppDataRoot()
        {
            return Path.GetFullPath(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "optiSCAN"));
        }

        /// <summary>Racines protégées (installation et sous-dossiers de données applicatives).</summary>
        public static IReadOnlyList<string> GetProtectedRoots() => CachedRoots.Value;

        /// <summary>
        /// Vrai si <paramref name="path"/> est exclu des analyses d'optiSCAN.
        /// <para>
        /// Une racine « entière » (installation réservée aux administrateurs, ou dossiers de
        /// moteurs d'une installation de développement) exclut tout ce qu'elle contient. Les
        /// sous-dossiers de <c>%LOCALAPPDATA%\optiSCAN</c>, eux, sont modifiables par n'importe quel
        /// programme de la session : n'y sont exclus que les fichiers de données d'optiSCAN
        /// (bases, règles, quarantaine chiffrée, configuration). Un exécutable déposé là est
        /// analysé : ces dossiers ne servent plus de cachette.
        /// </para>
        /// </summary>
        public static bool IsUnderProtectedPath(string? path)
        {
            if (string.IsNullOrWhiteSpace(path))
                return false;

            string fullPath;
            try
            {
                fullPath = Path.GetFullPath(path.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
            }
            catch (Exception ignored) when (!ignored.IsFatal())
            {
                return false;
            }

            foreach (var root in CachedWholeRoots.Value)
            {
                if (IsUnderRoot(fullPath, root))
                    return true;
            }

            foreach (var root in CachedDataRoots.Value)
            {
                if (IsUnderRoot(fullPath, root) && IsDataFileName(fullPath) && !IsDisguisedExecutable(fullPath))
                    return true;
            }

            return false;
        }

        /// <summary>Vrai si <paramref name="folder"/> est une racine où seuls les fichiers de données sont exclus.</summary>
        public static bool IsDataOnlyRoot(string? folder)
        {
            if (string.IsNullOrWhiteSpace(folder))
                return false;
            try
            {
                var norm = Path.GetFullPath(folder.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
                return CachedDataRoots.Value.Any(r => string.Equals(r, norm, StringComparison.OrdinalIgnoreCase));
            }
            catch (Exception ignored) when (!ignored.IsFatal())
            {
                return false;
            }
        }

        /// <summary>
        /// Fichiers que produit optiSCAN dans ses dossiers de données. Aucun format exécutable,
        /// script ou document n'y figure.
        /// </summary>
        internal static readonly HashSet<string> DataFileExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".cvd", ".cld", ".cud", ".cdiff", ".dat", ".ign", ".ign2", ".fp", ".sfp",
            ".hdb", ".hsb", ".ndb", ".ldb", ".mdb", ".msb", ".cbc", ".info",
            ".yar", ".yara", ".yarc", ".stamp", ".cache",
            ".conf", ".log", ".pid", ".port", ".pipe", ".lock", ".crt",
            ".quar", ".json", ".key", ".bak", ".optibak", ".optiscan-db-seeded",
        };

        /// <summary>
        /// Un exécutable PE renommé en fichier de données (« payload.dat », « x.cvd ») se lance
        /// quand même par CreateProcess ou rundll32 : il n'est pas exclu. L'en-tête n'est lu que
        /// pour les fichiers de ces dossiers, peu nombreux.
        /// </summary>
        private static bool IsDisguisedExecutable(string fullPath)
        {
            try
            {
                return File.Exists(fullPath) && ExecutableSniffer.IsPortableExecutable(fullPath);
            }
            catch (Exception ignored) when (!ignored.IsFatal())
            {
                return false;
            }
        }

        /// <summary>
        /// Extensions exclues par clamscan dans les dossiers de données (motifs <c>--exclude</c>,
        /// sans lecture d'en-tête possible) : seulement les gros fichiers binaires d'optiSCAN
        /// (signatures, règles compilées, quarantaine et copies chiffrées), pour la durée d'analyse
        /// et pour ne pas détecter les signatures elles-mêmes. Les petits fichiers de configuration
        /// et de journal y sont analysés ; un exécutable déguisé est aussi vu par YARA, clamd et le
        /// temps réel, qui lisent l'en-tête.
        /// </summary>
        internal static readonly string[] ClamScanDataExtensions =
        {
            "cvd", "cld", "cud", "cdiff", "yar", "yara", "yarc", "quar", "optibak",
        };

        internal static bool IsDataFileName(string path)
        {
            var name = Path.GetFileName(path);
            if (string.IsNullOrEmpty(name))
                return false;
            // relay-handles.txt (clamd), .optiscan-yara-meta.txt (règles) : textes d'optiSCAN.
            if (name.Equals("relay-handles.txt", StringComparison.OrdinalIgnoreCase)
                || name.Equals(".optiscan-yara-meta.txt", StringComparison.OrdinalIgnoreCase))
                return true;
            return DataFileExtensions.Contains(Path.GetExtension(name));
        }

        /// <summary>Vrai si le dossier fait partie des exclusions obligatoires (non supprimables dans Options).</summary>
        public static bool IsMandatoryExcludedFolder(string? folderPath)
        {
            if (string.IsNullOrWhiteSpace(folderPath))
                return false;

            string norm;
            try
            {
                norm = Path.GetFullPath(folderPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
            }
            catch (Exception ignored) when (!ignored.IsFatal())
            {
                return false;
            }

            foreach (var root in CachedRoots.Value)
            {
                if (string.Equals(norm, root, StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            return false;
        }

        public static IEnumerable<string> GetClamScanExcludePatterns()
        {
            foreach (var root in CachedWholeRoots.Value)
            {
                var trimmed = root.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                yield return "^" + Regex.Escape(trimmed) + @"([\\/]|$)";
            }

            // Racines de données : seuls les fichiers de données (par extension) sont exclus ;
            // les dossiers sont parcourus.
            var extensions = string.Join("|", ClamScanDataExtensions.Select(Regex.Escape));
            foreach (var root in CachedDataRoots.Value)
            {
                var trimmed = root.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                yield return "^" + Regex.Escape(trimmed) + @"[\\/].*\.(" + extensions + ")$";
            }
        }

        /// <summary>
        /// Sous-dossiers de %LOCALAPPDATA%\optiSCAN qui contiennent des signatures, des règles ou
        /// des copies chiffrées de menaces. Le reste de ce dossier, inscriptible par toute la
        /// session, est analysé : l'exclure entier en ferait une cachette pour un malware.
        /// </summary>
        internal static readonly string[] LocalAppDataProtectedSubfolders =
        {
            "clamav",
            "clamd",
            "rules",
            "Quarantine",
            "SafetyBackups",
        };

        /// <summary>
        /// Sous-dossiers d'une installation non réservée aux administrateurs qui restent exclus
        /// (moteurs, bases et règles, qui déclencheraient des auto-détections).
        /// </summary>
        internal static readonly string[] InstallDataSubfolders = { "clamav", "rules", "yara" };

        private static IReadOnlyList<string> ResolveDistinctRoots()
        {
            var roots = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var install in ResolveInstallRoots())
                AddInstallRoot(roots, install);

            var local = GetLocalAppDataRoot();
            foreach (var sub in LocalAppDataProtectedSubfolders)
                TryAddRoot(roots, Path.Combine(local, sub));

            return roots.OrderBy(r => r, StringComparer.OrdinalIgnoreCase).ToList();
        }

        /// <summary>Dossiers d'installation connus : celui du processus, Program Files, registre Inno.</summary>
        internal static IReadOnlyList<string> ResolveInstallRoots()
        {
            var installs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            TryAddRoot(installs, AppInstallPaths.GetInstallRootUncached());
            TryAddProgramFilesInstall(installs);
            TryAddFromInnoUninstallRegistry(installs);
            return installs.ToList();
        }

        /// <summary>
        /// Une installation réservée aux administrateurs est exclue entière. Ailleurs (build de
        /// développement, copie portable, dossier choisi hors Program Files), seuls ses moteurs,
        /// bases et règles le sont : un binaire déposé à côté reste analysé.
        /// </summary>
        private static void AddInstallRoot(HashSet<string> roots, string install)
        {
            if (optiSCAN.Platform.InstallLocationTrust.IsAdminOnlyInstall(install, out _))
            {
                roots.Add(install);
                return;
            }

            foreach (var sub in InstallDataSubfolders)
                TryAddRoot(roots, Path.Combine(install, sub));
        }

        private static void TryAddProgramFilesInstall(HashSet<string> roots)
        {
            foreach (var pf in new[]
                     {
                         Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                         Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                     })
            {
                if (string.IsNullOrWhiteSpace(pf))
                    continue;

                var candidate = Path.Combine(pf, "optiSCAN");
                if (File.Exists(Path.Combine(candidate, "optiSCAN.exe")))
                    TryAddRoot(roots, candidate);
            }
        }

        private static void TryAddFromInnoUninstallRegistry(HashSet<string> roots)
        {
            var subkeys = new[]
            {
                $@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{InnoUninstallGuid}_is1",
                $@"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{InnoUninstallGuid}_is1",
            };

            foreach (var subkey in subkeys)
            {
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(subkey);
                    // Même règle que pour l'installation courante : entière seulement si réservée
                    // aux administrateurs, sinon ses moteurs, bases et règles uniquement.
                    if (key?.GetValue("InstallLocation") is string location && !string.IsNullOrWhiteSpace(location))
                        AddInstallRoot(roots, location.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
                }
                catch (Exception ignored) when (!ignored.IsFatal())
                {
                    /* registre inaccessible */
                }
            }
        }

        private static void TryAddRoot(HashSet<string> roots, string? path)
        {
            if (string.IsNullOrWhiteSpace(path))
                return;

            try
            {
                roots.Add(Path.GetFullPath(path.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)));
            }
            catch (Exception ignored) when (!ignored.IsFatal())
            {
                /* chemin invalide */
            }
        }

        private static bool IsUnderRoot(string fullPath, string root)
        {
            if (fullPath.Equals(root, StringComparison.OrdinalIgnoreCase))
                return true;

            return fullPath.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)
                || fullPath.StartsWith(root + Path.AltDirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
        }
    }
}
