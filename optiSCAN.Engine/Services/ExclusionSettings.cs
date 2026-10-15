using System.IO;
using System.Runtime.Versioning;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace optiSCAN.Services
{
    /// <summary>
    /// Paramètres d'exclusion persistants (dossiers + règles de détection ignorés).
    /// Stockés chiffrés DPAPI + intégrité HMAC dans %LOCALAPPDATA%\optiSCAN\exclusions.dat.
    ///
    /// Exclusion implicite : installation réservée aux administrateurs (sinon ses seuls
    /// moteurs, bases et règles), et les sous-dossiers de <c>%LOCALAPPDATA%\optiSCAN</c> qui
    /// contiennent bases, règles et quarantaine — voir <see cref="OptiscanProtectedPaths"/>.
    ///
    /// Pourquoi protégé : un attaquant local pourrait sinon ajouter des dossiers
    /// à ExcludedFolders (en éditant le JSON en clair) pour cacher du malware
    /// aux scans suivants. Avec DPAPI+HMAC, toute modification est détectée.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public class ExclusionSettings
    {
        // ── Singleton thread-safe ────────────────────────────────────────────────
        // Lazy<T> avec ExecutionAndPublication garantit qu'une seule instance est
        // chargée même si Current est appelé concurremment depuis l'UI, le scan
        // temps réel et un scan planifié.
        private static Lazy<ExclusionSettings> _current = new(Load, LazyThreadSafetyMode.ExecutionAndPublication);
        public static ExclusionSettings Current => _current.Value;
        public static void Reload() =>
            _current = new Lazy<ExclusionSettings>(Load, LazyThreadSafetyMode.ExecutionAndPublication);

        // Sérialise les accès concurrents à Save() pour éviter qu'un Save de l'UI
        // n'écrase un Save de la protection temps réel (et vice-versa).
        private static readonly object _saveLock = new();

        // Les listes sont remplacées, jamais modifiées sur place, une fois publiées :
        // la protection temps réel et les scans les parcourent sans verrou pendant que
        // l'interface ajoute ou retire une exclusion (copie à l'écriture).
        private readonly object _mutationLock = new();

        // ── Chemins de persistance ────────────────────────────────────────────────
        // Nouveau : exclusions.dat (DPAPI + HMAC). Legacy : exclusions.json (clair),
        // migré au premier chargement.
        private static readonly string SettingsPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "optiSCAN", "exclusions.dat");

        private static readonly string LegacyPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "optiSCAN", "exclusions.json");

        // ── Données ───────────────────────────────────────────────────────────────
        public bool RealTimeEnabled { get; set; } = true;
        public bool AutoQuarantineEnabled { get; set; } = false;
        public List<string> ExcludedFolders { get; set; } = new();
        public List<string> ExcludedFilePaths { get; set; } = new();
        public List<string> ExcludedRuleNames { get; set; } = new() { "SuspiciousDownloads" };

        // ── Chargement / Sauvegarde ───────────────────────────────────────────────
        private static readonly JsonSerializerOptions _jsonOptions = new()
        {
            WriteIndented = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        public static ExclusionSettings Load()
        {
            // 1. Format chiffré DPAPI + HMAC
            var loaded = SecureStore.Load<ExclusionSettings>(SettingsPath);
            if (loaded != null)
            {
                loaded.EnsureProtectedFoldersListed();
                return loaded;
            }

            // 2. Migration depuis l'ancien JSON en clair
            var migrated = SecureStore.MigrateFromPlaintext<ExclusionSettings>(LegacyPath, SettingsPath);
            if (migrated != null)
            {
                migrated.EnsureProtectedFoldersListed();
                return migrated;
            }

            // 3. Premier lancement
            var fresh = new ExclusionSettings();
            fresh.EnsureProtectedFoldersListed();
            return fresh;
        }

        /// <summary>
        /// Ajoute les dossiers protégés (installation, bases, règles, quarantaine) aux exclusions
        /// persistées, visibles dans Options et non supprimables, et retire les anciennes
        /// exclusions trop larges.
        /// </summary>
        internal void EnsureProtectedFoldersListed()
        {
            var changed = false;
            lock (_mutationLock)
            {
                var folders = new List<string>(ExcludedFolders);

                // Les versions antérieures inscrivaient %LOCALAPPDATA%\optiSCAN entier, et le
                // dossier d'installation même modifiable par un utilisateur. Ces entrées, qui ne
                // sont plus des racines protégées, sont retirées de la liste.
                var stale = OptiscanProtectedPaths.ResolveInstallRoots()
                    .Append(OptiscanProtectedPaths.GetLocalAppDataRoot())
                    .Select(r => r.TrimEnd('\\', '/'))
                    .Where(r => !OptiscanProtectedPaths.IsMandatoryExcludedFolder(r))
                    .ToList();
                if (folders.RemoveAll(f => stale.Exists(r =>
                        string.Equals(f.TrimEnd('\\', '/'), r, StringComparison.OrdinalIgnoreCase))) > 0)
                    changed = true;

                foreach (var root in OptiscanProtectedPaths.GetProtectedRoots())
                {
                    var norm = root.TrimEnd('\\', '/');
                    if (folders.Exists(f =>
                            string.Equals(f.TrimEnd('\\', '/'), norm, StringComparison.OrdinalIgnoreCase)))
                        continue;

                    folders.Add(norm);
                    changed = true;
                }
                if (changed)
                    ExcludedFolders = folders;
            }

            if (changed)
                Save();
        }

        /// <summary>Dossier d'exclusion imposé par optiSCAN (non retirable dans Options).</summary>
        public static bool IsMandatoryExcludedFolder(string? folderPath)
            => OptiscanProtectedPaths.IsMandatoryExcludedFolder(folderPath);

        public void Save()
        {
            lock (_saveLock)
            {
                try
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(SettingsPath)!);
                    SecureStore.Save(SettingsPath, this);
                }
                catch (Exception ex)
                {
                    AppLogger.Warn("ExclusionSettings", "Save", ex);
                }
            }
        }

        // ── Helpers de vérification ───────────────────────────────────────────────
        public bool IsFileExcluded(string filePath)
        {
            if (string.IsNullOrEmpty(filePath)) return false;

            var norm = filePath.Replace('/', '\\');
            var files = ExcludedFilePaths;
            foreach (var f in files)
                if (string.Equals(f.Replace('/', '\\'), norm, StringComparison.OrdinalIgnoreCase))
                    return true;

            return IsFolderExcluded(filePath);
        }

        public bool IsFolderExcluded(string path)
        {
            if (string.IsNullOrEmpty(path)) return false;

            if (OptiscanProtectedPaths.IsUnderProtectedPath(path))
                return true;

            var folders = ExcludedFolders;
            foreach (var folder in folders)
            {
                if (string.IsNullOrWhiteSpace(folder)) continue;
                // Une exclusion de lecteur entier ou de dossier système (ajoutée avant ce
                // contrôle, ou par édition du fichier) est ignorée.
                if (IsForbiddenFolderExclusion(folder)) continue;
                // Dossier de données d'optiSCAN modifiable par la session : listé dans les Options,
                // mais seuls ses fichiers de données sont exclus (règle ci-dessus), pas le dossier.
                if (OptiscanProtectedPaths.IsDataOnlyRoot(folder)) continue;

                var normPath = path.Replace('/', '\\').TrimEnd('\\');
                var normFolder = folder.Replace('/', '\\').TrimEnd('\\');

                if (IsUnderExcludedFolder(normPath, normFolder))
                    return true;
            }
            return false;
        }

        private static bool IsUnderExcludedFolder(string normPath, string normFolder)
        {
            if (normPath.Length < normFolder.Length)
                return false;

            if (normPath.Equals(normFolder, StringComparison.OrdinalIgnoreCase))
                return true;

            return normPath.StartsWith(normFolder + '\\', StringComparison.OrdinalIgnoreCase);
        }

        public bool IsRuleExcluded(string ruleName)
        {
            if (string.IsNullOrEmpty(ruleName)) return false;

            var rules = ExcludedRuleNames;
            foreach (var rule in rules)
                if (string.Equals(rule, ruleName, StringComparison.OrdinalIgnoreCase))
                    return true;

            return false;
        }

        // ── Modification ──────────────────────────────────────────────────────────
        public bool AddFolder(string path)
        {
            if (string.IsNullOrWhiteSpace(path)) return false;
            var norm = path.TrimEnd('\\', '/');
            if (IsForbiddenFolderExclusion(norm))
            {
                AppLogger.Warn("ExclusionSettings", $"Exclusion refusée (lecteur ou dossier système) : {norm}");
                return false;
            }

            lock (_mutationLock)
            {
                if (ExcludedFolders.Exists(f => string.Equals(f.TrimEnd('\\', '/'), norm, StringComparison.OrdinalIgnoreCase)))
                    return false;
                ExcludedFolders = new List<string>(ExcludedFolders) { norm };
            }
            Save();
            return true;
        }

        /// <summary>
        /// Résultats déjà calculés : <see cref="IsFolderExcluded"/> le demande pour chaque exclusion
        /// et chaque fichier parcouru, et le calcul lit six dossiers connus de Windows.
        /// </summary>
        private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, bool> ForbiddenCache =
            new(StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// Exclusions refusées : racine d'un lecteur, dossier Windows (et tout son contenu),
        /// racines Program Files / ProgramData / Users, profil du compte courant, ou un parent
        /// de l'un d'eux. Exclure ces dossiers retirerait l'essentiel du système des analyses.
        /// </summary>
        public static bool IsForbiddenFolderExclusion(string? folder)
        {
            if (string.IsNullOrWhiteSpace(folder))
                return true;
            if (ForbiddenCache.TryGetValue(folder, out var cached))
                return cached;
            var computed = ComputeForbiddenFolderExclusion(folder);
            if (ForbiddenCache.Count < 1024)
                ForbiddenCache[folder] = computed;
            return computed;
        }

        private static bool ComputeForbiddenFolderExclusion(string folder)
        {
            string full;
            try { full = Path.GetFullPath(folder.Replace('/', '\\')).TrimEnd('\\'); }
            catch { return true; }

            var root = Path.GetPathRoot(full)?.TrimEnd('\\');
            if (string.IsNullOrEmpty(root) || string.Equals(full, root, StringComparison.OrdinalIgnoreCase))
                return true;

            static string Norm(string p) => p.TrimEnd('\\');
            bool IsSameOrParentOf(string sensitive) =>
                string.Equals(full, sensitive, StringComparison.OrdinalIgnoreCase)
                || sensitive.StartsWith(full + "\\", StringComparison.OrdinalIgnoreCase);

            // Dossier de données optiSCAN entier : inscriptible par la session, il ne doit pas
            // devenir une cachette. Seuls ses sous-dossiers protégés sont exclus.
            if (string.Equals(full, Norm(OptiscanProtectedPaths.GetLocalAppDataRoot()), StringComparison.OrdinalIgnoreCase))
                return true;

            var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            if (!string.IsNullOrEmpty(windows))
            {
                var w = Norm(windows);
                if (IsSameOrParentOf(w) || full.StartsWith(w + "\\", StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var users = string.IsNullOrEmpty(profile) ? null : Path.GetDirectoryName(Norm(profile));
            foreach (var sensitive in new[]
                     {
                         Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                         Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                         Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                         profile,
                         users,
                     })
            {
                if (!string.IsNullOrEmpty(sensitive) && IsSameOrParentOf(Norm(sensitive)))
                    return true;
            }

            return false;
        }

        public bool RemoveFolder(string path)
        {
            if (IsMandatoryExcludedFolder(path))
                return false;

            bool removed;
            lock (_mutationLock)
            {
                var copy = new List<string>(ExcludedFolders);
                removed = copy.RemoveAll(f => string.Equals(f.TrimEnd('\\', '/'), path.TrimEnd('\\', '/'), StringComparison.OrdinalIgnoreCase)) > 0;
                if (removed) ExcludedFolders = copy;
            }
            if (removed) Save();
            return removed;
        }

        public bool AddRule(string ruleName)
        {
            if (string.IsNullOrWhiteSpace(ruleName)) return false;
            lock (_mutationLock)
            {
                if (ExcludedRuleNames.Exists(r => string.Equals(r, ruleName, StringComparison.OrdinalIgnoreCase)))
                    return false;
                ExcludedRuleNames = new List<string>(ExcludedRuleNames) { ruleName.Trim() };
            }
            Save();
            return true;
        }

        public bool RemoveRule(string ruleName)
        {
            bool removed;
            lock (_mutationLock)
            {
                var copy = new List<string>(ExcludedRuleNames);
                removed = copy.RemoveAll(r => string.Equals(r, ruleName, StringComparison.OrdinalIgnoreCase)) > 0;
                if (removed) ExcludedRuleNames = copy;
            }
            if (removed) Save();
            return removed;
        }

        public bool AddFile(string filePath)
        {
            if (string.IsNullOrWhiteSpace(filePath)) return false;
            var norm = filePath.Replace('/', '\\').TrimEnd('\\');
            lock (_mutationLock)
            {
                if (ExcludedFilePaths.Exists(f => string.Equals(f.Replace('/', '\\').TrimEnd('\\'), norm, StringComparison.OrdinalIgnoreCase)))
                    return false;
                ExcludedFilePaths = new List<string>(ExcludedFilePaths) { norm };
            }
            Save();
            return true;
        }

        public bool RemoveFile(string filePath)
        {
            bool removed;
            lock (_mutationLock)
            {
                var copy = new List<string>(ExcludedFilePaths);
                removed = copy.RemoveAll(f => string.Equals(f.Replace('/', '\\').TrimEnd('\\'), filePath.Replace('/', '\\').TrimEnd('\\'), StringComparison.OrdinalIgnoreCase)) > 0;
                if (removed) ExcludedFilePaths = copy;
            }
            if (removed) Save();
            return removed;
        }
    }
}