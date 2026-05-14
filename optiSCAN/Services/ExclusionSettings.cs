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
            if (loaded != null) return loaded;

            // 2. Migration depuis l'ancien JSON en clair
            var migrated = SecureStore.MigrateFromPlaintext<ExclusionSettings>(LegacyPath, SettingsPath);
            if (migrated != null) return migrated;

            // 3. Premier lancement
            return new ExclusionSettings();
        }

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
            foreach (var f in ExcludedFilePaths)
                if (string.Equals(f.Replace('/', '\\'), norm, StringComparison.OrdinalIgnoreCase))
                    return true;

            return IsFolderExcluded(filePath);
        }

        public bool IsFolderExcluded(string path)
        {
            if (string.IsNullOrEmpty(path)) return false;

            foreach (var folder in ExcludedFolders)
            {
                if (string.IsNullOrWhiteSpace(folder)) continue;

                var normPath = path.Replace('/', '\\').TrimEnd('\\');
                var normFolder = folder.Replace('/', '\\').TrimEnd('\\');

                if (normPath.StartsWith(normFolder, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            return false;
        }

        public bool IsRuleExcluded(string ruleName)
        {
            if (string.IsNullOrEmpty(ruleName)) return false;

            foreach (var rule in ExcludedRuleNames)
                if (string.Equals(rule, ruleName, StringComparison.OrdinalIgnoreCase))
                    return true;

            return false;
        }

        // ── Modification ──────────────────────────────────────────────────────────
        public bool AddFolder(string path)
        {
            if (string.IsNullOrWhiteSpace(path)) return false;
            var norm = path.TrimEnd('\\', '/');
            if (ExcludedFolders.Exists(f => string.Equals(f.TrimEnd('\\', '/'), norm, StringComparison.OrdinalIgnoreCase)))
                return false;

            ExcludedFolders.Add(norm);
            Save();
            return true;
        }

        public bool RemoveFolder(string path)
        {
            var removed = ExcludedFolders.RemoveAll(f => string.Equals(f.TrimEnd('\\', '/'), path.TrimEnd('\\', '/'), StringComparison.OrdinalIgnoreCase)) > 0;
            if (removed) Save();
            return removed;
        }

        public bool AddRule(string ruleName)
        {
            if (string.IsNullOrWhiteSpace(ruleName)) return false;
            if (ExcludedRuleNames.Exists(r => string.Equals(r, ruleName, StringComparison.OrdinalIgnoreCase)))
                return false;

            ExcludedRuleNames.Add(ruleName.Trim());
            Save();
            return true;
        }

        public bool RemoveRule(string ruleName)
        {
            var removed = ExcludedRuleNames.RemoveAll(r => string.Equals(r, ruleName, StringComparison.OrdinalIgnoreCase)) > 0;
            if (removed) Save();
            return removed;
        }

        public bool AddFile(string filePath)
        {
            if (string.IsNullOrWhiteSpace(filePath)) return false;
            var norm = filePath.Replace('/', '\\').TrimEnd('\\');
            if (ExcludedFilePaths.Exists(f => string.Equals(f.Replace('/', '\\').TrimEnd('\\'), norm, StringComparison.OrdinalIgnoreCase)))
                return false;

            ExcludedFilePaths.Add(norm);
            Save();
            return true;
        }

        public bool RemoveFile(string filePath)
        {
            var removed = ExcludedFilePaths.RemoveAll(f => string.Equals(f.Replace('/', '\\').TrimEnd('\\'), filePath.Replace('/', '\\').TrimEnd('\\'), StringComparison.OrdinalIgnoreCase)) > 0;
            if (removed) Save();
            return removed;
        }
    }
}