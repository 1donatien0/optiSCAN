using optiSCAN.Models;
using System.IO;
using System.Runtime.Versioning;
using System.Text.Json.Serialization;

namespace optiSCAN.Services
{
    /// <summary>
    /// Sauvegarde les préférences utilisateur dans un fichier sécurisé
    /// (chiffrement DPAPI CurrentUser + HMAC-SHA256 d'intégrité).
    ///
    /// Persiste entre les sessions : cibles récentes, type de scan favori, etc.
    /// L'ancien format JSON en clair est migré automatiquement au premier
    /// chargement (renommé en .legacy puis ignoré ensuite).
    /// </summary>
    [SupportedOSPlatform("windows")]
    public sealed class UserPreferences
    {
        // ── Singleton thread-safe ────────────────────────────────────────────────
        // Lazy<T> ExecutionAndPublication = une seule instance même sous accès
        // concurrent (UI + protection temps réel + scan planifié).
        private static readonly Lazy<UserPreferences> _instance =
            new(Load, LazyThreadSafetyMode.ExecutionAndPublication);
        public static UserPreferences Current => _instance.Value;

        // Sérialise les écritures concurrentes pour éviter la corruption JSON.
        private static readonly object _saveLock = new();

        // ── Chemins ───────────────────────────────────────────────────────────────
        // Nouveau format : chiffré DPAPI + HMAC dans preferences.dat
        // Legacy   : JSON en clair preferences.json (migré au 1er chargement)
        private static readonly string FilePath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "optiSCAN", "preferences.dat");

        private static readonly string LegacyPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "optiSCAN", "preferences.json");

        // ── Propriétés persistées ─────────────────────────────────────────────────

        /// <summary>5 dernières cibles scannées (chemin + type).</summary>
        public List<RecentScanTarget> RecentTargets { get; set; } = new();

        /// <summary>Type de scan favori de l'utilisateur.</summary>
        // Auparavant `string` ("QuickScan", "FullScan"...) ce qui rendait toute
        // typo silencieusement valide. L'enum ScanType garantit la cohérence
        // avec le reste du domaine. JsonStringEnumConverter sérialise en
        // string lisible pour conserver la rétrocompatibilité du fichier JSON.
        [JsonConverter(typeof(JsonStringEnumConverter))]
        public ScanType FavoriteScanType { get; set; } = ScanType.QuickScan;

        /// <summary>Dernier chemin scanné (dossier ou fichier).</summary>
        public string? LastScanPath { get; set; }

        /// <summary>Nombre total de scans effectués (statistique affichée).</summary>
        public int TotalScansCount { get; set; } = 0;

        /// <summary>Date du dernier scan complet.</summary>
        public DateTime? LastFullScanDate { get; set; }

        /// <summary>Thème sombre activé (true) ou clair (false).</summary>
        /// <remarks>Par défaut clair, aligné sur Donaby.Light.xaml au premier lancement.</remarks>
        public bool DarkTheme { get; set; } = false;

        /// <summary>Suivre le thème Windows automatiquement.</summary>
        public bool SyncWindowsTheme { get; set; } = false;

        /// <summary>Afficher les notifications d'action (toast avec boutons).</summary>
        public bool ActionNotificationsEnabled { get; set; } = true;

        /// <summary>MAJ automatique des signatures ClamAV et des règles YARA (timers freshclam / YARA-Forge).</summary>
        public bool SignatureAutoUpdateEnabled { get; set; } = true;

        // ── Méthodes ──────────────────────────────────────────────────────────────

        /// <summary>
        /// Ajoute une cible récente (max 5). Les doublons sont déplacés en tête.
        /// </summary>
        public void AddRecentTarget(string path, ScanType scanType)
        {
            // Supprimer si déjà présent
            RecentTargets.RemoveAll(t => t.Path.Equals(path, StringComparison.OrdinalIgnoreCase));

            // Insérer en tête
            RecentTargets.Insert(0, new RecentScanTarget
            {
                Path = path,
                ScanType = scanType,
                LastUsed = DateTime.Now
            });

            // Garder seulement 5
            if (RecentTargets.Count > 5)
                RecentTargets.RemoveRange(5, RecentTargets.Count - 5);

            LastScanPath = path;
            Save();
        }

        /// <summary>Incrémente le compteur de scans terminés et sauvegarde.</summary>
        /// <remarks>Ne modifie pas <see cref="FavoriteScanType"/> (préférence utilisateur distincte).</remarks>
        public void IncrementScanCount(ScanType scanType)
        {
            TotalScansCount++;
            if (scanType == ScanType.FullScan)
                LastFullScanDate = DateTime.Now;
            Save();
        }

        /// <summary>Sauvegarde les préférences (DPAPI + HMAC, atomique, thread-safe).</summary>
        public void Save()
        {
            lock (_saveLock)
            {
                try
                {
                    var dir = Path.GetDirectoryName(FilePath)!;
                    if (!Directory.Exists(dir))
                        Directory.CreateDirectory(dir);

                    SecureStore.Save(FilePath, this);
                }
                catch (Exception ex)
                {
                    AppLogger.Warn("UserPreferences", "Save", ex);
                }
            }
        }

        /// <summary>
        /// Charge les préférences depuis le fichier sécurisé. Migre depuis le
        /// fichier JSON en clair si présent (anciennes versions optiSCAN).
        /// </summary>
        private static UserPreferences Load()
        {
            // 1. Format nouveau (DPAPI + HMAC)
            var loaded = SecureStore.Load<UserPreferences>(FilePath);
            if (loaded != null) return loaded;

            // 2. Migration depuis l'ancien JSON en clair, si présent
            var migrated = SecureStore.MigrateFromPlaintext<UserPreferences>(LegacyPath, FilePath);
            if (migrated != null) return migrated;

            // 3. Premier lancement ou fichier inutilisable → valeurs par défaut
            return new UserPreferences();
        }
    }

    /// <summary>Représente une cible de scan récente.</summary>
    public sealed class RecentScanTarget
    {
        public string Path { get; set; } = string.Empty;

        [JsonConverter(typeof(JsonStringEnumConverter))]
        public ScanType ScanType { get; set; } = Models.ScanType.QuickScan;

        public DateTime LastUsed { get; set; }

        /// <summary>Affichage court pour les menus.</summary>
        public string DisplayName => System.IO.Path.GetFileName(Path) is { Length: > 0 } n ? n : Path;

        /// <summary>Ligne pour la liste des cibles récentes (panneau Antivirus).</summary>
        [JsonIgnore]
        public string ListLabel => ScanType switch
        {
            ScanType.QuickScan => "Analyse rapide",
            ScanType.FullScan => "Analyse complète",
            ScanType.Folder => $"Dossier : {DisplayName}",
            ScanType.File => $"Fichier : {DisplayName}",
            _ => DisplayName
        };
    }
}
