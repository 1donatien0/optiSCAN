using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace optiSCAN.Services
{
    /// <summary>
    /// Paramètres d'exclusion persistants (dossiers + règles de détection ignorés).
    /// Chargé une seule fois via <see cref="Current"/> (singleton lazy).
    /// Persisté dans %LOCALAPPDATA%\optiSCAN\exclusions.json.
    /// </summary>
    public class ExclusionSettings
    {
        // ── Singleton ─────────────────────────────────────────────────────────────

        private static ExclusionSettings? _current;

        /// <summary>Instance partagée de l'application, chargée à la première utilisation.</summary>
        public static ExclusionSettings Current => _current ??= Load();

        /// <summary>Réinitialise le singleton (utile après sauvegarde pour forcer le rechargement).</summary>
        public static void Reload() => _current = Load();

        // ── Chemin de persistance ─────────────────────────────────────────────────

        private static readonly string SettingsPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "optiSCAN", "exclusions.json");

        // ── Données ───────────────────────────────────────────────────────────────

        /// <summary>Dossiers ignorés lors de l'analyse (et leurs sous-dossiers).</summary>
        public List<string> ExcludedFolders { get; set; } = new();

        /// <summary>
        /// Noms de règles de détection ignorés.
        /// "SuspiciousDownloads" est exclu par défaut — trop de faux positifs.
        /// </summary>
        public List<string> ExcludedRuleNames { get; set; } = new()
        {
            "SuspiciousDownloads"
        };

        // ── Chargement / Sauvegarde ───────────────────────────────────────────────

        private static readonly JsonSerializerOptions _jsonOptions = new()
        {
            WriteIndented       = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        /// <summary>Charge les paramètres depuis le fichier JSON, ou retourne les valeurs par défaut.</summary>
        public static ExclusionSettings Load()
        {
            try
            {
                if (File.Exists(SettingsPath))
                {
                    var json = File.ReadAllText(SettingsPath);
                    return JsonSerializer.Deserialize<ExclusionSettings>(json, _jsonOptions)
                           ?? new ExclusionSettings();
                }
            }
            catch { /* Fichier corrompu → valeurs par défaut */ }

            return new ExclusionSettings();
        }

        /// <summary>Sauvegarde les paramètres dans le fichier JSON.</summary>
        public void Save()
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(SettingsPath)!);
                File.WriteAllText(SettingsPath, JsonSerializer.Serialize(this, _jsonOptions));
            }
            catch { /* Non bloquant */ }
        }

        // ── Helpers de vérification ───────────────────────────────────────────────

        /// <summary>
        /// Retourne true si le chemin donné se trouve dans un dossier exclu
        /// (comparaison insensible à la casse, préfixe).
        /// </summary>
        public bool IsFolderExcluded(string path)
        {
            if (string.IsNullOrEmpty(path)) return false;

            foreach (var folder in ExcludedFolders)
            {
                if (string.IsNullOrWhiteSpace(folder)) continue;

                // Normaliser les séparateurs pour une comparaison fiable
                var normPath   = path.Replace('/', '\\').TrimEnd('\\');
                var normFolder = folder.Replace('/', '\\').TrimEnd('\\');

                if (normPath.StartsWith(normFolder, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            return false;
        }

        /// <summary>
        /// Retourne true si le nom de règle est dans la liste des exclusions.
        /// </summary>
        public bool IsRuleExcluded(string ruleName)
        {
            if (string.IsNullOrEmpty(ruleName)) return false;

            foreach (var rule in ExcludedRuleNames)
                if (string.Equals(rule, ruleName, StringComparison.OrdinalIgnoreCase))
                    return true;

            return false;
        }

        // ── Modification de la liste ──────────────────────────────────────────────

        /// <summary>Ajoute un dossier aux exclusions et sauvegarde.</summary>
        public bool AddFolder(string path)
        {
            if (string.IsNullOrWhiteSpace(path)) return false;
            var norm = path.TrimEnd('\\', '/');
            if (ExcludedFolders.Exists(f =>
                    string.Equals(f.TrimEnd('\\', '/'), norm, StringComparison.OrdinalIgnoreCase)))
                return false; // déjà présent

            ExcludedFolders.Add(norm);
            Save();
            return true;
        }

        /// <summary>Retire un dossier des exclusions et sauvegarde.</summary>
        public bool RemoveFolder(string path)
        {
            var removed = ExcludedFolders.RemoveAll(f =>
                string.Equals(f.TrimEnd('\\', '/'),
                              path.TrimEnd('\\', '/'),
                              StringComparison.OrdinalIgnoreCase)) > 0;
            if (removed) Save();
            return removed;
        }

        /// <summary>Ajoute un nom de règle aux exclusions et sauvegarde.</summary>
        public bool AddRule(string ruleName)
        {
            if (string.IsNullOrWhiteSpace(ruleName)) return false;
            if (ExcludedRuleNames.Exists(r =>
                    string.Equals(r, ruleName, StringComparison.OrdinalIgnoreCase)))
                return false;

            ExcludedRuleNames.Add(ruleName.Trim());
            Save();
            return true;
        }

        /// <summary>Retire un nom de règle des exclusions et sauvegarde.</summary>
        public bool RemoveRule(string ruleName)
        {
            var removed = ExcludedRuleNames.RemoveAll(r =>
                string.Equals(r, ruleName, StringComparison.OrdinalIgnoreCase)) > 0;
            if (removed) Save();
            return removed;
        }
    }
}
