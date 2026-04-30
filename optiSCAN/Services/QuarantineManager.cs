using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using optiSCAN.Models;

namespace optiSCAN.Services
{
    /// <summary>
    /// Gère la mise en quarantaine, la restauration et la suppression des fichiers infectés.
    /// Les fichiers en quarantaine sont chiffrés (XOR simple) pour empêcher leur exécution accidentelle.
    /// Un manifeste JSON conserve la trace des fichiers déplacés.
    /// </summary>
    public class QuarantineManager
    {
        private readonly string _quarantineDir;
        private readonly string _manifestPath;
        private List<QuarantineEntry> _manifest;

        // Clé XOR simple — suffit pour rendre le fichier non-exécutable accidentellement
        private const byte XorKey = 0x5A;

        public QuarantineManager(string? quarantineDir = null)
        {
            _quarantineDir = quarantineDir
                ?? Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "optiSCAN", "Quarantine");

            _manifestPath = Path.Combine(_quarantineDir, "manifest.json");

            EnsureDirectoryExists(_quarantineDir);
            _manifest = LoadManifest();
        }

        // ── Quarantaine ─────────────────────────────────────────────────────────

        /// <summary>
        /// Déplace le fichier infecté en quarantaine et met à jour la ThreatInfo.
        /// </summary>
        public bool Quarantine(ThreatInfo threat)
        {
            if (!File.Exists(threat.FilePath))
                return false;

            try
            {
                var id          = Guid.NewGuid().ToString("N");
                var qPath       = Path.Combine(_quarantineDir, id + ".quar");

                // Lecture + chiffrement XOR + écriture dans le dossier quarantaine
                var bytes = File.ReadAllBytes(threat.FilePath);
                for (int i = 0; i < bytes.Length; i++) bytes[i] ^= XorKey;
                File.WriteAllBytes(qPath, bytes);

                // Suppression de l'original
                File.Delete(threat.FilePath);

                // Mise à jour de la ThreatInfo
                threat.Status        = ThreatStatus.Quarantined;
                threat.QuarantinePath = qPath;

                // Ajout au manifeste
                _manifest.Add(new QuarantineEntry
                {
                    Id              = id,
                    OriginalPath    = threat.FilePath,
                    QuarantinePath  = qPath,
                    VirusName       = threat.VirusName,
                    QuarantinedAt   = DateTime.Now,
                    OriginalSize    = threat.FileSize
                });

                SaveManifest();
                return true;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[Quarantaine] Erreur : {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Met en quarantaine toutes les menaces d'un ScanResult.
        /// Retourne le nombre de fichiers traités avec succès.
        /// </summary>
        public int QuarantineAll(IEnumerable<ThreatInfo> threats)
        {
            int count = 0;
            foreach (var t in threats)
                if (Quarantine(t)) count++;
            return count;
        }

        // ── Restauration ───────────────────────────────────────────────────────

        /// <summary>
        /// Restaure un fichier de la quarantaine à son emplacement d'origine.
        /// ATTENTION : restaure un fichier potentiellement infecté.
        /// </summary>
        public bool Restore(string quarantineId)
        {
            var entry = _manifest.Find(e => e.Id == quarantineId);
            if (entry == null || !File.Exists(entry.QuarantinePath))
                return false;

            try
            {
                var dir = Path.GetDirectoryName(entry.OriginalPath);
                if (dir != null && !Directory.Exists(dir))
                    Directory.CreateDirectory(dir);

                var bytes = File.ReadAllBytes(entry.QuarantinePath);
                for (int i = 0; i < bytes.Length; i++) bytes[i] ^= XorKey; // déchiffrement
                File.WriteAllBytes(entry.OriginalPath, bytes);

                File.Delete(entry.QuarantinePath);
                _manifest.Remove(entry);
                SaveManifest();
                return true;
            }
            catch { return false; }
        }

        // ── Suppression définitive ──────────────────────────────────────────────

        /// <summary>
        /// Supprime définitivement un fichier en quarantaine.
        /// </summary>
        public bool DeletePermanently(string quarantineId)
        {
            var entry = _manifest.Find(e => e.Id == quarantineId);
            if (entry == null) return false;

            try
            {
                if (File.Exists(entry.QuarantinePath))
                    File.Delete(entry.QuarantinePath);

                _manifest.Remove(entry);
                SaveManifest();
                return true;
            }
            catch { return false; }
        }

        /// <summary>
        /// Vide complètement la quarantaine (suppression définitive de tout).
        /// </summary>
        public int PurgeAll()
        {
            int count = 0;
            foreach (var entry in _manifest.ToArray())
            {
                if (DeletePermanently(entry.Id)) count++;
            }
            return count;
        }

        // ── Lecture ─────────────────────────────────────────────────────────────

        /// <summary>
        /// Retourne la liste des entrées de quarantaine.
        /// </summary>
        public IReadOnlyList<QuarantineEntry> GetEntries() =>
            _manifest.AsReadOnly();

        public int Count => _manifest.Count;

        public long TotalSize => _manifest.Sum(e => e.OriginalSize > 0 ? e.OriginalSize : 0);

        // ── Manifeste JSON ──────────────────────────────────────────────────────

        private List<QuarantineEntry> LoadManifest()
        {
            if (!File.Exists(_manifestPath)) return new List<QuarantineEntry>();
            try
            {
                var json = File.ReadAllText(_manifestPath);
                return JsonSerializer.Deserialize<List<QuarantineEntry>>(json)
                    ?? new List<QuarantineEntry>();
            }
            catch { return new List<QuarantineEntry>(); }
        }

        private void SaveManifest()
        {
            var json = JsonSerializer.Serialize(_manifest,
                new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(_manifestPath, json);
        }

        private static void EnsureDirectoryExists(string dir)
        {
            if (!Directory.Exists(dir))
                Directory.CreateDirectory(dir);
        }
    }

    // ── Entrée de quarantaine ────────────────────────────────────────────────────

    public class QuarantineEntry
    {
        public string Id { get; set; } = string.Empty;
        public string OriginalPath { get; set; } = string.Empty;
        public string QuarantinePath { get; set; } = string.Empty;
        public string VirusName { get; set; } = string.Empty;
        public DateTime QuarantinedAt { get; set; }
        public long OriginalSize { get; set; }

        public string FileName => Path.GetFileName(OriginalPath);
        public string SizeDisplay => OriginalSize >= 0
            ? OriginalSize < 1024 ? $"{OriginalSize} o"
            : OriginalSize < 1048576 ? $"{OriginalSize / 1024.0:F1} Ko"
            : $"{OriginalSize / 1048576.0:F1} Mo"
            : "Inconnu";
    }
}
