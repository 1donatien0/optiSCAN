using optiSCAN.Models;
using System.IO;
using System.Text;
using System.Text.Json;

namespace optiSCAN.Services
{
    /// <summary>
    /// Gère l'historique des scans (persistance JSON) et les journaux texte.
    /// Fournit les méthodes pour sauvegarder, charger et effacer l'historique.
    /// </summary>
    public class ScanLogManager
    {
        private readonly string _logDir;
        private readonly string _historyPath;
        private readonly string _textLogPath;

        private List<ScanSession> _history;

        public ScanLogManager(string? logDir = null)
        {
            _logDir = logDir
                ?? Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "optiSCAN", "Logs");

            _historyPath = Path.Combine(_logDir, "scan_history.json");
            _textLogPath = Path.Combine(_logDir, "optiSCAN.log");

            EnsureDirectory(_logDir);
            _history = LoadHistory();
        }

        // ── Historique des scans ────────────────────────────────────────────────

        /// <summary>
        /// Sauvegarde un ScanResult terminé dans l'historique.
        /// </summary>
        public void SaveScanResult(ScanResult result)
        {
            var session = ScanSession.FromResult(result);
            _history.Insert(0, session); // plus récent en premier

            // Limiter à 100 entrées
            if (_history.Count > 100)
                _history.RemoveRange(100, _history.Count - 100);

            PersistHistory();

            // Journal texte enrichi
            AppendToTextLog(result);
        }

        /// <summary>
        /// Retourne l'historique complet (plus récent en premier).
        /// </summary>
        public IReadOnlyList<ScanSession> GetHistory() => _history.AsReadOnly();

        /// <summary>
        /// Efface tout l'historique.
        /// </summary>
        public void ClearHistory()
        {
            _history.Clear();
            PersistHistory();
            WriteToLog("Historique effacé par l'utilisateur.");
        }

        // ── Journal texte ───────────────────────────────────────────────────────

        /// <summary>
        /// Écrit une ligne horodatée dans le journal texte.
        /// </summary>
        public void WriteToLog(string message)
        {
            try
            {
                var line = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {message}";
                File.AppendAllText(_textLogPath, line + Environment.NewLine, Encoding.UTF8);
            }
            catch { /* Jamais lever d'exception dans les logs */ }
        }

        /// <summary>
        /// Retourne les N dernières lignes du journal texte.
        /// </summary>
        public string[] ReadLastLogLines(int count = 200)
        {
            if (!File.Exists(_textLogPath)) return Array.Empty<string>();
            try
            {
                var lines = File.ReadAllLines(_textLogPath, Encoding.UTF8);
                int start = Math.Max(0, lines.Length - count);
                var result = new string[lines.Length - start];
                Array.Copy(lines, start, result, 0, result.Length);
                return result;
            }
            catch { return Array.Empty<string>(); }
        }

        /// <summary>Chemin du fichier journal texte.</summary>
        public string TextLogPath => _textLogPath;

        /// <summary>Chemin du dossier de logs.</summary>
        public string LogDirectory => _logDir;

        // ── Helpers ─────────────────────────────────────────────────────────────

        private void AppendToTextLog(ScanResult result)
        {
            var sb = new StringBuilder();
            sb.AppendLine($"--- Scan {result.TypeDisplay} ---");
            sb.AppendLine($"  Cible      : {result.TargetPath}");
            sb.AppendLine($"  Démarré    : {result.StartedAt:dd/MM/yyyy HH:mm:ss}");
            sb.AppendLine($"  Terminé    : {result.FinishedAt?.ToString("dd/MM/yyyy HH:mm:ss") ?? "N/A"}");
            sb.AppendLine($"  Fichiers   : {result.FilesScanned}");
            sb.AppendLine($"  Menaces    : {result.ThreatsFound}");
            sb.AppendLine($"  Statut     : {result.Status}");

            if (result.Threats.Count > 0)
            {
                sb.AppendLine("  Détails menaces :");
                foreach (var t in result.Threats)
                    sb.AppendLine($"    • {t.FilePath} → {t.VirusName}");
            }

            sb.AppendLine();
            WriteToLog(sb.ToString());
        }

        private List<ScanSession> LoadHistory()
        {
            return AtomicFile.ReadWithBackup(
                _historyPath,
                json => JsonSerializer.Deserialize<List<ScanSession>>(json) ?? new List<ScanSession>(),
                fallbackValue: new List<ScanSession>());
        }

        private void PersistHistory()
        {
            try
            {
                var json = JsonSerializer.Serialize(_history,
                    new JsonSerializerOptions { WriteIndented = true });
                AtomicFile.WriteAllText(_historyPath, json);
            }
            catch (Exception ex)
            {
                AppLogger.Warn("ScanLogManager", "PersistHistory", ex);
            }
        }

        private static void EnsureDirectory(string dir)
        {
            if (!Directory.Exists(dir))
                Directory.CreateDirectory(dir);
        }
    }
}
