using optiSCAN.Models;
using System.IO;
using System.Text;
using System.Text.Json;

namespace optiSCAN.Services
{
    /// <summary>
    /// Gère l'historique des scans et des nettoyages système (JSON) et le journal texte.
    /// </summary>
    public class ScanLogManager
    {
        private readonly string _logDir;
        private readonly string _historyPath;
        private readonly string _cleanHistoryPath;
        private readonly string _textLogPath;

        private List<ScanSession> _history;
        private List<CleanSession> _cleanHistory;

        public ScanLogManager(string? logDir = null)
        {
            _logDir = logDir
                ?? Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "optiSCAN", "Logs");

            _historyPath = Path.Combine(_logDir, "scan_history.json");
            _cleanHistoryPath = Path.Combine(_logDir, "clean_history.json");
            _textLogPath = Path.Combine(_logDir, "optiSCAN.log");

            EnsureDirectory(_logDir);
            _history = LoadHistory();
            _cleanHistory = LoadCleanHistory();
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

            WriteToLog(FormatScanDetail(result));
        }

        /// <summary>
        /// Retourne l'historique complet (plus récent en premier).
        /// </summary>
        public IReadOnlyList<ScanSession> GetHistory() => _history.AsReadOnly();

        // ── Historique des nettoyages système (vue Historique → Nettoyages) ───────

        /// <summary>Enregistre un nettoyage terminé (plus récent en tête, max 100).</summary>
        public void SaveCleanSession(CleanSession session)
        {
            _cleanHistory.Insert(0, session);
            if (_cleanHistory.Count > 100)
                _cleanHistory.RemoveRange(100, _cleanHistory.Count - 100);
            PersistCleanHistory();
            WriteToLog($"Nettoyage système — {session.BytesDisplay} libéré(s) — {session.TargetsSummary}");
        }

        public IReadOnlyList<CleanSession> GetCleanHistory() => _cleanHistory.AsReadOnly();

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
        /// Écrit une ligne horodatée dans le journal texte (append-only, non atomique).
        /// En cas de crash brutal, seule la dernière écriture peut être tronquée ;
        /// les lignes précédentes restent intactes.
        /// </summary>
        public void WriteToLog(string message)
        {
            try
            {
                EnsureDirectory(_logDir);
                var line = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {message}";
                File.AppendAllText(_textLogPath, line + Environment.NewLine, Encoding.UTF8);
            }
            catch (Exception ex)
            {
                AppLogger.Warn("ScanLogManager", "WriteToLog", ex);
            }
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

        /// <summary>Texte détaillé d'une session (menaces, statut, erreurs) — affiché dans Historique et journal fichier.</summary>
        public static string FormatScanDetail(ScanResult result) =>
            FormatScanDetailCore(
                result.TypeDisplay,
                result.TargetPath,
                result.StartedAt,
                result.FinishedAt,
                result.FilesScanned,
                result.FilesSkipped,
                result.ThreatsFound,
                result.Status.ToString(),
                result.ErrorMessage,
                result.Threats);

        /// <summary>Texte détaillé à partir d'une entrée d'historique persistée.</summary>
        public static string FormatScanDetail(ScanSession session) =>
            FormatScanDetailCore(
                session.TypeDisplay,
                session.TargetPath,
                session.StartedAt,
                session.FinishedAt,
                session.FilesScanned,
                session.FilesSkipped,
                session.ThreatsFound,
                session.StatusDisplay,
                session.ErrorMessage,
                session.Threats);

        private static string FormatScanDetailCore(
            string typeDisplay,
            string targetPath,
            DateTime startedAt,
            DateTime? finishedAt,
            int filesScanned,
            int filesSkipped,
            int threatsFound,
            string status,
            string? errorMessage,
            IReadOnlyList<ThreatInfo> threats)
        {
            var sb = new StringBuilder();
            sb.AppendLine($"--- Scan {typeDisplay} ---");
            sb.AppendLine($"  Cible      : {targetPath}");
            sb.AppendLine($"  Démarré    : {startedAt:dd/MM/yyyy HH:mm:ss}");
            sb.AppendLine($"  Terminé    : {finishedAt?.ToString("dd/MM/yyyy HH:mm:ss") ?? "N/A"}");
            sb.AppendLine($"  Fichiers   : {filesScanned}");
            if (filesSkipped > 0)
                sb.AppendLine($"  Ignorés    : {filesSkipped}");
            sb.AppendLine($"  Menaces    : {threatsFound}");
            sb.AppendLine($"  Statut     : {status}");
            if (!string.IsNullOrWhiteSpace(errorMessage))
                sb.AppendLine($"  Erreur     : {errorMessage}");

            if (threats.Count > 0)
            {
                sb.AppendLine("  Détails menaces :");
                foreach (var t in threats)
                    sb.AppendLine($"    • {t.FilePath} → {t.VirusName} ({t.DetectedBy})");
            }

            return sb.ToString().TrimEnd();
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

        private List<CleanSession> LoadCleanHistory()
        {
            return AtomicFile.ReadWithBackup(
                _cleanHistoryPath,
                json => JsonSerializer.Deserialize<List<CleanSession>>(json) ?? new List<CleanSession>(),
                fallbackValue: new List<CleanSession>());
        }

        private void PersistCleanHistory()
        {
            try
            {
                var json = JsonSerializer.Serialize(_cleanHistory,
                    new JsonSerializerOptions { WriteIndented = true });
                AtomicFile.WriteAllText(_cleanHistoryPath, json);
            }
            catch (Exception ex)
            {
                AppLogger.Warn("ScanLogManager", "PersistCleanHistory", ex);
            }
        }

        private static void EnsureDirectory(string dir)
        {
            if (!Directory.Exists(dir))
                Directory.CreateDirectory(dir);
        }
    }
}
