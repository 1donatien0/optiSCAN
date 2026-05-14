using System.Diagnostics;
using System.IO;

namespace optiSCAN.Services
{
    /// <summary>
    /// Gère la création et la suppression d'une tâche planifiée Windows
    /// pour un scan quotidien automatique, via schtasks.exe (outil natif Windows).
    /// Aucune dépendance NuGet requise.
    /// </summary>
    public class ScheduledScanService
    {
        private const string TaskName = "optiSCAN_DailyScan";
        private readonly string _exePath;

        public ScheduledScanService()
        {
            _exePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "optiSCAN.exe");
        }

        /// <summary>
        /// Crée la tâche planifiée pour un scan quotidien.
        /// Par défaut à 02h00 du matin.
        /// </summary>
        public bool CreateDailyScan(TimeSpan? time = null)
        {
            try
            {
                var t = time ?? TimeSpan.FromHours(2);
                var startTime = $"{t.Hours:D2}:{t.Minutes:D2}";

                // Supprimer la tâche existante si présente
                DeleteTask();

                // /RL HIGHEST = droits administrateur
                // /F = forcer (écraser si elle existe déjà)
                var args = $"/Create /TN \"{TaskName}\" " +
                           $"/TR \"\\\"{_exePath}\\\" --fullscan --quiet\" " +
                           $"/SC DAILY /ST {startTime} /RL HIGHEST /F";

                return RunSchtasks(args) == 0;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[ScheduledScanService] Erreur création tâche : {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Supprime la tâche planifiée.
        /// </summary>
        public bool DeleteTask()
        {
            try
            {
                RunSchtasks($"/Delete /TN \"{TaskName}\" /F");
                return true;
            }
            catch { return false; }
        }

        /// <summary>
        /// Vérifie si la tâche existe.
        /// </summary>
        public bool IsTaskExists()
        {
            try
            {
                return RunSchtasks($"/Query /TN \"{TaskName}\"") == 0;
            }
            catch { return false; }
        }

        /// <summary>
        /// Retourne l'heure approximative de la prochaine exécution (2h00 AM).
        /// </summary>
        public DateTime? GetNextRunTime()
        {
            var next = DateTime.Today.AddHours(2);
            if (next <= DateTime.Now)
                next = next.AddDays(1);
            return next;
        }

        /// <summary>
        /// Exécute la tâche immédiatement.
        /// </summary>
        public bool RunNow()
        {
            try
            {
                return RunSchtasks($"/Run /TN \"{TaskName}\"") == 0;
            }
            catch { return false; }
        }

        // ── Helpers ──────────────────────────────────────────────────────────────

        private static int RunSchtasks(string arguments)
        {
            var psi = new ProcessStartInfo("schtasks.exe", arguments)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };

            using var p = Process.Start(psi)
                ?? throw new InvalidOperationException("Impossible de démarrer schtasks.exe");

            p.WaitForExit(10_000);
            return p.ExitCode;
        }
    }
}
