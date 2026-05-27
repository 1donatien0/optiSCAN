using optiSCAN.Models;
using System.IO;

namespace optiSCAN.Services
{
    /// <summary>
    /// Fusionne les résultats d'une série de scans par dossier (quick/full multi-répertoires).
    /// Évite la duplication entre <see cref="ClamAvEngine"/> et <see cref="ScanOrchestrator"/>.
    /// </summary>
    internal static class MultiTargetScanAggregator
    {
        /// <param name="skipIfDirectoryMissing">Si true, ignore les cibles dont le dossier n'existe pas.</param>
        /// <param name="reportTargetProgress">Si true, émet une progression « Cible i/n ».</param>
        public static async Task<ScanResult> AggregateAsync(
            ScanType type,
            IReadOnlyList<string> targets,
            Func<string, IProgress<ScanProgress>?, CancellationToken, Task<ScanResult>> scanOneAsync,
            CancellationToken ct,
            IProgress<ScanProgress>? progress = null,
            bool skipIfDirectoryMissing = false,
            bool reportTargetProgress = false)
        {
            var merged = new ScanResult
            {
                Type = type,
                TargetPath = string.Join(", ", targets),
                StartedAt = DateTime.Now,
                Status = ScanStatus.Running
            };

            int denom = targets.Count;
            int idx = 0;
            int filesBaseline = 0;

            foreach (var target in targets)
            {
                if (ct.IsCancellationRequested) break;
                if (skipIfDirectoryMissing && !Directory.Exists(target))
                    continue;

                idx++;
                if (reportTargetProgress && progress != null && denom > 0)
                {
                    progress.Report(new ScanProgress
                    {
                        Message = $"Zone {idx}/{denom} : {target}",
                        Phase = ScanPhase.Scanning,
                        CurrentFilePath = target,
                        FilesScanned = filesBaseline,
                    });
                }

                var targetProgress = CreateBaselineProgress(progress, filesBaseline);
                var sub = await scanOneAsync(target, targetProgress, ct).ConfigureAwait(false);

                filesBaseline += Math.Max(0, sub.FilesScanned);
                merged.FilesScanned = filesBaseline;
                merged.FilesSkipped += sub.FilesSkipped;
                merged.TotalBytesScanned += sub.TotalBytesScanned;
                foreach (var t in sub.Threats)
                {
                    if (!merged.Threats.Any(existing => ThreatsMatch(existing, t)))
                        merged.Threats.Add(t);
                }

                if (progress != null)
                {
                    progress.Report(new ScanProgress
                    {
                        Message = $"Zone {idx}/{denom} terminée — {filesBaseline:N0} fichier(s) analysés au total",
                        Phase = ScanPhase.Scanning,
                        FilesScanned = filesBaseline,
                        ThreatsFound = merged.Threats.Count,
                        CurrentFilePath = target,
                    });
                }
            }

            merged.FinishedAt = DateTime.Now;
            merged.Status = ct.IsCancellationRequested ? ScanStatus.Cancelled : ScanStatus.Completed;
            return merged;
        }

        /// <summary>
        /// Ajoute le cumul des cibles déjà terminées pour éviter que l'UI repasse de 12 000 à 12
        /// au début d'un petit dossier (Startup, etc.) ou lors des messages YARA locaux.
        /// </summary>
        private static IProgress<ScanProgress>? CreateBaselineProgress(
            IProgress<ScanProgress>? parent,
            int filesBaseline)
        {
            if (parent == null || filesBaseline <= 0)
                return parent;

            return new Progress<ScanProgress>(p =>
            {
                var r = p.Clone();
                r.FilesScanned = AdjustFilesScannedForBaseline(p, filesBaseline);

                // Barre % : TotalFiles ne concerne que la cible courante ; si le cumul dépasse
                // ce total (autre moteur / autre dossier), on masque le pourcentage trompeur.
                if (r.TotalFiles > 0 && r.FilesScanned > r.TotalFiles)
                    r.TotalFiles = 0;

                parent.Report(r);
            });
        }

        private static int AdjustFilesScannedForBaseline(ScanProgress p, int baseline)
        {
            if (p.FilesScanned > 0)
                return baseline + p.FilesScanned;

            // Messages YARA sans compteur ou phase démarrage : conserver le cumul affiché.
            return baseline;
        }

        private static bool ThreatsMatch(ThreatInfo a, ThreatInfo b) =>
            string.Equals(a.FilePath, b.FilePath, StringComparison.OrdinalIgnoreCase)
            && string.Equals(a.VirusName, b.VirusName, StringComparison.OrdinalIgnoreCase);
    }
}
