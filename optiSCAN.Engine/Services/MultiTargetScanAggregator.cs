using optiSCAN.Localization;
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
            var failedTargets = new List<string>();
            var scannedTargets = 0;

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
                        Message = LocalizationService.Format("Scan_Zone_Starting", idx, denom, target),
                        Phase = ScanPhase.Scanning,
                        CurrentFilePath = target,
                        FilesScanned = filesBaseline,
                    });
                }

                var relay = new ScanProgressRelay(filesBaseline);
                ScanResult sub;
                try
                {
                    sub = await scanOneAsync(target, relay.ToParent(progress), ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    // Une cible en échec ne doit pas interrompre les autres : elle est signalée
                    // et le scan global sera marqué incomplet.
                    AppLogger.Warn("MultiTargetScan", $"Cible en échec : {PathRedaction.RedactPath(target)}", ex);
                    sub = new ScanResult { Status = ScanStatus.Error, ErrorMessage = ex.Message, TargetPath = target };
                }
                scannedTargets++;
                if (sub.Status == ScanStatus.Error)
                    failedTargets.Add(target + (string.IsNullOrEmpty(sub.ErrorMessage) ? string.Empty : " (" + sub.ErrorMessage + ")"));
                else if (!string.IsNullOrEmpty(sub.ErrorMessage))
                    failedTargets.Add(target + " (" + sub.ErrorMessage + ")");

                // Sans progression (scan planifié, service), le relais ne voit rien passer : les
                // fichiers de chaque zone s'additionnent, au lieu de garder le plus grand total.
                filesBaseline = Math.Max(relay.FilesScannedHigh, filesBaseline + sub.FilesScanned);
                merged.FilesScanned = filesBaseline;
                merged.FilesSkipped += sub.FilesSkipped;
                merged.TotalBytesScanned += sub.TotalBytesScanned;
                merged.HasCoverageGaps |= sub.HasCoverageGaps;
                foreach (var t in sub.Threats)
                    ScanThreatMerger.AddOrMergeThreat(merged.Threats, t);

                if (progress != null)
                {
                    progress.Report(new ScanProgress
                    {
                        Message = LocalizationService.Format("Scan_Zone_Done", idx, denom, filesBaseline),
                        Phase = ScanPhase.Scanning,
                        FilesScanned = filesBaseline,
                        ThreatsFound = merged.Threats.Count,
                        CurrentFilePath = target,
                    });
                }
            }

            merged.FinishedAt = DateTime.Now;
            // Une zone illisible rend la couverture globale incomplète, même si les autres
            // zones ont été analysées. Si aucune zone n'a pu être analysée, le motif le précise.
            var allFailed = (scannedTargets > 0
                && failedTargets.Count == scannedTargets
                && merged.FilesScanned == 0
                && merged.Threats.Count == 0)
                || (scannedTargets == 0 && targets.Count > 0);
            merged.Status = ct.IsCancellationRequested
                ? ScanStatus.Cancelled
                : failedTargets.Count > 0 || allFailed ? ScanStatus.Error : ScanStatus.Completed;
            if (failedTargets.Count > 0)
                merged.ErrorMessage = (allFailed ? "Aucune zone analysée : " : "Scan partiel : ") + string.Join("; ", failedTargets);
            else if (allFailed)
                merged.ErrorMessage = "Aucune zone n'a pu être analysée.";
            return merged;
        }

    }
}
