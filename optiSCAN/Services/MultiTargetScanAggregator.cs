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
            Func<string, Task<ScanResult>> scanOneAsync,
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
                        Message = $"Cible {idx}/{denom} : {target}",
                        Phase = ScanPhase.Scanning,
                        CurrentFilePath = target,
                    });
                }

                var sub = await scanOneAsync(target).ConfigureAwait(false);
                merged.FilesScanned += sub.FilesScanned;
                merged.FilesSkipped += sub.FilesSkipped;
                merged.TotalBytesScanned += sub.TotalBytesScanned;
                merged.Threats.AddRange(sub.Threats);
            }

            merged.FinishedAt = DateTime.Now;
            merged.Status = ct.IsCancellationRequested ? ScanStatus.Cancelled : ScanStatus.Completed;
            return merged;
        }
    }
}
