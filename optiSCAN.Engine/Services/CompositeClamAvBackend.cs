// SPDX-License-Identifier: GPL-3.0-or-later
namespace optiSCAN.Services
{
    /// <summary>
    /// Préfère clamd (daemon) si activé et disponible, sinon repli sur clamscan.exe.
    /// </summary>
    internal sealed class CompositeClamAvBackend : IClamAvOrchestratorBackend
    {
        private readonly Func<CancellationToken, Task<bool>> _tryClamdReady;
        private readonly IClamAvOrchestratorBackend _clamd;
        private readonly IClamAvOrchestratorBackend _clamscan;

        public CompositeClamAvBackend(ClamdEngine clamd, ClamAvEngine clamscan)
            : this(ct => clamd.TryEnsureReadyAsync(ct), clamd, clamscan)
        {
        }

        /// <summary>Constructeur de test (backends injectables).</summary>
        internal CompositeClamAvBackend(
            Func<CancellationToken, Task<bool>> tryClamdReady,
            IClamAvOrchestratorBackend clamdBackend,
            IClamAvOrchestratorBackend clamscanBackend)
        {
            _tryClamdReady = tryClamdReady;
            _clamd = clamdBackend;
            _clamscan = clamscanBackend;
        }

        /// <summary><c>clamd</c> ou <c>clamscan</c> — dernier moteur Clam utilisé.</summary>
        public string ActiveEngine => ClamdEngine.LastMode;

        public bool IsClamAvInstalled() => _clamscan.IsClamAvInstalled();

        public async Task<Models.ScanResult> ScanFileAsync(
            string filePath,
            IProgress<Models.ScanProgress>? progress = null,
            CancellationToken ct = default)
        {
            if (await _tryClamdReady(ct).ConfigureAwait(false))
            {
                try
                {
                    var result = await _clamd.ScanFileAsync(filePath, progress, ct).ConfigureAwait(false);
                    if (result.Status != Models.ScanStatus.Error)
                        return result;
                    AppLogger.Warn("CompositeClamAv", "clamd fichier en erreur — repli clamscan");
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    AppLogger.Warn("CompositeClamAv", "clamd fichier — repli clamscan", ex);
                }
            }

            ClamdEngine.LastMode = "clamscan";
            return await _clamscan.ScanFileAsync(filePath, progress, ct).ConfigureAwait(false);
        }

        public async Task<Models.ScanResult> ScanFolderAsync(
            string folderPath,
            IProgress<Models.ScanProgress>? progress = null,
            CancellationToken ct = default)
        {
            if (await _tryClamdReady(ct).ConfigureAwait(false))
            {
                try
                {
                    var result = await _clamd.ScanFolderAsync(folderPath, progress, ct).ConfigureAwait(false);
                    if (result.Status != Models.ScanStatus.Error || result.HasCoverageGaps)
                        return await CompleteWithClamscanAsync(result, folderPath, ct).ConfigureAwait(false);
                    AppLogger.Warn("CompositeClamAv", "clamd dossier en erreur — repli clamscan");
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    AppLogger.Warn("CompositeClamAv", "clamd dossier — repli clamscan", ex);
                }
            }

            ClamdEngine.LastMode = "clamscan";
            return await _clamscan.ScanFolderAsync(folderPath, progress, ct).ConfigureAwait(false);
        }

        /// <summary>
        /// Les fichiers que clamd n'a pas lus repassent par clamscan : un dossier n'est
        /// « terminé » que si chaque fichier a été vu par un moteur ClamAV.
        /// </summary>
        internal async Task<Models.ScanResult> CompleteWithClamscanAsync(
            Models.ScanResult result,
            string targetPath,
            CancellationToken ct)
        {
            if (result.UnscannedFiles.Count == 0 || result.Status == Models.ScanStatus.Cancelled)
                return result;

            var pending = result.UnscannedFiles.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            result.UnscannedFiles.Clear();
            AppLogger.Info("CompositeClamAv", $"{pending.Count} fichier(s) repris par clamscan");

            var rest = await _clamscan.ScanFileListAsync(pending, targetPath, null, ct).ConfigureAwait(false);
            foreach (var threat in rest.Threats)
                result.Threats.Add(threat);
            result.FilesScanned += rest.FilesScanned;
            result.FilesSkipped += rest.FilesSkipped;
            result.HasCoverageGaps |= rest.HasCoverageGaps;
            result.FinishedAt = DateTime.Now;
            if (rest.Status == Models.ScanStatus.Cancelled)
                result.Status = Models.ScanStatus.Cancelled;
            else if (rest.Status == Models.ScanStatus.Error)
            {
                result.Status = Models.ScanStatus.Error;
                var fallbackError = rest.ErrorMessage ?? "Repli clamscan en erreur";
                result.ErrorMessage = string.IsNullOrWhiteSpace(result.ErrorMessage)
                    ? fallbackError
                    : result.ErrorMessage + "; " + fallbackError;
            }

            return result;
        }

        public Task<Models.ScanResult> ScanFileListAsync(
            IReadOnlyList<string> files,
            string targetPath,
            IProgress<Models.ScanProgress>? progress = null,
            CancellationToken ct = default)
        {
            // clamscan --file-list = un seul processus ; plus rapide que N appels clamd.
            ClamdEngine.LastMode = "clamscan";
            return _clamscan.ScanFileListAsync(files, targetPath, progress, ct);
        }
    }
}
