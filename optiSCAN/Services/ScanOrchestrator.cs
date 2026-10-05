using optiSCAN.Localization;
using optiSCAN.Models;
using System.IO;
using System.Linq;

namespace optiSCAN.Services
{
    /// <summary>
    /// Coordonne les moteurs ClamAV et YARA pour produire un <see cref="ScanResult"/> unifié.
    /// Lance les deux moteurs en parallèle (<see cref="Task.WhenAll"/>) puis fusionne leurs
    /// résultats en déduplicant les menaces détectées par les deux.
    /// </summary>
    /// <remarks>
    /// YaraParallelism retiré : depuis le passage en single-process (un seul
    /// yara64.exe avec --recursive), YARA gère lui-même son parallélisme
    /// interne et l'orchestration n'a plus à le faire.
    /// </remarks>
    public class ScanOrchestrator
    {
        private static readonly TimeSpan FileScanDeadline = TimeSpan.FromMinutes(10);
        private static readonly TimeSpan FolderScanDeadline = TimeSpan.FromHours(2);
        private static readonly TimeSpan QuickScanDeadline = TimeSpan.FromHours(4);
        private static readonly TimeSpan FullScanDeadline = TimeSpan.FromHours(12);

        private readonly IClamAvOrchestratorBackend _clamAv;
        private readonly IYaraOrchestratorBackend _yara;
        private readonly IUserPreferencesAccessor _prefs;
        private readonly IExclusionSettingsAccessor _exclusions;

        // ── État ─────────────────────────────────────────────────────────────────

        /// <summary><c>true</c> si clamscan.exe est détecté et opérationnel.</summary>
        public bool IsClamAvAvailable => _clamAv.IsClamAvInstalled();

        /// <summary><c>true</c> si le moteur YARA est disponible et possède des règles compilées.</summary>
        public bool IsYaraAvailable => _yara.IsAvailable;

        /// <summary>Nombre de règles YARA actuellement chargées.</summary>
        public int YaraRulesCount => _yara.RulesCount;

        // ── Construction ─────────────────────────────────────────────────────────

        /// <summary>
        /// Crée un orchestrateur avec les moteurs fournis (ou de nouveaux si <c>null</c>).
        /// </summary>
        public ScanOrchestrator(ClamAvEngine? clamAv = null, YaraEngine? yara = null)
            : this((IClamAvOrchestratorBackend?)clamAv, (IYaraOrchestratorBackend?)yara)
        {
        }

        internal ScanOrchestrator(
            IClamAvOrchestratorBackend? clamAv = null,
            IYaraOrchestratorBackend? yara = null,
            IUserPreferencesAccessor? preferences = null,
            IExclusionSettingsAccessor? exclusions = null)
        {
            _clamAv = clamAv ?? new ClamAvEngine();
            _yara = yara ?? new YaraEngine();
            _prefs = preferences ?? new DefaultUserPreferencesAccessor();
            _exclusions = exclusions ?? new DefaultExclusionSettingsAccessor();
        }

        // ── API publique ─────────────────────────────────────────────────────────

        /// <summary>
        /// Analyse un fichier unique avec ClamAV et YARA en parallèle.
        /// Retourne immédiatement un résultat vide si le fichier est dans les exclusions.
        /// </summary>
        public Task<ScanResult> ScanFileAsync(string filePath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default)
        {
            if (_exclusions.Current.IsFileExcluded(filePath))
            {
                return Task.FromResult(new ScanResult
                {
                    Type = ScanType.File,
                    TargetPath = filePath,
                    StartedAt = DateTime.Now,
                    FinishedAt = DateTime.Now,
                    Status = ScanStatus.Completed,
                    FilesSkipped = 1
                });
            }
            return RunWithDeadlineAsync(
                ScanType.File, filePath, FileScanDeadline, ct,
                token => RunPipelineAsync(ScanType.File, filePath, false, progress, token));
        }

        /// <summary>Analyse récursivement un dossier avec ClamAV et YARA en parallèle.</summary>
        public Task<ScanResult> ScanFolderAsync(string folderPath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default)
            => RunWithDeadlineAsync(
                ScanType.Folder, folderPath, FolderScanDeadline, ct,
                token => RunPipelineAsync(ScanType.Folder, folderPath, true, progress, token, skipYaraFileCount: false));

        /// <summary>Analyse récursive sans pré-dénombrement YARA (scan USB complet en arrière-plan).</summary>
        internal Task<ScanResult> ScanFolderBackgroundAsync(string folderPath, ScanType type, CancellationToken ct = default)
            => RunWithDeadlineAsync(
                type, folderPath, GetScanDeadline(type), ct,
                token => RunPipelineAsync(type, folderPath, true, progress: null, token, skipYaraFileCount: true));

        /// <summary>Analyse une liste de fichiers (ClamAV --file-list + YARA par lots).</summary>
        public Task<ScanResult> ScanFileListAsync(
            IReadOnlyList<string> files,
            string targetPath,
            ScanType type = ScanType.Folder,
            IProgress<ScanProgress>? progress = null,
            CancellationToken ct = default,
            bool scanEnginesSequentially = false)
        {
            var filtered = files
                .Where(f => !_exclusions.Current.IsFileExcluded(f))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            if (filtered.Count == 0)
            {
                var now = DateTime.Now;
                return Task.FromResult(new ScanResult
                {
                    Type = type,
                    TargetPath = targetPath,
                    StartedAt = now,
                    FinishedAt = now,
                    Status = ScanStatus.Completed,
                    FilesScanned = 0,
                });
            }

            return RunWithDeadlineAsync(
                type, targetPath, GetScanDeadline(type), ct,
                token => RunFileListPipelineAsync(type, targetPath, filtered, progress, token, scanEnginesSequentially));
        }

        /// <summary>Analyse rapide sur les dossiers système prioritaires (voir <see cref="ScanTargets"/>).</summary>
        public Task<ScanResult> QuickScanAsync(IProgress<ScanProgress>? progress = null, CancellationToken ct = default)
        {
            var targets = ScanTargets.QuickScanTargets();
            return RunWithDeadlineAsync(
                ScanType.QuickScan, string.Join("; ", targets), QuickScanDeadline, ct,
                token => RunMultiTargetPipelineAsync(ScanType.QuickScan, targets, progress, token));
        }

        /// <summary>Analyse complète sur l'ensemble des cibles définies dans <see cref="ScanTargets"/>.</summary>
        public Task<ScanResult> FullScanAsync(IProgress<ScanProgress>? progress = null, CancellationToken ct = default)
        {
            var targets = ScanTargets.FullScanTargets(_prefs.Current.IncludeRemovableInFullScan);
            return RunWithDeadlineAsync(
                ScanType.FullScan, string.Join("; ", targets), FullScanDeadline, ct,
                token => RunMultiTargetPipelineAsync(ScanType.FullScan, targets, progress, token));
        }

        private static TimeSpan GetScanDeadline(ScanType type) => type switch
        {
            ScanType.File or ScanType.RealTime => FileScanDeadline,
            ScanType.QuickScan => QuickScanDeadline,
            ScanType.FullScan => FullScanDeadline,
            _ => FolderScanDeadline,
        };

        /// <summary>
        /// Borne la durée totale d'une opération, y compris ses moteurs et ses cibles successives.
        /// L'annulation liée est transmise aux moteurs afin qu'ils arrêtent leurs sous-processus.
        /// </summary>
        private static async Task<ScanResult> RunWithDeadlineAsync(
            ScanType type,
            string targetPath,
            TimeSpan timeout,
            CancellationToken callerToken,
            Func<CancellationToken, Task<ScanResult>> operation)
        {
            var startedAt = DateTime.Now;
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(callerToken);
            deadline.CancelAfter(timeout);

            try
            {
                var result = await operation(deadline.Token).ConfigureAwait(false);
                if (!callerToken.IsCancellationRequested && deadline.IsCancellationRequested)
                    return MarkTimedOut(result, timeout);
                return result;
            }
            catch (OperationCanceledException) when (deadline.IsCancellationRequested && !callerToken.IsCancellationRequested)
            {
                var now = DateTime.Now;
                return new ScanResult
                {
                    Type = type,
                    TargetPath = targetPath,
                    StartedAt = startedAt,
                    FinishedAt = now,
                    Status = ScanStatus.Error,
                    ErrorMessage = $"Délai maximal de scan dépassé ({FormatTimeout(timeout)}).",
                    HasCoverageGaps = true,
                };
            }
        }

        private static ScanResult MarkTimedOut(ScanResult result, TimeSpan timeout)
        {
            result.Status = ScanStatus.Error;
            result.ErrorMessage = $"Délai maximal de scan dépassé ({FormatTimeout(timeout)}).";
            result.FinishedAt = DateTime.Now;
            result.HasCoverageGaps = true;
            return result;
        }

        private static string FormatTimeout(TimeSpan timeout) => timeout.TotalHours >= 1
            ? $"{timeout.TotalHours:0.#} h"
            : $"{timeout.TotalMinutes:0.#} min";

        // ── Pipeline interne ─────────────────────────────────────────────────────

        /// <summary>
        /// Exécute ClamAV et YARA en parallèle sur une cible unique, puis fusionne les résultats.
        /// Les dossiers appartenant au répertoire d'installation sont automatiquement exclus.
        /// </summary>
        private async Task<ScanResult> RunPipelineAsync(
            ScanType type, string target, bool recursive, IProgress<ScanProgress>? progress, CancellationToken ct,
            bool skipYaraFileCount = false)
        {
            if (recursive && AppInstallPaths.IsUnderInstallRoot(target))
            {
                var now = DateTime.Now;
                return new ScanResult
                {
                    Type = type,
                    TargetPath = target,
                    StartedAt = now,
                    FinishedAt = now,
                    Status = ScanStatus.Completed,
                    FilesSkipped = 1,
                };
            }

            var engineProgress = new ScanProgressRelay().ToParent(progress);

            Task<ScanResult> clamTask = recursive
                ? _clamAv.ScanFolderAsync(target, engineProgress, ct)
                : _clamAv.ScanFileAsync(target, engineProgress, ct);

            Task<ScanResult> yaraTask = recursive
                ? RunYaraOnFolderAsync(target, engineProgress, ct, skipYaraFileCount)
                : RunYaraOnFileAsync(target, engineProgress, ct);

            await Task.WhenAll(clamTask, yaraTask);

            return ScanThreatMerger.Merge(type, target, await clamTask, await yaraTask, _exclusions);
        }

        private async Task<ScanResult> RunFileListPipelineAsync(
            ScanType type,
            string targetPath,
            IReadOnlyList<string> files,
            IProgress<ScanProgress>? progress,
            CancellationToken ct,
            bool scanEnginesSequentially)
        {
            var engineProgress = new ScanProgressRelay().ToParent(progress);

            if (scanEnginesSequentially)
            {
                var clamResult = await _clamAv.ScanFileListAsync(files, targetPath, engineProgress, ct)
                    .ConfigureAwait(false);
                ct.ThrowIfCancellationRequested();
                var yaraResult = await RunYaraOnFileListAsync(files, targetPath, engineProgress, ct)
                    .ConfigureAwait(false);
                return ScanThreatMerger.Merge(type, targetPath, clamResult, yaraResult, _exclusions);
            }

            var clamTask = _clamAv.ScanFileListAsync(files, targetPath, engineProgress, ct);
            var yaraTask = RunYaraOnFileListAsync(files, targetPath, engineProgress, ct);
            await Task.WhenAll(clamTask, yaraTask).ConfigureAwait(false);
            return ScanThreatMerger.Merge(type, targetPath, await clamTask, await yaraTask, _exclusions);
        }

        /// <summary>Délègue l'agrégation multi-cibles à <see cref="MultiTargetScanAggregator"/>.</summary>
        private Task<ScanResult> RunMultiTargetPipelineAsync(ScanType type, List<string> targets, IProgress<ScanProgress>? progress, CancellationToken ct) =>
            MultiTargetScanAggregator.AggregateAsync(
                type,
                targets,
                (t, targetProgress, token) => RunPipelineAsync(type, t, true, targetProgress, token),
                ct,
                progress,
                skipIfDirectoryMissing: true,
                reportTargetProgress: true);

        // ── YARA helpers ─────────────────────────────────────────────────────────

        /// <summary>Exécute YARA sur un fichier unique et convertit les matchs en <see cref="ThreatInfo"/>.</summary>
        private async Task<ScanResult> RunYaraOnFileAsync(string filePath, IProgress<ScanProgress>? progress, CancellationToken ct)
        {
            var result = new ScanResult
            {
                Type = ScanType.File,
                TargetPath = filePath,
                StartedAt = DateTime.Now
            };

            if (!_yara.IsAvailable)
            {
                result.Status = ScanStatus.Completed;
                result.FinishedAt = DateTime.Now;
                return result;
            }

            if (_exclusions.Current.IsFileExcluded(filePath))
            {
                result.Status = ScanStatus.Completed;
                result.FinishedAt = DateTime.Now;
                result.FilesSkipped = 1;
                return result;
            }

            try
            {
                var (allMatches, yaraIncomplete) = await CollectYaraAsync(() => _yara.ScanFileAsync(filePath, ct)).ConfigureAwait(false);
                AddYaraThreats(result, allMatches, progress, fixedPath: filePath);

                result.FilesScanned = 1;
                FinishYaraResult(result, yaraIncomplete, cancelled: false);
            }
            catch (OperationCanceledException)
            {
                result.Status = ScanStatus.Cancelled;
                result.FinishedAt = DateTime.Now;
            }
            catch (Exception ex)
            {
                // CORRECTION : catch vide silencieux → impossible de diagnostiquer
                // un crash YARA (binaire manquant, règles corrompues, etc.).
                AppLogger.Warn("ScanOrchestrator", $"RunYaraOnFileAsync ({filePath})", ex);
                result.Status = ScanStatus.Error;
                result.ErrorMessage = ex.Message;
                result.FinishedAt = DateTime.Now;
            }

            return result;
        }

        private async Task<ScanResult> RunYaraOnFileListAsync(
            IReadOnlyList<string> files,
            string targetPath,
            IProgress<ScanProgress>? progress,
            CancellationToken ct)
        {
            var result = new ScanResult
            {
                Type = ScanType.Folder,
                TargetPath = targetPath,
                StartedAt = DateTime.Now,
            };

            if (!_yara.IsAvailable)
            {
                result.Status = ScanStatus.Completed;
                result.FinishedAt = DateTime.Now;
                return result;
            }

            try
            {
                progress?.Report(new ScanProgress
                {
                    Message = LocalizationService.Format("Scan_Yara_StartingWithCount", Path.GetFileName(targetPath), files.Count),
                    Phase = ScanPhase.Starting,
                    TotalFiles = files.Count,
                    CurrentFilePath = targetPath,
                });

                int scanned = 0;
                var yaraProgress = new Progress<string>(_ =>
                {
                    var n = System.Threading.Interlocked.Increment(ref scanned);
                    progress?.Report(new ScanProgress
                    {
                        Phase = ScanPhase.Scanning,
                        TotalFiles = files.Count,
                        FilesScanned = Math.Min(n, files.Count),
                        YaraFilesScanned = Math.Min(n, files.Count),
                        CurrentFilePath = targetPath,
                    });
                });

                var (allMatches, yaraIncomplete) = await CollectYaraAsync(() => _yara.ScanFilesAsync(files, yaraProgress, ct)).ConfigureAwait(false);
                AddYaraThreats(result, allMatches, progress, fixedPath: null);

                result.FilesScanned = files.Count;
                FinishYaraResult(result, yaraIncomplete, ct.IsCancellationRequested);

                progress?.Report(new ScanProgress
                {
                    Message = $"{result.FilesScanned:N0} fichiers analysés.",
                    Phase = ScanPhase.Completed,
                    FilesScanned = result.FilesScanned,
                    YaraFilesScanned = result.FilesScanned,
                    TotalFiles = files.Count,
                    ThreatsFound = result.Threats.Count,
                });
            }
            catch (OperationCanceledException)
            {
                result.Status = ScanStatus.Cancelled;
                result.FinishedAt = DateTime.Now;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("ScanOrchestrator", $"RunYaraOnFileListAsync ({targetPath})", ex);
                result.Status = ScanStatus.Error;
                result.ErrorMessage = ex.Message;
                result.FinishedAt = DateTime.Now;
            }

            return result;
        }

        /// <summary>Exécute YARA en mode récursif (single-process) sur un dossier et convertit les matchs en <see cref="ThreatInfo"/>.</summary>
        private async Task<ScanResult> RunYaraOnFolderAsync(
            string folderPath, IProgress<ScanProgress>? progress, CancellationToken ct, bool skipFileCount = false)
        {
            var result = new ScanResult
            {
                Type = ScanType.Folder,
                TargetPath = folderPath,
                StartedAt = DateTime.Now
            };

            if (!_yara.IsAvailable)
            {
                result.Status = ScanStatus.Completed;
                result.FinishedAt = DateTime.Now;
                return result;
            }

            try
            {
                const int CountCap = 100_000;
                const int UnknownTotalFiles = 0;
                int total = skipFileCount ? UnknownTotalFiles : 0;
                if (!skipFileCount)
                {
                    try
                    {
                        foreach (var file in Directory.EnumerateFiles(folderPath, "*.*", SearchOption.AllDirectories))
                        {
                            if (ct.IsCancellationRequested) break;
                            if (_exclusions.Current.IsFileExcluded(file))
                                continue;
                            if (++total >= CountCap) { total = UnknownTotalFiles; break; }
                        }
                    }
                    catch (Exception ex)
                    {
                        AppLogger.Warn("ScanOrchestrator", $"Énumération {folderPath}", ex);
                    }
                }

                progress?.Report(new ScanProgress
                {
                    Message = total > 0
                        ? LocalizationService.Format("Scan_Yara_StartingWithCount", Path.GetFileName(folderPath), total)
                        : LocalizationService.Format("Scan_Yara_Starting", Path.GetFileName(folderPath)),
                    Phase = ScanPhase.Starting,
                    TotalFiles = total,
                    CurrentFilePath = folderPath,
                });

                // Single-process : un seul yara64.exe avec --recursive.
                // YARA émet un message tous les ~20 lignes stdout (matches), pas par fichier.
                // Si total > 0, on répartit les N messages reçus uniformément sur [0, total]
                // pour une barre de progression fidèle au nombre de fichiers.
                // Si total = 0 (inconnu / >100k), on laisse le compteur libre (ProgressBar indéterminée).
                int filesYara = 0;
                int msgCount = 0;
                var yaraProgress = new Progress<string>(msg =>
                {
                    var msgs = System.Threading.Interlocked.Increment(ref msgCount);
                    int n;
                    if (total > 0)
                    {
                        // YaraEngine émet ~1 message par YaraProgressInterval (~20) lignes traitées.
                        // On interpole : chaque message ≈ YaraProgressInterval fichiers parcourus.
                        n = Math.Min(msgs * YaraEngine.YaraProgressInterval, total);
                        System.Threading.Interlocked.Exchange(ref filesYara, n);
                    }
                    else
                    {
                        n = System.Threading.Interlocked.Increment(ref filesYara);
                    }
                    progress?.Report(new ScanProgress
                    {
                        Message = msg,
                        Phase = ScanPhase.Scanning,
                        TotalFiles = total,
                        FilesScanned = n,
                        YaraFilesScanned = n,
                        CurrentFilePath = folderPath,
                    });
                });

                var (allMatches, yaraIncomplete) = await CollectYaraAsync(() => _yara.ScanFolderAsync(folderPath, yaraProgress, ct)).ConfigureAwait(false);
                AddYaraThreats(result, allMatches, progress, fixedPath: null);

                result.FilesScanned = total > 0 ? total : Math.Max(filesYara, 1);
                FinishYaraResult(result, yaraIncomplete, ct.IsCancellationRequested);

                progress?.Report(new ScanProgress
                {
                    Message = $"{result.FilesScanned:N0} fichiers analysés.",
                    Phase = ScanPhase.Completed,
                    FilesScanned = result.FilesScanned,
                    YaraFilesScanned = result.FilesScanned,
                    TotalFiles = total,
                    ThreatsFound = result.Threats.Count,
                });
            }
            catch (OperationCanceledException)
            {
                result.Status = ScanStatus.Cancelled;
                result.FinishedAt = DateTime.Now;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("ScanOrchestrator", $"RunYaraOnFolderAsync ({folderPath})", ex);
                result.Status = ScanStatus.Error;
                result.ErrorMessage = ex.Message;
                result.FinishedAt = DateTime.Now;
            }

            return result;
        }

        // ── Conversion des correspondances YARA (commune aux trois modes de scan) ──

        /// <summary>
        /// Lance YARA et rend ses correspondances. Un scan incomplet garde les correspondances
        /// déjà lues (ce sont des menaces) et rend le motif d'incomplétude.
        /// </summary>
        private static async Task<(List<YaraMatch> Matches, string? Incomplete)> CollectYaraAsync(Func<Task<List<YaraMatch>>> run)
        {
            try
            {
                return (await run().ConfigureAwait(false), null);
            }
            catch (YaraScanIncompleteException ex)
            {
                return (ex.PartialMatches, ex.Message);
            }
        }

        /// <summary>
        /// Une correspondance = une menace, après exclusions (fichier, dossier, règle) et
        /// dédoublonnage par (chemin, règle) : YARA peut sortir plusieurs fois la même règle.
        /// <paramref name="fixedPath"/> : chemin du fichier pour un scan unitaire.
        /// </summary>
        private void AddYaraThreats(ScanResult result, IEnumerable<YaraMatch> matches, IProgress<ScanProgress>? progress, string? fixedPath)
        {
            var exclusions = _exclusions.Current;
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var sizes = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
            foreach (var m in matches)
            {
                var path = fixedPath ?? m.FilePath;
                if (exclusions.IsFileExcluded(path) || exclusions.IsRuleExcluded(m.RuleName))
                    continue;
                if (!seen.Add(path + "|" + m.RuleName))
                    continue;

                if (!sizes.TryGetValue(path, out var fileSize))
                {
                    fileSize = -1;
                    try { fileSize = new FileInfo(path).Length; }
                    catch { /* taille indisponible — non bloquant */ }
                    sizes[path] = fileSize;
                }

                var threat = new ThreatInfo
                {
                    FilePath = path,
                    VirusName = m.RuleName,
                    DetectedAt = DateTime.Now,
                    Status = ThreatStatus.Detected,
                    FileSize = fileSize,
                    DetectedBy = "YARA"
                };
                result.Threats.Add(threat);

                progress?.Report(new ScanProgress
                {
                    Message = $"{m.RuleName} — {path}",
                    Phase = ScanPhase.ThreatFound,
                    ThreatsFound = result.Threats.Count,
                    ThreatInfo = threat,
                    CurrentFilePath = path,
                    YaraMatchesFound = result.Threats.Count,
                });
            }
        }

        /// <summary>Statut final : un scan YARA incomplet n'est jamais « terminé sans menace ».</summary>
        private static void FinishYaraResult(ScanResult result, string? yaraIncomplete, bool cancelled)
        {
            result.Status = cancelled ? ScanStatus.Cancelled : ScanStatus.Completed;
            if (yaraIncomplete != null && result.Status != ScanStatus.Cancelled)
            {
                result.Status = ScanStatus.Error;
                result.ErrorMessage = yaraIncomplete;
            }
            result.FinishedAt = DateTime.Now;
        }

        // GetQuickScanTargets retiré : la source unique est désormais
        // ScanTargets.QuickScanTargets() (cf. ScanTargets.cs).
    }
}