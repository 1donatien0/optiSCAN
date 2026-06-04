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
        private readonly IClamAvOrchestratorBackend _clamAv;
        private readonly IYaraOrchestratorBackend _yara;

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

        internal ScanOrchestrator(IClamAvOrchestratorBackend? clamAv = null, IYaraOrchestratorBackend? yara = null)
        {
            _clamAv = clamAv ?? new ClamAvEngine();
            _yara = yara ?? new YaraEngine();
        }

        // ── API publique ─────────────────────────────────────────────────────────

        /// <summary>
        /// Analyse un fichier unique avec ClamAV et YARA en parallèle.
        /// Retourne immédiatement un résultat vide si le fichier est dans les exclusions.
        /// </summary>
        public Task<ScanResult> ScanFileAsync(string filePath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default)
        {
            if (ExclusionSettings.Current.IsFileExcluded(filePath))
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
            return RunPipelineAsync(ScanType.File, filePath, false, progress, ct);
        }

        /// <summary>Analyse récursivement un dossier avec ClamAV et YARA en parallèle.</summary>
        public Task<ScanResult> ScanFolderAsync(string folderPath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default)
            => RunPipelineAsync(ScanType.Folder, folderPath, true, progress, ct);

        /// <summary>Analyse rapide sur les dossiers système prioritaires (voir <see cref="ScanTargets"/>).</summary>
        public Task<ScanResult> QuickScanAsync(IProgress<ScanProgress>? progress = null, CancellationToken ct = default)
            => RunMultiTargetPipelineAsync(ScanType.QuickScan, ScanTargets.QuickScanTargets(), progress, ct);

        /// <summary>Analyse complète sur l'ensemble des cibles définies dans <see cref="ScanTargets"/>.</summary>
        public Task<ScanResult> FullScanAsync(IProgress<ScanProgress>? progress = null, CancellationToken ct = default)
            => RunMultiTargetPipelineAsync(
                ScanType.FullScan,
                ScanTargets.FullScanTargets(UserPreferences.Current.IncludeRemovableInFullScan),
                progress,
                ct);

        // ── Pipeline interne ─────────────────────────────────────────────────────

        /// <summary>
        /// Exécute ClamAV et YARA en parallèle sur une cible unique, puis fusionne les résultats.
        /// Les dossiers appartenant au répertoire d'installation sont automatiquement exclus.
        /// </summary>
        private async Task<ScanResult> RunPipelineAsync(ScanType type, string target, bool recursive, IProgress<ScanProgress>? progress, CancellationToken ct)
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

            // Un seul relais pour ClamAV + YARA : le compteur et les messages restent monotones.
            var engineProgress = new ScanProgressRelay().ToParent(progress);

            Task<ScanResult> clamTask = recursive
                ? _clamAv.ScanFolderAsync(target, engineProgress, ct)
                : _clamAv.ScanFileAsync(target, engineProgress, ct);

            Task<ScanResult> yaraTask = recursive
                ? RunYaraOnFolderAsync(target, engineProgress, ct)
                : RunYaraOnFileAsync(target, engineProgress, ct);

            await Task.WhenAll(clamTask, yaraTask);

            return ScanThreatMerger.Merge(type, target, await clamTask, await yaraTask);
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

            if (ExclusionSettings.Current.IsFileExcluded(filePath))
            {
                result.Status = ScanStatus.Completed;
                result.FinishedAt = DateTime.Now;
                result.FilesSkipped = 1;
                return result;
            }

            try
            {
                var allMatches = await _yara.ScanFileAsync(filePath, ct);
                var excl = ExclusionSettings.Current;
                var matches = allMatches
                    .FindAll(m => !excl.IsFileExcluded(m.FilePath) && !excl.IsRuleExcluded(m.RuleName));

                long fileSize = -1;
                try { fileSize = new FileInfo(filePath).Length; }
                catch { /* taille indisponible — non bloquant */ }

                foreach (var m in matches)
                {
                    var threat = new ThreatInfo
                    {
                        FilePath = filePath,
                        VirusName = m.RuleName,
                        DetectedAt = DateTime.Now,
                        Status = ThreatStatus.Detected,
                        FileSize = fileSize,
                        DetectedBy = "YARA"
                    };
                    result.Threats.Add(threat);

                    progress?.Report(new ScanProgress
                    {
                        Message = $"{m.RuleName} — {filePath}",
                        Phase = ScanPhase.ThreatFound,
                        ThreatInfo = threat,
                        ThreatsFound = result.ThreatsFound,
                        CurrentFilePath = filePath,
                    });
                }

                result.FilesScanned = 1;
                result.Status = ScanStatus.Completed;
                result.FinishedAt = DateTime.Now;
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
                result.Status = ScanStatus.Completed;
                result.FinishedAt = DateTime.Now;
            }

            return result;
        }

        /// <summary>Exécute YARA en mode récursif (single-process) sur un dossier et convertit les matchs en <see cref="ThreatInfo"/>.</summary>
        private async Task<ScanResult> RunYaraOnFolderAsync(string folderPath, IProgress<ScanProgress>? progress, CancellationToken ct)
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
                // Énumération streaming pour connaître le total (ProgressBar UI).
                // On cape à 100k pour éviter de bloquer 30 s sur un disque entier
                // avant même de commencer à scanner — au-delà, ProgressBar reste
                // indéterminée et on affiche "100k+ fichiers" plutôt qu'un total
                // potentiellement faux.
                const int CountCap = 100_000;
                const int UnknownTotalFiles = 0; // ProgressBar indéterminée (voir TotalFiles)
                int total = 0;
                try
                {
                    foreach (var file in Directory.EnumerateFiles(folderPath, "*.*", SearchOption.AllDirectories))
                    {
                        if (ct.IsCancellationRequested) break;
                        if (ExclusionSettings.Current.IsFileExcluded(file))
                            continue;
                        if (++total >= CountCap) { total = UnknownTotalFiles; break; }
                    }
                }
                catch (Exception ex)
                {
                    AppLogger.Warn("ScanOrchestrator", $"Énumération {folderPath}", ex);
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

                var allMatches = await _yara.ScanFolderAsync(folderPath, yaraProgress, ct);

                // Filtre exclusions (dossiers + règles ignorées).
                var exclusions = ExclusionSettings.Current;
                var filteredMatches = allMatches
                    .Where(m => !exclusions.IsFileExcluded(m.FilePath))
                    .Where(m => !exclusions.IsRuleExcluded(m.RuleName))
                    .ToList();

                // Conversion en ThreatInfo : un match = une menace, dédupliquée
                // par (chemin + règle). yara peut émettre la même règle plusieurs
                // fois pour un même fichier si plusieurs strings matchent.
                var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var m in filteredMatches)
                {
                    var key = $"{m.FilePath}|{m.RuleName}";
                    if (!seen.Add(key)) continue;

                    long fileSize = -1;
                    try { fileSize = new FileInfo(m.FilePath).Length; }
                    catch { /* taille indisponible */ }

                    var threat = new ThreatInfo
                    {
                        FilePath = m.FilePath,
                        VirusName = m.RuleName,
                        DetectedAt = DateTime.Now,
                        Status = ThreatStatus.Detected,
                        FileSize = fileSize,
                        DetectedBy = "YARA"
                    };
                    result.Threats.Add(threat);

                    progress?.Report(new ScanProgress
                    {
                        Message = $"{m.RuleName} — {m.FilePath}",
                        Phase = ScanPhase.ThreatFound,
                        ThreatsFound = result.Threats.Count,
                        ThreatInfo = threat,
                        CurrentFilePath = m.FilePath,
                        YaraMatchesFound = result.Threats.Count,
                    });
                }

                result.FilesScanned = total > 0 ? total : Math.Max(filesYara, 1);
                result.Status = ct.IsCancellationRequested ? ScanStatus.Cancelled : ScanStatus.Completed;
                result.FinishedAt = DateTime.Now;

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
                result.Status = ScanStatus.Completed;
                result.FinishedAt = DateTime.Now;
            }

            return result;
        }

        // GetQuickScanTargets retiré : la source unique est désormais
        // ScanTargets.QuickScanTargets() (cf. ScanTargets.cs).
    }
}