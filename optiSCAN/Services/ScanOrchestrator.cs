using optiSCAN.Models;
using System.IO;

namespace optiSCAN.Services
{
    public class ScanOrchestrator
    {
        private readonly ClamAvEngine _clamAv;
        private readonly YaraEngine _yara;

        // YaraParallelism retiré : depuis le passage en single-process (un seul
        // yara64.exe avec --recursive), yara gère lui-même son parallélisme
        // interne et l'orchestration n'a plus à le faire.

        public bool IsClamAvAvailable => _clamAv.IsClamAvInstalled();
        public bool IsYaraAvailable => _yara.IsAvailable;
        public int YaraRulesCount => _yara.RulesCount;

        public ScanOrchestrator(ClamAvEngine? clamAv = null, YaraEngine? yara = null)
        {
            _clamAv = clamAv ?? new ClamAvEngine();
            _yara = yara ?? new YaraEngine();
        }

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

        public Task<ScanResult> ScanFolderAsync(string folderPath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default)
            => RunPipelineAsync(ScanType.Folder, folderPath, true, progress, ct);

        public Task<ScanResult> QuickScanAsync(IProgress<ScanProgress>? progress = null, CancellationToken ct = default)
            => RunMultiTargetPipelineAsync(ScanType.QuickScan, ScanTargets.QuickScanTargets(), progress, ct);

        public Task<ScanResult> FullScanAsync(IProgress<ScanProgress>? progress = null, CancellationToken ct = default)
            => RunMultiTargetPipelineAsync(ScanType.FullScan, ScanTargets.FullScanTargets(), progress, ct);

        private async Task<ScanResult> RunPipelineAsync(ScanType type, string target, bool recursive, IProgress<ScanProgress>? progress, CancellationToken ct)
        {
            var clamProgress = new Progress<ScanProgress>(p =>
            {
                var c = p.Clone();
                c.Message = $"[ClamAV] {p.Message}";
                progress?.Report(c);
            });

            var yaraProgress = new Progress<ScanProgress>(p =>
            {
                var c = p.Clone();
                c.Message = $"[YARA] {p.Message}";
                progress?.Report(c);
            });

            Task<ScanResult> clamTask = recursive
                ? _clamAv.ScanFolderAsync(target, clamProgress, ct)
                : _clamAv.ScanFileAsync(target, clamProgress, ct);

            Task<ScanResult> yaraTask = recursive
                ? RunYaraOnFolderAsync(target, yaraProgress, ct)
                : RunYaraOnFileAsync(target, yaraProgress, ct);

            await Task.WhenAll(clamTask, yaraTask);

            return MergeResults(type, target, await clamTask, await yaraTask);
        }

        private Task<ScanResult> RunMultiTargetPipelineAsync(ScanType type, List<string> targets, IProgress<ScanProgress>? progress, CancellationToken ct) =>
            MultiTargetScanAggregator.AggregateAsync(
                type,
                targets,
                t => RunPipelineAsync(type, t, true, progress, ct),
                ct,
                progress,
                skipIfDirectoryMissing: true,
                reportTargetProgress: true);

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

            try
            {
                var allMatches = await _yara.ScanFileAsync(filePath, ct);
                var excl = ExclusionSettings.Current;
                var matches = allMatches.FindAll(m => !excl.IsRuleExcluded(m.RuleName));

                long fileSize = -1;
                try { fileSize = new FileInfo(filePath).Length; } catch { }

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
                        Message = $"Match : {m.RuleName} [{Path.GetFileName(filePath)}]",
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
            catch
            {
                result.Status = ScanStatus.Completed;
                result.FinishedAt = DateTime.Now;
            }

            return result;
        }

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
                int total = 0;
                try
                {
                    foreach (var _ in Directory.EnumerateFiles(folderPath, "*.*", SearchOption.AllDirectories))
                    {
                        if (ct.IsCancellationRequested) break;
                        if (++total >= CountCap) { total = 0; break; } // 0 = inconnu
                    }
                }
                catch (Exception ex)
                {
                    AppLogger.Warn("ScanOrchestrator", $"Énumération {folderPath}", ex);
                }

                progress?.Report(new ScanProgress
                {
                    Message = $"YARA — scan récursif de {Path.GetFileName(folderPath)} ({total} fichiers)…",
                    Phase = ScanPhase.Starting,
                    TotalFiles = total,
                    CurrentFilePath = folderPath,
                });

                // Single-process : un seul yara64.exe avec --recursive.
                // 10 à 50× plus rapide que l'ancienne approche un-process-par-fichier.
                var yaraProgress = new Progress<string>(msg =>
                    progress?.Report(new ScanProgress
                    {
                        Message = msg,
                        Phase = ScanPhase.Scanning,
                        TotalFiles = total,
                        CurrentFilePath = folderPath,
                    }));

                var allMatches = await _yara.ScanFolderAsync(folderPath, yaraProgress, ct);

                // Filtre exclusions (dossiers + règles ignorées).
                var exclusions = ExclusionSettings.Current;
                var filteredMatches = allMatches
                    .Where(m => !exclusions.IsFolderExcluded(m.FilePath))
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
                    try { fileSize = new FileInfo(m.FilePath).Length; } catch { }

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
                        Message = $"Menace : {m.RuleName} [{Path.GetFileName(m.FilePath)}]",
                        Phase = ScanPhase.ThreatFound,
                        FilesScanned = total, // yara a tout itéré
                        TotalFiles = total,
                        ThreatsFound = result.Threats.Count,
                        ThreatInfo = threat,
                        YaraMatchesFound = result.Threats.Count,
                    });
                }

                result.FilesScanned = total;
                result.Status = ct.IsCancellationRequested ? ScanStatus.Cancelled : ScanStatus.Completed;
                result.FinishedAt = DateTime.Now;
            }
            catch (OperationCanceledException)
            {
                result.Status = ScanStatus.Cancelled;
                result.FinishedAt = DateTime.Now;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[ScanOrchestrator] RunYaraOnFolderAsync: {ex.Message}");
                result.Status = ScanStatus.Completed;
                result.FinishedAt = DateTime.Now;
            }

            return result;
        }

        private static ScanResult MergeResults(ScanType type, string target, ScanResult clamResult, ScanResult yaraResult)
        {
            var merged = new ScanResult
            {
                Type = type,
                TargetPath = target,
                StartedAt = clamResult.StartedAt < yaraResult.StartedAt ? clamResult.StartedAt : yaraResult.StartedAt,
                FinishedAt = DateTime.Now,
                FilesScanned = Math.Max(clamResult.FilesScanned, yaraResult.FilesScanned),
                FilesSkipped = clamResult.FilesSkipped,
                TotalBytesScanned = clamResult.TotalBytesScanned,
                Status = (clamResult.Status == ScanStatus.Cancelled || yaraResult.Status == ScanStatus.Cancelled)
                    ? ScanStatus.Cancelled : ScanStatus.Completed
            };

            var clamByPath = new Dictionary<string, ThreatInfo>(StringComparer.OrdinalIgnoreCase);
            foreach (var t in clamResult.Threats)
                clamByPath[t.FilePath] = t;

            merged.Threats.AddRange(clamResult.Threats);

            // Pour chaque match YARA on agrège proprement les noms de règles
            // dans un set (HashSet) afin d'éviter les VirusName en accumulation
            // type "X / YARA:Y / YARA:Y / YARA:Y" si plusieurs règles matchent.
            var yaraNamesByPath = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
            var seenYaraTriples = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var yaraT in yaraResult.Threats)
            {
                var triple = $"{yaraT.FilePath}|{yaraT.VirusName}";
                if (!seenYaraTriples.Add(triple)) continue; // déjà compté

                if (clamByPath.TryGetValue(yaraT.FilePath, out var existing))
                {
                    if (!yaraNamesByPath.TryGetValue(yaraT.FilePath, out var names))
                        yaraNamesByPath[yaraT.FilePath] = names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    names.Add(yaraT.VirusName);
                    existing.DetectedBy = "ClamAV+YARA";
                }
                else
                {
                    merged.Threats.Add(yaraT);
                }
            }

            // Composition finale du VirusName pour les détections fusionnées.
            foreach (var kv in yaraNamesByPath)
            {
                var t = clamByPath[kv.Key];
                var sortedRules = string.Join(",", kv.Value.OrderBy(s => s, StringComparer.Ordinal));
                if (!t.VirusName.Contains(sortedRules))
                    t.VirusName += $" / YARA:{sortedRules}";
            }

            return merged;
        }

        // GetQuickScanTargets retiré : la source unique est désormais
        // ScanTargets.QuickScanTargets() (cf. ScanTargets.cs).
    }
}