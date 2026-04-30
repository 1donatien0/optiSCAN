using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using optiSCAN.Models;

namespace optiSCAN.Services
{
    /// <summary>
    /// Orchestre le scan en pipeline ClamAV + YARA.
    ///
    /// Méthode Pipeline :
    ///   1. ClamAV et YARA tournent en PARALLÈLE sur la même cible.
    ///   2. Les résultats sont fusionnés :
    ///      - Si les deux détectent le même fichier → DetectedBy = "ClamAV+YARA" (menace confirmée)
    ///      - Si seulement ClamAV                  → DetectedBy = "ClamAV"
    ///      - Si seulement YARA                    → DetectedBy = "YARA"
    ///   3. EICAR est supporté nativement par ClamAV (Eicar-Test-Signature)
    ///      et par les règles YARA (EICAR_Test).
    /// </summary>
    public class ScanOrchestrator
    {
        private readonly ClamAvEngine _clamAv;
        private readonly YaraEngine   _yara;

        public bool IsClamAvAvailable => _clamAv.IsClamAvInstalled();
        public bool IsYaraAvailable   => _yara.IsAvailable;
        public int  YaraRulesCount    => _yara.RulesCount;

        // ── Constructeur ─────────────────────────────────────────────────────────

        public ScanOrchestrator(ClamAvEngine? clamAv = null, YaraEngine? yara = null)
        {
            _clamAv = clamAv ?? new ClamAvEngine();
            _yara   = yara   ?? new YaraEngine();
        }

        // ── API publique ──────────────────────────────────────────────────────────

        public Task<ScanResult> ScanFileAsync(
            string filePath,
            IProgress<ScanProgress>? progress = null,
            CancellationToken ct = default)
            => RunPipelineAsync(ScanType.File, filePath, false, progress, ct);

        public Task<ScanResult> ScanFolderAsync(
            string folderPath,
            IProgress<ScanProgress>? progress = null,
            CancellationToken ct = default)
            => RunPipelineAsync(ScanType.Folder, folderPath, true, progress, ct);

        public Task<ScanResult> QuickScanAsync(
            IProgress<ScanProgress>? progress = null,
            CancellationToken ct = default)
            => RunMultiTargetPipelineAsync(ScanType.QuickScan, GetQuickScanTargets(), progress, ct);

        public Task<ScanResult> FullScanAsync(
            IProgress<ScanProgress>? progress = null,
            CancellationToken ct = default)
        {
            var drives = DriveInfo.GetDrives()
                .Where(d => d.IsReady && d.DriveType == DriveType.Fixed)
                .Select(d => d.RootDirectory.FullName)
                .ToList();
            return RunMultiTargetPipelineAsync(ScanType.FullScan, drives, progress, ct);
        }

        // ── Test EICAR ────────────────────────────────────────────────────────────

        /// <summary>
        /// Génère un fichier EICAR temporaire, le scanne avec les deux moteurs,
        /// retourne le résultat et supprime le fichier de test.
        ///
        /// Standard EICAR : X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
        /// ClamAV le détecte comme "Eicar-Test-Signature".
        /// YARA le détecte avec la règle EICAR_Test.
        /// </summary>
        public async Task<ScanResult> RunEicarTestAsync(
            IProgress<ScanProgress>? progress = null,
            CancellationToken ct = default)
        {
            const string EicarString =
                "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

            var tmpPath = Path.Combine(Path.GetTempPath(), "eicar_test.com");

            progress?.Report(new ScanProgress
            {
                Message = "Test EICAR — génération du fichier de test…",
                Phase   = ScanPhase.Starting
            });

            try
            {
                // Écrire le fichier EICAR (ASCII pur, ne PAS encoder en UTF-8 BOM)
                File.WriteAllText(tmpPath, EicarString,
                    new System.Text.UTF8Encoding(encoderShouldEmitUTF8Identifier: false));

                var result = await ScanFileAsync(tmpPath, progress, ct);

                // Ajouter tag EICAR au type
                result.TargetPath = "EICAR Test File";

                return result;
            }
            finally
            {
                // Toujours supprimer le fichier de test
                try { if (File.Exists(tmpPath)) File.Delete(tmpPath); } catch { }
            }
        }

        // ── Pipeline interne ──────────────────────────────────────────────────────

        private async Task<ScanResult> RunPipelineAsync(
            ScanType type, string target, bool recursive,
            IProgress<ScanProgress>? progress, CancellationToken ct)
        {
            // Progression wrapper : préfixe l'émetteur dans le message
            var clamProgress = new Progress<ScanProgress>(p =>
            {
                var copy = p.Clone();
                copy.Message = $"[ClamAV] {p.Message}";
                progress?.Report(copy);
            });

            var yaraProgress = new Progress<ScanProgress>(p =>
            {
                var copy = p.Clone();
                copy.Message = $"[Analyse] {p.Message}";
                progress?.Report(copy);
            });

            // ── Lancement en parallèle ─────────────────────────────────────────
            Task<ScanResult> clamTask = recursive
                ? _clamAv.ScanFolderAsync(target, clamProgress, ct)
                : _clamAv.ScanFileAsync(target, clamProgress, ct);

            Task<ScanResult> yaraTask = recursive
                ? RunYaraOnFolderAsync(target, yaraProgress, ct)
                : RunYaraOnFileAsync(target, yaraProgress, ct);

            await Task.WhenAll(clamTask, yaraTask);

            var clamResult = await clamTask;
            var yaraResult = await yaraTask;

            // ── Fusion des résultats ───────────────────────────────────────────
            return MergeResults(type, target, clamResult, yaraResult);
        }

        private async Task<ScanResult> RunMultiTargetPipelineAsync(
            ScanType type, List<string> targets,
            IProgress<ScanProgress>? progress, CancellationToken ct)
        {
            var merged = new ScanResult
            {
                Type      = type,
                TargetPath = string.Join(", ", targets),
                StartedAt = DateTime.Now,
                Status    = ScanStatus.Running
            };

            foreach (var target in targets)
            {
                if (ct.IsCancellationRequested) break;
                if (!Directory.Exists(target)) continue;

                var sub = await RunPipelineAsync(type, target, true, progress, ct);
                merged.FilesScanned      += sub.FilesScanned;
                merged.FilesSkipped      += sub.FilesSkipped;
                merged.TotalBytesScanned += sub.TotalBytesScanned;
                merged.Threats.AddRange(sub.Threats);
            }

            merged.FinishedAt = DateTime.Now;
            merged.Status = ct.IsCancellationRequested ? ScanStatus.Cancelled : ScanStatus.Completed;
            return merged;
        }

        // ── YARA sur dossier ──────────────────────────────────────────────────────

        private async Task<ScanResult> RunYaraOnFileAsync(
            string filePath, IProgress<ScanProgress>? progress, CancellationToken ct)
        {
            var result = new ScanResult
            {
                Type      = ScanType.File,
                TargetPath = filePath,
                StartedAt = DateTime.Now
            };

            if (!_yara.IsAvailable)
            {
                result.Status     = ScanStatus.Completed;
                result.FinishedAt = DateTime.Now;
                return result;
            }

            try
            {
                var allMatches = await _yara.ScanFileAsync(filePath, ct);

                // Filtrer les règles exclues (ex. SuspiciousDownloads — trop de faux positifs)
                var excl = ExclusionSettings.Current;
                var matches = allMatches.FindAll(m => !excl.IsRuleExcluded(m.RuleName));

                foreach (var m in matches)
                {
                    long size = -1;
                    try { size = new FileInfo(filePath).Length; } catch { }

                    var threat = new ThreatInfo
                    {
                        FilePath   = filePath,
                        VirusName  = m.RuleName,
                        DetectedAt = DateTime.Now,
                        Status     = ThreatStatus.Detected,
                        FileSize   = size,
                        DetectedBy = "YARA"
                    };
                    result.Threats.Add(threat);

                    progress?.Report(new ScanProgress
                    {
                        Message      = $"YARA match : {m.RuleName} [{Path.GetFileName(filePath)}]",
                        Phase        = ScanPhase.ThreatFound,
                        ThreatInfo   = threat,
                        ThreatsFound = result.ThreatsFound
                    });
                }

                result.FilesScanned = 1;
                result.Status       = ScanStatus.Completed;
                result.FinishedAt   = DateTime.Now;
            }
            catch
            {
                result.Status     = ScanStatus.Completed; // YARA non bloquant
                result.FinishedAt = DateTime.Now;
            }

            return result;
        }

        private async Task<ScanResult> RunYaraOnFolderAsync(
            string folderPath, IProgress<ScanProgress>? progress, CancellationToken ct)
        {
            var result = new ScanResult
            {
                Type      = ScanType.Folder,
                TargetPath = folderPath,
                StartedAt = DateTime.Now
            };

            if (!_yara.IsAvailable)
            {
                result.Status     = ScanStatus.Completed;
                result.FinishedAt = DateTime.Now;
                return result;
            }

            try
            {
                var files = Directory.GetFiles(folderPath, "*.*", SearchOption.AllDirectories);

                progress?.Report(new ScanProgress
                {
                    Message = $"YARA — {files.Length} fichiers à analyser dans {Path.GetFileName(folderPath)}…",
                    Phase   = ScanPhase.Starting
                });

                // Exclure les fichiers dans des dossiers ignorés
                var exclusions = ExclusionSettings.Current;

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) break;

                    // Sauter les fichiers dans un dossier exclu
                    if (exclusions.IsFolderExcluded(file))
                    {
                        result.FilesScanned++;
                        continue;
                    }

                    var subResult = await RunYaraOnFileAsync(file, progress, ct);
                    result.FilesScanned++;
                    result.Threats.AddRange(subResult.Threats);

                    if (result.FilesScanned % 100 == 0)
                    {
                        progress?.Report(new ScanProgress
                        {
                            Message      = $"YARA : {result.FilesScanned}/{files.Length} fichiers…",
                            Phase        = ScanPhase.Scanning,
                            FilesScanned = result.FilesScanned,
                            ThreatsFound = result.ThreatsFound
                        });
                    }
                }

                result.Status     = ct.IsCancellationRequested ? ScanStatus.Cancelled : ScanStatus.Completed;
                result.FinishedAt = DateTime.Now;
            }
            catch
            {
                result.Status     = ScanStatus.Completed;
                result.FinishedAt = DateTime.Now;
            }

            return result;
        }

        // ── Fusion des résultats ──────────────────────────────────────────────────

        private static ScanResult MergeResults(
            ScanType type, string target,
            ScanResult clamResult, ScanResult yaraResult)
        {
            var merged = new ScanResult
            {
                Type             = type,
                TargetPath       = target,
                StartedAt        = clamResult.StartedAt < yaraResult.StartedAt
                                    ? clamResult.StartedAt : yaraResult.StartedAt,
                FinishedAt       = DateTime.Now,
                FilesScanned     = Math.Max(clamResult.FilesScanned, yaraResult.FilesScanned),
                FilesSkipped     = clamResult.FilesSkipped,
                TotalBytesScanned = clamResult.TotalBytesScanned,
                Status           = (clamResult.Status == ScanStatus.Cancelled ||
                                    yaraResult.Status == ScanStatus.Cancelled)
                                    ? ScanStatus.Cancelled
                                    : ScanStatus.Completed
            };

            // Indexer les menaces ClamAV par chemin de fichier (normalisé en minuscules)
            var clamByPath = new Dictionary<string, ThreatInfo>(StringComparer.OrdinalIgnoreCase);
            foreach (var t in clamResult.Threats)
                clamByPath[t.FilePath] = t;

            // Ajouter toutes les menaces ClamAV
            merged.Threats.AddRange(clamResult.Threats);

            // Fusionner avec les menaces YARA
            foreach (var yaraT in yaraResult.Threats)
            {
                if (clamByPath.TryGetValue(yaraT.FilePath, out var existing))
                {
                    // Même fichier détecté par les deux → double confirmation
                    existing.DetectedBy = "ClamAV+YARA";
                    // Ajouter le nom de règle YARA au nom de menace
                    if (!existing.VirusName.Contains(yaraT.VirusName))
                        existing.VirusName += $" / YARA:{yaraT.VirusName}";
                }
                else
                {
                    // Détection YARA uniquement
                    merged.Threats.Add(yaraT);
                }
            }

            return merged;
        }

        // ── Helpers ──────────────────────────────────────────────────────────────

        private static List<string> GetQuickScanTargets()
        {
            var dirs = new List<string>();
            void Add(string path) { if (Directory.Exists(path)) dirs.Add(path); }

            Add(Environment.GetEnvironmentVariable("TEMP") ?? "");
            Add(Environment.GetEnvironmentVariable("TMP")  ?? "");
            Add(@"C:\Windows\Temp");
            Add(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"));
            Add(Environment.GetFolderPath(Environment.SpecialFolder.Desktop));
            return dirs;
        }
    }
}
