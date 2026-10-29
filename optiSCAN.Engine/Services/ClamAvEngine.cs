// SPDX-License-Identifier: GPL-3.0-or-later
using optiSCAN.Localization;
using optiSCAN.Models;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Text.RegularExpressions;

namespace optiSCAN.Services
{
    /// <summary>
    /// Moteur de scan ClamAV — enveloppe clamscan.exe en mode processus.
    /// Détecte automatiquement clamav/x64 ou clamav/x86 selon l'architecture.
    /// Supporte : fichier, dossier, scan rapide, scan complet, annulation, progression.
    /// </summary>
    public class ClamAvEngine : IClamAvOrchestratorBackend
    {
        private readonly string _clamavDir;
        private readonly string _clamscanExe;
        private readonly object _parseLock = new();
        private readonly IExclusionSettingsAccessor _exclusions;

        // ── Construction ─────────────────────────────────────────────────────────

        public ClamAvEngine(string? clamavDir = null, IExclusionSettingsAccessor? exclusions = null)
        {
            _exclusions = exclusions ?? new DefaultExclusionSettingsAccessor();
            _clamavDir = clamavDir ?? ClamAvDatabasePaths.ResolveClamAvBinDir("clamscan.exe");
            _clamscanExe = Path.Combine(_clamavDir, "clamscan.exe");
        }

        /// <summary>
        /// Répertoire de la base de signatures : priorité dossier 'database' local,
        /// sinon le répertoire ClamAV lui-même (pour les installs système).
        /// </summary>
        /// <remarks>
        /// Résolu une fois par instance puis gardé : la résolution crée et supprime un dossier de
        /// test, vérifie les droits de ProgramData en SYSTEM et retente la copie initiale des
        /// signatures, ce qui n'a pas à se refaire à chaque lancement de clamscan (un par fichier
        /// en temps réel sans clamd). Recalculé seulement si le dossier a disparu entre-temps.
        /// </remarks>
        public string DatabaseDir
        {
            get
            {
                var cached = Volatile.Read(ref _databaseDir);
                if (cached != null && Directory.Exists(cached))
                    return cached;

                // Même logique que FreshclamUpdater : dossier inscriptible (souvent
                // %LocalAppData% si l'app est sous Program Files).
                var resolved = ClamAvDatabasePaths.ResolveWritableDatabaseDir(_clamavDir);
                Volatile.Write(ref _databaseDir, resolved);
                return resolved;
            }
        }

        private string? _databaseDir;

        // ── Vérification ─────────────────────────────────────────────────────────

        private readonly object _installProbeGate = new();
        private bool? _cachedInstalled;
        private DateTime _cachedInstalledAtUtc = DateTime.MinValue;
        private static readonly TimeSpan InstallProbeCacheTtl = TimeSpan.FromSeconds(60);

        /// <summary>
        /// Vérifie que clamscan.exe est présent. Le contrôle <c>--version</c> est
        /// fait par <see cref="GetVersionAsync"/>, hors du fil de l'interface.
        /// </summary>
        public bool IsClamAvInstalled()
        {
            lock (_installProbeGate)
            {
                if (_cachedInstalled.HasValue
                    && (DateTime.UtcNow - _cachedInstalledAtUtc) < InstallProbeCacheTtl)
                    return _cachedInstalled.Value;

                var result = ProbeClamAvInstalled();
                _cachedInstalled = result;
                _cachedInstalledAtUtc = DateTime.UtcNow;
                return result;
            }
        }

        private bool ProbeClamAvInstalled()
        {
            // Pas de clamscan --version ici : lancé sur le fil UI au démarrage, il
            // charge les bases (ou attend clamd) et laisse la fenêtre blanche.
            // GetVersionAsync confirme ensuite que le binaire répond.
            return File.Exists(_clamscanExe);
        }

        /// <summary>
        /// Retourne la version de ClamAV (première ligne de <c>clamscan --version</c>).
        /// Retourne la clé localisée <c>Clam_NotInstalled</c> ou <c>Clam_VersionError</c>
        /// si l'exécutable est absent ou si une exception survient.
        /// </summary>
        public async Task<string> GetVersionAsync()
        {
            if (!File.Exists(_clamscanExe))
                return LocalizationService.GetString("Clam_NotInstalled");
            try
            {
                var (stdout, _) = await RunProcessAsync(_clamscanExe, "--version");
                return stdout.Trim().Split('\n')[0]; // Première ligne seulement
            }
            catch (Exception ex) when (!ex.IsFatal())
            {
                AppLogger.Warn("ClamAvEngine", "GetVersionAsync", ex);
                return LocalizationService.GetString("Clam_VersionError");
            }
        }

        // ── Méthodes de scan publiques ────────────────────────────────────────────

        /// <summary>
        /// Analyse un fichier unique avec clamscan.
        /// Lève <see cref="FileNotFoundException"/> si le fichier est introuvable.
        /// </summary>
        public Task<ScanResult> ScanFileAsync(
            string filePath,
            IProgress<ScanProgress>? progress = null,
            CancellationToken ct = default)
        {
            if (!File.Exists(filePath))
                throw new FileNotFoundException("Fichier introuvable.", filePath);
            if (SandboxStaging.NeedsStaging(filePath))
                return RunStagedAsync(ScanType.File, filePath, new[] { filePath }, progress, ct);
            return RunScanAsync(ScanType.File, filePath, recursive: false, progress, ct);
        }

        /// <summary>
        /// Analyse récursivement un dossier avec clamscan.
        /// Lève <see cref="DirectoryNotFoundException"/> si le dossier est introuvable.
        /// </summary>
        public Task<ScanResult> ScanFolderAsync(
            string folderPath,
            IProgress<ScanProgress>? progress = null,
            CancellationToken ct = default)
        {
            if (!Directory.Exists(folderPath))
                throw new DirectoryNotFoundException($"Dossier introuvable : {folderPath}");
            if (SandboxStaging.NeedsStaging(folderPath))
            {
                var files = AppInstallPaths.IsUnderInstallRoot(folderPath)
                    ? SandboxStaging.EnumerateFolder(folderPath)
                    : SandboxStaging.EnumerateFolder(folderPath).Where(f => !AppInstallPaths.IsUnderInstallRoot(f));
                return RunStagedAsync(ScanType.Folder, folderPath, files, progress, ct);
            }
            return RunScanAsync(ScanType.Folder, folderPath, recursive: true, progress, ct);
        }

        /// <summary>
        /// Analyse une liste de fichiers en un seul processus clamscan (--file-list).
        /// Utilisé pour le scan USB rapide (extensions à risque uniquement).
        /// </summary>
        public Task<ScanResult> ScanFileListAsync(
            IReadOnlyList<string> files,
            string targetPath,
            IProgress<ScanProgress>? progress = null,
            CancellationToken ct = default)
        {
            if (files.Count == 0)
            {
                var now = DateTime.Now;
                return Task.FromResult(new ScanResult
                {
                    Type = ScanType.Folder,
                    TargetPath = targetPath,
                    StartedAt = now,
                    FinishedAt = now,
                    Status = ScanStatus.Completed,
                    FilesScanned = 0,
                });
            }

            if (files.Any(SandboxStaging.NeedsStaging))
                return RunStagedAsync(ScanType.Folder, targetPath, files.Where(File.Exists), progress, ct);
            return RunFileListScanAsync(files, targetPath, progress, ct);
        }

        /// <summary>
        /// Analyse confinée de fichiers que le conteneur ne peut pas lire : copie par lots,
        /// analyse des copies par liste, menaces rapportées aux chemins d'origine.
        /// </summary>
        private async Task<ScanResult> RunStagedAsync(
            ScanType type,
            string targetPath,
            IEnumerable<string> files,
            IProgress<ScanProgress>? progress,
            CancellationToken ct)
        {
            var total = new ScanResult
            {
                Type = type,
                TargetPath = targetPath,
                StartedAt = DateTime.Now,
                Status = ScanStatus.Completed,
            };

            try
            {
                foreach (var chunk in SandboxStaging.Batches(files))
                {
                    ct.ThrowIfCancellationRequested();
                    using var batch = SandboxStaging.Stage(chunk, ct);
                    foreach (var missed in batch.Skipped.Concat(batch.TooLarge))
                    {
                        total.FilesSkipped++;
                        total.HasCoverageGaps = true;
                        total.UnscannedFiles.Add(missed);
                    }

                    var staged = batch.StagedPaths;
                    if (staged.Count == 0)
                        continue;

                    // Un fichier seul garde le délai propre aux fichiers (archive piégée).
                    var part = type == ScanType.File && staged.Count == 1
                        ? await RunScanAsync(ScanType.File, staged[0], recursive: false, progress, ct).ConfigureAwait(false)
                        : await RunFileListScanAsync(staged, targetPath, progress, ct).ConfigureAwait(false);
                    total.FilesScanned += part.FilesScanned;
                    total.TotalBytesScanned += part.TotalBytesScanned;
                    foreach (var threat in part.Threats)
                    {
                        threat.FilePath = batch.OriginalOf(threat.FilePath);
                        total.Threats.Add(threat);
                    }
                    foreach (var unscanned in part.UnscannedFiles)
                        total.UnscannedFiles.Add(batch.OriginalOf(unscanned));
                    total.FilesSkipped += part.FilesSkipped;
                    total.HasCoverageGaps |= part.HasCoverageGaps;

                    if (part.Status == ScanStatus.Cancelled)
                    {
                        total.Status = ScanStatus.Cancelled;
                        break;
                    }
                    if (part.Status == ScanStatus.Error)
                    {
                        total.Status = ScanStatus.Error;
                        total.ErrorMessage ??= part.ErrorMessage;
                    }
                }
            }
            catch (OperationCanceledException)
            {
                total.Status = ScanStatus.Cancelled;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
            {
                total.Status = ScanStatus.Error;
                total.ErrorMessage = ex.Message;
            }

            total.FinishedAt = DateTime.Now;
            return total;
        }

        /// <summary>Analyse rapide sur les dossiers système prioritaires (chemins définis dans <see cref="ScanTargets"/>).</summary>
        public async Task<ScanResult> QuickScanAsync(
            IProgress<ScanProgress>? progress = null,
            CancellationToken ct = default)
        {
            return await RunMultiTargetScanAsync(ScanType.QuickScan, ScanTargets.QuickScanTargets(), progress, ct);
        }

        /// <summary>Analyse complète sur l'ensemble des cibles définies dans <see cref="ScanTargets"/>.</summary>
        public async Task<ScanResult> FullScanAsync(
            IProgress<ScanProgress>? progress = null,
            CancellationToken ct = default)
        {
            return await RunMultiTargetScanAsync(ScanType.FullScan, ScanTargets.FullScanTargets(), progress, ct);
        }

        // ── Implémentation interne ────────────────────────────────────────────────

        private Task<ScanResult> RunFileListScanAsync(
            IReadOnlyList<string> files,
            string targetPath,
            IProgress<ScanProgress>? progress,
            CancellationToken ct) =>
            RunScanCoreAsync(ScanType.Folder, targetPath, progress, ct, args =>
            {
                var listPath = ScannerSandbox.NewWorkFile("optiscan_clam_", ".lst");
                var existing = files.Where(File.Exists).ToList();
                if (existing.Count == 0)
                    throw new InvalidOperationException("Aucun fichier accessible dans la liste de scan.");

                File.WriteAllLines(listPath, existing, new System.Text.UTF8Encoding(encoderShouldEmitUTF8Identifier: false)); // Sans BOM : sinon le premier chemin de la liste est invalide pour clamscan.
                BuildFileListScanArgs(args, listPath);
                return listPath;
            });

        private Task<ScanResult> RunScanAsync(
            ScanType type, string targetPath, bool recursive,
            IProgress<ScanProgress>? progress, CancellationToken ct) =>
            RunScanCoreAsync(type, targetPath, progress, ct, args =>
            {
                BuildScanArgs(args, targetPath, recursive);
                return null;
            });

        private async Task<ScanResult> RunScanCoreAsync(
            ScanType type,
            string targetPath,
            IProgress<ScanProgress>? progress,
            CancellationToken ct,
            Func<Collection<string>, string?> configureArgs)
        {
            ValidateInstallation();

            var result = new ScanResult
            {
                Type = type,
                TargetPath = targetPath,
                StartedAt = DateTime.Now,
                Status = ScanStatus.Running
            };

            progress?.Report(new ScanProgress
            {
                Message = LocalizationService.Format("Scan_Progress_Starting", Path.GetFileName(targetPath)),
                Phase = ScanPhase.Starting,
                CurrentFilePath = targetPath,
            });

            string? tempFileList = null;
            ScannerProcess? proc = null;
            try
            {
                var args = new Collection<string>();
                tempFileList = configureArgs(args);

                proc = ScannerProcess.Start(new ScannerLaunch(_clamscanExe, args)
                {
                    OnOutput = line =>
                    {
                        if (!string.IsNullOrWhiteSpace(line))
                            ParseScanLine(line, result, progress);
                    },
                    OnError = line =>
                    {
                        if (!string.IsNullOrWhiteSpace(line))
                            AppLogger.Warn("ClamAV", $"stderr: {PathRedaction.RedactPath(line)}");
                    },
                    ReadableDirectories = ScanReadableDirectories(),
                });

                // Un fichier seul a un délai : un clamscan bloqué (archive piégée) est arrêté et le
                // résultat marqué en erreur, au lieu d'attendre indéfiniment. Les scans de dossier
                // ou de volume, longs par nature, restent bornés par l'annulation de l'utilisateur.
                using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
                if (type == ScanType.File)
                    deadline.CancelAfter(SingleFileScanTimeout);
                await WaitForProcessAsync(proc, deadline.Token);

                result.FinishedAt = DateTime.Now;
                var timedOut = deadline.IsCancellationRequested && !ct.IsCancellationRequested;
                var exitCode = proc.HasExited ? proc.ExitCode : -1;
                // Les détections écartées par une exclusion comptent : clamscan rend 1 pour elles aussi.
                result.Status = ClassifyExit(exitCode, result.Threats.Count + result.SuppressedDetections, ct.IsCancellationRequested, out var exitError);
                if (exitError != null)
                    result.ErrorMessage = exitError;
                if (timedOut)
                {
                    result.Status = ScanStatus.Error;
                    result.ErrorMessage = "clamscan : délai dépassé";
                }

                if (ct.IsCancellationRequested && !proc.HasExited)
                    proc.Kill();
            }
            catch (OperationCanceledException)
            {
                result.Status = ScanStatus.Cancelled;
                result.FinishedAt = DateTime.Now;
            }
            catch (Exception ex) when (!ex.IsFatal())
            {
                result.Status = ScanStatus.Error;
                result.ErrorMessage = ex.Message;
                result.FinishedAt = DateTime.Now;
            }
            finally
            {
                proc?.Dispose();
                if (!string.IsNullOrEmpty(tempFileList))
                {
                    try { File.Delete(tempFileList); } catch (Exception ignored) when (!ignored.IsFatal()) { /* ignore */ }
                }
            }

            progress?.Report(new ScanProgress
            {
                Message = result.SummaryDisplay,
                Phase = ScanPhase.Completed,
                FilesScanned = result.FilesScanned,
                ClamFilesScanned = result.FilesScanned,
                ThreatsFound = result.ThreatsFound
            });

            return result;
        }

        private Task<ScanResult> RunMultiTargetScanAsync(
            ScanType type, List<string> targets,
            IProgress<ScanProgress>? progress, CancellationToken ct) =>
            MultiTargetScanAggregator.AggregateAsync(
                type,
                targets,
                (t, targetProgress, token) => RunScanAsync(type, t, recursive: true, targetProgress, token),
                ct,
                progress,
                skipIfDirectoryMissing: false,
                reportTargetProgress: true);

        // ── Parsing ──────────────────────────────────────────────────────────────

        private void ParseScanLine(
            string line, ScanResult result, IProgress<ScanProgress>? progress)
        {
            lock (_parseLock)
            {
                ParseScanLineCore(line, result, progress);
            }
        }

        private void ParseScanLineCore(
            string line, ScanResult result, IProgress<ScanProgress>? progress) =>
            ClamScanLineParser.ProcessLine(line, result, progress, _exclusions);

        // ── Helpers ──────────────────────────────────────────────────────────────

        /// <summary>
        /// Remplit ArgumentList plutôt que de construire une string.
        /// ArgumentList échappe correctement les espaces, guillemets et
        /// caractères spéciaux (CommandLineToArgvW round-trip), évitant les
        /// pièges d'injection si target contient un caractère exotique.
        /// </summary>
        private void BuildScanArgs(Collection<string> args, string target, bool recursive)
        {
            if (recursive) args.Add("--recursive");

            // Ne pas parcourir le dossier d'optiSCAN lors d'un scan parent (ex. C:\).
            if (recursive && !AppInstallPaths.IsUnderInstallRoot(target))
            {
                foreach (var pattern in AppInstallPaths.GetClamScanExcludePatterns())
                    args.Add($"--exclude={pattern}");
            }

            args.Add("--stdout");
            AddSandboxTempDir(args);
            // NB: --no-summary supprimé. Le résumé "Scanned files: N" en fin
            // d'output est notre source de vérité pour le compteur final
            // (cf. ParseStats), à la place de l'incrément ligne par ligne.

            var dbDir = DatabaseDir;
            if (!string.IsNullOrEmpty(dbDir))
                args.Add($"--database={dbDir}"); // ArgumentList gère l'échappement (quoting)

            args.Add(target);
        }

        private void BuildFileListScanArgs(Collection<string> args, string listPath)
        {
            args.Add("--stdout");
            AddSandboxTempDir(args);
            var dbDir = DatabaseDir;
            if (!string.IsNullOrEmpty(dbDir))
                args.Add($"--database={dbDir}");
            args.Add($"--file-list={listPath}");
        }

        /// <summary>
        /// Sous SYSTEM, clamscan est confiné : ses fichiers temporaires (archives décompressées)
        /// vont dans le dossier de travail du conteneur, le seul où il peut écrire.
        /// </summary>
        private static void AddSandboxTempDir(Collection<string> args)
        {
            if (ScannerSandbox.IsRequired)
                args.Add($"--tempdir={ScannerSandbox.WorkDirectory}");
        }

        /// <summary>Dossiers que clamscan doit lire : signatures et, sous SYSTEM, copies d'analyse.</summary>
        private IReadOnlyList<string> ScanReadableDirectories()
        {
            var directories = new List<string>();
            var db = DatabaseDir;
            if (!string.IsNullOrEmpty(db))
                directories.Add(db);
            directories.AddRange(ScannerSandbox.StagingDirectories());
            return directories;
        }

        /// <summary>Délai maximal de clamscan sur un fichier seul.</summary>
        internal static readonly TimeSpan SingleFileScanTimeout = TimeSpan.FromMinutes(10);

        private static async Task WaitForProcessAsync(ScannerProcess proc, CancellationToken ct)
        {
            using (ct.Register(proc.Kill))
            {
                try
                {
                    await proc.WaitForExitAsync(ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    // Attendu lors de l'annulation : la sortie déjà lue reste exploitable.
                    proc.WaitForExit(TimeSpan.FromSeconds(5));
                }
            }
        }

        private async Task<(string stdout, string stderr)> RunProcessAsync(string exe, string args)
        {
            var stdout = new System.Text.StringBuilder();
            var stderr = new System.Text.StringBuilder();
            using var proc = ScannerProcess.Start(new ScannerLaunch(exe, new[] { args })
            {
                OnOutput = line => { if (line != null) stdout.AppendLine(line); },
                OnError = line => { if (line != null) stderr.AppendLine(line); },
            });
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            try
            {
                await proc.WaitForExitAsync(deadline.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                proc.Kill();
                return (string.Empty, "délai dépassé");
            }
            return (stdout.ToString(), stderr.ToString());
        }

        private void ValidateInstallation()
        {
            if (!File.Exists(_clamscanExe))
                throw new InvalidOperationException(
                    $"clamscan.exe introuvable dans : {_clamavDir}\n" +
                    "Placez les binaires ClamAV dans 'clamav/x64/' ou 'clamav/x86/'.");
        }

        /// <summary>
        /// 0 = rien trouvé, 1 = menace lue, 2 = erreur. Une menace déjà extraite reste visible.
        /// </summary>
        internal static ScanStatus ClassifyExit(int exitCode, int threatCount, bool cancelled, out string? error)
        {
            error = null;
            if (cancelled)
                return ScanStatus.Cancelled;
            if (exitCode == 0)
                return ScanStatus.Completed;
            if (exitCode == 1 && threatCount > 0)
                return ScanStatus.Completed;
            if (exitCode == 1)
            {
                error = "clamscan a signalé une menace qui n'a pas été lue";
                return ScanStatus.Error;
            }
            error = "clamscan s'est terminé avec le code " + exitCode;
            return ScanStatus.Error;
        }

        // GetQuickScanTargets retiré : la source unique est désormais
        // ScanTargets.QuickScanTargets() (cf. ScanTargets.cs).
    }

}
