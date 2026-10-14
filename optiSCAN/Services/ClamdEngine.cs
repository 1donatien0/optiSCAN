using optiSCAN.Localization;
using optiSCAN.Models;
using System.IO;
using System.Runtime.Versioning;

namespace optiSCAN.Services
{
    /// <summary>
    /// Moteur ClamAV via clamd (signatures chargées une fois en mémoire).
    /// clamd tourne dans un AppContainer sans accès aux fichiers : l'hôte ouvre chaque
    /// fichier avec ses propres droits et l'envoie en flux (<c>zINSTREAM</c>).
    /// Aucune ACL n'est modifiée. Un fichier non lu est rendu dans
    /// <see cref="ScanResult.UnscannedFiles"/> pour le repli clamscan.
    /// </summary>
    [SupportedOSPlatform("windows")]
    internal sealed class ClamdEngine : IClamAvOrchestratorBackend
    {
        private readonly ClamAvEngine _fallbackProbe;
        private readonly object _parseLock = new();
        private readonly IUserPreferencesAccessor _prefs;
        private readonly IExclusionSettingsAccessor _exclusions;

        public ClamdEngine(
            IUserPreferencesAccessor? preferences = null,
            IExclusionSettingsAccessor? exclusions = null)
        {
            _prefs = preferences ?? new DefaultUserPreferencesAccessor();
            _exclusions = exclusions ?? new DefaultExclusionSettingsAccessor();
            _fallbackProbe = new ClamAvEngine();
        }

        /// <summary>Dernier mode utilisé (diagnostic UI).</summary>
        public static string LastMode { get; internal set; } = "clamd";

        public bool IsClamAvInstalled() => _fallbackProbe.IsClamAvInstalled();

        public async Task<bool> TryEnsureReadyAsync(CancellationToken ct = default)
        {
            if (!_prefs.Current.UseClamdEngine)
                return false;
            if (!ClamdHost.Shared.IsBinaryPresent)
                return false;
            return await ClamdHost.Shared.EnsureRunningAsync(ct).ConfigureAwait(false);
        }

        /// <summary>Doit rester ≤ StreamMaxLength de clamd.conf (100M).</summary>
        internal const long MaxInstreamBytes = 100L * 1024 * 1024;

        /// <summary>Au-delà, sans aucun succès, clamd est considéré hors service pour ce dossier.</summary>
        private const int MaxFailuresBeforeAbort = 25;

        private const FileAttributes RecallOnDataAccess = (FileAttributes)0x00400000;

        public Task<ScanResult> ScanFileAsync(
            string filePath,
            IProgress<ScanProgress>? progress = null,
            CancellationToken ct = default)
        {
            if (!File.Exists(filePath))
                throw new FileNotFoundException("Fichier introuvable.", filePath);
            return ScanSingleAsync(filePath, progress, ct);
        }

        public Task<ScanResult> ScanFolderAsync(
            string folderPath,
            IProgress<ScanProgress>? progress = null,
            CancellationToken ct = default)
        {
            if (!Directory.Exists(folderPath))
                throw new DirectoryNotFoundException($"Dossier introuvable : {folderPath}");
            var exclusions = _exclusions.Current;
            return ScanFolderEnumeratedAsync(folderPath, exclusions.IsFolderExcluded, progress, ct);
        }

        private async Task<ScanResult> ScanFolderEnumeratedAsync(
            string folderPath,
            Func<string, bool> isFolderExcluded,
            IProgress<ScanProgress>? progress,
            CancellationToken ct)
        {
            // Parcours en flux : un disque entier n'est plus d'abord copié en liste en mémoire.
            var unscannedEntries = new System.Collections.Concurrent.ConcurrentQueue<string>();
            var files = EnumerateScannableFiles(folderPath, isFolderExcluded, unscannedEntries.Enqueue);
            var (result, aborted) = await RunFilesViaClamdAsync(files, folderPath, ScanType.Folder, progress, ct)
                .ConfigureAwait(false);

            if (aborted)
            {
                // clamd hors service : tout le dossier repasse par clamscan (repli du composite),
                // qui signalera lui-même les éléments illisibles.
                result.UnscannedFiles.Clear();
                result.HasCoverageGaps = false;
                return result;
            }

            if (!unscannedEntries.IsEmpty)
            {
                result.FilesSkipped += unscannedEntries.Count;
                result.HasCoverageGaps = true;
                if (result.Status != ScanStatus.Cancelled)
                {
                    result.Status = ScanStatus.Error;
                    var reason = $"{unscannedEntries.Count} élément(s) inaccessible(s), hors ligne ou lié(s) n'ont pas été analysés.";
                    result.ErrorMessage = string.IsNullOrWhiteSpace(result.ErrorMessage)
                        ? reason
                        : result.ErrorMessage + "; " + reason;
                }
            }

            return result;
        }

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

            return RunFileListViaClamdAsync(files, targetPath, ScanType.Folder, progress, ct);
        }

        /// <summary>
        /// Fichiers d'un dossier, sans suivre les liens. Les éléments inaccessibles ou cloud
        /// hors ligne sont signalés au lieu d'être omis silencieusement.
        /// </summary>
        internal static IEnumerable<string> EnumerateScannableFiles(
            string folderPath,
            Func<string, bool>? isFolderExcluded = null,
            Action<string>? onUnscanned = null)
        {
            var options = new EnumerationOptions
            {
                RecurseSubdirectories = false,
                IgnoreInaccessible = false,
                AttributesToSkip = 0,
            };

            var pending = new Stack<string>();
            pending.Push(folderPath);
            while (pending.Count > 0)
            {
                var directory = pending.Pop();
                IEnumerable<FileSystemInfo> entries;
                IEnumerator<FileSystemInfo> enumerator;
                try
                {
                    entries = new DirectoryInfo(directory).EnumerateFileSystemInfos("*", options);
                    enumerator = entries.GetEnumerator();
                }
                catch
                {
                    onUnscanned?.Invoke(directory);
                    continue;
                }

                using (enumerator)
                {
                    while (true)
                    {
                        FileSystemInfo entry;
                        try
                        {
                            if (!enumerator.MoveNext())
                                break;
                            entry = enumerator.Current;
                        }
                        catch
                        {
                            onUnscanned?.Invoke(directory);
                            break;
                        }

                        FileAttributes attributes;
                        try { attributes = entry.Attributes; }
                        catch
                        {
                            onUnscanned?.Invoke(entry.FullName);
                            continue;
                        }

                        if ((attributes & FileAttributes.Directory) != 0)
                        {
                            // Ne pas suivre une jonction ou un lien ; son contenu n'est pas
                            // dans la couverture et doit donc rendre le scan incomplet.
                            if ((attributes & FileAttributes.ReparsePoint) != 0)
                            {
                                onUnscanned?.Invoke(entry.FullName);
                                continue;
                            }

                            if (isFolderExcluded?.Invoke(entry.FullName) != true)
                                pending.Push(entry.FullName);
                            continue;
                        }

                        // Fichier cloud hors ligne : l'ouvrir le téléchargerait. Signalé, pas lu.
                        if ((attributes & (RecallOnDataAccess | FileAttributes.Offline)) != 0)
                        {
                            onUnscanned?.Invoke(entry.FullName);
                            continue;
                        }

                        // Point de réanalyse : seul un lien (symbolique, jonction) est écarté. Un
                        // fichier OneDrive présent sur le disque porte lui aussi ce marqueur ; il
                        // était ignoré, alors que Bureau et Documents sont souvent dans OneDrive.
                        if ((attributes & FileAttributes.ReparsePoint) != 0 && !IsLocalNonLinkReparse(entry))
                        {
                            onUnscanned?.Invoke(entry.FullName);
                            continue;
                        }

                        yield return entry.FullName;
                    }
                }
            }
        }

        /// <summary>
        /// Vrai pour un point de réanalyse qui n'est pas un lien (fichier cloud présent, fichier
        /// dédupliqué) : son contenu est local et s'ouvre normalement. Faux pour un lien
        /// symbolique ou une jonction, ou si la cible ne peut pas être lue.
        /// </summary>
        internal static bool IsLocalNonLinkReparse(FileSystemInfo entry)
        {
            try
            {
                return entry.LinkTarget == null;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Connexions clamd simultanées : clamd traite plusieurs flux à la fois (MaxThreads 10 par
        /// défaut) ; un fichier à la fois laissait le processeur presque inactif pendant un scan
        /// complet.
        /// </summary>
        internal static int ScanParallelism => Math.Clamp(Environment.ProcessorCount / 2, 2, 4);

        private async Task<ScanResult> RunFileListViaClamdAsync(
            IEnumerable<string> files,
            string targetPath,
            ScanType type,
            IProgress<ScanProgress>? progress,
            CancellationToken ct)
        {
            var list = files as IReadOnlyList<string> ?? files.ToList();
            var processed = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var (result, aborted) = await RunFilesViaClamdAsync(list, targetPath, type, progress, ct, processed).ConfigureAwait(false);
            if (aborted)
            {
                // Liste connue : les fichiers non vus sont confiés au repli clamscan.
                foreach (var f in result.UnscannedFiles)
                    processed.Add(f);
                foreach (var file in list)
                {
                    if (!processed.Contains(file) && !_exclusions.Current.IsFileExcluded(file))
                        result.UnscannedFiles.Add(file);
                }
            }

            return result;
        }

        private async Task<(ScanResult Result, bool Aborted)> RunFilesViaClamdAsync(
            IEnumerable<string> files,
            string targetPath,
            ScanType type,
            IProgress<ScanProgress>? progress,
            CancellationToken ct,
            HashSet<string>? processed = null)
        {
            var pipeName = await RequirePipeAsync(ct).ConfigureAwait(false);
            LastMode = "clamd";
            var merged = new ScanResult
            {
                Type = type,
                TargetPath = targetPath,
                StartedAt = DateTime.Now,
                Status = ScanStatus.Running,
            };

            var gate = new object();
            var successes = 0;
            var failures = 0;
            var aborted = false;
            using var abort = CancellationTokenSource.CreateLinkedTokenSource(ct);
            var options = new ParallelOptions
            {
                MaxDegreeOfParallelism = ScanParallelism,
                CancellationToken = abort.Token,
            };

            try
            {
                await Parallel.ForEachAsync(files, options, async (file, token) =>
                {
                    if (_exclusions.Current.IsFileExcluded(file))
                    {
                        lock (gate)
                            merged.FilesSkipped++;
                        return;
                    }

                    var partial = await ScanSingleCoreAsync(file, pipeName, progress: null, token).ConfigureAwait(false);
                    if (partial.Status == ScanStatus.Cancelled)
                        return;

                    lock (gate)
                    {
                        if (partial.Status == ScanStatus.Error)
                        {
                            failures++;
                            merged.UnscannedFiles.Add(file);
                            if (successes == 0 && failures >= MaxFailuresBeforeAbort && !aborted)
                            {
                                aborted = true;
                                abort.Cancel();
                            }
                            return;
                        }

                        successes++;
                        processed?.Add(file);
                        foreach (var threat in partial.Threats)
                            merged.Threats.Add(threat);
                        merged.FilesScanned += Math.Max(partial.FilesScanned, 1);
                        ReportFileProgress(progress, merged, file);
                    }
                }).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (aborted && !ct.IsCancellationRequested)
            {
                /* clamd ne répond plus : traité ci-dessous */
            }
            catch (OperationCanceledException)
            {
                merged.Status = ScanStatus.Cancelled;
                merged.FinishedAt = DateTime.Now;
                return (merged, false);
            }

            merged.FinishedAt = DateTime.Now;
            if (aborted)
            {
                merged.Status = ScanStatus.Error;
                merged.ErrorMessage = "clamd ne répond pas pour ce dossier";
                return (merged, true);
            }

            merged.Status = ct.IsCancellationRequested ? ScanStatus.Cancelled : ScanStatus.Completed;
            if (failures > 0)
                AppLogger.Info("ClamdEngine", $"{failures} fichier(s) non lus par clamd, confiés au repli clamscan");

            progress?.Report(new ScanProgress
            {
                Message = merged.SummaryDisplay,
                Phase = ScanPhase.Completed,
                FilesScanned = merged.FilesScanned,
                ThreatsFound = merged.ThreatsFound,
            });
            return (merged, false);
        }

        private static void ReportFileProgress(IProgress<ScanProgress>? progress, ScanResult merged, string file)
        {
            if (progress == null || merged.FilesScanned % 25 != 0)
                return;
            progress.Report(new ScanProgress
            {
                Message = LocalizationService.Format("Scan_Progress_Starting", Path.GetFileName(file)),
                Phase = ScanPhase.Scanning,
                CurrentFilePath = file,
                FilesScanned = merged.FilesScanned,
                ThreatsFound = merged.ThreatsFound,
            });
        }

        private async Task<string> RequirePipeAsync(CancellationToken ct)
        {
            var pipeName = await TryEnsureReadyAsync(ct).ConfigureAwait(false) ? ClamdHost.Shared.PipeName : null;
            if (string.IsNullOrEmpty(pipeName))
                throw new InvalidOperationException(LocalizationService.GetString("Clamd_NotReady"));
            return pipeName;
        }

        private async Task<ScanResult> ScanSingleAsync(
            string filePath,
            IProgress<ScanProgress>? progress,
            CancellationToken ct)
        {
            var pipeName = await RequirePipeAsync(ct).ConfigureAwait(false);
            LastMode = "clamd";
            return await ScanSingleCoreAsync(filePath, pipeName, progress, ct).ConfigureAwait(false);
        }

        /// <summary>Un fichier : ouvert ici, envoyé à clamd en flux.</summary>
        private async Task<ScanResult> ScanSingleCoreAsync(
            string filePath,
            string pipeName,
            IProgress<ScanProgress>? progress,
            CancellationToken ct)
        {

            var result = new ScanResult
            {
                Type = ScanType.File,
                TargetPath = filePath,
                StartedAt = DateTime.Now,
                Status = ScanStatus.Running,
            };

            progress?.Report(new ScanProgress
            {
                Message = LocalizationService.Format("Scan_Progress_Starting", Path.GetFileName(filePath)),
                Phase = ScanPhase.Starting,
                CurrentFilePath = filePath,
            });

            try
            {
                ClamdCommandResult response;
                await using (var content = new FileStream(
                                 filePath,
                                 FileMode.Open,
                                 FileAccess.Read,
                                 FileShare.ReadWrite | FileShare.Delete,
                                 bufferSize: 1,
                                 FileOptions.SequentialScan | FileOptions.Asynchronous))
                {
                    if (content.Length > MaxInstreamBytes)
                        throw new ClamdStreamTooLargeException(MaxInstreamBytes);

                    using var client = ClamdClient.ForPipe(pipeName);
                    response = await client.InstreamAsync(content, MaxInstreamBytes, ct).ConfigureAwait(false);
                }

                lock (_parseLock)
                    ApplyInstreamResponse(response, filePath, result, progress, _exclusions);
                result.FinishedAt = DateTime.Now;
                if (ct.IsCancellationRequested)
                    result.Status = ScanStatus.Cancelled;
            }
            catch (OperationCanceledException)
            {
                result.Status = ScanStatus.Cancelled;
                result.FinishedAt = DateTime.Now;
            }
            catch (Exception ex)
            {
                result.Status = ScanStatus.Error;
                result.ErrorMessage = ex.Message;
                result.FinishedAt = DateTime.Now;
                result.UnscannedFiles.Add(filePath);
                AppLogger.Warn("ClamdEngine", "Fichier non scanné par clamd : " + PathRedaction.RedactPath(filePath) + " — " + ex.Message);
            }

            progress?.Report(new ScanProgress
            {
                Message = result.SummaryDisplay,
                Phase = ScanPhase.Completed,
                FilesScanned = result.FilesScanned,
                ThreatsFound = result.ThreatsFound,
            });

            return result;
        }

        /// <summary>
        /// Traduit la réponse INSTREAM (« stream: … ») en ligne clamscan pour le chemin réel,
        /// afin de réutiliser le même analyseur (exclusions, menaces).
        /// </summary>
        internal static void ApplyInstreamResponse(
            ClamdCommandResult response,
            string filePath,
            ScanResult result,
            IProgress<ScanProgress>? progress,
            IExclusionSettingsAccessor? exclusions)
        {
            var text = response.Text.Trim();
            const string prefix = "stream:";
            if (!response.Completed
                || ClamScanLineParser.IsErrorLine(text)
                || !text.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                result.Status = ScanStatus.Error;
                result.ErrorMessage = string.IsNullOrEmpty(text) ? "Réponse clamd incomplète" : text;
                result.UnscannedFiles.Add(filePath);
                return;
            }

            var verdict = text[prefix.Length..].Trim();
            if (verdict.Equals("OK", StringComparison.OrdinalIgnoreCase))
            {
                result.FilesScanned = 1;
                result.Status = ScanStatus.Completed;
                return;
            }

            if (verdict.EndsWith(" FOUND", StringComparison.OrdinalIgnoreCase))
            {
                ClamScanLineParser.ProcessLine(filePath + ": " + verdict, result, progress, exclusions);
                result.FilesScanned = 1;
                result.Status = ScanStatus.Completed;
                return;
            }

            result.Status = ScanStatus.Error;
            result.ErrorMessage = text;
            result.UnscannedFiles.Add(filePath);
        }
    }
}
