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

        // Regex : "C:\path\file.exe: Win.Trojan.Generic-123 FOUND"
        private static readonly Regex InfectedRegex =
            new Regex(@"^(.+):\s+(.+)\s+FOUND\s*$", RegexOptions.Compiled);

        // Lignes de scan : "C:\path\file.exe: OK" ou "...: ... FOUND"
        private static readonly Regex ScannedFileLineRegex =
            new(@"^(?<path>.+):\s+(?<verdict>OK|FOUND|Empty file|Excluded|Symbolic link)\s*$",
                RegexOptions.Compiled | RegexOptions.IgnoreCase);

        // Regex statistiques finales : "Scanned files: 123"
        private static readonly Regex StatsRegex =
            new Regex(@"^([\w\s]+):\s+(\d+)", RegexOptions.Compiled);

        // ── Construction ─────────────────────────────────────────────────────────

        public ClamAvEngine(string? clamavDir = null)
        {
            _clamavDir = clamavDir ?? ClamAvDatabasePaths.ResolveClamAvBinDir("clamscan.exe");
            _clamscanExe = Path.Combine(_clamavDir, "clamscan.exe");
        }

        /// <summary>
        /// Répertoire de la base de signatures : priorité dossier 'database' local,
        /// sinon le répertoire ClamAV lui-même (pour les installs système).
        /// </summary>
        public string DatabaseDir
        {
            get
            {
                // Même logique que FreshclamUpdater : dossier inscriptible (souvent
                // %LocalAppData% si l'app est sous Program Files).
                return ClamAvDatabasePaths.ResolveWritableDatabaseDir(_clamavDir);
            }
        }

        // ── Vérification ─────────────────────────────────────────────────────────

        private bool? _cachedInstalled;
        private DateTime _cachedInstalledAtUtc = DateTime.MinValue;
        private static readonly TimeSpan InstallProbeCacheTtl = TimeSpan.FromSeconds(60);

        /// <summary>
        /// Vérifie que clamscan.exe est présent et fonctionnel en exécutant <c>--version</c>.
        /// Résultat mis en cache 60 s pour limiter les lancements de processus à chaque navigation.
        /// </summary>
        public bool IsClamAvInstalled()
        {
            if (_cachedInstalled.HasValue
                && (DateTime.UtcNow - _cachedInstalledAtUtc) < InstallProbeCacheTtl)
                return _cachedInstalled.Value;

            var result = ProbeClamAvInstalled();
            _cachedInstalled = result;
            _cachedInstalledAtUtc = DateTime.UtcNow;
            return result;
        }

        private bool ProbeClamAvInstalled()
        {
            if (!File.Exists(_clamscanExe)) return false;
            try
            {
                using var proc = new Process { StartInfo = BuildStartInfo(_clamscanExe, "--version") };
                proc.Start();
                string output = proc.StandardOutput.ReadToEnd();
                proc.WaitForExit(3000);
                return output.Contains("ClamAV");
            }
            catch (Exception ex)
            {
                AppLogger.Warn("ClamAvEngine", "IsClamAvInstalled — version ou processus indisponible", ex);
                return false;
            }
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
            catch (Exception ex)
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
            return RunScanAsync(ScanType.Folder, folderPath, recursive: true, progress, ct);
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

        private async Task<ScanResult> RunScanAsync(
            ScanType type, string targetPath, bool recursive,
            IProgress<ScanProgress>? progress, CancellationToken ct)
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
                Message = $"Analyse de {Path.GetFileName(targetPath)}…",
                Phase = ScanPhase.Starting,
                CurrentFilePath = targetPath,
            });

            try
            {
                var startInfo = BuildStartInfo(_clamscanExe);
                BuildScanArgs(startInfo.ArgumentList, targetPath, recursive);
                using var proc = new Process { StartInfo = startInfo };

                proc.OutputDataReceived += (_, e) =>
                {
                    if (!string.IsNullOrWhiteSpace(e.Data))
                        ParseScanLine(e.Data, result, progress);
                };
                proc.ErrorDataReceived += (_, e) =>
                {
                    if (!string.IsNullOrWhiteSpace(e.Data))
                        AppLogger.Warn("ClamAV", $"stderr: {e.Data}");
                };

                proc.Start();
                proc.BeginOutputReadLine();
                proc.BeginErrorReadLine();

                await WaitForProcessAsync(proc, ct);

                // Drain : selon la doc Microsoft, après un WaitForExit asynchrone
                // avec des async readers (BeginOutputReadLine), il faut un appel
                // synchrone WaitForExit() pour garantir que les derniers buffers
                // stdout/stderr aient été remis aux handlers.
                try { proc.WaitForExit(); } catch { /* déjà terminé */ }

                result.FinishedAt = DateTime.Now;
                result.Status = ct.IsCancellationRequested
                    ? ScanStatus.Cancelled
                    : ScanStatus.Completed;

                if (ct.IsCancellationRequested && !proc.HasExited)
                    proc.Kill(entireProcessTree: true);
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
            }

            progress?.Report(new ScanProgress
            {
                Message = result.SummaryDisplay,
                Phase = ScanPhase.Completed,
                FilesScanned = result.FilesScanned,
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
            string line, ScanResult result, IProgress<ScanProgress>? progress)
        {
            var infectedMatch = InfectedRegex.Match(line);
            if (infectedMatch.Success)
            {
                var filePath = infectedMatch.Groups[1].Value.Trim();
                var virusName = infectedMatch.Groups[2].Value.Trim();

                if (ExclusionSettings.Current.IsFileExcluded(filePath))
                    return;

                long fileSize = -1;
                try { fileSize = new FileInfo(filePath).Length; }
                catch (Exception ex)
                {
                    AppLogger.Warn("ClamAvEngine", $"Taille fichier indisponible : {filePath}", ex);
                }

                var threat = new ThreatInfo
                {
                    FilePath = filePath,
                    VirusName = virusName,
                    DetectedAt = DateTime.Now,
                    Status = ThreatStatus.Detected,
                    FileSize = fileSize,
                    DetectedBy = "ClamAV"
                };
                result.Threats.Add(threat);

                progress?.Report(new ScanProgress
                {
                    Message = $"{threat.VirusName} — {filePath}",
                    Phase = ScanPhase.ThreatFound,
                    ThreatInfo = threat,
                    FilesScanned = result.FilesScanned,
                    ThreatsFound = result.ThreatsFound,
                    CurrentFilePath = filePath,
                });
                return;
            }

            if (line.StartsWith("Scanned files:") || line.StartsWith("Data scanned:"))
            {
                ParseStats(line, result);
                // Mise à jour finale du compteur depuis les stats officielles de
                // clamscan (autorité absolue) — remplace l'estimation incrémentale.
                progress?.Report(new ScanProgress
                {
                    Message = $"{result.FilesScanned:N0} fichiers analysés.",
                    Phase = ScanPhase.Scanning,
                    FilesScanned = result.FilesScanned,
                    ThreatsFound = result.ThreatsFound,
                });
                return;
            }

            // Comptage strict : seules les lignes au format "<chemin>: <verdict>"
            // sont comptabilisées. L'ancienne heuristique (line.Contains(":"))
            // captait aussi les lignes de stats, warnings et lettres de lecteur,
            // donnant un compteur systématiquement faux.
            if (ScannedFileLineRegex.IsMatch(line))
            {
                var m = ScannedFileLineRegex.Match(line);
                var scannedPath = m.Success ? m.Groups["path"].Value.Trim() : string.Empty;

                result.FilesScanned++;
                const int pathUpdateEvery = 12;
                if (result.FilesScanned % pathUpdateEvery == 0 || result.FilesScanned % 50 == 0)
                {
                    progress?.Report(new ScanProgress
                    {
                        Message = $"{result.FilesScanned:N0} fichiers analysés…",
                        Phase = ScanPhase.Scanning,
                        FilesScanned = result.FilesScanned,
                        ThreatsFound = result.ThreatsFound,
                        CurrentFilePath = string.IsNullOrEmpty(scannedPath) ? null : scannedPath,
                    });
                }
            }
        }

        private static void ParseStats(string line, ScanResult result)
        {
            var m = StatsRegex.Match(line);
            if (!m.Success) return;
            var key = m.Groups[1].Value.Trim().ToLower();
            var value = long.Parse(m.Groups[2].Value);
            switch (key)
            {
                case "scanned files": result.FilesScanned = (int)value; break;
                case "data scanned": result.TotalBytesScanned = value * 1024; break;
            }
        }

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
                args.Add($"--exclude={AppInstallPaths.GetClamScanExcludePattern()}");

            args.Add("--stdout");
            // NB: --no-summary supprimé. Le résumé "Scanned files: N" en fin
            // d'output est notre source de vérité pour le compteur final
            // (cf. ParseStats), à la place de l'incrément ligne par ligne.

            var dbDir = DatabaseDir;
            if (!string.IsNullOrEmpty(dbDir))
                args.Add($"--database={dbDir}"); // ArgumentList gère l'échappement (quoting)

            args.Add(target);
        }

        /// <summary>
        /// Crée un ProcessStartInfo avec les bons drapeaux I/O. L'appelant doit
        /// remplir <c>ArgumentList</c> via une surcharge dédiée (BuildScanArgs).
        /// On ne définit jamais Arguments en chaîne — pour un échappement sûr.
        /// </summary>
        private static ProcessStartInfo BuildStartInfo(string exe) =>
            new ProcessStartInfo
            {
                FileName = exe,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                StandardOutputEncoding = System.Text.Encoding.UTF8
            };

        /// <summary>Surcharge pour les commandes simples (--version) avec un seul argument.</summary>
        private static ProcessStartInfo BuildStartInfo(string exe, string singleArg)
        {
            var psi = BuildStartInfo(exe);
            psi.ArgumentList.Add(singleArg);
            return psi;
        }

        private static async Task WaitForProcessAsync(Process proc, CancellationToken ct)
        {
            var tcs = new TaskCompletionSource<bool>();
            proc.EnableRaisingEvents = true;
            proc.Exited += (_, _) => tcs.TrySetResult(true);

            using (ct.Register(() =>
            {
                try { if (!proc.HasExited) proc.Kill(entireProcessTree: true); }
                catch (Exception ex)
                {
                    AppLogger.Warn("ClamAvEngine", "Annulation — arrêt clamscan", ex);
                }
                tcs.TrySetCanceled();
            }))
            {
                try { await tcs.Task; }
                catch (TaskCanceledException) { }
            }
        }

        private async Task<(string stdout, string stderr)> RunProcessAsync(string exe, string args)
        {
            using var proc = new Process { StartInfo = BuildStartInfo(exe, args) };
            proc.Start();
            var stdout = await proc.StandardOutput.ReadToEndAsync();
            var stderr = await proc.StandardError.ReadToEndAsync();
            await proc.WaitForExitAsync();
            return (stdout, stderr);
        }

        private void ValidateInstallation()
        {
            if (!File.Exists(_clamscanExe))
                throw new InvalidOperationException(
                    $"clamscan.exe introuvable dans : {_clamavDir}\n" +
                    "Placez les binaires ClamAV dans 'clamav/x64/' ou 'clamav/x86/'.");
        }

        // GetQuickScanTargets retiré : la source unique est désormais
        // ScanTargets.QuickScanTargets() (cf. ScanTargets.cs).
    }

}
