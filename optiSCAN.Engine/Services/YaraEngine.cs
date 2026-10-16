// SPDX-License-Identifier: GPL-3.0-or-later
using optiSCAN.Localization;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace optiSCAN.Services
{
    /// <summary>
    /// Moteur YARA — exécute yara64/yara32.exe en ligne de commande.
    /// Compile les règles avec yarac64/yarac32.exe pour accélérer les scans répétés.
    /// </summary>
    public class YaraEngine : IYaraOrchestratorBackend
    {
        /// <summary>
        /// Fréquence d'émission des messages de progression dans RunYaraScanRecursiveAsync :
        /// un message est émis toutes les N lignes stdout traitées.
        /// Exposé pour que ScanOrchestrator puisse interpoler le compteur de fichiers.
        /// </summary>
        public const int YaraProgressInterval = 20;

        private readonly string _yaraExe;     // yara64.exe / yara32.exe
        private readonly string _yaracExe;    // yarac64.exe / yarac32.exe (compilateur)
        private readonly string _rulesDirectory;
        private readonly string _compiledRulesPath;
        private readonly string _rulesCountCachePath;
        // Empreinte enregistrée au moment de la dernière compilation réussie.
        // Permet de détecter qu'un .yar a été modifié depuis la dernière compilation
        // sans attendre la suppression manuelle de _compiled.yarc.
        private readonly string _compiledStampPath;
        private readonly IExclusionSettingsAccessor _exclusions;

        /// <summary>Limite de caractères capturés depuis la sortie standard de yara.</summary>
        private const int MaxYaraStdoutCaptureChars = 2_000_000;

        public bool IsAvailable { get; private set; }
        public int RulesCount { get; private set; }

        /// <summary>
        /// <c>true</c> si <c>_compiled.yarc</c> existe ET correspond à l'état actuel des fichiers .yar.
        /// Un <c>false</c> ici déclenche automatiquement une recompilation au prochain scan.
        /// </summary>
        public bool HasCompiled => YaraRulesCacheSupport.IsCompiledUpToDate(
            _rulesDirectory, _compiledRulesPath, _compiledStampPath);

        // ── Constructeur ─────────────────────────────────────────────────────────

        public YaraEngine(
            string? yaraDir = null,
            string? rulesDir = null,
            IExclusionSettingsAccessor? exclusions = null)
        {
            _exclusions = exclusions ?? new DefaultExclusionSettingsAccessor();
            var baseDir = AppDomain.CurrentDomain.BaseDirectory;
            var arch = Environment.Is64BitProcess ? "64" : "32";

            var resolvedYaraDir = yaraDir ?? Path.Combine(baseDir, "yara");

            _yaraExe = Path.Combine(resolvedYaraDir, $"yara{arch}.exe");
            _yaracExe = Path.Combine(resolvedYaraDir, $"yarac{arch}.exe");

            _rulesDirectory = YaraRulesLocation.ResolveWritable(rulesDir);
            _compiledRulesPath = Path.Combine(_rulesDirectory, "_compiled.yarc");
            _rulesCountCachePath = Path.Combine(_rulesDirectory, ".rules_count.cache");
            _compiledStampPath = Path.Combine(_rulesDirectory, "_compiled.stamp");

            IsAvailable = CheckAvailability();
            if (IsAvailable)
                RulesCount = CountRules();
        }

        // ── Disponibilité ─────────────────────────────────────────────────────────

        private bool CheckAvailability()
        {
            if (!File.Exists(_yaraExe))
                return false;
            if (!Directory.Exists(_rulesDirectory))
                return false;
            return Directory.GetFiles(_rulesDirectory, "*.yar").Length > 0;
        }

        /// <summary>
        /// Vérifie que <c>_compiled.yarc</c> existe ET que son empreinte correspond
        /// à l'état actuel des fichiers .yar. Retourne <c>false</c> si le fichier
        /// est absent, si <c>_compiled.stamp</c> est absent ou périmé (modification
        /// manuelle d'une règle, ajout/suppression d'un .yar).
        /// </summary>
        // L2 fix : regex multiline plutôt que StartsWith("rule ") ligne par ligne.
        // StartsWith manquait les règles précédées d'indentation, de commentaires,
        // ou définies sans espace supplémentaire ; la regex matche "rule <ident>"
        // n'importe où en début de ligne (y compris avec tabulation).
        private static readonly Regex RuleStartRegex = new(
            @"^\s*rule\s+[A-Za-z_]\w*",
            RegexOptions.Multiline | RegexOptions.Compiled);

        private int CountRules()
        {
            try
            {
                var files = Directory.GetFiles(_rulesDirectory, "*.yar");
                if (files.Length == 0)
                    return 0;

                Array.Sort(files, StringComparer.OrdinalIgnoreCase);
                var stamp = YaraRulesCacheSupport.ComputeRulesDirectoryFingerprint(files);
                if (TryReadRulesCountCache(stamp, out var cached))
                    return cached;

                int count = 0;
                foreach (var f in files)
                    count += RuleStartRegex.Count(File.ReadAllText(f));
                if (count <= 0)
                    count = files.Length;

                TryWriteRulesCountCache(stamp, count);
                return count;
            }
            catch (Exception ex) when (!ex.IsFatal())
            {
                AppLogger.Warn("YaraEngine", "CountRules", ex);
                return 0;
            }
        }

        private bool TryReadRulesCountCache(string stamp, out int count)
        {
            count = 0;
            if (!File.Exists(_rulesCountCachePath))
                return false;
            try
            {
                var lines = File.ReadAllLines(_rulesCountCachePath);
                if (lines.Length < 2)
                    return false;
                if (!string.Equals(lines[0].Trim(), stamp, StringComparison.Ordinal))
                    return false;
                return int.TryParse(lines[1].Trim(), out count) && count >= 0;
            }
            catch (Exception ignored) when (!ignored.IsFatal())
            {
                return false;
            }
        }

        private void TryWriteRulesCountCache(string stamp, int count)
        {
            try
            {
                File.WriteAllText(_rulesCountCachePath, stamp + Environment.NewLine + count, Encoding.UTF8);
            }
            catch (Exception ex) when (!ex.IsFatal())
            {
                AppLogger.Warn("YaraEngine", "Écriture .rules_count.cache", ex);
            }
        }

        /// <summary>Accumule stdout yara avec un plafond pour limiter la mémoire.</summary>
        private sealed class YaraStdoutCapture
        {
            public readonly StringBuilder Builder = new();
            public bool Truncated;
            private int _capturedChars;

            public void SurLigneYara(string? line, int maxChars)
            {
                if (line == null || Truncated)
                    return;
                var add = line.Length + 2;
                if (_capturedChars + add > maxChars)
                {
                    Truncated = true;
                    return;
                }
                Builder.AppendLine(line);
                _capturedChars += add;
            }
        }

        /// <summary>Plafond de stderr gardé pour le journal : un scan complet peut produire une erreur par fichier illisible.</summary>
        private const int MaxStderrCaptureChars = 64 * 1024;

        private static void AppendBounded(StringBuilder sb, string? line)
        {
            if (line == null)
                return;
            lock (sb)
            {
                if (sb.Length < MaxStderrCaptureChars)
                    sb.AppendLine(line);
            }
        }

        /// <summary>
        /// Une seule compilation à la fois : le temps réel lance jusqu'à trois scans en parallèle,
        /// et chacun compilait <c>_compiled.yarc</c> à l'endroit même où les autres le lisaient.
        /// </summary>
        private static readonly SemaphoreSlim CompileGate = new(1, 1);

        // ── Compilation des règles ────────────────────────────────────────────────

        /// <summary>
        /// Compile toutes les règles .yar en un fichier .yarc pour accélérer les scans.
        /// Utilise yarac64.exe (ou yarac32.exe).
        /// </summary>
        public async Task<bool> CompileRulesAsync(CancellationToken ct = default)
        {
            if (!IsAvailable) return false;
            if (!File.Exists(_yaracExe)) return false; // yarac non disponible

            await CompileGate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                // Un autre scan a pu compiler pendant l'attente.
                if (HasCompiled)
                    return true;
                return await CompileRulesCoreAsync(ct).ConfigureAwait(false);
            }
            finally
            {
                CompileGate.Release();
            }
        }

        private async Task<bool> CompileRulesCoreAsync(CancellationToken ct)
        {
            var ruleFiles = Directory.GetFiles(_rulesDirectory, "*.yar");
            if (ruleFiles.Length == 0) return false;

            // ArgumentList plutôt que concaténation de chaîne —
            // chaque fichier de règle est passé comme argument distinct, le
            // quoting est géré par .NET (CommandLineToArgvW round-trip safe)
            // même si un chemin contient des espaces ou des guillemets.
            // Compilation vers un fichier temporaire, puis remplacement : un scan en cours ne lit
            // jamais un .yarc à moitié écrit. Sous SYSTEM, yarac est confiné et n'écrit que dans
            // le dossier de travail du conteneur ; le résultat est recopié dans le dossier des
            // règles, dont il prend l'ACL (le conteneur ne peut pas le modifier ensuite).
            var compiledTemp = ScannerSandbox.IsRequired
                ? ScannerSandbox.NewWorkFile("yarac_", ".tmp")
                : _compiledRulesPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
            var args = new List<string>(ruleFiles) { compiledTemp };
            var stderr = new StringBuilder();

            ScannerProcess? process = null;
            try
            {
                // Les deux flux sont drainés : un yarac qui remplit le tampon de sortie
                // standard sans être lu resterait bloqué indéfiniment.
                process = ScannerProcess.Start(new ScannerLaunch(_yaracExe, args)
                {
                    OnError = line => AppendBounded(stderr, line),
                    ReadableDirectories = new[] { _rulesDirectory },
                });
                var running = process;
                using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
                deadline.CancelAfter(CompileTimeout);
                using (deadline.Token.Register(running.Kill))
                {
                    try
                    {
                        await running.WaitForExitAsync(deadline.Token).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException) when (!ct.IsCancellationRequested)
                    {
                        AppLogger.Warn("yarac", "Compilation arrêtée : délai dépassé");
                        return false;
                    }
                }

                var err = stderr.ToString();
                if (!string.IsNullOrWhiteSpace(err))
                    AppLogger.Warn("yarac", PathRedaction.RedactPath(err));

                var success = running.ExitCode == 0 && File.Exists(compiledTemp);
                if (success)
                {
                    try
                    {
                        if (ScannerSandbox.IsRequired)
                        {
                            var local = _compiledRulesPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
                            File.Copy(compiledTemp, local, overwrite: false);
                            File.Move(local, _compiledRulesPath, overwrite: true);
                        }
                        else
                        {
                            File.Move(compiledTemp, _compiledRulesPath, overwrite: true);
                        }
                    }
                    catch (Exception moveEx) when (!moveEx.IsFatal())
                    {
                        // Ancien .yarc encore lu par un scan : il reste en place, la compilation
                        // sera refaite au prochain scan.
                        AppLogger.Warn("yarac", "Remplacement de _compiled.yarc différé", moveEx);
                        success = false;
                    }
                }
                if (success)
                {
                    // Persiste l'empreinte courante → HasCompiled détectera tout
                    // changement ultérieur dans les .yar sans attendre une suppression manuelle.
                    try
                    {
                        Array.Sort(ruleFiles, StringComparer.OrdinalIgnoreCase);
                        YaraRulesCacheSupport.WriteCompiledStamp(_compiledStampPath, ruleFiles);
                    }
                    catch (Exception stampEx) when (!stampEx.IsFatal())
                    {
                        AppLogger.Warn("yarac", "Écriture _compiled.stamp échouée", stampEx);
                    }
                }
                return success;
            }
            catch (Exception ex) when (!ex.IsFatal())
            {
                AppLogger.Error("yarac", "Compilation échouée", ex);
                return false;
            }
            finally
            {
                process?.Dispose();
                try { if (File.Exists(compiledTemp)) File.Delete(compiledTemp); }
                catch (Exception ex) when (!ex.IsFatal()) { AppLogger.Debug("yarac", "Fichier temporaire : " + ex.Message); }
                CleanupLocalCompileTemps();
            }
        }

        // ── Scan d'un fichier ─────────────────────────────────────────────────────

        /// <summary>
        /// Scanne un fichier. Retourne la liste des règles qui ont matché.
        /// Utilise les règles compilées si disponibles, sinon les .yar un par un.
        /// </summary>
        public async Task<List<YaraMatch>> ScanFileAsync(
            string filePath, CancellationToken ct = default)
        {
            var matches = new List<YaraMatch>();
            if (!IsAvailable || !File.Exists(filePath)) return matches;
            if (_exclusions.Current.IsFileExcluded(filePath)) return matches;
            if (SandboxStaging.NeedsStaging(filePath))
                return await ScanStagedAsync(new[] { filePath }, progress: null, ct).ConfigureAwait(false);
            var state = new YaraRunState();

            // Tenter compilation si pas encore fait
            if (!HasCompiled)
                await CompileRulesAsync(ct);

            if (HasCompiled)
            {
                // Scan avec règles compilées : yara64.exe --compiled-rules rules.yarc fichier
                // ArgumentList → guillemets/échappement sûr, pas de concaténation de chaîne.
                await CollectAsync(matches, state, RunYaraScanAsync(
                    new[] { "--compiled-rules", _compiledRulesPath, filePath },
                    filePath, ct));
            }
            else
            {
                // Solution de repli : scan avec chaque .yar individuellement
                foreach (var ruleFile in Directory.GetFiles(_rulesDirectory, "*.yar"))
                {
                    if (ct.IsCancellationRequested) break;
                    await CollectAsync(matches, state, RunYaraScanAsync(
                        new[] { ruleFile, filePath }, filePath, ct));
                }
            }

            return state.Finish(matches);
        }

        /// <summary>
        /// Scanne une liste de fichiers en lots (un processus yara par lot).
        /// Évite le scan récursif complet du volume pour le mode USB rapide.
        /// </summary>
        public async Task<List<YaraMatch>> ScanFilesAsync(
            IReadOnlyList<string> files,
            IProgress<string>? progress = null,
            CancellationToken ct = default)
        {
            if (!IsAvailable || files.Count == 0) return new List<YaraMatch>();
            if (files.Any(SandboxStaging.NeedsStaging))
            {
                return await ScanStagedAsync(
                    files.Where(f => File.Exists(f) && !_exclusions.Current.IsFileExcluded(f)),
                    progress,
                    ct).ConfigureAwait(false);
            }
            return await ScanFilesCoreAsync(files, progress, ct).ConfigureAwait(false);
        }

        /// <summary>
        /// Analyse confinée de fichiers que le conteneur ne peut pas lire : copie par lots,
        /// analyse des copies, correspondances rapportées aux chemins d'origine.
        /// </summary>
        private async Task<List<YaraMatch>> ScanStagedAsync(
            IEnumerable<string> files,
            IProgress<string>? progress,
            CancellationToken ct)
        {
            var matches = new List<YaraMatch>();
            var state = new YaraRunState();
            var tooLarge = 0;
            foreach (var chunk in SandboxStaging.Batches(files))
            {
                if (ct.IsCancellationRequested) break;
                using var batch = SandboxStaging.Stage(chunk, ct);
                tooLarge += batch.TooLarge.Count;
                if (batch.Skipped.Count > 0)
                    state.Incomplete ??= $"YARA : {batch.Skipped.Count} fichier(s) illisible(s) non analysé(s).";

                var staged = batch.StagedPaths;
                if (staged.Count == 0)
                    continue;

                var found = new List<YaraMatch>();
                await CollectAsync(found, state, ScanFilesCoreAsync(staged, progress, ct)).ConfigureAwait(false);
                foreach (var match in found)
                    match.FilePath = batch.OriginalOf(match.FilePath);
                matches.AddRange(found);
            }

            if (tooLarge > 0)
                AppLogger.Info("YaraEngine", $"{tooLarge} fichier(s) de plus de {SandboxStaging.MaxFileBytes / (1024 * 1024)} Mo non copiés pour YARA (analysés par ClamAV).");
            return state.Finish(matches);
        }

        private async Task<List<YaraMatch>> ScanFilesCoreAsync(
            IReadOnlyList<string> files,
            IProgress<string>? progress,
            CancellationToken ct)
        {
            var matches = new List<YaraMatch>();
            if (!HasCompiled)
                await CompileRulesAsync(ct);

            var state = new YaraRunState();
            const int batchSize = 256;
            for (var i = 0; i < files.Count; i += batchSize)
            {
                if (ct.IsCancellationRequested) break;

                var batch = new List<string>(batchSize);
                for (var j = i; j < files.Count && batch.Count < batchSize; j++)
                {
                    var path = files[j];
                    if (File.Exists(path) && !_exclusions.Current.IsFileExcluded(path))
                        batch.Add(path);
                }

                if (batch.Count == 0) continue;

                progress?.Report(LocalizationService.Format("Scan_Yara_Recursive", batch.Count.ToString()));

                // yara n'accepte qu'une cible : plusieurs fichiers à la suite seraient lus
                // comme des fichiers de règles (« can't accept multiple rules files » avec -C).
                // --scan-list (YARA ≥ 4.1) lit la liste des cibles dans un fichier.
                var listFile = ScannerSandbox.NewWorkFile("optiscan_yara_", ".txt");
                try
                {
                    await File.WriteAllLinesAsync(listFile, batch, new UTF8Encoding(false), ct).ConfigureAwait(false);
                    if (HasCompiled)
                    {
                        await CollectAsync(matches, state, RunYaraScanRecursiveAsync(
                            new[] { "-N", "--compiled-rules", "--scan-list", _compiledRulesPath, listFile },
                            ct,
                            progress)).ConfigureAwait(false);
                    }
                    else
                    {
                        foreach (var ruleFile in Directory.GetFiles(_rulesDirectory, "*.yar"))
                        {
                            if (ct.IsCancellationRequested) break;
                            await CollectAsync(matches, state, RunYaraScanRecursiveAsync(
                                new[] { "-N", "--scan-list", ruleFile, listFile },
                                ct,
                                progress)).ConfigureAwait(false);
                        }
                    }
                }
                finally
                {
                    try { File.Delete(listFile); }
                    catch (Exception ex) when (!ex.IsFatal()) { AppLogger.Debug("YaraEngine", "Liste temporaire : " + ex.Message); }
                }
            }

            return state.Finish(matches);
        }

        /// <summary>Retourne true si au moins une règle YARA matche le fichier.</summary>
        public async Task<bool> IsMaliciousAsync(string filePath, CancellationToken ct = default)
            => (await ScanFileAsync(filePath, ct)).Count > 0;

        /// <summary>
        /// Scanne un dossier entier en UN SEUL processus yara avec --recursive.
        ///
        /// L'ancienne approche (un processus par fichier dans ScanOrchestrator)
        /// dominait le temps de scan pour les gros dossiers : pour 10 000 fichiers,
        /// 10 000 lancements de yara64.exe, soit ~10 minutes uniquement de
        /// surcoût lié aux lancements. Cette méthode passe le dossier directement à yara qui
        /// l'itère lui-même, divisant le temps global par un facteur 10 à 50.
        ///
        /// La sortie de yara conserve le format "RuleName Path" pour chaque match,
        /// avec un chemin absolu permettant de reconstruire le ThreatInfo correctement.
        /// </summary>
        public async Task<List<YaraMatch>> ScanFolderAsync(
            string folderPath,
            IProgress<string>? progress = null,
            CancellationToken ct = default)
        {
            var matches = new List<YaraMatch>();
            if (!IsAvailable || !Directory.Exists(folderPath)) return matches;
            if (AppInstallPaths.IsUnderInstallRoot(folderPath)) return matches;
            if (SandboxStaging.NeedsStaging(folderPath))
            {
                progress?.Report(LocalizationService.Format("Scan_Yara_Recursive", Path.GetFileName(folderPath)));
                return await ScanStagedAsync(
                    SandboxStaging.EnumerateFolder(folderPath)
                        .Where(f => !AppInstallPaths.IsUnderInstallRoot(f) && !_exclusions.Current.IsFileExcluded(f)),
                    progress,
                    ct).ConfigureAwait(false);
            }

            // Compilation au besoin (idem ScanFileAsync).
            if (!HasCompiled)
                await CompileRulesAsync(ct);

            // Construction de la commande : --recursive + dossier en argument.
            // -N (no-warnings) supprime les avertissements verbeux.
            // ArgumentList : guillemets et chemins correctement échappés.
            string[] args;
            if (HasCompiled)
            {
                args = new[] { "-N", "--compiled-rules", "--recursive", _compiledRulesPath, folderPath };
            }
            else
            {
                // Sans règles compilées : scan séquentiel par règle, encore N fois
                // moins de lancements qu'un processus par fichier.
                var state = new YaraRunState();
                foreach (var ruleFile in Directory.GetFiles(_rulesDirectory, "*.yar"))
                {
                    if (ct.IsCancellationRequested) break;
                    progress?.Report(LocalizationService.Format("Scan_Yara_Rule", Path.GetFileNameWithoutExtension(ruleFile)));
                    // Récursif : la sortie porte le chemin de chaque fichier (« Règle chemin »).
                    await CollectAsync(matches, state, RunYaraScanRecursiveAsync(
                        new[] { "-N", "--recursive", ruleFile, folderPath },
                        ct,
                        progress)).ConfigureAwait(false);
                }
                return state.Finish(matches);
            }

            progress?.Report(LocalizationService.Format("Scan_Yara_Recursive", Path.GetFileName(folderPath)));
            return await RunYaraScanRecursiveAsync(args, ct, progress);
        }

        /// <summary>
        /// Variante de RunYaraScanAsync pour les scans récursifs : la sortie yara
        /// est au format "RuleName /chemin/absolu/fichier" — chaque ligne est un
        /// match indépendant, avec un fichier potentiellement différent.
        /// </summary>
        private async Task<List<YaraMatch>> RunYaraScanRecursiveAsync(
            IEnumerable<string> args,
            CancellationToken ct,
            IProgress<string>? progress = null)
        {
            var matches = new List<YaraMatch>();
            var stdoutLines = 0;

            var cap = new YaraStdoutCapture();
            var stderrLines = new StringBuilder();
            ScannerProcess? process = null;
            try
            {
                process = ScannerProcess.Start(new ScannerLaunch(_yaraExe, args)
                {
                    OnOutput = line =>
                    {
                        cap.SurLigneYara(line, MaxYaraStdoutCaptureChars);
                        if (string.IsNullOrEmpty(line)) return;
                        var n = System.Threading.Interlocked.Increment(ref stdoutLines);
                        if (progress != null && (n == 1 || n % YaraProgressInterval == 0))
                            progress.Report(line);
                    },
                    OnError = line => AppendBounded(stderrLines, line),
                    ReadableDirectories = ScanReadableDirectories(),
                });

                var running = process;
                using (ct.Register(running.Kill))
                {
                    await running.WaitForExitAsync(ct).ConfigureAwait(false);
                }

                if (cap.Truncated)
                {
                    AppLogger.Warn("YaraEngine",
                        "Sortie stdout YARA tronquée (limite mémoire) — scan signalé incomplet.");
                }

                var stderrContent = stderrLines.ToString().Trim();
                if (!string.IsNullOrEmpty(stderrContent))
                    AppLogger.Warn("YARA/stderr (récursif)", PathRedaction.RedactPath(stderrContent));


                foreach (var line in cap.Builder.ToString()
                    .Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    if (line.StartsWith("0x")) continue;

                    // Format yara : "RuleName <espace> /chemin/absolu/fichier"
                    // Le chemin peut contenir des espaces — on prend le premier
                    // espace après la règle puis tout le reste.
                    var spaceIdx = line.IndexOf(' ');
                    if (spaceIdx <= 0) continue;

                    var ruleName = line[..spaceIdx].Trim();
                    var matchedPath = line[(spaceIdx + 1)..].Trim();

                    if (!string.IsNullOrEmpty(ruleName) && !string.IsNullOrEmpty(matchedPath)
                        && !_exclusions.Current.IsFileExcluded(matchedPath))
                        matches.Add(new YaraMatch { RuleName = ruleName, FilePath = matchedPath });
                }

                // Après l'analyse : un code non nul ne doit pas faire perdre les correspondances lues.
                ThrowIfYaraFailed(process, ct, matches, cap.Truncated);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (IOException)
            {
                throw;
            }
            catch (Exception ex) when (!ex.IsFatal())
            {
                // yara introuvable, refus de lancement... : rien n'a été analysé, ce n'est pas « propre ».
                AppLogger.Error("YARA", "Scan récursif", ex);
                throw new YaraScanIncompleteException("YARA n'a pas pu analyser : " + ex.Message, matches);
            }
            finally
            {
                process?.Dispose();
            }

            return matches;
        }

        // ── Helpers ──────────────────────────────────────────────────────────────

        /// <summary>
        /// YARA rend 0 quand le scan est allé au bout, même sans correspondance.
        /// Un autre code signifie que le fichier n'a pas été analysé.
        /// </summary>
        /// <summary>Délai maximal d'un yara sur un seul fichier.</summary>
        internal static readonly TimeSpan SingleFileScanTimeout = TimeSpan.FromMinutes(5);

        /// <summary>Délai maximal de compilation des règles par yarac.</summary>
        internal static readonly TimeSpan CompileTimeout = TimeSpan.FromMinutes(10);

        /// <summary>
        /// Dossiers que yara doit lire : les règles et, sous SYSTEM, les copies d'analyse.
        /// </summary>
        private IReadOnlyList<string> ScanReadableDirectories()
        {
            var directories = new List<string> { _rulesDirectory };
            directories.AddRange(ScannerSandbox.StagingDirectories());
            return directories;
        }

        /// <summary>Copies locales de .yarc laissées par un arrêt pendant le remplacement.</summary>
        private void CleanupLocalCompileTemps()
        {
            try
            {
                var cutoff = DateTime.UtcNow - CompileTimeout;
                foreach (var stale in Directory.EnumerateFiles(_rulesDirectory, "_compiled.yarc.*.tmp"))
                {
                    if (File.GetLastWriteTimeUtc(stale) < cutoff)
                        File.Delete(stale);
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                AppLogger.Debug("yarac", "Copies temporaires : " + ex.Message);
            }
        }

        private static void ThrowIfYaraFailed(ScannerProcess process, CancellationToken ct, List<YaraMatch> matches, bool outputTruncated = false)
        {
            if (ct.IsCancellationRequested)
                return;
            if (process.HasExited && process.ExitCode != 0)
                throw new YaraScanIncompleteException("YARA s'est terminé avec le code " + process.ExitCode + ".", matches);
            // Sortie plafonnée : des correspondances au-delà sont perdues, le résultat ne
            // peut pas être déclaré « propre ».
            if (outputTruncated)
                throw new YaraScanIncompleteException("Sortie YARA tronquée : des correspondances peuvent manquer.", matches);
        }

        /// <summary>
        /// Exécute un lancement YARA et cumule ses correspondances, même s'il échoue :
        /// l'échec est mémorisé dans <paramref name="state"/> et relevé à la fin.
        /// </summary>
        private static async Task CollectAsync(List<YaraMatch> matches, YaraRunState state, Task<List<YaraMatch>> run)
        {
            try
            {
                matches.AddRange(await run.ConfigureAwait(false));
            }
            catch (YaraScanIncompleteException ex)
            {
                matches.AddRange(ex.PartialMatches);
                state.Incomplete ??= ex.Message;
            }
        }

        private sealed class YaraRunState
        {
            public string? Incomplete { get; set; }

            public List<YaraMatch> Finish(List<YaraMatch> matches)
            {
                if (Incomplete != null)
                    throw new YaraScanIncompleteException(Incomplete, matches);
                return matches;
            }
        }

        private async Task<List<YaraMatch>> RunYaraScanAsync(
            IEnumerable<string> args, string filePath, CancellationToken ct)
        {
            var matches = new List<YaraMatch>();

            var cap = new YaraStdoutCapture();
            var stderrLines = new StringBuilder();
            ScannerProcess? process = null;
            try
            {
                // Sortie lue en UTF-8 : chemins accentués intacts. Stderr gardé pour le journal.
                process = ScannerProcess.Start(new ScannerLaunch(_yaraExe, args)
                {
                    OnOutput = line => cap.SurLigneYara(line, MaxYaraStdoutCaptureChars),
                    OnError = line => AppendBounded(stderrLines, line),
                    ReadableDirectories = ScanReadableDirectories(),
                });

                // Délai par fichier : un yara bloqué (fichier piégé, règle coûteuse) est arrêté
                // et le scan signalé incomplet, au lieu d'attendre indéfiniment.
                var running = process;
                using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
                deadline.CancelAfter(SingleFileScanTimeout);
                using (deadline.Token.Register(running.Kill))
                {
                    try
                    {
                        await running.WaitForExitAsync(deadline.Token).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException) when (!ct.IsCancellationRequested)
                    {
                        throw new YaraScanIncompleteException("YARA : délai dépassé.", matches);
                    }
                }

                if (cap.Truncated)
                {
                    AppLogger.Warn("YaraEngine",
                        "Sortie stdout YARA tronquée (limite mémoire) — scan signalé incomplet.");
                }

                // Log les erreurs/avertissements YARA capturés depuis stderr
                var stderrContent = stderrLines.ToString().Trim();
                if (!string.IsNullOrEmpty(stderrContent))
                    AppLogger.Warn("YARA/stderr", PathRedaction.RedactPath(stderrContent));


                // Format sortie YARA : "RuleName FilePath"
                foreach (var line in cap.Builder.ToString()
                    .Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    // Ignorer les lignes qui commencent par 0x (hex dump des strings)
                    if (line.StartsWith("0x")) continue;

                    var spaceIdx = line.IndexOf(' ');
                    if (spaceIdx > 0)
                    {
                        var ruleName = line[..spaceIdx].Trim();
                        if (!string.IsNullOrEmpty(ruleName))
                            matches.Add(new YaraMatch { RuleName = ruleName, FilePath = filePath });
                    }
                }

                ThrowIfYaraFailed(process, ct, matches, cap.Truncated);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (IOException)
            {
                throw;
            }
            catch (Exception ex) when (!ex.IsFatal())
            {
                AppLogger.Error("YARA", "Scan", ex);
                throw new YaraScanIncompleteException("YARA n'a pas pu analyser : " + ex.Message, matches);
            }
            finally
            {
                process?.Dispose();
            }

            return matches;
        }

        // ── Invalidation du cache compilé ─────────────────────────────────────────

        /// <summary>Supprime le fichier de règles compilées (force recompilation).</summary>
        public void InvalidateCompiledRules()
        {
            try
            {
                if (File.Exists(_compiledRulesPath))
                    File.Delete(_compiledRulesPath);
            }
            catch (Exception ex) when (!ex.IsFatal())
            {
                AppLogger.Warn("YaraEngine", "InvalidateCompiledRules (.yarc)", ex);
            }
            try
            {
                if (File.Exists(_rulesCountCachePath))
                    File.Delete(_rulesCountCachePath);
            }
            catch (Exception ex) when (!ex.IsFatal())
            {
                AppLogger.Warn("YaraEngine", "InvalidateCompiledRules (cache comptage)", ex);
            }
            try
            {
                if (File.Exists(_compiledStampPath))
                    File.Delete(_compiledStampPath);
            }
            catch (Exception ex) when (!ex.IsFatal())
            {
                AppLogger.Warn("YaraEngine", "InvalidateCompiledRules (stamp)", ex);
            }
        }
    }

    /// <summary>Un match YARA (règle + fichier).</summary>
    public class YaraMatch
    {
        public string RuleName { get; set; } = string.Empty;
        public string FilePath { get; set; } = string.Empty;
    }

    /// <summary>
    /// YARA s'est arrêté avec un code d'erreur. Les correspondances lues avant l'arrêt
    /// sont jointes : ce sont des détections réelles, le scan est seulement incomplet.
    /// </summary>
    public sealed class YaraScanIncompleteException : IOException
    {
        public YaraScanIncompleteException(string message, List<YaraMatch> partialMatches)
            : base(message)
        {
            PartialMatches = partialMatches;
        }

        public List<YaraMatch> PartialMatches { get; }
    }
}
