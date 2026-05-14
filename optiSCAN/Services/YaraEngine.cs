using System.Diagnostics;
using System.IO;
using System.Text;

namespace optiSCAN.Services
{
    /// <summary>
    /// Moteur YARA — exécute yara64/yara32.exe en ligne de commande.
    /// Compile les règles avec yarac64/yarac32.exe pour accélérer les scans répétés.
    /// </summary>
    public class YaraEngine
    {
        private readonly string _yaraExe;     // yara64.exe / yara32.exe
        private readonly string _yaracExe;    // yarac64.exe / yarac32.exe (compilateur)
        private readonly string _rulesDirectory;
        private readonly string _compiledRulesPath;

        public bool IsAvailable { get; private set; }
        public int RulesCount { get; private set; }
        public bool HasCompiled => File.Exists(_compiledRulesPath);

        // ── Constructeur ─────────────────────────────────────────────────────────

        public YaraEngine(string? yaraDir = null, string? rulesDir = null)
        {
            var baseDir = AppDomain.CurrentDomain.BaseDirectory;
            var arch = Environment.Is64BitProcess ? "64" : "32";

            var resolvedYaraDir = yaraDir ?? Path.Combine(baseDir, "yara");

            _yaraExe = Path.Combine(resolvedYaraDir, $"yara{arch}.exe");
            _yaracExe = Path.Combine(resolvedYaraDir, $"yarac{arch}.exe");

            _rulesDirectory = rulesDir ?? Path.Combine(baseDir, "rules");
            _compiledRulesPath = Path.Combine(_rulesDirectory, "_compiled.yarc");

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

        private int CountRules()
        {
            try
            {
                // Compte le nombre de règles dans tous les .yar
                int count = 0;
                foreach (var f in Directory.GetFiles(_rulesDirectory, "*.yar"))
                    foreach (var line in File.ReadAllLines(f))
                        if (line.TrimStart().StartsWith("rule "))
                            count++;
                return count > 0 ? count : Directory.GetFiles(_rulesDirectory, "*.yar").Length;
            }
            catch { return 0; }
        }

        // ── Compilation des règles ────────────────────────────────────────────────

        /// <summary>
        /// Compile toutes les règles .yar en un fichier .yarc pour accélérer les scans.
        /// Utilise yarac64.exe (ou yarac32.exe).
        /// </summary>
        public async Task<bool> CompileRulesAsync(CancellationToken ct = default)
        {
            if (!IsAvailable) return false;
            if (!File.Exists(_yaracExe)) return false; // yarac non disponible

            var ruleFiles = Directory.GetFiles(_rulesDirectory, "*.yar");
            if (ruleFiles.Length == 0) return false;

            // Audit S4 : ArgumentList plutôt que concatenation de string —
            // chaque fichier de règle est passé comme argument distinct, le
            // quoting est géré par .NET (CommandLineToArgvW round-trip safe)
            // même si un chemin contient des espaces ou des guillemets.
            var psi = new ProcessStartInfo
            {
                FileName = _yaracExe,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            foreach (var f in ruleFiles) psi.ArgumentList.Add(f);
            psi.ArgumentList.Add(_compiledRulesPath);

            using var process = new Process { StartInfo = psi };

            try
            {
                process.Start();
                // Lire stderr pour les erreurs de compilation
                var errTask = process.StandardError.ReadToEndAsync();
                await process.WaitForExitAsync(ct);
                try { process.WaitForExit(); } catch { }
                var err = await errTask;

                if (!string.IsNullOrWhiteSpace(err))
                    AppLogger.Warn("yarac", err);

                return process.ExitCode == 0 && File.Exists(_compiledRulesPath);
            }
            catch (Exception ex)
            {
                AppLogger.Error("yarac", "Compilation échouée", ex);
                return false;
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

            // Tenter compilation si pas encore fait
            if (!HasCompiled)
                await CompileRulesAsync(ct);

            if (HasCompiled)
            {
                // Scan avec règles compilées : yara64.exe --compiled-rules rules.yarc file
                // ArgumentList → quoting sûr, pas de concat string.
                var results = await RunYaraScanAsync(
                    new[] { "--compiled-rules", _compiledRulesPath, filePath },
                    filePath, ct);
                matches.AddRange(results);
            }
            else
            {
                // Fallback : scan avec chaque .yar individuellement
                foreach (var ruleFile in Directory.GetFiles(_rulesDirectory, "*.yar"))
                {
                    if (ct.IsCancellationRequested) break;
                    var results = await RunYaraScanAsync(
                        new[] { ruleFile, filePath }, filePath, ct);
                    matches.AddRange(results);
                }
            }

            return matches;
        }

        /// <summary>Retourne true si au moins une règle YARA matche le fichier.</summary>
        public async Task<bool> IsMaliciousAsync(string filePath, CancellationToken ct = default)
            => (await ScanFileAsync(filePath, ct)).Count > 0;

        /// <summary>
        /// Scanne un dossier entier en UN SEUL processus yara avec --recursive.
        ///
        /// L'ancienne approche (un process par fichier dans ScanOrchestrator)
        /// dominait le temps de scan pour les gros dossiers : pour 10 000 fichiers,
        /// 10 000 spawns de yara64.exe, soit ~10 minutes uniquement de spawn
        /// overhead. Cette méthode passe le dossier directement à yara qui
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

            // Compilation au besoin (idem ScanFileAsync).
            if (!HasCompiled)
                await CompileRulesAsync(ct);

            // Construction de la commande : --recursive + dossier en argument.
            // -N (no-warnings) supprime les avertissements verbeux.
            // ArgumentList systématique (audit S4) → quoting sûr.
            string[] args;
            if (HasCompiled)
            {
                args = new[] { "-N", "--compiled-rules", "--recursive", _compiledRulesPath, folderPath };
            }
            else
            {
                // Sans règles compilées : scan séquentiel par règle, encore N fois
                // moins de spawn qu'un process par fichier.
                foreach (var ruleFile in Directory.GetFiles(_rulesDirectory, "*.yar"))
                {
                    if (ct.IsCancellationRequested) break;
                    progress?.Report($"YARA : règle {Path.GetFileNameWithoutExtension(ruleFile)}");
                    var sub = await RunYaraScanAsync(
                        new[] { "-N", "--recursive", ruleFile, folderPath },
                        folderPath, ct);
                    matches.AddRange(sub);
                }
                return matches;
            }

            progress?.Report($"YARA : scan récursif de {Path.GetFileName(folderPath)}…");
            return await RunYaraScanRecursiveAsync(args, ct);
        }

        /// <summary>
        /// Variante de RunYaraScanAsync pour les scans récursifs : la sortie yara
        /// est au format "RuleName /chemin/absolu/fichier" — chaque ligne est un
        /// match indépendant, avec un fichier potentiellement différent.
        /// </summary>
        private async Task<List<YaraMatch>> RunYaraScanRecursiveAsync(IEnumerable<string> args, CancellationToken ct)
        {
            var matches = new List<YaraMatch>();

            var psi = new ProcessStartInfo
            {
                FileName = _yaraExe,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8,
            };
            foreach (var a in args) psi.ArgumentList.Add(a);

            using var process = new Process { StartInfo = psi };

            try
            {
                process.Start();

                var outputSb = new StringBuilder();
                process.OutputDataReceived += (_, e) =>
                {
                    if (e.Data != null) outputSb.AppendLine(e.Data);
                };
                process.BeginOutputReadLine();
                process.BeginErrorReadLine();

                await process.WaitForExitAsync(ct);
                try { process.WaitForExit(); } catch { }

                foreach (var line in outputSb.ToString()
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

                    if (!string.IsNullOrEmpty(ruleName) && !string.IsNullOrEmpty(matchedPath))
                        matches.Add(new YaraMatch { RuleName = ruleName, FilePath = matchedPath });
                }
            }
            catch (Exception ex)
            {
                AppLogger.Error("YARA", "Scan récursif", ex);
            }

            return matches;
        }

        // ── Helpers ──────────────────────────────────────────────────────────────

        private async Task<List<YaraMatch>> RunYaraScanAsync(
            IEnumerable<string> args, string filePath, CancellationToken ct)
        {
            var matches = new List<YaraMatch>();

            // Audit S4 + R4 : ArgumentList + using var (dispose garanti).
            var psi = new ProcessStartInfo
            {
                FileName = _yaraExe,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            foreach (var a in args) psi.ArgumentList.Add(a);

            using var process = new Process { StartInfo = psi };

            try
            {
                process.Start();

                var outputSb = new StringBuilder();
                process.OutputDataReceived += (_, e) =>
                {
                    if (e.Data != null) outputSb.AppendLine(e.Data);
                };
                process.BeginOutputReadLine();
                process.BeginErrorReadLine(); // Absorber stderr

                await process.WaitForExitAsync(ct);

                // Drain final synchrone : garantit la réception des dernières
                // lignes capturées avant que outputSb soit lu (cf. doc MS).
                try { process.WaitForExit(); } catch { }

                // Format sortie YARA : "RuleName FilePath"
                foreach (var line in outputSb.ToString()
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
            }
            catch (Exception ex)
            {
                AppLogger.Error("YARA", "Scan", ex);
            }

            return matches;
        }

        // ── Invalidation du cache compilé ─────────────────────────────────────────

        /// <summary>Supprime le fichier de règles compilées (force recompilation).</summary>
        public void InvalidateCompiledRules()
        {
            try { if (File.Exists(_compiledRulesPath)) File.Delete(_compiledRulesPath); }
            catch { }
        }
    }

    /// <summary>Un match YARA (règle + fichier).</summary>
    public class YaraMatch
    {
        public string RuleName { get; set; } = string.Empty;
        public string FilePath { get; set; } = string.Empty;
    }
}
