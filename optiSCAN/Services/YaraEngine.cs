using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

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

        public bool IsAvailable  { get; private set; }
        public int  RulesCount   { get; private set; }
        public bool HasCompiled  => File.Exists(_compiledRulesPath);

        // ── Constructeur ─────────────────────────────────────────────────────────

        public YaraEngine(string? yaraDir = null, string? rulesDir = null)
        {
            var baseDir = AppDomain.CurrentDomain.BaseDirectory;
            var arch    = Environment.Is64BitProcess ? "64" : "32";

            var resolvedYaraDir = yaraDir ?? Path.Combine(baseDir, "yara");

            _yaraExe   = Path.Combine(resolvedYaraDir, $"yara{arch}.exe");
            _yaracExe  = Path.Combine(resolvedYaraDir, $"yarac{arch}.exe");

            _rulesDirectory    = rulesDir ?? Path.Combine(baseDir, "rules");
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

            // yarac usage : yarac [options] source_file1 [source_file2 ...] output_file
            var sb = new StringBuilder();
            foreach (var f in ruleFiles)
                sb.Append($"\"{f}\" ");
            sb.Append($"\"{_compiledRulesPath}\"");

            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName               = _yaracExe,
                    Arguments              = sb.ToString(),
                    UseShellExecute        = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError  = true,
                    CreateNoWindow         = true
                }
            };

            try
            {
                process.Start();
                // Lire stderr pour les erreurs de compilation
                var errTask = process.StandardError.ReadToEndAsync();
                await process.WaitForExitAsync(ct);
                var err = await errTask;

                if (!string.IsNullOrWhiteSpace(err))
                    Debug.WriteLine($"[yarac] {err}");

                return process.ExitCode == 0 && File.Exists(_compiledRulesPath);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[yarac] Exception : {ex.Message}");
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
                var results = await RunYaraScanAsync(
                    $"--compiled-rules \"{_compiledRulesPath}\" \"{filePath}\"",
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
                        $"\"{ruleFile}\" \"{filePath}\"",
                        filePath, ct);
                    matches.AddRange(results);
                }
            }

            return matches;
        }

        /// <summary>Retourne true si au moins une règle YARA matche le fichier.</summary>
        public async Task<bool> IsMaliciousAsync(string filePath, CancellationToken ct = default)
            => (await ScanFileAsync(filePath, ct)).Count > 0;

        // ── Helpers ──────────────────────────────────────────────────────────────

        private async Task<List<YaraMatch>> RunYaraScanAsync(
            string args, string filePath, CancellationToken ct)
        {
            var matches = new List<YaraMatch>();

            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName               = _yaraExe,
                    Arguments              = args,
                    UseShellExecute        = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError  = true,
                    CreateNoWindow         = true
                }
            };

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
                Debug.WriteLine($"[YARA] Erreur : {ex.Message}");
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
