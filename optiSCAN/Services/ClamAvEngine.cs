using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using optiSCAN.Models;

namespace optiSCAN.Services
{
    /// <summary>
    /// Moteur de scan ClamAV — enveloppe clamscan.exe en mode processus.
    /// Détecte automatiquement clamav/x64 ou clamav/x86 selon l'architecture.
    /// Supporte : fichier, dossier, scan rapide, scan complet, annulation, progression.
    /// </summary>
    public class ClamAvEngine
    {
        private readonly string _clamavDir;
        private readonly string _clamscanExe;

        // Regex : "C:\path\file.exe: Win.Trojan.Generic-123 FOUND"
        private static readonly Regex InfectedRegex =
            new Regex(@"^(.+):\s+(.+)\s+FOUND\s*$", RegexOptions.Compiled);

        // Regex statistiques finales : "Scanned files: 123"
        private static readonly Regex StatsRegex =
            new Regex(@"^([\w\s]+):\s+(\d+)", RegexOptions.Compiled);

        // ── Construction ─────────────────────────────────────────────────────────

        public ClamAvEngine(string? clamavDir = null)
        {
            _clamavDir   = clamavDir ?? ResolveClamAvDir();
            _clamscanExe = Path.Combine(_clamavDir, "clamscan.exe");
        }

        /// <summary>
        /// Résout le dossier ClamAV en tenant compte de l'architecture (x64/x86)
        /// et d'une installation système (PATH).
        /// </summary>
        private static string ResolveClamAvDir()
        {
            var baseDir = AppDomain.CurrentDomain.BaseDirectory;
            var arch    = Environment.Is64BitProcess ? "x64" : "x86";

            // 1) clamav/<arch>/clamscan.exe  (binaires embarqués)
            var archPath = Path.Combine(baseDir, "clamav", arch);
            if (File.Exists(Path.Combine(archPath, "clamscan.exe")))
                return archPath;

            // 2) clamav/clamscan.exe  (flat layout de secours)
            var flatPath = Path.Combine(baseDir, "clamav");
            if (File.Exists(Path.Combine(flatPath, "clamscan.exe")))
                return flatPath;

            // 3) Program Files (installation système)
            var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            var systemPath   = Path.Combine(programFiles, "ClamAV");
            if (File.Exists(Path.Combine(systemPath, "clamscan.exe")))
                return systemPath;

            // Fallback : retour flat (l'erreur sera levée à l'utilisation)
            return flatPath;
        }

        /// <summary>
        /// Répertoire de la base de signatures : priorité dossier 'database' local,
        /// sinon le répertoire ClamAV lui-même (pour les installs système).
        /// </summary>
        public string DatabaseDir
        {
            get
            {
                // Chercher database/ à côté des binaires
                var local = Path.Combine(_clamavDir, "database");
                if (Directory.Exists(local)) return local;

                // Chercher un niveau au-dessus (clamav/database/)
                var parent = Path.GetDirectoryName(_clamavDir);
                if (parent != null)
                {
                    var parentDb = Path.Combine(parent, "database");
                    if (Directory.Exists(parentDb)) return parentDb;
                }

                // Laisser ClamAV trouver sa base (install système)
                return string.Empty;
            }
        }

        // ── Vérification ─────────────────────────────────────────────────────────

        public bool IsClamAvInstalled()
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
            catch { return false; }
        }

        public async Task<string> GetVersionAsync()
        {
            if (!File.Exists(_clamscanExe)) return "Non installé";
            try
            {
                var (stdout, _) = await RunProcessAsync(_clamscanExe, "--version");
                return stdout.Trim().Split('\n')[0]; // Première ligne seulement
            }
            catch { return "Erreur"; }
        }

        // ── Méthodes de scan publiques ────────────────────────────────────────────

        public Task<ScanResult> ScanFileAsync(
            string filePath,
            IProgress<ScanProgress>? progress = null,
            CancellationToken ct = default)
        {
            if (!File.Exists(filePath))
                throw new FileNotFoundException("Fichier introuvable.", filePath);
            return RunScanAsync(ScanType.File, filePath, recursive: false, progress, ct);
        }

        public Task<ScanResult> ScanFolderAsync(
            string folderPath,
            IProgress<ScanProgress>? progress = null,
            CancellationToken ct = default)
        {
            if (!Directory.Exists(folderPath))
                throw new DirectoryNotFoundException($"Dossier introuvable : {folderPath}");
            return RunScanAsync(ScanType.Folder, folderPath, recursive: true, progress, ct);
        }

        public async Task<ScanResult> QuickScanAsync(
            IProgress<ScanProgress>? progress = null,
            CancellationToken ct = default)
        {
            var targets = GetQuickScanTargets();
            return await RunMultiTargetScanAsync(ScanType.QuickScan, targets, progress, ct);
        }

        public async Task<ScanResult> FullScanAsync(
            IProgress<ScanProgress>? progress = null,
            CancellationToken ct = default)
        {
            var targets = new List<string>();
            foreach (var d in DriveInfo.GetDrives())
                if (d.IsReady && d.DriveType == DriveType.Fixed)
                    targets.Add(d.RootDirectory.FullName);
            return await RunMultiTargetScanAsync(ScanType.FullScan, targets, progress, ct);
        }

        // ── Implémentation interne ────────────────────────────────────────────────

        private async Task<ScanResult> RunScanAsync(
            ScanType type, string targetPath, bool recursive,
            IProgress<ScanProgress>? progress, CancellationToken ct)
        {
            ValidateInstallation();

            var result = new ScanResult
            {
                Type       = type,
                TargetPath = targetPath,
                StartedAt  = DateTime.Now,
                Status     = ScanStatus.Running
            };

            var args = BuildScanArgs(targetPath, recursive);

            progress?.Report(new ScanProgress
            {
                Message = $"ClamAV — démarrage : {Path.GetFileName(targetPath)}",
                Phase   = ScanPhase.Starting
            });

            try
            {
                using var proc = new Process { StartInfo = BuildStartInfo(_clamscanExe, args) };

                proc.OutputDataReceived += (_, e) =>
                {
                    if (!string.IsNullOrWhiteSpace(e.Data))
                        ParseScanLine(e.Data, result, progress);
                };
                proc.ErrorDataReceived += (_, e) =>
                {
                    if (!string.IsNullOrWhiteSpace(e.Data))
                        Debug.WriteLine($"[ClamAV stderr] {e.Data}");
                };

                proc.Start();
                proc.BeginOutputReadLine();
                proc.BeginErrorReadLine();

                await WaitForProcessAsync(proc, ct);

                result.FinishedAt = DateTime.Now;
                result.Status = ct.IsCancellationRequested
                    ? ScanStatus.Cancelled
                    : ScanStatus.Completed;

                if (ct.IsCancellationRequested && !proc.HasExited)
                    proc.Kill(entireProcessTree: true);
            }
            catch (OperationCanceledException)
            {
                result.Status     = ScanStatus.Cancelled;
                result.FinishedAt = DateTime.Now;
            }
            catch (Exception ex)
            {
                result.Status       = ScanStatus.Error;
                result.ErrorMessage = ex.Message;
                result.FinishedAt   = DateTime.Now;
            }

            progress?.Report(new ScanProgress
            {
                Message      = result.SummaryDisplay,
                Phase        = ScanPhase.Completed,
                FilesScanned = result.FilesScanned,
                ThreatsFound = result.ThreatsFound
            });

            return result;
        }

        private async Task<ScanResult> RunMultiTargetScanAsync(
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
                var sub = await RunScanAsync(type, target, recursive: true, progress, ct);
                merged.FilesScanned      += sub.FilesScanned;
                merged.FilesSkipped      += sub.FilesSkipped;
                merged.TotalBytesScanned += sub.TotalBytesScanned;
                merged.Threats.AddRange(sub.Threats);
            }

            merged.FinishedAt = DateTime.Now;
            merged.Status = ct.IsCancellationRequested
                ? ScanStatus.Cancelled
                : ScanStatus.Completed;
            return merged;
        }

        // ── Parsing ──────────────────────────────────────────────────────────────

        private void ParseScanLine(
            string line, ScanResult result, IProgress<ScanProgress>? progress)
        {
            var infectedMatch = InfectedRegex.Match(line);
            if (infectedMatch.Success)
            {
                var filePath  = infectedMatch.Groups[1].Value.Trim();
                var virusName = infectedMatch.Groups[2].Value.Trim();

                long fileSize = -1;
                try { fileSize = new FileInfo(filePath).Length; } catch { }

                var threat = new ThreatInfo
                {
                    FilePath   = filePath,
                    VirusName  = virusName,
                    DetectedAt = DateTime.Now,
                    Status     = ThreatStatus.Detected,
                    FileSize   = fileSize,
                    DetectedBy = "ClamAV"
                };
                result.Threats.Add(threat);

                progress?.Report(new ScanProgress
                {
                    Message      = $"Menace : {threat.VirusName} [{threat.FileName}]",
                    Phase        = ScanPhase.ThreatFound,
                    ThreatInfo   = threat,
                    FilesScanned = result.FilesScanned,
                    ThreatsFound = result.ThreatsFound
                });
                return;
            }

            if (line.StartsWith("Scanned files:") || line.StartsWith("Data scanned:"))
            {
                ParseStats(line, result);
                return;
            }

            // Comptage fichiers en cours
            if (line.Contains(":") && !line.StartsWith("-") && !line.StartsWith(" "))
            {
                result.FilesScanned++;
                if (result.FilesScanned % 50 == 0)
                {
                    progress?.Report(new ScanProgress
                    {
                        Message      = $"ClamAV : {result.FilesScanned} fichiers analysés…",
                        Phase        = ScanPhase.Scanning,
                        FilesScanned = result.FilesScanned,
                        ThreatsFound = result.ThreatsFound
                    });
                }
            }
        }

        private static void ParseStats(string line, ScanResult result)
        {
            var m = StatsRegex.Match(line);
            if (!m.Success) return;
            var key   = m.Groups[1].Value.Trim().ToLower();
            var value = long.Parse(m.Groups[2].Value);
            switch (key)
            {
                case "scanned files": result.FilesScanned      = (int)value; break;
                case "data scanned":  result.TotalBytesScanned = value * 1024; break;
            }
        }

        // ── Helpers ──────────────────────────────────────────────────────────────

        private string BuildScanArgs(string target, bool recursive)
        {
            var parts = new List<string>();
            if (recursive) parts.Add("--recursive");
            parts.Add("--stdout");
            parts.Add("--no-summary");

            // Base de signatures locale (si disponible)
            var dbDir = DatabaseDir;
            if (!string.IsNullOrEmpty(dbDir))
                parts.Add($"--database=\"{dbDir}\"");

            parts.Add($"\"{target}\"");
            return string.Join(" ", parts);
        }

        private static ProcessStartInfo BuildStartInfo(string exe, string args) =>
            new ProcessStartInfo
            {
                FileName               = exe,
                Arguments              = args,
                UseShellExecute        = false,
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
                CreateNoWindow         = true,
                StandardOutputEncoding = System.Text.Encoding.UTF8
            };

        private static async Task WaitForProcessAsync(Process proc, CancellationToken ct)
        {
            var tcs = new TaskCompletionSource<bool>();
            proc.EnableRaisingEvents = true;
            proc.Exited += (_, _) => tcs.TrySetResult(true);

            using (ct.Register(() =>
            {
                try { if (!proc.HasExited) proc.Kill(entireProcessTree: true); }
                catch { }
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
            Add(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"));
            return dirs;
        }
    }

}
