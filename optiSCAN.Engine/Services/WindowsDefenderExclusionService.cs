using optiSCAN.Platform;
using System.Diagnostics;
using System.IO;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;

namespace optiSCAN.Services
{
    /// <summary>
    /// Enregistre les dossiers d'optiSCAN réservés aux administrateurs (installation,
    /// <c>%ProgramData%\optiSCAN</c>) et les moteurs (ClamAV, YARA) dans les exclusions
    /// Windows Defender.
    /// <para>
    /// Jamais d'exclusion de processus sur <c>optiSCAN.exe</c> ni <c>optiSCAN.Service.exe</c> :
    /// Defender ne verrait plus aucun fichier ouvert par eux, dont les copies d'analyse de
    /// l'hôte SYSTEM et les fichiers restaurés de la quarantaine (audit A3). Les données
    /// qu'ils produisent et qui ressemblent à des menaces (bases, copies, quarantaine) sont
    /// couvertes par l'exclusion du dossier <c>%ProgramData%\optiSCAN</c>.
    /// </para>
    /// </summary>
    [SupportedOSPlatform("windows")]
    internal static class WindowsDefenderExclusionService
    {
        /// <summary>Noms nus propres à optiSCAN (exclusions de la 3.0.0).</summary>
        private static readonly string[] LegacyOwnProcessNames =
        {
            "optiSCAN.exe",
            "optiSCAN.Service.exe",
        };

        /// <summary>
        /// Noms nus des moteurs ajoutés par la 3.0.0. Une autre installation de ClamAV ou de YARA
        /// a pu les exclure elle aussi : ils ne sont retirés que si les noms d'optiSCAN
        /// l'étaient également.
        /// </summary>
        private static readonly string[] LegacyEngineProcessNames =
        {
            "clamscan.exe",
            "freshclam.exe",
            "clamd.exe",
            "yara64.exe",
        };

        private static string[] LegacyProcessNames => LegacyOwnProcessNames.Concat(LegacyEngineProcessNames).ToArray();

        /// <summary>Moteurs exclus par chemin complet : ils écrivent bases et extractions temporaires.</summary>
        internal static readonly string[] EngineProcessRelativePaths =
        {
            Path.Combine("clamav", "x64", "clamscan.exe"),
            Path.Combine("clamav", "x64", "freshclam.exe"),
            Path.Combine("clamav", "x64", "clamd.exe"),
            Path.Combine("yara", "yara64.exe"),
        };

        /// <summary>
        /// Binaires d'optiSCAN exclus par chemin complet jusqu'à la 3.1 candidate : retirés à chaque
        /// application ou retrait des exclusions.
        /// </summary>
        internal static readonly string[] RetiredAppProcessRelativePaths =
        {
            "optiSCAN.exe",
            "optiSCAN.Service.exe",
        };

        private static int _ensureInFlight;

        /// <summary>Dernier résultat connu (Options / onboarding).</summary>
        private static DefenderExclusionResult? _lastExclusionResult;
        private static readonly object LastResultGate = new();

        /// <summary>Dernier résultat (écrit par un thread de fond, lu par l'interface).</summary>
        internal static DefenderExclusionResult? LastExclusionResult
        {
            get { lock (LastResultGate) { return _lastExclusionResult; } }
            private set { lock (LastResultGate) { _lastExclusionResult = value; } }
        }

        /// <summary>Opt-in — Options / bouton « Réappliquer les exclusions » (pas au démarrage).</summary>
        public static void EnsureOptiscanExclusionsAsync()
        {
            if (Interlocked.CompareExchange(ref _ensureInFlight, 1, 0) != 0)
                return;

            _ = Task.Run(() =>
            {
                try
                {
                    var result = EnsureOptiscanExclusions();
                    LastExclusionResult = result;
                    if (result.Status == DefenderExclusionStatus.Added)
                        AppLogger.Info("DefenderExclusion", $"Exclusions ajoutées ({result.AddedCount})");
                    else if (result.Status is DefenderExclusionStatus.PartialFailure or DefenderExclusionStatus.AccessDenied)
                        TryElevatedDefenderExclusionRetry();
                }
                catch (Exception ex)
                {
                    AppLogger.Warn("DefenderExclusion", "EnsureOptiscanExclusionsAsync", ex);
                }
                finally
                {
                    Interlocked.Exchange(ref _ensureInFlight, 0);
                }
            });
        }

        public static DefenderExclusionResult EnsureOptiscanExclusions()
        {
            if (!OperatingSystem.IsWindows())
                return DefenderExclusionResult.NotApplicable();

            if (!IsWindowsDefenderPresent())
                return DefenderExclusionResult.Unavailable("Windows Defender introuvable");

            var paths = CollectExclusionPaths();
            var processes = CollectProcessExclusionPaths();

            var payload = Convert.ToBase64String(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new
            {
                paths,
                processes,
                own = LegacyOwnProcessNames,
                engine = LegacyEngineProcessNames,
                retired = CollectRetiredProcessExclusionPaths(),
            })));

            const string script = """
                $ErrorActionPreference = 'Continue'
                $payload = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__PAYLOAD__'))
                $data = $payload | ConvertFrom-Json
                try {
                    $status = Get-MpComputerStatus -ErrorAction Stop
                    if (-not $status.AMServiceEnabled) { Write-Output 'DEFENDER_DISABLED'; exit 2 }
                } catch {
                    Write-Output 'DEFENDER_UNAVAILABLE'
                    exit 2
                }
                try {
                    $pref = Get-MpPreference -ErrorAction Stop
                } catch {
                    Write-Output 'PREF_READ_FAILED'
                    exit 3
                }
                $pathExisting = @($pref.ExclusionPath)
                $procExisting = @($pref.ExclusionProcess)
                $added = 0
                $failures = @()
                foreach ($p in $data.paths) {
                    if (-not (Test-Path -LiteralPath $p)) { continue }
                    $norm = (Resolve-Path -LiteralPath $p).Path
                    $exists = $false
                    foreach ($e in $pathExisting) {
                        if ($e.Equals($norm, [System.StringComparison]::OrdinalIgnoreCase)) { $exists = $true; break }
                    }
                    if ($exists) { continue }
                    try {
                        Add-MpPreference -ExclusionPath $norm -ErrorAction Stop
                        $pathExisting += $norm
                        $added++
                    } catch {
                        $failures += "PATH:$norm"
                    }
                }
                foreach ($proc in $data.processes) {
                    $exists = $false
                    foreach ($e in $procExisting) {
                        if ($e.Equals([string]$proc, [System.StringComparison]::OrdinalIgnoreCase)) { $exists = $true; break }
                    }
                    if ($exists) { continue }
                    try {
                        Add-MpPreference -ExclusionProcess ([string]$proc) -ErrorAction Stop
                        $procExisting += [string]$proc
                        $added++
                    } catch {
                        $failures += "PROC:$proc"
                    }
                }
                # Noms nus de la 3.0.0 : ceux d'optiSCAN sont retirés ; ceux des moteurs
                # (clamscan.exe...) peuvent appartenir à une autre installation, ils ne sont
                # retirés que si les noms d'optiSCAN étaient aussi présents (lot de la 3.0.0).
                $procNow = @((Get-MpPreference).ExclusionProcess)
                $ours = @($data.own | Where-Object { $procNow -contains [string]$_ })
                $legacyTargets = @($ours)
                if ($ours.Count -gt 0) { $legacyTargets += @($data.engine | Where-Object { $procNow -contains [string]$_ }) }
                foreach ($name in $legacyTargets) {
                    try { Remove-MpPreference -ExclusionProcess ([string]$name) -ErrorAction Stop } catch { Write-Output "FAILED:$name" }
                }
                # optiSCAN.exe / optiSCAN.Service.exe par chemin complet : plus jamais exclus.
                foreach ($proc in @($data.retired | Where-Object { $procNow -contains [string]$_ })) {
                    try { Remove-MpPreference -ExclusionProcess ([string]$proc) -ErrorAction Stop } catch { Write-Output "FAILED:$proc" }
                }
                if ($failures.Count -gt 0) {
                    Write-Output ('PARTIAL:' + ($failures -join ';') + ';ADDED=' + $added)
                    exit 4
                }
                Write-Output ('OK:' + $added)
                exit 0
                """;

            var run = RunPowerShell(script.Replace("__PAYLOAD__", payload, StringComparison.Ordinal));
            var result = ParseResult(run.ExitCode, run.Output);
            LastExclusionResult = result;
            return result;
        }

        internal static IReadOnlyList<string> CollectExclusionPaths()
        {
            var local = OptiscanProtectedPaths.GetLocalAppDataRoot();
            var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var root in OptiscanProtectedPaths.GetProtectedRoots())
            {
                if (string.IsNullOrWhiteSpace(root))
                    continue;
                try
                {
                    var full = Path.GetFullPath(root.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
                    if (IsUnderRoot(full, local))
                        continue;
                    // Jamais d'exclusion Defender sur un dossier qu'un utilisateur peut modifier.
                    if (!InstallLocationTrust.IsAdminOnlyInstall(full, out _))
                        continue;
                    paths.Add(full);
                }
                catch
                {
                    /* chemin invalide */
                }
            }

            // Bases ClamAV du service, copies d'analyse et quarantaine de l'hôte SYSTEM. Le dossier
            // n'est exclu que s'il est réservé aux administrateurs, comme l'installation.
            try
            {
                var programData = Path.GetFullPath(OptiScanProgramData.DirectoryPath);
                if (Directory.Exists(programData) && InstallLocationTrust.IsAdminOnlyInstall(programData, out _))
                    paths.Add(programData);
            }
            catch
            {
                /* ProgramData illisible : pas d'exclusion */
            }

            return paths.OrderBy(p => p, StringComparer.OrdinalIgnoreCase).ToList();
        }

        /// <summary>Chemins complets des moteurs, jamais un simple nom d'image ni un binaire d'optiSCAN.</summary>
        internal static IReadOnlyList<string> CollectProcessExclusionPaths(bool requireTrustedInstall = true)
        {
            // Hors d'un dossier réservé aux administrateurs, un binaire remplacé hériterait de
            // l'exclusion : aucune exclusion de processus dans ce cas. Le retrait, lui, vise
            // toujours ces chemins, pour nettoyer ce qu'une version antérieure a pu ajouter.
            if (requireTrustedInstall && !InstallLocationTrust.IsCurrentInstallTrusted(out _))
                return Array.Empty<string>();

            var root = AppContext.BaseDirectory;
            var list = new List<string>();
            foreach (var name in EngineProcessRelativePaths)
            {
                var path = Path.GetFullPath(Path.Combine(root, name));
                if (File.Exists(path))
                    list.Add(path);
            }

            return list;
        }

        /// <summary>Chemins complets d'optiSCAN.exe et d'optiSCAN.Service.exe, à retirer des exclusions.</summary>
        internal static IReadOnlyList<string> CollectRetiredProcessExclusionPaths()
        {
            var roots = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { AppContext.BaseDirectory };
            foreach (var install in OptiscanProtectedPaths.ResolveInstallRoots())
                roots.Add(install);

            var list = new List<string>();
            foreach (var root in roots)
            {
                foreach (var name in RetiredAppProcessRelativePaths)
                {
                    try { list.Add(Path.GetFullPath(Path.Combine(root, name))); }
                    catch { /* chemin invalide */ }
                }
            }

            return list.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        }

        internal static IReadOnlyList<string> LegacyBareProcessNames => LegacyProcessNames;

        /// <summary>
        /// Retire les exclusions de processus sur optiSCAN.exe et optiSCAN.Service.exe posées
        /// jusqu'à la 3.1 candidate. Appelé une fois par version par l'hôte SYSTEM ou une instance
        /// élevée (<see cref="DefenderLegacyCleanup"/>) : une installation existante est nettoyée
        /// sans que l'utilisateur ait à rouvrir les Options.
        /// </summary>
        public static DefenderExclusionResult RemoveRetiredProcessExclusions()
        {
            if (!OperatingSystem.IsWindows())
                return DefenderExclusionResult.NotApplicable();
            if (!IsWindowsDefenderPresent())
                return DefenderExclusionResult.Unavailable("Windows Defender introuvable");

            var payload = Convert.ToBase64String(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new
            {
                retired = CollectRetiredProcessExclusionPaths(),
            })));

            const string script = """
                $ErrorActionPreference = 'Continue'
                $payload = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__PAYLOAD__'))
                $data = $payload | ConvertFrom-Json
                try { $procNow = @((Get-MpPreference -ErrorAction Stop).ExclusionProcess) } catch { Write-Output 'PREF_READ_FAILED'; exit 3 }
                $removed = 0
                foreach ($proc in @($data.retired | Where-Object { $procNow -contains [string]$_ })) {
                    try { Remove-MpPreference -ExclusionProcess ([string]$proc) -ErrorAction Stop; $removed++ } catch { Write-Output "FAILED:$proc" }
                }
                Write-Output ('OK:' + $removed)
                exit 0
                """;

            var run = RunPowerShell(script.Replace("__PAYLOAD__", payload, StringComparison.Ordinal));
            AppLogger.Info("DefenderExclusion", "Exclusions de processus retirées (optiSCAN.exe, service) : " + run.Output.Trim());
            return ParseResult(run.ExitCode, run.Output);
        }

        private static bool IsUnderRoot(string full, string root)
        {
            var normRoot = root.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            return string.Equals(full, normRoot, StringComparison.OrdinalIgnoreCase)
                || full.StartsWith(normRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)
                || full.StartsWith(normRoot + Path.AltDirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
        }

        public static DefenderExclusionResult RemoveOptiscanExclusions()
        {
            if (!OperatingSystem.IsWindows())
                return DefenderExclusionResult.NotApplicable();

            // Retrait large : tout ce qu'une version antérieure a pu exclure, y compris un dossier
            // d'installation que l'on n'exclurait plus aujourd'hui.
            // ProgramData\optiSCAN toujours retiré, même déjà supprimé : une exclusion restée sur
            // ce chemin deviendrait une cachette, un compte standard pouvant le recréer.
            var paths = CollectExclusionPaths()
                .Concat(OptiscanProtectedPaths.ResolveInstallRoots())
                .Append(OptiscanProtectedPaths.GetLocalAppDataRoot())
                .Append(Path.GetFullPath(OptiScanProgramData.DirectoryPath))
                .Distinct(StringComparer.OrdinalIgnoreCase);
            var processes = CollectProcessExclusionPaths(requireTrustedInstall: false);
            var payload = Convert.ToBase64String(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new
            {
                paths,
                processes,
                own = LegacyOwnProcessNames,
                engine = LegacyEngineProcessNames,
                retired = CollectRetiredProcessExclusionPaths(),
            })));

            const string script = """
                $ErrorActionPreference = 'Continue'
                $payload = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__PAYLOAD__'))
                $data = $payload | ConvertFrom-Json
                $removed = 0
                foreach ($p in $data.paths) {
                    try { Remove-MpPreference -ExclusionPath ([string]$p) -ErrorAction Stop; $removed++ } catch { Write-Output "FAILED:$p" }
                }
                foreach ($proc in @($data.processes) + @($data.retired)) {
                    try { Remove-MpPreference -ExclusionProcess ([string]$proc) -ErrorAction Stop; $removed++ } catch { Write-Output "FAILED:$proc" }
                }
                # Noms nus de la 3.0.0 : ceux d'optiSCAN sont retirés ; ceux des moteurs
                # (clamscan.exe...) peuvent appartenir à une autre installation, ils ne sont
                # retirés que si les noms d'optiSCAN étaient aussi présents (lot de la 3.0.0).
                $procNow = @((Get-MpPreference).ExclusionProcess)
                $ours = @($data.own | Where-Object { $procNow -contains [string]$_ })
                $legacyTargets = @($ours)
                if ($ours.Count -gt 0) { $legacyTargets += @($data.engine | Where-Object { $procNow -contains [string]$_ }) }
                foreach ($name in $legacyTargets) {
                    try { Remove-MpPreference -ExclusionProcess ([string]$name) -ErrorAction Stop; $removed++ } catch { Write-Output "FAILED:$name" }
                }
                Write-Output ('OK:' + $removed)
                exit 0
                """;

            var run = RunPowerShell(script.Replace("__PAYLOAD__", payload, StringComparison.Ordinal));
            return ParseResult(run.ExitCode, run.Output);
        }

        /// <summary>
        /// Exclusions laissées par optiSCAN 3.0.0 : processus par simple nom (valables pour
        /// n'importe quel exécutable du même nom) et dossiers <c>AppData\Local\optiSCAN</c>
        /// de tous les profils. Appelé par l'installeur à chaque mise à jour.
        /// </summary>
        public static DefenderExclusionResult RemoveLegacyExclusions()
        {
            if (!OperatingSystem.IsWindows())
                return DefenderExclusionResult.NotApplicable();
            if (!IsWindowsDefenderPresent())
                return DefenderExclusionResult.Unavailable("Windows Defender introuvable");

            var payload = Convert.ToBase64String(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new
            {
                own = LegacyOwnProcessNames,
                engine = LegacyEngineProcessNames,
                retired = CollectRetiredProcessExclusionPaths(),
            })));

            const string script = """
                $ErrorActionPreference = 'Continue'
                $payload = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__PAYLOAD__'))
                $data = $payload | ConvertFrom-Json
                $pref = Get-MpPreference
                $removed = 0
                # Noms nus de la 3.0.0 : ceux d'optiSCAN sont retirés ; ceux des moteurs
                # (clamscan.exe...) peuvent appartenir à une autre installation, ils ne sont
                # retirés que si les noms d'optiSCAN étaient aussi présents (lot de la 3.0.0).
                $procNow = @((Get-MpPreference).ExclusionProcess)
                $ours = @($data.own | Where-Object { $procNow -contains [string]$_ })
                $legacyTargets = @($ours)
                if ($ours.Count -gt 0) { $legacyTargets += @($data.engine | Where-Object { $procNow -contains [string]$_ }) }
                foreach ($name in $legacyTargets) {
                    try { Remove-MpPreference -ExclusionProcess ([string]$name) -ErrorAction Stop; $removed++ } catch { Write-Output "FAILED:$name" }
                }
                foreach ($p in @($pref.ExclusionPath)) {
                    if ([string]$p -match '\\AppData\\Local\\optiSCAN\\?$') {
                        try { Remove-MpPreference -ExclusionPath ([string]$p) -ErrorAction Stop; $removed++ } catch { Write-Output "FAILED:$p" }
                    }
                }
                Write-Output ('OK:' + $removed)
                exit 0
                """;

            var run = RunPowerShell(script.Replace("__PAYLOAD__", payload, StringComparison.Ordinal));
            var result = ParseResult(run.ExitCode, run.Output);
            AppLogger.Info("DefenderExclusion", "Nettoyage des exclusions 3.0.0 : " + run.Output.Trim());
            return result;
        }

        internal static bool IsWindowsDefenderPresent()
        {
            var mpcmd = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                "Windows Defender",
                "MpCmdRun.exe");
            return File.Exists(mpcmd);
        }

        private static DefenderExclusionResult ParseResult(int exitCode, string output)
        {
            var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            var line = lines.LastOrDefault() ?? string.Empty;

            // Retraits refusés par Defender (« FAILED:<valeur> ») : le script continue, on les journalise.
            var failed = lines
                .Where(l => l.StartsWith("FAILED:", StringComparison.Ordinal))
                .Select(l => PathRedaction.RedactPath(l["FAILED:".Length..]))
                .ToList();
            if (failed.Count > 0)
                AppLogger.Warn("DefenderExclusion",
                    $"{failed.Count} exclusion(s) non retirée(s) : {string.Join(", ", failed)}");

            if (exitCode == 0)
            {
                var added = 0;
                if (line.StartsWith("OK:", StringComparison.Ordinal))
                    int.TryParse(line.AsSpan(3), out added);
                return added > 0
                    ? DefenderExclusionResult.Added(added)
                    : DefenderExclusionResult.AlreadyConfigured();
            }

            if (exitCode == 2)
                return DefenderExclusionResult.Unavailable(line);

            if (exitCode == 3)
                return DefenderExclusionResult.AccessDenied();

            if (exitCode == 4 && line.StartsWith("PARTIAL:", StringComparison.Ordinal))
            {
                var added = 0;
                var idx = line.LastIndexOf("ADDED=", StringComparison.Ordinal);
                if (idx >= 0)
                    int.TryParse(line.AsSpan(idx + 6), out added);
                return DefenderExclusionResult.Partial(line, added);
            }

            return DefenderExclusionResult.Partial(line, 0);
        }

        private static (int ExitCode, string Output) RunPowerShell(string script)
        {
            var psi = new ProcessStartInfo
            {
                FileName = SystemExecutables.PowerShell,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            psi.ArgumentList.Add("-NoProfile");
            psi.ArgumentList.Add("-NonInteractive");
            psi.ArgumentList.Add("-ExecutionPolicy");
            psi.ArgumentList.Add("Bypass");
            psi.ArgumentList.Add("-Command");
            psi.ArgumentList.Add(script);

            using var proc = Process.Start(psi)
                ?? throw new InvalidOperationException("Impossible de lancer powershell.exe");

            // Lecture simultanée des deux flux (sinon blocage si stderr remplit son tampon
            // pendant la lecture de stdout), et délai réel : PowerShell bloqué est arrêté.
            var stdoutTask = proc.StandardOutput.ReadToEndAsync();
            var stderrTask = proc.StandardError.ReadToEndAsync();
            if (!proc.WaitForExit(60_000))
            {
                try { proc.Kill(entireProcessTree: true); }
                catch (Exception ex) { AppLogger.Debug("DefenderExclusion", "Arrêt PowerShell : " + ex.Message); }
                return (-1, "PowerShell : délai dépassé");
            }
            proc.WaitForExit();
            var stdout = stdoutTask.GetAwaiter().GetResult();
            var stderr = stderrTask.GetAwaiter().GetResult();

            var combined = string.IsNullOrWhiteSpace(stderr)
                ? stdout
                : stdout + Environment.NewLine + stderr;
            return (proc.ExitCode, combined.Trim());
        }

        private static void TryElevatedDefenderExclusionRetry()
        {
            if (ElevationHelper.IsRunningElevated())
            {
                AppLogger.Info("DefenderExclusion",
                    "Exclusions Defender non modifiées (protection contre la falsification ou autre AV)");
                return;
            }

            if (!ShouldAttemptElevationRetry())
            {
                AppLogger.Info("DefenderExclusion",
                    "Exclusions Defender : élévation UAC déjà proposée récemment");
                return;
            }

            MarkElevationRetryAttempted();
            if (ElevationHelper.RelaunchElevated(HeadlessScanArguments.DefenderExclusions, HeadlessScanArguments.Quiet))
                AppLogger.Info("DefenderExclusion", "Relance élevée pour exclusions Defender");
            else
                AppLogger.Info("DefenderExclusion", "Exclusions Defender : UAC refusé");
        }

        private static bool ShouldAttemptElevationRetry()
        {
            try
            {
                var marker = Path.Combine(OptiscanProtectedPaths.GetLocalAppDataRoot(), "defender-exclusion-uac.marker");
                if (!File.Exists(marker))
                    return true;
                var written = File.GetLastWriteTimeUtc(marker);
                return DateTime.UtcNow - written > TimeSpan.FromHours(24);
            }
            catch
            {
                return true;
            }
        }

        private static void MarkElevationRetryAttempted()
        {
            try
            {
                var dir = OptiscanProtectedPaths.GetLocalAppDataRoot();
                Directory.CreateDirectory(dir);
                var marker = Path.Combine(dir, "defender-exclusion-uac.marker");
                File.WriteAllText(marker, DateTime.UtcNow.ToString("O"));
            }
            catch
            {
                /* non bloquant */
            }
        }
    }

    public enum DefenderExclusionStatus
    {
        NotApplicable,
        DefenderUnavailable,
        AlreadyConfigured,
        Added,
        PartialFailure,
        AccessDenied,
    }

    public readonly struct DefenderExclusionResult
    {
        public DefenderExclusionStatus Status { get; }
        public int AddedCount { get; }
        public string Message { get; }

        private DefenderExclusionResult(DefenderExclusionStatus status, int addedCount, string message)
        {
            Status = status;
            AddedCount = addedCount;
            Message = message;
        }

        public static DefenderExclusionResult NotApplicable() =>
            new(DefenderExclusionStatus.NotApplicable, 0, string.Empty);

        public static DefenderExclusionResult Unavailable(string detail) =>
            new(DefenderExclusionStatus.DefenderUnavailable, 0, detail);

        public static DefenderExclusionResult AlreadyConfigured() =>
            new(DefenderExclusionStatus.AlreadyConfigured, 0, string.Empty);

        public static DefenderExclusionResult Added(int count) =>
            new(DefenderExclusionStatus.Added, count, string.Empty);

        public static DefenderExclusionResult AccessDenied() =>
            new(DefenderExclusionStatus.AccessDenied, 0, "Accès refusé");

        public static DefenderExclusionResult Partial(string detail, int added) =>
            new(DefenderExclusionStatus.PartialFailure, added, detail);
    }
}
