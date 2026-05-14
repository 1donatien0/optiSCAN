using System;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace optiSCAN.Services
{
    /// <summary>
    /// Gère les mises à jour de la base de signatures ClamAV via freshclam.exe.
    /// Peut être lancé à la demande ou automatiquement (timer planifié).
    /// </summary>
    public class FreshclamUpdater
    {
        private readonly string _freshclamExe;
        private readonly string _databaseDir;
        private readonly string _freshclamConf;
        private readonly string _certsDir;
        private readonly string _caBundlePath;
        private readonly string _clamavRootCertPath;

        private System.Threading.Timer? _autoUpdateTimer;  // ← Correction ici

        /// <summary>Événement déclenché à chaque ligne de sortie freshclam.</summary>
        public event EventHandler<string>? UpdateOutput;

        /// <summary>Événement déclenché quand la mise à jour est terminée.</summary>
        public event EventHandler<UpdateResult>? UpdateCompleted;

        public DateTime? LastUpdateTime { get; private set; }
        public string DatabaseVersion { get; private set; } = "Inconnue";
        public bool IsUpdating { get; private set; }

        public FreshclamUpdater(string? clamavDir = null)
        {
            var dir = clamavDir
                ?? Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "clamav");

            _freshclamExe = ResolveFreshclamExecutable(dir);
            _databaseDir = Path.Combine(dir, "database");
            _freshclamConf = Path.Combine(dir, "freshclam.conf");
            _certsDir = Path.Combine(Path.GetDirectoryName(_freshclamExe) ?? dir, "certs");
            _caBundlePath = Path.Combine(Path.GetDirectoryName(_freshclamExe) ?? dir, "cacert.pem");
            _clamavRootCertPath = Path.Combine(_certsDir, "clamav.crt");

            EnsureDirectoryExists(_databaseDir);
            EnsureDirectoryExists(_certsDir);
            EnsureFreshclamConf();
        }

        // ── Mise à jour manuelle ────────────────────────────────────────────────

        /// <summary>
        /// Lance freshclam pour mettre à jour les signatures.
        /// </summary>
        public async Task<UpdateResult> UpdateAsync(CancellationToken ct = default)
        {
            if (IsUpdating)
                return new UpdateResult { Success = false, Message = "Mise à jour déjà en cours." };

            if (!File.Exists(_freshclamExe))
                return new UpdateResult
                {
                    Success = false,
                    Message = $"freshclam.exe introuvable dans : {Path.GetDirectoryName(_freshclamExe)}"
                };

            IsUpdating = true;
            var result = new UpdateResult { StartedAt = DateTime.Now };

            try
            {
                if (!await EnsureCertificateBundleAsync().ConfigureAwait(false))
                {
                    result.Success = false;
                    result.Message = "Impossible de préparer le bundle de certificats (cacert.pem).";
                    result.FinishedAt = DateTime.Now;
                    return result;
                }
                if (!await EnsureClamAvCodeSignCertificateAsync().ConfigureAwait(false))
                {
                    result.Success = false;
                    result.Message = "Impossible de préparer le certificat de signature ClamAV (clamav.crt).";
                    result.FinishedAt = DateTime.Now;
                    return result;
                }

                var args = $"--config-file=\"{_freshclamConf}\" --datadir=\"{_databaseDir}\" --verbose";

                using var proc = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = _freshclamExe,
                        Arguments = args,
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true
                    }
                };
                proc.StartInfo.EnvironmentVariables["CURL_CA_BUNDLE"] = _caBundlePath;
                proc.StartInfo.EnvironmentVariables["SSL_CERT_FILE"] = _caBundlePath;
                proc.StartInfo.EnvironmentVariables["SSL_CERT_DIR"] = string.Empty;

                proc.OutputDataReceived += (_, e) =>
                {
                    if (!string.IsNullOrWhiteSpace(e.Data))
                    {
                        UpdateOutput?.Invoke(this, e.Data);
                        ParseUpdateOutput(e.Data, result);
                    }
                };

                proc.ErrorDataReceived += (_, e) =>
                {
                    if (!string.IsNullOrWhiteSpace(e.Data))
                        UpdateOutput?.Invoke(this, $"[!] {e.Data}");
                };

                proc.Start();
                proc.BeginOutputReadLine();
                proc.BeginErrorReadLine();

                // Timeout de 5 minutes pour la mise à jour
                using var timeoutCts = new CancellationTokenSource(TimeSpan.FromMinutes(5));
                using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, timeoutCts.Token);

                try
                {
                    await Task.Run(() => proc.WaitForExit((int)TimeSpan.FromMinutes(5).TotalMilliseconds), linked.Token);

                    if (!proc.HasExited)
                    {
                        proc.Kill();
                        result.Success = false;
                        result.Message = "Timeout dépassé.";
                        return result;
                    }
                }
                catch (OperationCanceledException)
                {
                    if (!proc.HasExited)
                        proc.Kill();
                    result.Success = false;
                    result.Message = ct.IsCancellationRequested ? "Mise à jour annulée." : "Timeout dépassé.";
                    return result;
                }

                result.ExitCode = proc.ExitCode;
                result.Success = proc.ExitCode == 0 || proc.ExitCode == 1;
                result.FinishedAt = DateTime.Now;
                result.Message = proc.ExitCode == 0
                    ? "Base de signatures mise à jour avec succès."
                    : proc.ExitCode == 1
                    ? "La base de signatures est déjà à jour."
                    : $"Erreur freshclam (code {proc.ExitCode}).";

                if (result.Success)
                {
                    LastUpdateTime = DateTime.Now;
                    DatabaseVersion = GetLocalDatabaseVersion();
                }

                UpdateCompleted?.Invoke(this, result);
                return result;
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.Message = $"Exception : {ex.Message}";
                result.FinishedAt = DateTime.Now;
                return result;
            }
            finally
            {
                IsUpdating = false;
            }
        }

        // ── Mise à jour automatique ─────────────────────────────────────────────

        /// <summary>
        /// Active les mises à jour automatiques selon un intervalle (par défaut : toutes les 4 heures).
        /// </summary>
        public void EnableAutoUpdate(TimeSpan? interval = null)
        {
            var period = interval ?? TimeSpan.FromHours(4);
            _autoUpdateTimer = new System.Threading.Timer(  // ← Correction ici
                async _ => await UpdateAsync(),
                null,
                period,
                period);
        }

        /// <summary>Désactive les mises à jour automatiques.</summary>
        public void DisableAutoUpdate()
        {
            _autoUpdateTimer?.Dispose();
            _autoUpdateTimer = null;
        }

        // ── Version et état ─────────────────────────────────────────────────────

        /// <summary>
        /// Lit la version de la base locale depuis les fichiers .cvd/.cld.
        /// </summary>
        public string GetLocalDatabaseVersion()
        {
            try
            {
                var mainCvd = Path.Combine(_databaseDir, "main.cvd");
                var dailyCvd = Path.Combine(_databaseDir, "daily.cvd");
                var dailyCld = Path.Combine(_databaseDir, "daily.cld");

                var daily = File.Exists(dailyCld) ? dailyCld : dailyCvd;

                if (File.Exists(daily))
                {
                    using var fs = new FileStream(daily, FileMode.Open, FileAccess.Read);
                    var buf = new byte[512];
                    fs.Read(buf, 0, buf.Length);
                    var header = System.Text.Encoding.ASCII.GetString(buf);
                    var match = Regex.Match(header, @"ClamAV-VDB:\d+:\d+:(\d+):");
                    if (match.Success) return match.Groups[1].Value;
                }

                return File.Exists(mainCvd) ? "Installée (version exacte inconnue)" : "Aucune base";
            }
            catch { return "Lecture impossible"; }
        }

        /// <summary>
        /// Vérifie si la base de signatures est présente localement.
        /// </summary>
        public bool IsDatabasePresent()
        {
            return File.Exists(Path.Combine(_databaseDir, "main.cvd"))
                || File.Exists(Path.Combine(_databaseDir, "main.cld"))
                || File.Exists(Path.Combine(_databaseDir, "daily.cvd"))
                || File.Exists(Path.Combine(_databaseDir, "daily.cld"));
        }

        // ── Helpers privés ──────────────────────────────────────────────────────

        private void ParseUpdateOutput(string line, UpdateResult result)
        {
            if (line.Contains("up-to-date")) result.AlreadyUpToDate = true;
            if (line.Contains("updated")) result.Updated = true;

            var m = Regex.Match(line, @"version:\s*(\d+)");
            if (m.Success) result.NewVersion = m.Groups[1].Value;
        }

        private static void EnsureDirectoryExists(string dir)
        {
            if (!Directory.Exists(dir))
                Directory.CreateDirectory(dir);
        }

        private static string ResolveFreshclamExecutable(string clamavDir)
        {
            string preferredArch = Environment.Is64BitProcess ? "x64" : "x86";
            string otherArch = preferredArch == "x64" ? "x86" : "x64";

            string[] candidates =
            {
                Path.Combine(clamavDir, preferredArch, "freshclam.exe"),
                Path.Combine(clamavDir, otherArch, "freshclam.exe"),
                Path.Combine(clamavDir, "freshclam.exe"),
            };

            foreach (var candidate in candidates)
            {
                if (File.Exists(candidate))
                    return candidate;
            }

            // Retourne le chemin préféré pour garder un message d'erreur explicite.
            return candidates[0];
        }

        private void EnsureFreshclamConf()
        {
            var content = $@"# freshclam.conf généré par optiSCAN
DatabaseDirectory {_databaseDir}
UpdateLogFile {Path.Combine(_databaseDir, "freshclam.log")}
LogTime yes
DatabaseMirror database.clamav.net
CVDCertsDirectory {_certsDir}
MaxAttempts 3
ConnectTimeout 30
ReceiveTimeout 30
";

            if (!File.Exists(_freshclamConf))
            {
                File.WriteAllText(_freshclamConf, content);
                return;
            }

            var existing = File.ReadAllText(_freshclamConf);
            if (existing.Contains("CVDCertsDirectory", StringComparison.OrdinalIgnoreCase))
                return;

            File.WriteAllText(_freshclamConf, existing.TrimEnd() + Environment.NewLine + $"CVDCertsDirectory {_certsDir}" + Environment.NewLine);
        }

        private async Task<bool> EnsureCertificateBundleAsync()
        {
            if (File.Exists(_caBundlePath))
                return true;

            try
            {
                using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(20) };
                string pem = await http.GetStringAsync("https://curl.se/ca/cacert.pem").ConfigureAwait(false);
                if (string.IsNullOrWhiteSpace(pem))
                    return false;

                await File.WriteAllTextAsync(_caBundlePath, pem).ConfigureAwait(false);
                return true;
            }
            catch
            {
                return false;
            }
        }

        private async Task<bool> EnsureClamAvCodeSignCertificateAsync()
        {
            try
            {
                // Evite le panic connu de ClamAV 1.5.x en retirant les certificats non ClamAV du dossier certs.
                foreach (var file in Directory.GetFiles(_certsDir))
                {
                    string name = Path.GetFileName(file);
                    if (!name.Equals("clamav.crt", StringComparison.OrdinalIgnoreCase))
                    {
                        try { File.Delete(file); } catch { }
                    }
                }

                if (File.Exists(_clamavRootCertPath))
                    return true;

                using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(20) };
                string cert = await http.GetStringAsync("https://raw.githubusercontent.com/Cisco-Talos/clamav/main/certs/clamav.crt").ConfigureAwait(false);
                if (string.IsNullOrWhiteSpace(cert) || !cert.Contains("BEGIN CERTIFICATE"))
                    return false;

                await File.WriteAllTextAsync(_clamavRootCertPath, cert).ConfigureAwait(false);
                return true;
            }
            catch
            {
                return false;
            }
        }
    }

    public class UpdateResult
    {
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
        public int ExitCode { get; set; }
        public DateTime StartedAt { get; set; }
        public DateTime? FinishedAt { get; set; }
        public string? NewVersion { get; set; }
        public bool AlreadyUpToDate { get; set; }
        public bool Updated { get; set; }

        public TimeSpan Duration =>
            FinishedAt.HasValue ? FinishedAt.Value - StartedAt : TimeSpan.Zero;
    }
}