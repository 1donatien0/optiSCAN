// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Net.Http;
using System.Text.Json.Nodes;
using optiSCAN.Localization;
using optiSCAN.Strings;

namespace optiSCAN.Services
{
    /// <summary>
    /// Récupère et installe les règles de détection comportementale depuis le dépôt public
    /// de référence YARA-Forge. Transparence totale vis-à-vis de l'utilisateur :
    /// l'intitulé affiché est "règles de détection" — pas de référence technique externe.
    ///
    /// Fonctionnement :
    ///   1. Interroge l'API GitHub pour la dernière version publiée.
    ///   2. Télécharge le paquet de règles (core — équilibre performance/couverture).
    ///   3. Extrait les fichiers .yar dans le dossier rules/ du projet.
    ///   4. Invalide le cache de règles compilées afin que le moteur les recharge au
    ///      prochain scan.
    ///   5. Expose EnableAutoUpdate() pour planifier des vérifications périodiques.
    /// </summary>
    public class YaraForgeUpdater : ISignatureUpdateCanceller, ISignatureAutoUpdateTarget
    {
        // ── Constantes ────────────────────────────────────────────────────────────

        private const string ApiUrl = OptiscanStrings.Urls.YaraForgeApiLatest;
        private const string PackageName = "yara-forge-rules-core.zip";

        private readonly string _rulesDirectory;
        private readonly string _compiledRulesPath;
        private readonly string _rulesMetaPath;

        private System.Threading.Timer? _autoTimer;
        private CancellationTokenSource? _currentCts;
        private readonly object _ctsLock = new();

        private static readonly HttpClient _http;

        // ── Initialisation statique ───────────────────────────────────────────────

        static YaraForgeUpdater()
        {
            _http = new HttpClient();
            _http.DefaultRequestHeaders.UserAgent.ParseAdd(ProductVersionInfo.HttpUserAgent);
            _http.Timeout = TimeSpan.FromMinutes(10);
        }

        // ── Événements et état ────────────────────────────────────────────────────

        /// <summary>Déclenché à chaque étape notable de la mise à jour.</summary>
        public event EventHandler<string>? UpdateOutput;

        /// <summary>Déclenché à la fin de la mise à jour (succès ou échec).</summary>
        public event EventHandler<RulesUpdateResult>? UpdateCompleted;

        public bool IsUpdating { get; private set; }
        public string? LastVersion { get; private set; }
        public DateTime? LastUpdateTime { get; private set; }

        // ── Constructeur ─────────────────────────────────────────────────────────

        public YaraForgeUpdater(string? rulesDir = null)
        {
            _rulesDirectory = YaraRulesLocation.ResolveWritable(rulesDir);
            _compiledRulesPath = Path.Combine(_rulesDirectory, "_compiled.yarc");
            _rulesMetaPath = Path.Combine(_rulesDirectory, ".optiscan-yara-meta.txt");
            LoadPersistedMeta();
        }

        /// <summary>True si au moins un fichier .yar est présent localement.</summary>
        public bool HasLocalRulesFiles()
        {
            try
            {
                return Directory.Exists(_rulesDirectory)
                    && Directory.GetFiles(_rulesDirectory, "*.yar").Length > 0;
            }
            catch (Exception ignored) when (!ignored.IsFatal())
            {
                return false;
            }
        }

        /// <summary>Version du paquet YARA-Forge affichable (persistée sur disque).</summary>
        public string GetRulesPackVersionDisplay()
            => string.IsNullOrWhiteSpace(LastVersion) ? "—" : LastVersion!.Trim();

        /// <summary>Date de dernière mise à jour réussie des règles (persistée).</summary>
        public string GetRulesLastUpdateDisplay()
            => LastUpdateTime.HasValue
                ? LastUpdateTime.Value.ToString("g", CultureInfo.CurrentCulture)
                : "—";

        private void LoadPersistedMeta()
        {
            try
            {
                if (!File.Exists(_rulesMetaPath)) return;
                var lines = File.ReadAllLines(_rulesMetaPath);
                if (lines.Length >= 1 && !string.IsNullOrWhiteSpace(lines[0]))
                    LastVersion = lines[0].Trim();
                if (lines.Length >= 2
                    && DateTime.TryParse(lines[1], CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var utc))
                    LastUpdateTime = utc.ToLocalTime();
            }
            catch (Exception ex) when (!ex.IsFatal())
            {
                AppLogger.Warn("YaraForgeUpdater", "LoadPersistedMeta", ex);
            }
        }

        private void SavePersistedMeta()
        {
            try
            {
                if (string.IsNullOrWhiteSpace(LastVersion)) return;
                Directory.CreateDirectory(_rulesDirectory);
                var line2 = LastUpdateTime?.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture) ?? "";
                File.WriteAllText(_rulesMetaPath, LastVersion + "\n" + line2);
            }
            catch (Exception ex) when (!ex.IsFatal())
            {
                AppLogger.Warn("YaraForgeUpdater", "SavePersistedMeta", ex);
            }
        }

        // ── Mise à jour automatique ───────────────────────────────────────────────

        /// <summary>
        /// Active les mises à jour automatiques des règles de détection.
        /// Par défaut : vérification quotidienne.
        /// </summary>
        public void EnableAutoUpdate(TimeSpan? interval = null)
        {
            var period = interval ?? TimeSpan.FromHours(24);
            _autoTimer?.Dispose();
            _autoTimer = new System.Threading.Timer(
                _ =>
                {
                    if (IsUpdating) return;
                    _ = Task.Run(async () =>
                    {
                        try { await UpdateAsync().ConfigureAwait(false); }
                        catch (OperationCanceledException) { /* annulé */ }
                        catch (Exception ex) when (!ex.IsFatal()) { AppLogger.Warn("YaraForgeUpdater", "Auto-update", ex); }
                    });
                },
                null,
                period,
                period);
        }

        /// <summary>Désactive les mises à jour automatiques.</summary>
        public void DisableAutoUpdate()
        {
            _autoTimer?.Dispose();
            _autoTimer = null;
        }

        /// <summary>Indique si le timer de mise à jour périodique est actif.</summary>
        public bool IsAutoUpdateEnabled => _autoTimer != null;

        /// <summary>
        /// Annule la mise à jour des règles en cours (interrompt téléchargement
        /// HTTP / extraction). Sans effet si aucune mise à jour n'est active.
        /// </summary>
        public void CancelUpdate()
        {
            lock (_ctsLock)
            {
                try { _currentCts?.Cancel(); }
                catch (ObjectDisposedException) { /* déjà disposé */ }
            }
        }

        // ── Mise à jour manuelle ──────────────────────────────────────────────────

        /// <summary>
        /// Vérifie et installe la dernière version des règles de détection.
        /// </summary>
        public async Task<RulesUpdateResult> UpdateAsync(
            IProgress<string>? progress = null,
            CancellationToken ct = default)
        {
            if (IsUpdating)
                return new RulesUpdateResult
                {
                    Success = false,
                    Message = LocalizationService.GetString("YaraForge_AlreadyRunning")
                };

            IsUpdating = true;
            var result = new RulesUpdateResult { StartedAt = DateTime.Now };

            // CTS lié au token externe : permet à CancelUpdate() d'interrompre
            // les opérations HTTP/I/O ci-dessous.
            var internalCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            lock (_ctsLock) { _currentCts = internalCts; }
            var token = internalCts.Token;

            try
            {
                // ── 1. Récupération de la dernière version ─────────────────────
                Report(progress, LocalizationService.GetString("SigUpd_VerifyingRules"));

                string releaseJson;
                try
                {
                    releaseJson = await _http.GetStringAsync(ApiUrl, token);
                }
                catch (Exception ex) when (!ex.IsFatal())
                {
                    result.Success = false;
                    result.Message = LocalizationService.Format("YaraForge_ContactError", ex.Message);
                    return result;
                }

                var release = JsonNode.Parse(releaseJson);
                var tagName = release?["tag_name"]?.GetValue<string>() ?? LocalizationService.GetString("Common_Unknown");

                Report(progress, LocalizationService.Format("YaraForge_VersionAvailable", tagName));

                // Déjà à jour ?
                if (LastVersion != null && LastVersion == tagName)
                {
                    result.Success = true;
                    result.AlreadyUpToDate = true;
                    result.Message = LocalizationService.GetString("YaraForge_AlreadyUpToDate");
                    return result;
                }

                // ── 2. Localisation de l'asset ────────────────────────────────
                var assets = release?["assets"]?.AsArray();
                string? downloadUrl = null;
                JsonNode? packageAsset = null;

                if (assets != null)
                {
                    foreach (var asset in assets)
                    {
                        var name = asset?["name"]?.GetValue<string>() ?? string.Empty;
                        if (name.Equals(PackageName, StringComparison.OrdinalIgnoreCase))
                        {
                            downloadUrl = asset?["browser_download_url"]?.GetValue<string>();
                            packageAsset = asset;
                            break;
                        }
                    }
                }

                if (string.IsNullOrEmpty(downloadUrl))
                {
                    result.Success = false;
                    result.Message = LocalizationService.GetString("YaraForge_PackageNotFound");
                    return result;
                }

                // Release, asset, taille et SHA-256 doivent tous correspondre à l'allowlist locale.
                if (!YaraForgePackageIntegrity.TryGetTrustedExpectedDigest(
                        tagName, PackageName, packageAsset, out var expectedSize, out var expectedSha256)
                    || !YaraForgePackageIntegrity.IsAllowedDownloadUrl(downloadUrl, tagName, PackageName))
                {
                    result.Success = false;
                    result.Message = LocalizationService.GetString("YaraForge_IntegrityError");
                    AppLogger.Warn("YaraForgeUpdater", "Asset YARA-Forge sans empreinte SHA-256 ou URL inattendue : refusé");
                    return result;
                }

                // ── 3. Téléchargement ─────────────────────────────────────────
                Report(progress, LocalizationService.GetString("YaraForge_Downloading"));

                byte[] zipBytes;
                try
                {
                    using var response = await _http.GetAsync(downloadUrl, HttpCompletionOption.ResponseHeadersRead, token);
                    response.EnsureSuccessStatusCode();
                    await using var body = await response.Content.ReadAsStreamAsync(token);
                    zipBytes = await YaraForgePackageIntegrity.ReadBoundedAsync(
                        body, YaraForgePackageIntegrity.MaxPackageBytes, token);
                }
                catch (Exception ex) when (!ex.IsFatal())
                {
                    result.Success = false;
                    result.Message = LocalizationService.Format("YaraForge_DownloadError", ex.Message);
                    return result;
                }

                if (!YaraForgePackageIntegrity.Validate(zipBytes, expectedSize, expectedSha256))
                {
                    result.Success = false;
                    result.Message = LocalizationService.GetString("YaraForge_IntegrityError");
                    AppLogger.Warn("YaraForgeUpdater", "Intégrité du paquet YARA-Forge refusée");
                    return result;
                }

                // ── 4. Extraction (I/O synchrone, centaines de fichiers) ─────
                // Hors thread UI : UpdateAsync peut reprendre le dispatcher (ConfigureAwait(true))
                // depuis MainWindow — extraire ici bloquait l'interface plusieurs secondes.
                Report(progress, LocalizationService.GetString("YaraForge_Installing"));

                if (!Directory.Exists(_rulesDirectory))
                    Directory.CreateDirectory(_rulesDirectory);

                var rulesDir = _rulesDirectory;
                var compiledPath = _compiledRulesPath;
                int installed = await Task.Run(
                    () => InstallYarPackageFromZipBytes(zipBytes, rulesDir, compiledPath, token),
                    token).ConfigureAwait(false);

                // ── 5. Résultat ───────────────────────────────────────────────
                LastVersion = tagName;
                LastUpdateTime = DateTime.Now;
                SavePersistedMeta();

                result.Success = true;
                result.Version = tagName;
                result.FilesInstalled = installed;
                result.Message = installed > 0
                    ? LocalizationService.Format("YaraForge_UpdateOk", installed, tagName)
                    : LocalizationService.GetString("YaraForge_NoNewFiles");

                Report(progress, result.Message);
            }
            catch (OperationCanceledException)
            {
                result.Success = false;
                result.Message = LocalizationService.GetString("YaraForge_Cancelled");
            }
            catch (Exception ex) when (!ex.IsFatal())
            {
                result.Success = false;
                result.Message = LocalizationService.Format("YaraForge_Error", ex.Message);
            }
            finally
            {
                lock (_ctsLock)
                {
                    if (ReferenceEquals(_currentCts, internalCts))
                        _currentCts = null;
                }
                internalCts.Dispose();
                IsUpdating = false;
                result.FinishedAt = DateTime.Now;
                UpdateCompleted?.Invoke(this, result);
            }

            return result;
        }

        /// <summary>
        /// Extraction synchrone du ZIP — doit tourner sur un thread pool (<see cref="Task.Run"/>)
        /// pour ne pas bloquer le dispatcher WPF.
        /// </summary>
        private static int InstallYarPackageFromZipBytes(
            byte[] zipBytes,
            string rulesDirectory,
            string compiledRulesPath,
            CancellationToken ct)
        {
            // Extraction dans un dossier temporaire voisin : un paquet refusé (plafond, nom
            // invalide) n'installe rien ; sinon les règles remplacent les anciennes une à une.
            var staging = Path.Combine(
                Path.GetDirectoryName(Path.GetFullPath(rulesDirectory).TrimEnd(Path.DirectorySeparatorChar)) ?? rulesDirectory,
                "rules.staging-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(staging);
            int installed = 0;
            try
            {
                using (var ms = new MemoryStream(zipBytes, writable: false))
                using (var archive = new ZipArchive(ms, ZipArchiveMode.Read))
                    YaraForgePackageIntegrity.ExtractRules(archive, staging, ct);

                foreach (var file in Directory.EnumerateFiles(staging, "*.yar"))
                {
                    var dest = Path.Combine(rulesDirectory, Path.GetFileName(file));
                    try
                    {
                        File.Move(file, dest, overwrite: true);
                        installed++;
                    }
                    catch (Exception ex) when (!ex.IsFatal())
                    {
                        AppLogger.Warn("YaraForgeUpdater", $"Installation ignorée : {Path.GetFileName(file)}", ex);
                    }
                }
            }
            finally
            {
                try { Directory.Delete(staging, recursive: true); }
                catch (Exception ex) when (!ex.IsFatal()) { AppLogger.Debug("YaraForgeUpdater", "Nettoyage du dossier temporaire : " + ex.Message); }
            }

            try
            {
                if (File.Exists(compiledRulesPath))
                    File.Delete(compiledRulesPath);
            }
            catch (Exception ex) when (!ex.IsFatal())
            {
                AppLogger.Warn("YaraForgeUpdater", "Suppression du cache .yarc compilé", ex);
            }

            return installed;
        }

        // ── Helpers ───────────────────────────────────────────────────────────────

        private void Report(IProgress<string>? progress, string message)
        {
            // Si un IProgress est branché (ex. MAJ manuelle depuis MainWindow), ne pas
            // doubler avec UpdateOutput — sinon deux flux AppendSignatureLog saturent le dispatcher.
            if (progress != null)
                progress.Report(message);
            else
                UpdateOutput?.Invoke(this, message);
        }
    }

    // ── DTO résultat ──────────────────────────────────────────────────────────────

    public class RulesUpdateResult
    {
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
        public string? Version { get; set; }
        public int FilesInstalled { get; set; }
        public bool AlreadyUpToDate { get; set; }
        public DateTime StartedAt { get; set; }
        public DateTime? FinishedAt { get; set; }

        public TimeSpan Duration =>
            FinishedAt.HasValue ? FinishedAt.Value - StartedAt : TimeSpan.Zero;
    }
}
