using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Text.RegularExpressions;

namespace optiSCAN.Services
{
    /// <summary>
    /// Lance freshclam.exe pour mettre à jour la base de signatures ClamAV.
    /// Découverte automatique des chemins selon l'architecture (x64/x86) et
    /// l'installation système.
    /// </summary>
    public class FreshclamUpdater
    {
        // ── Constantes ────────────────────────────────────────────────────────────

        /// <summary>Délai max d'une mise à jour avant kill automatique.</summary>
        private static readonly TimeSpan UpdateTimeout = TimeSpan.FromMinutes(5);

        /// <summary>Âge à partir duquel un verrou freshclam est considéré orphelin.</summary>
        private static readonly TimeSpan StaleLockAge = TimeSpan.FromMinutes(10);

        // ── Chemins ───────────────────────────────────────────────────────────────

        private readonly string _freshclamExe;
        /// <summary>Répertoire inscriptible pour daily/main et les tmp freshclam.</summary>
        private readonly string _databaseDir;
        private readonly string _freshclamConf;
        private readonly string _certsDir;
        /// <summary>Répertoire contenant <c>clamav.crt</c> pour freshclam 1.5+ (souvent LocalAppData si PF en lecture seule).</summary>
        private string _effectiveCvdCertsDir;

        private static readonly Uri ClamAvRootCertUri =
            new("https://raw.githubusercontent.com/Cisco-Talos/clamav/main/certs/clamav.crt", UriKind.Absolute);

        private System.Threading.Timer? _autoUpdateTimer;
        private CancellationTokenSource? _currentCts;
        private readonly object _ctsLock = new();

        // ── Événements et état ────────────────────────────────────────────────────

        /// <summary>Déclenché à chaque ligne de sortie de freshclam.</summary>
        public event EventHandler<string>? UpdateOutput;

        /// <summary>Déclenché à la fin de la mise à jour (succès ou échec).</summary>
        public event EventHandler<UpdateResult>? UpdateCompleted;

        public DateTime? LastUpdateTime { get; private set; }
        public string DatabaseVersion { get; private set; } = "Inconnue";
        public bool IsUpdating { get; private set; }

        // ── Constructeur ──────────────────────────────────────────────────────────

        public FreshclamUpdater(string? clamavDir = null)
        {
            var dir = clamavDir ?? ResolveClamAvDir();

            _freshclamExe = Path.Combine(dir, "freshclam.exe");
            _databaseDir = ClamAvDatabasePaths.ResolveWritableDatabaseDir(dir);
            _freshclamConf = Path.Combine(dir, "freshclam.conf");
            _certsDir = Path.Combine(dir, "certs");
            _effectiveCvdCertsDir = _certsDir;
        }

        private static string ResolveClamAvDir()
        {
            var baseDir = AppDomain.CurrentDomain.BaseDirectory;
            var arch = Environment.Is64BitProcess ? "x64" : "x86";

            var candidates = new[]
            {
                Path.Combine(baseDir, "clamav", arch),
                Path.Combine(baseDir, "clamav"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "ClamAV"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "ClamAV"),
            };

            foreach (var candidate in candidates)
                if (File.Exists(Path.Combine(candidate, "freshclam.exe")))
                    return candidate;

            return Path.Combine(baseDir, "clamav");
        }

        // ── Mise à jour automatique ───────────────────────────────────────────────

        /// <summary>Active les mises à jour automatiques (toutes les 24 h par défaut).</summary>
        public void EnableAutoUpdate(TimeSpan? interval = null)
        {
            var period = interval ?? TimeSpan.FromHours(24);
            _autoUpdateTimer?.Dispose();
            _autoUpdateTimer = new System.Threading.Timer(
                async _ =>
                {
                    // Skip silencieux si une mise à jour est déjà en cours
                    // (manuelle ou auto précédente non terminée).
                    if (IsUpdating) return;
                    try { await UpdateAsync(); }
                    catch (Exception ex)
                    {
                        AppLogger.Warn("FreshclamUpdater", "Auto-update", ex);
                    }
                },
                null, period, period);
        }

        /// <summary>Désactive les mises à jour automatiques.</summary>
        public void DisableAutoUpdate()
        {
            _autoUpdateTimer?.Dispose();
            _autoUpdateTimer = null;
        }

        /// <summary>Indique si le timer de mise à jour périodique est actif.</summary>
        public bool IsAutoUpdateEnabled => _autoUpdateTimer != null;

        // ── Annulation ─────────────────────────────────────────────────────────────

        /// <summary>
        /// Annule la mise à jour en cours (tue freshclam.exe).
        /// Sans effet si aucune mise à jour n'est active.
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
        /// Lance freshclam.exe et retourne le résultat.
        /// Si freshclam.exe est absent, retourne un succès silencieux (signatures locales).
        /// </summary>
        public async Task<UpdateResult> UpdateAsync(CancellationToken ct = default)
        {
            if (IsUpdating)
                return new UpdateResult { Success = false, Message = "Mise à jour ClamAV déjà en cours." };

            IsUpdating = true;

            // CTS interne lié au token externe + au timeout global.
            var internalCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            internalCts.CancelAfter(UpdateTimeout);

            lock (_ctsLock) { _currentCts = internalCts; }

            var token = internalCts.Token;
            var result = new UpdateResult { StartedAt = DateTime.Now };

            try
            {
                if (!File.Exists(_freshclamExe))
                {
                    result.Success = true;
                    result.Message = "freshclam.exe non trouvé — signatures locales utilisées.";
                    result.AlreadyUpToDate = true;
                    OnOutput("freshclam.exe introuvable — mise à jour ignorée.");
                    return result;
                }

                // Pré-vérification : connectivité réseau (évite un timeout long et opaque).
                if (!IsNetworkAvailable())
                {
                    result.Success = false;
                    result.Message = "Pas de connexion réseau — mise à jour reportée.";
                    OnOutput("[NET] Aucune connexion réseau détectée.");
                    return result;
                }

                // Pré-vérification : nettoyer un éventuel verrou freshclam orphelin.
                CleanupStaleLocks();

                await EnsureCodeSigningCertificatesPresentAsync(token).ConfigureAwait(false);

                // ArgumentList : pas de concaténation de chaîne ; conf et datadir (chemins avec espaces) sont échappés token par token.
                var psi = new ProcessStartInfo
                {
                    FileName = _freshclamExe,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true,
                    // Working dir explicite : freshclam cherche freshclam.conf
                    // dans son cwd si --config-file n'est pas trouvé.
                    WorkingDirectory = Path.GetDirectoryName(_freshclamExe) ?? string.Empty,
                };
                if (HasUsableRootCert())
                {
                    psi.Environment["CVD_CERTS_DIR"] = _effectiveCvdCertsDir;
                }

                BuildArguments(psi.ArgumentList);

                using var proc = new Process
                {
                    StartInfo = psi,
                    EnableRaisingEvents = true,
                };

                var tcs = new TaskCompletionSource<bool>(
                    TaskCreationOptions.RunContinuationsAsynchronously);
                proc.Exited += (_, _) => tcs.TrySetResult(true);

                proc.OutputDataReceived += (_, e) =>
                {
                    if (e.Data == null) return;
                    OnOutput(e.Data);
                    if (e.Data.Contains("up-to-date", StringComparison.OrdinalIgnoreCase) ||
                        e.Data.Contains("up to date", StringComparison.OrdinalIgnoreCase))
                        result.AlreadyUpToDate = true;
                };
                proc.ErrorDataReceived += (_, e) =>
                {
                    if (e.Data != null) OnOutput($"[ERR] {e.Data}");
                };

                using (token.Register(() =>
                {
                    try
                    {
                        if (!proc.HasExited)
                        {
                            OnOutput("⏹️ Annulation : arrêt du process freshclam...");
                            proc.Kill(entireProcessTree: true);
                        }
                    }
                    catch (Exception ex)
                    {
                        AppLogger.Warn("FreshclamUpdater", "Kill process", ex);
                    }
                    tcs.TrySetCanceled(token);
                }))
                {
                    proc.Start();
                    proc.BeginOutputReadLine();
                    proc.BeginErrorReadLine();
                    await tcs.Task.ConfigureAwait(false);
                }

                result.ExitCode = proc.ExitCode;
                result.FinishedAt = DateTime.Now;

                // freshclam: 0 = mis à jour, 1 = déjà à jour, >=2 = erreur
                result.Success = proc.ExitCode is 0 or 1;
                result.Message = proc.ExitCode switch
                {
                    0 => "Signatures ClamAV mises à jour avec succès.",
                    1 => "Signatures ClamAV déjà à jour.",
                    _ => $"Erreur freshclam (code {proc.ExitCode})."
                };

                if (result.Success)
                {
                    LastUpdateTime = DateTime.Now;
                    DatabaseVersion = GetLocalDatabaseVersion();
                    result.Version = DatabaseVersion;
                }
            }
            catch (OperationCanceledException)
            {
                result.Success = false;
                // Différencier annulation utilisateur vs timeout global.
                result.Message = ct.IsCancellationRequested
                    ? "Mise à jour annulée par l'utilisateur."
                    : $"Mise à jour annulée (timeout {UpdateTimeout.TotalMinutes:0} min ou stop manuel).";
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.Message = $"Erreur : {ex.Message}";
                AppLogger.Error("FreshclamUpdater", "UpdateAsync", ex);
            }
            finally
            {
                DatabaseVersion = GetLocalDatabaseVersion();
                lock (_ctsLock)
                {
                    if (ReferenceEquals(_currentCts, internalCts))
                        _currentCts = null;
                }
                internalCts.Dispose();
                IsUpdating = false;
                UpdateCompleted?.Invoke(this, result);
            }

            return result;
        }

        // ── Version locale ─────────────────────────────────────────────────────────

        public string GetLocalDatabaseVersion()
        {
            try
            {
                if (!Directory.Exists(_databaseDir))
                    return "Inconnue";

                string[] candidates = {
                    Path.Combine(_databaseDir, "daily.cld"),
                    Path.Combine(_databaseDir, "daily.cvd"),
                    Path.Combine(_databaseDir, "main.cld"),
                    Path.Combine(_databaseDir, "main.cvd")
                };

                foreach (var filePath in candidates)
                {
                    if (!File.Exists(filePath)) continue;
                    try
                    {
                        var header = ReadFileHeader(filePath, 512);

                        var m = Regex.Match(header, @"ClamAV-VDB:[^:]+:(\d+):");
                        if (m.Success && m.Groups[1].Value.All(char.IsDigit))
                            return m.Groups[1].Value;

                        m = Regex.Match(header, @"version:\s*(\d+)", RegexOptions.IgnoreCase);
                        if (m.Success && m.Groups[1].Value.All(char.IsDigit))
                            return m.Groups[1].Value;
                    }
                    catch (Exception ex)
                    {
                        AppLogger.Warn("FreshclamUpdater", $"Lecture {filePath}", ex);
                    }
                }

                if (File.Exists(_freshclamExe))
                    return GetVersionFromProcess();

                return "Inconnue";
            }
            catch (Exception ex)
            {
                AppLogger.Warn("FreshclamUpdater", "GetLocalDatabaseVersion", ex);
                return "Inconnue";
            }
        }

        /// <summary>
        /// Date du dernier succès freshclam, sinon dernière modification des bases .cld/.cvd.
        /// </summary>
        public string GetLastSignatureChangeDisplay()
        {
            if (LastUpdateTime.HasValue)
                return LastUpdateTime.Value.ToString("dd/MM/yyyy HH:mm");
            var t = GetLatestLocalDatabaseWriteTime();
            return t.HasValue ? t.Value.ToLocalTime().ToString("dd/MM/yyyy HH:mm") : "—";
        }

        private DateTime? GetLatestLocalDatabaseWriteTime()
        {
            try
            {
                if (!Directory.Exists(_databaseDir))
                    return null;
                DateTime? max = null;
                foreach (var name in new[] { "daily.cld", "daily.cvd", "main.cld", "main.cvd" })
                {
                    var p = Path.Combine(_databaseDir, name);
                    if (!File.Exists(p)) continue;
                    var w = File.GetLastWriteTimeUtc(p);
                    if (max == null || w > max.Value) max = w;
                }
                return max;
            }
            catch
            {
                return null;
            }
        }

        // ── Helpers privés ─────────────────────────────────────────────────────────

        /// <summary>
        /// Vérifie qu'au moins une interface réseau est UP et non-loopback.
        /// Test rapide local — ne garantit pas que database.clamav.net est joignable
        /// mais évite un timeout long quand l'utilisateur est offline.
        /// </summary>
        private static bool IsNetworkAvailable()
        {
            try { return NetworkInterface.GetIsNetworkAvailable(); }
            catch { return true; /* en cas de doute, on laisse passer */ }
        }

        /// <summary>
        /// Supprime les verrous freshclam orphelins (mirrors.dat lock, freshclam.pid)
        /// laissés par un process précédent qui aurait crashé.
        /// </summary>
        private void CleanupStaleLocks()
        {
            try
            {
                if (!Directory.Exists(_databaseDir)) return;

                // Noms de verrous connus de freshclam selon les versions.
                string[] lockFiles =
                {
                    Path.Combine(_databaseDir, "freshclam.pid"),
                    Path.Combine(_databaseDir, "mirrors.dat.lock"),
                    Path.Combine(_databaseDir, "freshclam.dat.lock"),
                };

                foreach (var lockPath in lockFiles)
                {
                    if (!File.Exists(lockPath)) continue;
                    try
                    {
                        var age = DateTime.Now - File.GetLastWriteTime(lockPath);
                        if (age > StaleLockAge)
                        {
                            File.Delete(lockPath);
                            OnOutput($"🧹 Verrou orphelin supprimé : {Path.GetFileName(lockPath)}");
                        }
                    }
                    catch (Exception ex)
                    {
                        AppLogger.Warn("FreshclamUpdater", $"Cleanup {lockPath}", ex);
                    }
                }
            }
            catch (Exception ex)
            {
                AppLogger.Warn("FreshclamUpdater", "CleanupStaleLocks", ex);
            }
        }

        /// <summary>
        /// Remplit <see cref="ProcessStartInfo.ArgumentList"/> (échappement sûr des chemins) au lieu de concaténer une ligne de commande.
        /// .NET gère le quoting Windows pour chaque token.
        ///
        /// IMPORTANT : freshclam exige le format "--option=valeur" (un seul
        /// token, avec '=') et NON "--option valeur" (deux tokens séparés)
        /// pour les options à valeur (--datadir, --config-file). Le format
        /// espacé renvoie freshclam exit code 2 (FCE_CONFIG, erreur de
        /// configuration). On construit donc un seul argument par option.
        /// </summary>
        private void BuildArguments(System.Collections.ObjectModel.Collection<string> args)
        {
            args.Add("--show-progress");
            args.Add("--no-warnings");

            try
            {
                Directory.CreateDirectory(_databaseDir);
                // Toujours passer --datadir : même si le conf contient DatabaseDirectory,
                // freshclam doit pouvoir créer tmp.* dans un dossier inscriptible.
                args.Add($"--datadir={_databaseDir}");
            }
            catch (Exception ex)
            {
                AppLogger.Warn("FreshclamUpdater", "BuildArguments datadir", ex);
            }

            var conf = EnsureConfExists();
            if (conf != null)
            {
                args.Add($"--config-file={conf}");
            }

            AppLogger.Info("FreshclamUpdater",
                $"Args: {string.Join(" ", args)}");
        }

        /// <summary>
        /// Garantit l'existence d'un freshclam.conf valide.
        ///
        /// Stratégie : on privilégie TOUJOURS un emplacement writable hors
        /// Program Files (LocalAppData), pour deux raisons :
        ///  1. Le fichier dans Program Files peut être en lecture seule sans
        ///     droits admin.
        ///  2. La UAC Virtualization de Windows redirige les écritures dans
        ///     Program Files vers VirtualStore, ce qui peut faire diverger le
        ///     fichier vu par notre process et celui vu par freshclam.exe.
        ///
        /// On tente aussi en best effort de "neutraliser" le conf corrompu
        /// dans Program Files (BOM, ancienne version) pour éviter qu'il soit
        /// chargé si jamais notre --config-file était ignoré.
        /// </summary>
        private string? EnsureConfExists()
        {
            // 1. Cible préférée : LocalAppData\optiSCAN\clamav\freshclam.conf
            var fallbackDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "optiSCAN", "clamav");
            var fallbackConf = Path.Combine(fallbackDir, "freshclam.conf");

            // Si un conf existant a une directive CVDCertsDirectory cassée
            // (héritée d'une ancienne version d'optiSCAN), on le supprime
            // pour forcer la régénération propre. Sinon freshclam plante
            // avec exit code 2 et "Invalid certs directory".
            InvalidateConfIfBroken(fallbackConf);
            InvalidateConfIfBroken(_freshclamConf);

            var primary = TryWriteConf(fallbackConf);
            if (primary != null)
            {
                // 2. Best effort : si un conf corrompu (BOM) traîne dans le
                //    dossier ClamAV d'origine, on tente de le réparer pour
                //    éviter toute confusion future.
                TryRepairLegacyConf();
                return primary;
            }

            // 3. Dernier recours : conf à côté de freshclam.exe
            return TryWriteConf(_freshclamConf);
        }

        /// <summary>
        /// Détecte les freshclam.conf générés par les anciennes versions
        /// d'optiSCAN qui contenaient une ligne CVDCertsDirectory pointant
        /// vers un dossier vide. Ces conf font crasher freshclam à l'init.
        /// On les renomme en .bak pour forcer la régénération sans la
        /// directive problématique.
        /// </summary>
        private void InvalidateConfIfBroken(string confPath)
        {
            try
            {
                if (!File.Exists(confPath)) return;

                var content = File.ReadAllText(confPath);

                // Marque de version : si le conf n'a pas "generated by optiSCAN v"
                // c'est un conf legacy potentiellement cassé.
                if (IsOurManagedConf(content))
                    return;

                // Conf legacy : on le renomme pour forcer la régénération.
                var bak = confPath + ".v1.bak";
                try
                {
                    if (File.Exists(bak)) File.Delete(bak);
                    File.Move(confPath, bak);
                    AppLogger.Info("FreshclamUpdater",
                        $"Conf legacy renommé en {Path.GetFileName(bak)} — régénération à venir");
                }
                catch (Exception ex)
                {
                    // Si on ne peut pas le renommer (droits), on tente une suppression
                    // directe — sinon on laisse le conf en place avec un warning.
                    try { File.Delete(confPath); AppLogger.Info("FreshclamUpdater", "Conf legacy supprimé"); }
                    catch { AppLogger.Warn("FreshclamUpdater", $"Conf legacy non remplaçable: {confPath}", ex); }
                }
            }
            catch (Exception ex)
            {
                AppLogger.Warn("FreshclamUpdater", $"InvalidateConfIfBroken {confPath}", ex);
            }
        }

        /// <summary>
        /// Tente de réparer (réécrire sans BOM) ou supprimer le freshclam.conf
        /// historique situé à côté de freshclam.exe s'il est corrompu.
        /// Best effort uniquement — un échec ici n'empêche pas la mise à jour
        /// puisque --config-file pointe vers la copie LocalAppData.
        /// </summary>
        private void TryRepairLegacyConf()
        {
            try
            {
                if (!File.Exists(_freshclamConf)) return;
                if (!HasUtf8Bom(_freshclamConf)) return;

                // 1. Tentative de réécriture sans BOM
                if (TryWriteConf(_freshclamConf) != null)
                {
                    OnOutput($"🔧 freshclam.conf réparé (BOM retiré) : {_freshclamConf}");
                    return;
                }

                // 2. Sinon on tente de le renommer pour qu'il ne soit plus chargé
                //    par défaut (au cas où --config-file serait ignoré).
                var bak = _freshclamConf + ".bom-corrupt.bak";
                try
                {
                    if (File.Exists(bak)) File.Delete(bak);
                    File.Move(_freshclamConf, bak);
                    OnOutput($"🔧 freshclam.conf corrompu déplacé vers {Path.GetFileName(bak)}");
                }
                catch (Exception ex)
                {
                    AppLogger.Warn("FreshclamUpdater", "TryRepairLegacyConf rename", ex);
                    OnOutput("⚠️ freshclam.conf corrompu détecté dans Program Files — exécutez fix-freshclam-conf.ps1 en admin pour le réparer.");
                }
            }
            catch (Exception ex)
            {
                AppLogger.Warn("FreshclamUpdater", "TryRepairLegacyConf", ex);
            }
        }

        /// <summary>
        /// Tente d'écrire un freshclam.conf valide au chemin donné. Retourne le chemin
        /// si succès, null si l'écriture a échoué.
        ///
        /// Utilise <see cref="File.WriteAllBytes(string, byte[])"/> avec un buffer
        /// ASCII manuel : ainsi on garantit l'absence absolue de BOM, indépendamment
        /// du comportement de l'API <c>StreamWriter</c> / encoding par défaut.
        /// </summary>
        private string? TryWriteConf(string targetPath)
        {
            try
            {
                var dir = Path.GetDirectoryName(targetPath);
                if (!string.IsNullOrEmpty(dir))
                    Directory.CreateDirectory(dir);

                Directory.CreateDirectory(_databaseDir);

                // freshclam parse les chemins de manière sensible aux backslashes.
                // Sur Windows on normalise en forward slashes pour éviter toute
                // ambiguïté avec les séquences d'échappement.
                var dbDirForConf = NormalizePathForConf(_databaseDir);
                var logPath = ResolveWritableLogPath();
                var logForConf = NormalizePathForConf(logPath);

                // Marque de version : permet à EnsureConfExists de détecter
                // un conf généré par une ancienne version d'optiSCAN qui contenait
                // une directive CVDCertsDirectory cassée, et de le régénérer.
                var lines = new List<string>
                {
                    $"# freshclam.conf generated by optiSCAN v{ProductVersionInfo.ConfMarkerMajor}",
                    $"DatabaseDirectory \"{dbDirForConf}\"",
                };

                if (HasUsableRootCert())
                {
                    lines.Add($"CVDCertsDirectory \"{NormalizePathForConf(_effectiveCvdCertsDir)}\"");
                }

                lines.AddRange(new[]
                {
                    $"UpdateLogFile \"{logForConf}\"",
                    "LogTime yes",
                    "LogVerbose no",
                    "DatabaseMirror database.clamav.net",
                    "MaxAttempts 3",
                    "ConnectTimeout 30",
                    "ReceiveTimeout 30",
                });

                // ClamAV 1.5+ : vérification des signatures CVD — exige clamav.crt
                // dans CVDCertsDirectory (ou CVD_CERTS_DIR). On déploie le fichier
                // depuis clamav/certs de l'app ou %LocalAppData% si Program Files
                // est en lecture seule (cf. EnsureCodeSigningCertificatesPresentAsync).

                // Construction binaire pour garantir 0 BOM, peu importe l'API .NET utilisée.
                // freshclam.conf ne contient que de l'ASCII (paths Windows + mots-clés),
                // donc UTF8 == ASCII ici. Si un path contenait un caractère non-ASCII,
                // l'encodage UTF-8 sans BOM s'applique automatiquement.
                var content = string.Join("\n", lines) + "\n";
                var bytes = new System.Text.UTF8Encoding(encoderShouldEmitUTF8Identifier: false)
                    .GetBytes(content);

                // Sanity check : on n'écrit que si on est sûr qu'il n'y a pas de BOM
                // dans notre buffer.
                if (bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF)
                {
                    AppLogger.Error("FreshclamUpdater", "BOM détecté dans le buffer — abandon");
                    return null;
                }

                // Suppression préalable pour éviter toute fusion bizarre / ACL
                // héritée d'une version antérieure.
                try { if (File.Exists(targetPath)) File.Delete(targetPath); }
                catch (UnauthorizedAccessException) { /* on tentera l'écriture quand même */ }
                catch (IOException) { /* idem */ }

                File.WriteAllBytes(targetPath, bytes);

                // Vérification post-écriture — si jamais le système a injecté un BOM
                // (cas très rare avec Defender / outils tiers), on échoue proprement.
                if (HasUtf8Bom(targetPath))
                {
                    AppLogger.Error("FreshclamUpdater", $"BOM détecté APRÈS écriture: {targetPath}");
                    try { File.Delete(targetPath); } catch { }
                    return null;
                }

                AppLogger.Info("FreshclamUpdater", $"Conf généré : {targetPath}");
                return targetPath;
            }
            catch (UnauthorizedAccessException ex)
            {
                AppLogger.Warn("FreshclamUpdater", $"TryWriteConf {targetPath}: accès refusé", ex);
                return null;
            }
            catch (Exception ex)
            {
                AppLogger.Error("FreshclamUpdater", $"TryWriteConf {targetPath}", ex);
                return null;
            }
        }

        /// <summary>
        /// Détermine un chemin de log writable. Retourne le chemin dans le dossier
        /// database s'il est accessible en écriture, sinon un fallback dans
        /// LocalAppData (évite les échecs sur Program Files sans admin).
        /// </summary>
        private string ResolveWritableLogPath()
        {
            var primary = Path.Combine(_databaseDir, "freshclam.log");
            try
            {
                Directory.CreateDirectory(_databaseDir);
                using var fs = new FileStream(primary, FileMode.OpenOrCreate, FileAccess.Write, FileShare.ReadWrite);
                return primary;
            }
            catch
            {
                var fallbackDir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "optiSCAN", "logs");
                try { Directory.CreateDirectory(fallbackDir); } catch { /* best effort */ }
                return Path.Combine(fallbackDir, "freshclam.log");
            }
        }

        /// <summary>
        /// Normalise un chemin Windows pour le fichier de configuration freshclam :
        /// les backslashes deviennent des forward slashes (acceptés par freshclam
        /// sur Windows et plus sûrs vis-à-vis du parser).
        /// </summary>
        private static string NormalizePathForConf(string path)
            => path.Replace('\\', '/');

        /// <summary>Détecte la présence du BOM UTF-8 (0xEF 0xBB 0xBF) en début de fichier.</summary>
        private static bool HasUtf8Bom(string path)
        {
            try
            {
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
                if (fs.Length < 3) return false;
                var bom = new byte[3];
                _ = fs.Read(bom, 0, 3);
                return bom[0] == 0xEF && bom[1] == 0xBB && bom[2] == 0xBF;
            }
            catch { return false; }
        }

        private static string ReadFileHeader(string path, int maxBytes)
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            var buf = new byte[Math.Min(maxBytes, (int)fs.Length)];
            _ = fs.Read(buf, 0, buf.Length);
            return System.Text.Encoding.ASCII.GetString(buf);
        }

        private string GetVersionFromProcess()
        {
            try
            {
                using var proc = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = _freshclamExe,
                        Arguments = "--version",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    }
                };
                proc.Start();
                var output = proc.StandardOutput.ReadToEnd();
                proc.WaitForExit(3000);

                var m = Regex.Match(output, @"(?:ClamAV\s+[\d.]+/|version\s+)(\d{4,6})");
                return m.Success ? m.Groups[1].Value : "Inconnue";
            }
            catch { return "Inconnue"; }
        }

        private static bool IsOurManagedConf(string content) =>
            Regex.IsMatch(content, @"generated\s+by\s+optiSCAN\s+v\d+", RegexOptions.IgnoreCase);

        private bool HasUsableRootCert()
        {
            try
            {
                var p = Path.Combine(_effectiveCvdCertsDir, "clamav.crt");
                return Directory.Exists(_effectiveCvdCertsDir)
                       && File.Exists(p)
                       && new FileInfo(p).Length >= 256;
            }
            catch
            {
                return false;
            }
        }

        private async Task EnsureCodeSigningCertificatesPresentAsync(CancellationToken ct)
        {
            _effectiveCvdCertsDir = _certsDir;
            var bundled = Path.Combine(AppContext.BaseDirectory, "clamav", "certs", "clamav.crt");

            bool tryDeploy(string dir)
            {
                try
                {
                    Directory.CreateDirectory(dir);
                    var dest = Path.Combine(dir, "clamav.crt");
                    if (File.Exists(dest) && new FileInfo(dest).Length >= 256)
                        return true;
                    if (File.Exists(bundled))
                    {
                        File.Copy(bundled, dest, overwrite: true);
                        OnOutput($"Certificat CVD (clamav.crt) : {dest}");
                    }
                    return File.Exists(dest) && new FileInfo(dest).Length >= 256;
                }
                catch (Exception ex)
                {
                    AppLogger.Warn("FreshclamUpdater", $"tryDeploy {dir}", ex);
                    return false;
                }
            }

            if (tryDeploy(_certsDir))
                return;

            var fallback = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "optiSCAN", "clamav", "cvd-certs");

            if (!tryDeploy(fallback))
                await TryDownloadClamAvRootCertAsync(fallback, ct).ConfigureAwait(false);

            var fbCert = Path.Combine(fallback, "clamav.crt");
            if (File.Exists(fbCert) && new FileInfo(fbCert).Length >= 256)
            {
                _effectiveCvdCertsDir = fallback;
                if (!string.Equals(_effectiveCvdCertsDir, _certsDir, StringComparison.OrdinalIgnoreCase))
                    OnOutput($"Certificats CVD (hors Program Files) : {_effectiveCvdCertsDir}");
                return;
            }

            OnOutput("⚠️ clamav.crt introuvable — vérifiez l'installation ou la connexion réseau.");
        }

        private static async Task TryDownloadClamAvRootCertAsync(string destDir, CancellationToken ct)
        {
            try
            {
                Directory.CreateDirectory(destDir);
                using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(25) };
                http.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", ProductVersionInfo.HttpUserAgent);
                var bytes = await http.GetByteArrayAsync(ClamAvRootCertUri, ct).ConfigureAwait(false);
                if (bytes.Length < 256) return;
                var path = Path.Combine(destDir, "clamav.crt");
                await File.WriteAllBytesAsync(path, bytes, ct).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                AppLogger.Warn("FreshclamUpdater", "TryDownloadClamAvRootCertAsync", ex);
            }
        }

        private void OnOutput(string line)
            => UpdateOutput?.Invoke(this, line);
    }

    // ── DTO de résultat ────────────────────────────────────────────────────────────

    /// <summary>Résultat d'une mise à jour de signatures ClamAV.</summary>
    public class UpdateResult
    {
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
        public string? Version { get; set; }
        public bool AlreadyUpToDate { get; set; }
        public int ExitCode { get; set; }
        public DateTime StartedAt { get; set; }
        public DateTime? FinishedAt { get; set; }
    }
}
