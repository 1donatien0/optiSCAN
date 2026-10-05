using System.Collections.Concurrent;
using System.IO;

namespace optiSCAN.Services
{
    /// <summary>
    /// Protection en temps réel via FileSystemWatcher.
    /// Surveille les dossiers critiques et analyse immédiatement les nouveaux/modifiés fichiers.
    /// </summary>
    public class RealTimeProtection : IDisposable
    {
        private readonly ScanOrchestrator _orchestrator;
        private readonly QuarantineManager _quarantineManager;
        private readonly NotificationService _notifications;
        private readonly ConcurrentDictionary<string, DateTime> _recentlyScanned;
        private readonly ConcurrentDictionary<string, byte> _recoveringWatchers = new(StringComparer.OrdinalIgnoreCase);
        private readonly List<FileSystemWatcher> _watchers;
        private readonly SemaphoreSlim _scanSemaphore;
        // Timer dédié au nettoyage périodique du cache, même si le watcher ne reçoit pas d'événements.
        private System.Threading.Timer? _cacheCleanupTimer;
        private bool _isEnabled;
        private volatile bool _disposed;
        private const int MaxConcurrentScans = 3;
        private int _suspendCount;

        // Délai d'attente après création/modification (éviter les scans sur écriture partielle)
        private static readonly TimeSpan StabilizationDelay = TimeSpan.FromMilliseconds(500);
        private static readonly TimeSpan StabilitySampleDelay = TimeSpan.FromMilliseconds(250);
        private static readonly TimeSpan StabilityTimeout = TimeSpan.FromSeconds(20);

        public event EventHandler<Models.ThreatInfo>? ThreatDetected;
        public bool IsEnabled => _isEnabled;

        /// <summary>Ignore les événements watcher pendant un scan manuel (compteur réentrant).</summary>
        public void Suspend() => Interlocked.Increment(ref _suspendCount);

        /// <summary>Réactive la surveillance après <see cref="Suspend"/>.</summary>
        public void Resume()
        {
            if (Interlocked.Decrement(ref _suspendCount) < 0)
                Interlocked.Exchange(ref _suspendCount, 0);
        }

        private bool IsSuspended => Volatile.Read(ref _suspendCount) > 0;

        /// <summary>Vrai pendant un scan manuel ou USB (surveillance processus en pause).</summary>
        public bool IsPaused => IsSuspended;

        private readonly IUserPreferencesAccessor _prefs;
        private readonly IExclusionSettingsAccessor _exclusions;
        private readonly ScanLogManager? _logger;
        private readonly IUiEventBus? _uiEvents;

        public RealTimeProtection(
            ScanOrchestrator orchestrator,
            QuarantineManager quarantineManager,
            NotificationService notifications,
            IUserPreferencesAccessor? preferences = null,
            IExclusionSettingsAccessor? exclusions = null,
            ScanLogManager? logger = null,
            IUiEventBus? uiEvents = null)
        {
            _logger = logger;
            _uiEvents = uiEvents;
            _prefs = preferences ?? new DefaultUserPreferencesAccessor();
            _exclusions = exclusions ?? new DefaultExclusionSettingsAccessor();
            _orchestrator = orchestrator;
            _quarantineManager = quarantineManager;
            _notifications = notifications;
            _recentlyScanned = new ConcurrentDictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase); // NTFS : chemins insensibles à la casse
            _watchers = new List<FileSystemWatcher>();
            _scanSemaphore = new SemaphoreSlim(MaxConcurrentScans);
        }

        /// <summary>
        /// Démarre la surveillance en temps réel sur les dossiers critiques, le bureau et les téléchargements.
        /// Sans effet si la protection est déjà active.
        /// </summary>
        public void Start()
        {
            if (_isEnabled || _disposed) return;

            // Les événements d'erreur des watchers peuvent arriver dès leur création.
            _isEnabled = true;
            foreach (var folder in RealTimeWatchPaths.GetWatchFolders(_exclusions))
                AddWatcher(folder);

            // Cleanup périodique du cache : toutes les 5 min, on supprime les
            // entrées de plus de 5 min. Indépendant de l'arrivée d'événements,
            // ce qui évite la croissance silencieuse du cache si la machine reste inactive.
            _cacheCleanupTimer = new System.Threading.Timer(
                _ => { try { CleanupRecentCache(); } catch { /* swallow */ } },
                state: null,
                dueTime: TimeSpan.FromMinutes(5),
                period: TimeSpan.FromMinutes(5));

            lock (_watchers)
                _isEnabled = _watchers.Count > 0;
            WriteLog(_isEnabled
                ? $"Protection temps réel activée ({_watchers.Count} dossier(s) surveillé(s))"
                : "Protection temps réel indisponible : aucun dossier n'a pu être surveillé");
        }

        /// <summary>
        /// Arrête la surveillance en temps réel et libère tous les <see cref="FileSystemWatcher"/> actifs.
        /// Sans effet si la protection est déjà arrêtée.
        /// </summary>
        public void Stop()
        {
            if (!_isEnabled && _watchers.Count == 0)
            {
                _cacheCleanupTimer?.Dispose();
                _cacheCleanupTimer = null;
                return;
            }

            _cacheCleanupTimer?.Dispose();
            _cacheCleanupTimer = null;

            lock (_watchers)
            {
                foreach (var watcher in _watchers)
                {
                    watcher.EnableRaisingEvents = false;
                    watcher.Dispose();
                }
                _watchers.Clear();
            }
            _recentlyScanned.Clear();

            _isEnabled = false;
            WriteLog("Protection temps réel désactivée");
        }

        private bool AddWatcher(string path)
        {
            if (_exclusions.Current.IsFolderExcluded(path))
                return false;

            // Un dossier surveillé qui est (ou passe par) une jonction ferait analyser par SYSTEM
            // tout un autre emplacement : refusé dès le démarrage.
            if (!RealTimePathGuard.IsDirectPath(path))
            {
                AppLogger.Warn("RealTimeProtection", $"Dossier non surveillé (jonction ou lien dans le chemin) : {PathRedaction.RedactPath(path)}");
                return false;
            }

            FileSystemWatcher? watcher = null;
            try
            {
                watcher = new FileSystemWatcher(path)
                {
                    IncludeSubdirectories = true,
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.CreationTime,
                    Filter = "*.*",
                    // Buffer 64 KB (vs 8 KB par défaut) : sur les machines avec
                    // beaucoup d'écritures (build IDE, navigateurs, antivirus tiers),
                    // évite la perte d'événements liée à un overflow buffer kernel.
                    InternalBufferSize = 64 * 1024,
                };

                watcher.Created += SurFichierModifie;
                watcher.Changed += SurFichierModifie;
                watcher.Renamed += SurFichierRenomme;
                watcher.Error += SurErreurWatcher;

                lock (_watchers)
                {
                    if (_disposed)
                    {
                        watcher.Dispose();
                        return false;
                    }
                    _watchers.Add(watcher);
                    try
                    {
                        watcher.EnableRaisingEvents = true;
                    }
                    catch
                    {
                        _watchers.Remove(watcher);
                        throw;
                    }
                }
                return true;
            }
            catch (Exception ex)
            {
                watcher?.Dispose();
                WriteLog($"Impossible de surveiller {PathRedaction.RedactPath(path)} : {PathRedaction.RedactPath(ex.Message)}");
                return false;
            }
        }

        // CRITIQUE : ces deux handlers sont async void (imposé par la signature
        // FileSystemEventHandler). Toute exception non gérée crashe le process.
        // Un fichier crafté qui déclenche une exception suffirait à désactiver la
        // protection temps réel. On enrobe donc TOUT le corps en try/catch global.
        /// <summary>
        /// Réagit à la création/modification d'un fichier et déclenche un scan si nécessaire.
        /// </summary>
        /// <remarks>
        /// Le corps est en <c>try/catch</c> global : un crash dans un handler <c>async void</c>
        /// mettrait fin à la protection temps réel.
        /// On dé-duplique et on attend un bref délai de stabilisation pour éviter de scanner
        /// un fichier encore en cours d'écriture.
        /// </remarks>
        private async void SurFichierModifie(object sender, FileSystemEventArgs e)
        {
            try
            {
                // Ignorer les dossiers
                if (Directory.Exists(e.FullPath)) return;

                if (IsSuspended) return;

                if (!RiskyFileExtensions.IsRisky(e.FullPath)) return;

                var utcNow = DateTime.UtcNow;
                _recentlyScanned[e.FullPath] = utcNow;

                await Task.Delay(StabilizationDelay);

                // Un événement plus récent a repoussé le scan : seul le dernier traite le fichier.
                if (!_recentlyScanned.TryGetValue(e.FullPath, out var latest) || latest != utcNow)
                    return;
                if (!await WaitForStableFileAsync(e.FullPath, utcNow))
                    return;

                if (!File.Exists(e.FullPath)) return;

                CleanupRecentCache();

                await _scanSemaphore.WaitAsync();
                try
                {
                    if (!_recentlyScanned.TryGetValue(e.FullPath, out latest) || latest != utcNow)
                        return;
                    await ScanFileAsync(WatchRootOf(sender), e.FullPath, e.ChangeType);
                }
                finally
                {
                    _scanSemaphore.Release();
                }

            }
            catch (Exception ex)
            {
                // Logger sans propager — protection temps réel ne doit JAMAIS crasher.
                WriteLog($"[RTP] SurFichierModifie exception ({PathRedaction.RedactPath(e.FullPath)}): {PathRedaction.RedactPath(ex.Message)}");
            }
        }

        /// <summary>
        /// Réagit à un renommage de fichier (scan sur le nouveau chemin si applicable).
        /// </summary>
        /// <remarks>
        /// Même stratégie que SurFichierModifie : déduplication + stabilisation + protection
        /// contre les exceptions (handler async void).
        /// </remarks>
        private async void SurFichierRenomme(object sender, RenamedEventArgs e)
        {
            try
            {
                if (Directory.Exists(e.FullPath)) return;

                if (IsSuspended) return;

                if (!RiskyFileExtensions.IsRisky(e.FullPath)) return;

                var utcNow = DateTime.UtcNow;
                _recentlyScanned[e.FullPath] = utcNow;

                await Task.Delay(StabilizationDelay);
                if (!_recentlyScanned.TryGetValue(e.FullPath, out var latest) || latest != utcNow)
                    return;
                if (!await WaitForStableFileAsync(e.FullPath, utcNow))
                    return;
                if (!File.Exists(e.FullPath)) return;

                CleanupRecentCache();

                await _scanSemaphore.WaitAsync();
                try
                {
                    if (!_recentlyScanned.TryGetValue(e.FullPath, out latest) || latest != utcNow)
                        return;
                    await ScanFileAsync(WatchRootOf(sender), e.FullPath, WatcherChangeTypes.Renamed);
                }
                finally
                {
                    _scanSemaphore.Release();
                }

            }
            catch (Exception ex)
            {
                WriteLog($"[RTP] SurFichierRenomme exception ({PathRedaction.RedactPath(e.FullPath)}): {PathRedaction.RedactPath(ex.Message)}");
            }
        }

        /// <summary>
        /// Logue les erreurs du <see cref="FileSystemWatcher"/>.
        /// </summary>
        /// <remarks>
        /// Une erreur signifie potentiellement une perte d'événements : le watcher est recréé
        /// et les fichiers à risque existants sont parcourus pour tenter un rattrapage.
        /// </remarks>
        private void SurErreurWatcher(object sender, ErrorEventArgs e)
        {
            if (sender is not FileSystemWatcher watcher)
                return;

            var path = watcher.Path;
            WriteLog($"Perte d'événements FileSystemWatcher sur {PathRedaction.RedactPath(path)} : {PathRedaction.RedactPath(e.GetException()?.Message)}. Réinitialisation et rattrapage en cours.");
            if (!_recoveringWatchers.TryAdd(path, 0))
                return;

            _ = Task.Run(() => RecoverWatcherAsync(watcher, path));
        }

        private async Task<bool> WaitForStableFileAsync(string filePath, DateTime eventTime)
        {
            var deadline = DateTime.UtcNow + StabilityTimeout;
            long previousLength = -1;
            DateTime previousWrite = DateTime.MinValue;
            var stableSamples = 0;

            while (DateTime.UtcNow < deadline)
            {
                if (!_isEnabled || IsSuspended)
                    return false;
                if (!_recentlyScanned.TryGetValue(filePath, out var latest) || latest != eventTime)
                    return false;
                if (!File.Exists(filePath))
                    return false;

                try
                {
                    var info = new FileInfo(filePath);
                    info.Refresh();
                    if (info.Length == previousLength && info.LastWriteTimeUtc == previousWrite)
                    {
                        if (++stableSamples >= 2)
                            return true;
                    }
                    else
                    {
                        previousLength = info.Length;
                        previousWrite = info.LastWriteTimeUtc;
                        stableSamples = 0;
                    }
                }
                catch
                {
                    stableSamples = 0;
                }

                await Task.Delay(StabilitySampleDelay).ConfigureAwait(false);
            }

            WriteLog($"[RTP] Fichier non analysé car il ne s'est pas stabilisé : {PathRedaction.RedactPath(filePath)}");
            return false;
        }

        private async Task RecoverWatcherAsync(FileSystemWatcher failedWatcher, string path)
        {
            try
            {
                if (!OperatingSystem.IsWindows())
                    return;

                lock (_watchers)
                {
                    if (_disposed || !_isEnabled)
                        return;
                    _watchers.Remove(failedWatcher);
                    failedWatcher.EnableRaisingEvents = false;
                    failedWatcher.Dispose();
                }

                if (!AddWatcher(path))
                {
                    lock (_watchers)
                        _isEnabled = _watchers.Count > 0;
                    WriteLog($"Surveillance non rétablie : {PathRedaction.RedactPath(path)}");
                    return;
                }

                var skipped = 0;
                foreach (var file in ClamdEngine.EnumerateScannableFiles(
                             path,
                             _exclusions.Current.IsFolderExcluded,
                             _ => Interlocked.Increment(ref skipped)))
                {
                    if (IsSuspended || _disposed)
                        break;
                    if (!RiskyFileExtensions.IsRisky(file))
                        continue;

                    await _scanSemaphore.WaitAsync().ConfigureAwait(false);
                    try
                    {
                        await ScanFileAsync(path, file, WatcherChangeTypes.Changed).ConfigureAwait(false);
                    }
                    finally
                    {
                        _scanSemaphore.Release();
                    }
                }

                if (skipped > 0)
                    WriteLog($"Rattrapage incomplet pour {PathRedaction.RedactPath(path)} : {skipped} élément(s) inaccessible(s), hors ligne ou lié(s).");
            }
            catch (Exception ex)
            {
                WriteLog($"Récupération du watcher impossible ({PathRedaction.RedactPath(path)}) : {PathRedaction.RedactPath(ex.Message)}");
            }
            finally
            {
                _recoveringWatchers.TryRemove(path, out _);
            }
        }

        private static string? WatchRootOf(object sender) => (sender as FileSystemWatcher)?.Path;

        private async Task ScanFileAsync(string? watchRoot, string filePath, WatcherChangeTypes changeType)
        {
            try
            {
                // Copies du service pour un scan IPC : déjà analysées, et supprimées juste après.
                if (ScanStaging.IsStagingPath(filePath))
                    return;

                // Ne pas rescanner un fichier individuellement exclu
                if (_exclusions.Current.IsFileExcluded(filePath))
                {
                    WriteLog($"[RTP] Fichier exclu, ignoré : {PathRedaction.RedactPath(filePath)}");
                    return;
                }

                // Le fichier doit être réellement sous le dossier surveillé (pas atteint par une
                // jonction), et reste ouvert pendant l'analyse pour que le chemin ne change pas.
                Models.ScanResult result;
                string? scannedSha256;
                string? refusal = "dossier surveillé inconnu";
                using (var pin = watchRoot == null ? null : RealTimePathGuard.PinWithinRoot(watchRoot, filePath, out refusal))
                {
                    if (pin == null)
                    {
                        WriteLog($"[RTP] Fichier ignoré ({refusal}) : {PathRedaction.RedactPath(filePath)}");
                        return;
                    }

                    (result, scannedSha256) = await ScanPinnedAsync(pin, filePath).ConfigureAwait(false);
                }

                if (result.Status != Models.ScanStatus.Completed)
                    WriteLog($"[RTP] Scan incomplet ({PathRedaction.RedactPath(filePath)}) : {result.ErrorMessage ?? result.Status.ToString()}");

                if (result.ThreatsFound > 0)
                {
                    // Trace persistante (Historique) : le toast seul disparait sans laisser de trace.
                    DetectionHistoryRecorder.Record(_logger, _uiEvents, result, filePath);

                    foreach (var threat in result.Threats)
                    {
                        // Notification toast
                        _notifications.ShowThreatDetected(threat);

                        if (_exclusions.Current.AutoQuarantineEnabled)
                        {
                            // Quarantaine automatique activée par l'utilisateur
                            // Empreinte du contenu analysé : si le fichier a changé depuis, la
                            // quarantaine est refusée plutôt que d'isoler un autre contenu.
                            if (_quarantineManager.Quarantine(threat, result.SessionId, scannedSha256))
                            {
                                WriteLog($"[RTP] Quarantaine auto : {threat.FileName} ({threat.VirusName})");
                                _notifications.ShowQuarantined(threat);
                            }
                        }

                        // Notifier l'UI dans tous les cas — elle gère l'action si pas d'auto-quarantaine
                        ThreatDetected?.Invoke(this, threat);
                    }
                }
            }
            catch (Exception ex)
            {
                WriteLog($"[RTP] Erreur scan {PathRedaction.RedactPath(filePath)} : {PathRedaction.RedactPath(ex.Message)}");
            }
        }

        /// <summary>
        /// Analyse le contenu de la poignée épinglée, pas le chemin : une copie est faite depuis
        /// cette poignée (<see cref="ScanStaging"/>), puis analysée. Renommer un dossier parent
        /// et y substituer une jonction après la vérification ne change donc pas ce qui est
        /// analysé. Les menaces sont rattachées au chemin d'origine.
        /// La copie couvre toute la taille du fichier si l'espace temporaire le permet ;
        /// en cas d'échec, le scan est incomplet et aucun repli par chemin n'est effectué.
        /// </summary>
        private async Task<(Models.ScanResult Result, string? Sha256)> ScanPinnedAsync(IDisposable pin, string filePath)
        {
            if (pin is not Microsoft.Win32.SafeHandles.SafeFileHandle handle)
                return (CreateStagingFailure(filePath, "La poignée épinglée n'est pas disponible."), null);

            ScanStaging.StagedFile staged;
            try
            {
                var sourceLength = RandomAccess.GetLength(handle);
                using var stream = new FileStream(handle, FileAccess.Read, bufferSize: 0);
                staged = ScanStaging.Stage(stream, Path.GetFileName(filePath), sourceLength);
            }
            catch (Exception ex)
            {
                return (CreateStagingFailure(filePath, ex.Message), null);
            }

            using (staged)
            {
                var result = await _orchestrator.ScanFileAsync(staged.Path).ConfigureAwait(false);
                RebindStagedResult(result, staged.Path, filePath);
                return (result, staged.Sha256);
            }
        }

        private static Models.ScanResult CreateStagingFailure(string filePath, string reason)
        {
            var now = DateTime.Now;
            return new Models.ScanResult
            {
                Type = Models.ScanType.File,
                TargetPath = filePath,
                StartedAt = now,
                FinishedAt = now,
                Status = Models.ScanStatus.Error,
                ErrorMessage = "Copie de scan sécurisée impossible : " + reason,
                HasCoverageGaps = true,
            };
        }

        /// <summary>Remplace le chemin de la copie analysée par le chemin d'origine dans le résultat.</summary>
        internal static void RebindStagedResult(Models.ScanResult result, string stagedPath, string originalPath)
        {
            if (string.Equals(result.TargetPath, stagedPath, StringComparison.OrdinalIgnoreCase))
                result.TargetPath = originalPath;

            foreach (var threat in result.Threats)
            {
                if (threat.FilePath.StartsWith(stagedPath, StringComparison.OrdinalIgnoreCase))
                    threat.FilePath = originalPath + threat.FilePath[stagedPath.Length..];
            }
        }

        private void CleanupRecentCache()
        {
            var threshold = DateTime.UtcNow.AddMinutes(-5);
            foreach (var kvp in _recentlyScanned)
            {
                if (kvp.Value < threshold)
                    _recentlyScanned.TryRemove(kvp.Key, out _);
            }
        }

        private static void WriteLog(string message)
        {
            // Niveau Info par défaut. Les exceptions sérieuses sont loggées en
            // Error directement par les handlers async void.
            AppLogger.Info("RealTimeProtection", message);
        }

        /// <summary>Arrête la protection et libère le sémaphore et le timer de nettoyage.</summary>
        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            Stop();

            // Les handlers async void peuvent encore tenir une place : on attend qu'elles
            // soient toutes libres avant de libérer le sémaphore. Sinon (scan bloqué), il est
            // laissé au ramasse-miettes plutôt que libéré sous les pieds d'un scan en cours.
            var drained = 0;
            for (; drained < MaxConcurrentScans; drained++)
            {
                if (!_scanSemaphore.Wait(TimeSpan.FromSeconds(5)))
                    break;
            }

            if (drained == MaxConcurrentScans)
                _scanSemaphore.Dispose();
            else
                AppLogger.Warn("RealTimeProtection", "Arrêt : un scan est encore en cours, sémaphore laissé en place");
        }
    }
}
