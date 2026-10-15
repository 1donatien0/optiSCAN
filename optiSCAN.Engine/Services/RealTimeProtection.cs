using System.Collections.Concurrent;
using System.IO;

namespace optiSCAN.Services
{
    /// <summary>
    /// Surveillance des fichiers via FileSystemWatcher.
    /// Analyse les nouveaux fichiers et les modifications après leur stabilisation.
    /// </summary>
    public class RealTimeProtection : IDisposable
    {
        private readonly ScanOrchestrator _orchestrator;
        private readonly QuarantineManager _quarantineManager;
        private readonly INotificationSink _notifications;
        private readonly ConcurrentDictionary<string, DateTime> _recentlyScanned;
        private readonly Dictionary<string, WatcherRecoveryState> _watcherRecoveryStates = new(StringComparer.OrdinalIgnoreCase);
        private readonly List<FileSystemWatcher> _watchers;
        private readonly SemaphoreSlim _scanSemaphore;
        private readonly object _watcherEventGate = new();
        private readonly object _recentCacheGate = new();
        // Timer dédié au nettoyage périodique du cache, même si le watcher ne reçoit pas d'événements.
        private System.Threading.Timer? _cacheCleanupTimer;
        private CancellationTokenSource? _watcherRecoveryLifetime;
        private volatile bool _isEnabled;
        private volatile bool _disposed;
        private const int MaxConcurrentScans = 3;
        internal const int MaxPendingWatcherEvents = 128;
        private const int MaxRecentPathEntries = 8192;
        private const int RecentPathTrimTarget = MaxRecentPathEntries * 3 / 4;
        private const int WatcherRecoveryCooldownMilliseconds = 30_000;
        private readonly int _watcherRecoveryCooldownMilliseconds;
        private int _suspendCount;
        private int _pendingWatcherEvents;
        private int _maxPendingWatcherEventsObserved;
        private int _watcherQueueOverflowCount;
        private int _activeRecoveries;
        private int _watcherRecoveryPassCount;
        private int _watcherRecoveryRescheduleCount;
        private long _lastQueueOverflowLogMilliseconds = -30_000;

        // Délai d'attente après création/modification (éviter les scans sur écriture partielle)
        private static readonly TimeSpan StabilizationDelay = TimeSpan.FromMilliseconds(500);
        private static readonly TimeSpan StabilitySampleDelay = TimeSpan.FromMilliseconds(250);
        private static readonly TimeSpan StabilityTimeout = TimeSpan.FromSeconds(20);
        private const int PinRetryCount = 3;
        private static readonly TimeSpan PinRetryDelay = TimeSpan.FromMilliseconds(1500);

        public event EventHandler<Models.ThreatInfo>? ThreatDetected;
        public bool IsEnabled => _isEnabled;

        // ── Santé (audit A15) ───────────────────────────────────────────────
        // Un dossier qui n'a pas pu être surveillé, un watcher non rétabli ou un rattrapage
        // incomplet n'étaient visibles que dans les journaux : l'interface affichait « protégé ».
        private readonly Dictionary<string, string> _healthIssues = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>Changement de l'état de santé (dossiers en défaut). Peut venir de n'importe quel thread.</summary>
        public event EventHandler? HealthChanged;

        /// <summary>Nombre de dossiers surveillés en défaut (0 : surveillance complète).</summary>
        public int DegradedFolderCount
        {
            get { lock (_healthIssues) return _healthIssues.Count; }
        }

        /// <summary>Raisons des dossiers en défaut, chemins masqués, pour l'infobulle et le journal.</summary>
        public IReadOnlyList<string> HealthIssues
        {
            get { lock (_healthIssues) return _healthIssues.Values.ToList(); }
        }

        private void SetHealthIssue(string path, string? reason)
        {
            bool changed;
            lock (_healthIssues)
            {
                if (reason == null)
                    changed = _healthIssues.Remove(path);
                else
                {
                    changed = !_healthIssues.TryGetValue(path, out var previous) || previous != reason;
                    _healthIssues[path] = reason;
                }
            }

            if (changed)
                RaiseHealthChanged();
        }

        private void ClearHealthIssues()
        {
            bool changed;
            lock (_healthIssues)
            {
                changed = _healthIssues.Count > 0;
                _healthIssues.Clear();
            }

            if (changed)
                RaiseHealthChanged();
        }

        private void RaiseHealthChanged()
        {
            try { HealthChanged?.Invoke(this, EventArgs.Empty); }
            catch (Exception ex) { AppLogger.Warn("RealTimeProtection", "HealthChanged", ex); }
        }
        internal int PendingWatcherEvents => Volatile.Read(ref _pendingWatcherEvents);
        internal int MaxPendingWatcherEventsObserved => Volatile.Read(ref _maxPendingWatcherEventsObserved);
        internal int WatcherQueueOverflowCount => Volatile.Read(ref _watcherQueueOverflowCount);
        internal int ActiveWatcherRecoveries => Volatile.Read(ref _activeRecoveries);
        internal int WatcherRecoveryPassCount => Volatile.Read(ref _watcherRecoveryPassCount);
        internal int WatcherRecoveryRescheduleCount => Volatile.Read(ref _watcherRecoveryRescheduleCount);

        /// <summary>
        /// Ignore les événements du watcher (compteur réentrant). N'est plus appelé pendant les
        /// scans manuels ni USB (audit V2) : à réserver à un arrêt bref et explicite.
        /// </summary>
        public void Suspend() => Interlocked.Increment(ref _suspendCount);

        /// <summary>Réactive la surveillance après <see cref="Suspend"/>.</summary>
        public void Resume()
        {
            if (Interlocked.Decrement(ref _suspendCount) < 0)
                Interlocked.Exchange(ref _suspendCount, 0);
        }

        private bool IsSuspended => Volatile.Read(ref _suspendCount) > 0;

        /// <summary>Vrai tant qu'une suspension explicite est en cours (surveillance processus en pause).</summary>
        public bool IsPaused => IsSuspended;

        private readonly IUserPreferencesAccessor _prefs;
        private readonly IExclusionSettingsAccessor _exclusions;
        private readonly ScanLogManager? _logger;
        private readonly IUiEventBus? _uiEvents;

        public RealTimeProtection(
            ScanOrchestrator orchestrator,
            QuarantineManager quarantineManager,
            INotificationSink notifications,
            IUserPreferencesAccessor? preferences = null,
            IExclusionSettingsAccessor? exclusions = null,
            ScanLogManager? logger = null,
            IUiEventBus? uiEvents = null)
            : this(orchestrator, quarantineManager, notifications, preferences, exclusions, logger, uiEvents,
                WatcherRecoveryCooldownMilliseconds)
        {
        }

        internal RealTimeProtection(
            ScanOrchestrator orchestrator,
            QuarantineManager quarantineManager,
            INotificationSink notifications,
            int watcherRecoveryCooldownMilliseconds)
            : this(orchestrator, quarantineManager, notifications, null, null, null, null, watcherRecoveryCooldownMilliseconds)
        {
        }

        private RealTimeProtection(
            ScanOrchestrator orchestrator,
            QuarantineManager quarantineManager,
            INotificationSink notifications,
            IUserPreferencesAccessor? preferences,
            IExclusionSettingsAccessor? exclusions,
            ScanLogManager? logger,
            IUiEventBus? uiEvents,
            int watcherRecoveryCooldownMilliseconds)
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
            _watcherRecoveryCooldownMilliseconds = Math.Max(0, watcherRecoveryCooldownMilliseconds);
        }

        /// <summary>
        /// Démarre la surveillance en temps réel sur les dossiers critiques, le bureau et les téléchargements.
        /// Sans effet si la protection est déjà active.
        /// </summary>
        public void Start() => Start(RealTimeWatchPaths.GetWatchFolders(_exclusions));

        internal void Start(IEnumerable<string> watchPaths)
        {
            lock (_watcherEventGate)
            {
                if (_isEnabled || _disposed) return;
                _watcherRecoveryLifetime?.Dispose();
                _watcherRecoveryLifetime = new CancellationTokenSource();
                _watcherRecoveryStates.Clear();
                Interlocked.Exchange(ref _maxPendingWatcherEventsObserved, 0);
                Interlocked.Exchange(ref _watcherQueueOverflowCount, 0);
                Interlocked.Exchange(ref _watcherRecoveryPassCount, 0);
                Interlocked.Exchange(ref _watcherRecoveryRescheduleCount, 0);
                _isEnabled = true;
            }
            ClearHealthIssues();

            // Les événements d'erreur des watchers peuvent arriver dès leur création.
            foreach (var folder in watchPaths)
                AddWatcher(folder);

            // Cleanup périodique du cache : toutes les 5 min, on supprime les
            // entrées de plus de 5 min. Indépendant de l'arrivée d'événements,
            // ce qui évite la croissance silencieuse du cache si la machine reste inactive.
            _cacheCleanupTimer = new System.Threading.Timer(
                _ => { try { CleanupRecentCache(); } catch { /* swallow */ } },
                state: null,
                dueTime: TimeSpan.FromMinutes(5),
                period: TimeSpan.FromMinutes(5));

            lock (_watcherEventGate)
            {
                lock (_watchers)
                    _isEnabled = !_disposed && _isEnabled && _watchers.Count > 0;
            }
            WriteLog(_isEnabled
                ? $"Surveillance temps réel activée ({_watchers.Count} dossier(s) surveillé(s))"
                : "Surveillance temps réel indisponible : aucun dossier n'a pu être surveillé");
        }

        /// <summary>
        /// Arrête la surveillance en temps réel et libère tous les <see cref="FileSystemWatcher"/> actifs.
        /// Sans effet si la protection est déjà arrêtée.
        /// </summary>
        public void Stop()
        {
            bool hadWatchers;
            lock (_watcherEventGate)
            {
                _isEnabled = false;
                _watcherRecoveryLifetime?.Cancel();
                _watcherRecoveryStates.Clear();
            }
            ClearHealthIssues();

            _cacheCleanupTimer?.Dispose();
            _cacheCleanupTimer = null;

            lock (_watchers)
            {
                hadWatchers = _watchers.Count > 0;
                foreach (var watcher in _watchers)
                {
                    watcher.EnableRaisingEvents = false;
                    watcher.Dispose();
                }
                _watchers.Clear();
            }
            if (!hadWatchers)
                return;

            lock (_recentCacheGate)
                _recentlyScanned.Clear();

            WriteLog("Surveillance temps réel désactivée");
        }

        private FileSystemWatcher? AddWatcher(string path)
        {
            if (_exclusions.Current.IsFolderExcluded(path))
                return null;

            // Un dossier surveillé qui est (ou passe par) une jonction ferait analyser par SYSTEM
            // tout un autre emplacement : refusé dès le démarrage.
            if (!RealTimePathGuard.IsDirectPath(path))
            {
                AppLogger.Warn("RealTimeProtection", $"Dossier non surveillé (jonction ou lien dans le chemin) : {PathRedaction.RedactPath(path)}");
                return null;
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
                    if (_disposed || !_isEnabled)
                    {
                        watcher.Dispose();
                        return null;
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
                return watcher;
            }
            catch (Exception ex)
            {
                watcher?.Dispose();
                WriteLog($"Impossible de surveiller {PathRedaction.RedactPath(path)} : {PathRedaction.RedactPath(ex.Message)}");
                if (_isEnabled && !_disposed)
                    SetHealthIssue(path, $"non surveillé : {PathRedaction.RedactPath(path)}");
                return null;
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
            if (!TryReserveWatcherEvent(sender, e.FullPath))
                return;

            try
            {
                // Ignorer les dossiers
                if (Directory.Exists(e.FullPath)) return;

                if (IsSuspended) return;

                var listed = RiskyFileExtensions.IsRisky(e.FullPath);

                var utcNow = DateTime.UtcNow;
                if (TrackRecentPath(e.FullPath, utcNow))
                    HandleRecentCacheSaturation(sender, e.FullPath);

                await Task.Delay(StabilizationDelay);

                // Un événement plus récent a repoussé le scan : seul le dernier traite le fichier.
                if (!_recentlyScanned.TryGetValue(e.FullPath, out var latest) || latest != utcNow)
                    return;
                if (!listed && !IsUnlistedExecutable(sender, e.FullPath, utcNow))
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
            finally
            {
                Interlocked.Decrement(ref _pendingWatcherEvents);
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
            if (!TryReserveWatcherEvent(sender, e.FullPath))
                return;

            try
            {
                if (Directory.Exists(e.FullPath)) return;

                if (IsSuspended) return;

                var listed = RiskyFileExtensions.IsRisky(e.FullPath);

                var utcNow = DateTime.UtcNow;
                if (TrackRecentPath(e.FullPath, utcNow))
                    HandleRecentCacheSaturation(sender, e.FullPath);

                await Task.Delay(StabilizationDelay);
                if (!_recentlyScanned.TryGetValue(e.FullPath, out var latest) || latest != utcNow)
                    return;
                if (!listed && !IsUnlistedExecutable(sender, e.FullPath, utcNow))
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
            finally
            {
                Interlocked.Decrement(ref _pendingWatcherEvents);
            }
        }

        private bool TryReserveWatcherEvent(object sender, string filePath)
        {
            lock (_watcherEventGate)
            {
                if (_disposed || !_isEnabled)
                    return false;
                if (_pendingWatcherEvents < MaxPendingWatcherEvents)
                {
                    var pending = Interlocked.Increment(ref _pendingWatcherEvents);
                    UpdateMaximum(ref _maxPendingWatcherEventsObserved, pending);
                    return true;
                }
            }

            Interlocked.Increment(ref _watcherQueueOverflowCount);
            try { HandleWatcherQueueOverflow(sender, filePath); }
            catch (Exception ex) { AppLogger.Error("RealTimeProtection", "Could not schedule watcher overflow recovery", ex); }
            return false;
        }

        private void HandleWatcherQueueOverflow(object sender, string filePath)
        {
            var recoveryScheduled = sender is FileSystemWatcher watcher
                && ScheduleWatcherRecovery(watcher, watcher.Path);
            if (!TryAcquireRecoveryLogWindow())
                return;

            AppLogger.Warn("RealTimeProtection",
                $"[RTP] Limite de {MaxPendingWatcherEvents} événements en attente atteinte sur {PathRedaction.RedactPath(filePath)}. "
                + (recoveryScheduled
                    ? "Rattrapage du dossier programmé ; couverture potentiellement incomplète pendant la saturation."
                    : "Un nouveau rattrapage est conservé après le passage en cours ou le délai de reprise ; couverture potentiellement incomplète pendant la saturation."));
        }

        private void HandleRecentCacheSaturation(object sender, string filePath)
        {
            var recoveryScheduled = sender is FileSystemWatcher watcher
                && ScheduleWatcherRecovery(watcher, watcher.Path);
            if (!TryAcquireRecoveryLogWindow())
                return;

            AppLogger.Warn("RealTimeProtection",
                $"[RTP] Le cache de déduplication a atteint {MaxRecentPathEntries} chemins sur {PathRedaction.RedactPath(filePath)} ; "
                + (recoveryScheduled
                    ? "les entrées les plus anciennes ont été retirées et un rattrapage est programmé."
                    : "les entrées les plus anciennes ont été retirées ; un nouveau rattrapage est conservé après le passage en cours ou le délai de reprise."));
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
            // Événements perdus : le dossier est en défaut jusqu'à la fin du rattrapage.
            if (_isEnabled && !_disposed)
                SetHealthIssue(path, $"événements perdus, rattrapage en cours : {PathRedaction.RedactPath(path)}");
            if (ScheduleWatcherRecovery(watcher, path))
                WriteLog($"Perte d'événements FileSystemWatcher sur {PathRedaction.RedactPath(path)} : {PathRedaction.RedactPath(e.GetException()?.Message)}. Réinitialisation et rattrapage en cours.");
            else if (_isEnabled && !_disposed && TryAcquireRecoveryLogWindow())
                AppLogger.Warn("RealTimeProtection", $"Perte d'événements FileSystemWatcher sur {PathRedaction.RedactPath(path)} ; un nouveau rattrapage est conservé après le passage en cours ou le délai de reprise.");
        }

        private bool TryAcquireRecoveryLogWindow()
        {
            var now = Environment.TickCount64;
            var previous = Interlocked.Read(ref _lastQueueOverflowLogMilliseconds);
            return now - previous >= WatcherRecoveryCooldownMilliseconds
                && Interlocked.CompareExchange(ref _lastQueueOverflowLogMilliseconds, now, previous) == previous;
        }

        private bool ScheduleWatcherRecovery(FileSystemWatcher watcher, string path)
        {
            WatcherRecoveryState state;
            CancellationToken token;
            var startsWorker = false;
            lock (_watcherEventGate)
            {
                if (_disposed || !_isEnabled || _watcherRecoveryLifetime == null)
                    return false;

                if (!_watcherRecoveryStates.TryGetValue(path, out var existingState))
                {
                    state = new WatcherRecoveryState(watcher, path);
                    _watcherRecoveryStates.Add(path, state);
                }
                else
                {
                    state = existingState;
                    state.Watcher = watcher;
                }

                var wasAlreadyRequested = state.Requested;
                state.Requested = true;
                token = _watcherRecoveryLifetime.Token;
                if (state.Running)
                {
                    if (!wasAlreadyRequested)
                        Interlocked.Increment(ref _watcherRecoveryRescheduleCount);
                    return false;
                }

                state.Running = true;
                startsWorker = true;
                Interlocked.Increment(ref _activeRecoveries);
            }

            try
            {
                if (!startsWorker)
                    return false;
                _ = Task.Run(() => RunWatcherRecoveryLoopAsync(state, token));
                return true;
            }
            catch (Exception ex)
            {
                lock (_watcherEventGate)
                    FinishWatcherRecoveryWorkerUnderLock(state);
                AppLogger.Error("RealTimeProtection", "Could not start watcher recovery", ex);
                return false;
            }
        }

        private async Task RunWatcherRecoveryLoopAsync(WatcherRecoveryState state, CancellationToken ct)
        {
            try
            {
                while (true)
                {
                    FileSystemWatcher watcher;
                    int delayMilliseconds;
                    lock (_watcherEventGate)
                    {
                        if (_disposed || !_isEnabled || ct.IsCancellationRequested || !state.Requested)
                        {
                            FinishWatcherRecoveryWorkerUnderLock(state);
                            return;
                        }

                        watcher = state.Watcher;
                        var now = Environment.TickCount64;
                        delayMilliseconds = state.LastStartedMilliseconds == 0
                            ? 0
                            : (int)Math.Max(0, _watcherRecoveryCooldownMilliseconds - (now - state.LastStartedMilliseconds));

                        if (delayMilliseconds == 0)
                        {
                            state.Requested = false;
                            state.LastStartedMilliseconds = now;
                            Interlocked.Increment(ref _watcherRecoveryPassCount);
                        }
                    }

                    if (delayMilliseconds > 0)
                    {
                        await Task.Delay(delayMilliseconds, ct).ConfigureAwait(false);
                        continue;
                    }

                    var replacement = await RecoverWatcherAsync(watcher, state.Path, ct).ConfigureAwait(false);
                    if (replacement != null)
                    {
                        lock (_watcherEventGate)
                        {
                            if (_watcherRecoveryStates.TryGetValue(state.Path, out var current)
                                && ReferenceEquals(current, state))
                                state.Watcher = replacement;
                        }
                    }
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                lock (_watcherEventGate)
                    FinishWatcherRecoveryWorkerUnderLock(state);
            }
            catch (Exception ex)
            {
                lock (_watcherEventGate)
                    FinishWatcherRecoveryWorkerUnderLock(state);
                AppLogger.Error("RealTimeProtection", "RecoverWatcherAsync failed", ex);
            }
        }

        private void FinishWatcherRecoveryWorkerUnderLock(WatcherRecoveryState state)
        {
            if (!state.Running)
                return;

            state.Running = false;
            if (_watcherRecoveryStates.TryGetValue(state.Path, out var current)
                && ReferenceEquals(current, state))
                _watcherRecoveryStates.Remove(state.Path);
            Interlocked.Decrement(ref _activeRecoveries);
        }

        private static void UpdateMaximum(ref int maximum, int value)
        {
            var observed = Volatile.Read(ref maximum);
            while (value > observed)
            {
                var previous = Interlocked.CompareExchange(ref maximum, value, observed);
                if (previous == observed)
                    return;
                observed = previous;
            }
        }

        /// <summary>
        /// Fichier dont l'extension n'est pas listée : analysé seulement si son contenu est un
        /// exécutable PE (un second étage déposé en <c>.dat</c> ou <c>.tmp</c>). L'en-tête est lu
        /// une fois, après le délai de stabilisation, par une ouverture qui ne gêne pas l'auteur du
        /// fichier. Sinon l'entrée de dé-duplication est retirée : le volume d'écritures de
        /// %TEMP% ou de ProgramData ne fait pas grossir le cache.
        /// </summary>
        private bool IsUnlistedExecutable(object sender, string filePath, DateTime eventTime)
        {
            var root = WatchRootOf(sender);
            if (root != null
                && !ScanStaging.IsStagingPath(filePath)
                && RealTimePathGuard.IsExecutableWithinRoot(root, filePath))
                return true;

            lock (_recentCacheGate)
                _recentlyScanned.TryRemove(new KeyValuePair<string, DateTime>(filePath, eventTime));
            return false;
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

        private async Task<FileSystemWatcher?> RecoverWatcherAsync(FileSystemWatcher failedWatcher, string path, CancellationToken ct)
        {
            try
            {
                if (!OperatingSystem.IsWindows())
                    return null;

                lock (_watchers)
                {
                    if (_disposed || !_isEnabled)
                        return null;
                    _watchers.Remove(failedWatcher);
                    failedWatcher.EnableRaisingEvents = false;
                    failedWatcher.Dispose();
                }

                var replacementWatcher = AddWatcher(path);
                if (replacementWatcher == null)
                {
                    lock (_watchers)
                        _isEnabled = _watchers.Count > 0;
                    WriteLog($"Surveillance non rétablie : {PathRedaction.RedactPath(path)}");
                    SetHealthIssue(path, $"surveillance non rétablie : {PathRedaction.RedactPath(path)}");
                    return null;
                }

                var skipped = 0;
                foreach (var file in ClamdEngine.EnumerateScannableFiles(
                             path,
                             _exclusions.Current.IsFolderExcluded,
                             _ => Interlocked.Increment(ref skipped)))
                {
                    if (ct.IsCancellationRequested || IsSuspended || _disposed)
                        break;
                    if (!RiskyFileExtensions.IsRisky(file)
                        && !RealTimePathGuard.IsExecutableWithinRoot(path, file))
                        continue;

                    await _scanSemaphore.WaitAsync(ct).ConfigureAwait(false);
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
                // Watcher rétabli et rattrapage terminé : le dossier est de nouveau couvert.
                // Les éléments inaccessibles sont ceux qu'une analyse manuelle ne lirait pas non
                // plus ; ils ne rendent pas la surveillance défaillante.
                if (!ct.IsCancellationRequested)
                    SetHealthIssue(path, null);
                return replacementWatcher;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                // Arrêt demandé : le worker est terminé par le coordinateur.
                return null;
            }
            catch (Exception ex)
            {
                WriteLog($"Récupération du watcher impossible ({PathRedaction.RedactPath(path)}) : {PathRedaction.RedactPath(ex.Message)}");
                return null;
            }
        }

        private sealed class WatcherRecoveryState(FileSystemWatcher watcher, string path)
        {
            public FileSystemWatcher Watcher { get; set; } = watcher;
            public string Path { get; } = path;
            public bool Requested { get; set; } = true;
            public bool Running { get; set; }
            public long LastStartedMilliseconds { get; set; }
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
                IDisposable? pinned = null;
                // Un fichier encore ouvert en écriture par son auteur (téléchargement, archive en
                // cours d'extraction) refuse l'ouverture exclusive : sans nouvel essai, il n'était
                // jamais analysé. Trois essais espacés, puis abandon journalisé.
                for (var attempt = 0; watchRoot != null; attempt++)
                {
                    pinned = RealTimePathGuard.PinWithinRoot(watchRoot, filePath, out refusal);
                    if (pinned != null || attempt >= PinRetryCount
                        || !string.Equals(refusal, RealTimePathGuard.InaccessibleRefusal, StringComparison.Ordinal)
                        || !File.Exists(filePath))
                        break;
                    await Task.Delay(PinRetryDelay).ConfigureAwait(false);
                }

                using (var pin = pinned)
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

                if (result.ThreatsFound > 0
                    && scannedSha256 != null
                    && RestoredContentGrace.IsGranted(filePath, scannedSha256))
                {
                    // Fichier que l'utilisateur vient de restaurer, contenu inchangé : ni alerte
                    // ni nouvelle quarantaine. Toute modification du contenu annule ce répit.
                    WriteLog($"[RTP] Fichier restauré par l'utilisateur, ignoré : {PathRedaction.RedactPath(filePath)}");
                    return;
                }

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
            lock (_recentCacheGate)
                CleanupRecentCacheUnderLock();
        }

        private bool TrackRecentPath(string filePath, DateTime eventTime)
        {
            var evictedRecentEntries = false;
            lock (_recentCacheGate)
            {
                _recentlyScanned[filePath] = eventTime;
                if (_recentlyScanned.Count <= MaxRecentPathEntries)
                    return false;

                CleanupRecentCacheUnderLock();
                var count = _recentlyScanned.Count;
                if (count <= MaxRecentPathEntries)
                    return false;

                var removeCount = count - RecentPathTrimTarget;
                foreach (var entry in _recentlyScanned.OrderBy(pair => pair.Value).Take(removeCount))
                    _recentlyScanned.TryRemove(new KeyValuePair<string, DateTime>(entry.Key, entry.Value));
                evictedRecentEntries = true;
            }

            return evictedRecentEntries;
        }

        private void CleanupRecentCacheUnderLock()
        {
            var threshold = DateTime.UtcNow.AddMinutes(-5);
            foreach (var kvp in _recentlyScanned)
            {
                if (kvp.Value < threshold)
                    _recentlyScanned.TryRemove(new KeyValuePair<string, DateTime>(kvp.Key, kvp.Value));
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
            lock (_watcherEventGate)
            {
                if (_disposed) return;
                _disposed = true;
            }
            Stop();

            // Les callbacks et rattrapages sont bornés et comptés. Attendre leur fin avant
            // de libérer le sémaphore évite une utilisation après Dispose.
            var deadline = DateTime.UtcNow.AddSeconds(15);
            while ((Volatile.Read(ref _pendingWatcherEvents) > 0 || Volatile.Read(ref _activeRecoveries) > 0)
                   && DateTime.UtcNow < deadline)
                Thread.Sleep(50);

            if (Volatile.Read(ref _pendingWatcherEvents) > 0 || Volatile.Read(ref _activeRecoveries) > 0)
            {
                AppLogger.Warn("RealTimeProtection", "Arrêt : des événements ou rattrapages sont encore en cours, sémaphore laissé en place");
                return;
            }

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
