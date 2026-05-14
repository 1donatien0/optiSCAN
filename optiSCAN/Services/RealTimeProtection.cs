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
        private readonly List<FileSystemWatcher> _watchers;
        private readonly SemaphoreSlim _scanSemaphore;
        // Audit R14 : timer dédié pour le nettoyage périodique du cache, garantit
        // la libération même quand FileSystemWatcher reste silencieux.
        private System.Threading.Timer? _cacheCleanupTimer;
        private bool _isEnabled;
        private bool _disposed;

        // Dossiers surveillés par défaut
        private static readonly string[] DefaultWatchFolders = new[]
        {
            @"C:\Users",
            @"C:\ProgramData",
            @"C:\Windows\Temp",
            @"C:\Windows\Downloaded Program Files"
        };

        // Extensions surveillées (fichiers exécutables et scripts)
        private static readonly HashSet<string> WatchedExtensions = new(
            new[] { ".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".msi", ".docm", ".xlsm", ".pptm" },
            StringComparer.OrdinalIgnoreCase);

        // Délai d'attente après création/modification (éviter les scans sur écriture partielle)
        private static readonly TimeSpan StabilizationDelay = TimeSpan.FromMilliseconds(500);

        public event EventHandler<Models.ThreatInfo>? ThreatDetected;
        public bool IsEnabled => _isEnabled;

        public RealTimeProtection(ScanOrchestrator orchestrator, QuarantineManager quarantineManager, NotificationService notifications)
        {
            _orchestrator = orchestrator;
            _quarantineManager = quarantineManager;
            _notifications = notifications;
            _recentlyScanned = new ConcurrentDictionary<string, DateTime>();
            _watchers = new List<FileSystemWatcher>();
            _scanSemaphore = new SemaphoreSlim(3); // Max 3 scans simultanés
        }

        /// <summary>
        /// Démarre la surveillance temps réel
        /// </summary>
        public void Start()
        {
            if (_isEnabled) return;

            foreach (var folder in DefaultWatchFolders)
            {
                if (Directory.Exists(folder))
                    AddWatcher(folder);
            }

            // Ajouter le dossier Desktop et Downloads de l'utilisateur
            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            AddWatcher(Path.Combine(userProfile, "Desktop"));
            AddWatcher(Path.Combine(userProfile, "Downloads"));

            // Cleanup périodique du cache : toutes les 5 min, on supprime les
            // entrées de plus de 5 min. Indépendant de l'arrivée d'événements,
            // ce qui évite la croissance silencieuse du cache si la machine
            // reste idle (audit R14).
            _cacheCleanupTimer = new System.Threading.Timer(
                _ => { try { CleanupRecentCache(); } catch { /* swallow */ } },
                state: null,
                dueTime: TimeSpan.FromMinutes(5),
                period: TimeSpan.FromMinutes(5));

            _isEnabled = true;
            WriteLog("Protection temps réel activée");
        }

        /// <summary>
        /// Arrête la surveillance
        /// </summary>
        public void Stop()
        {
            if (!_isEnabled) return;

            _cacheCleanupTimer?.Dispose();
            _cacheCleanupTimer = null;

            foreach (var watcher in _watchers)
            {
                watcher.EnableRaisingEvents = false;
                watcher.Dispose();
            }
            _watchers.Clear();
            _recentlyScanned.Clear();

            _isEnabled = false;
            WriteLog("Protection temps réel désactivée");
        }

        private void AddWatcher(string path)
        {
            try
            {
                var watcher = new FileSystemWatcher(path)
                {
                    IncludeSubdirectories = true,
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.CreationTime,
                    Filter = "*.*",
                    // Buffer 64 KB (vs 8 KB par défaut) : sur les machines avec
                    // beaucoup d'écritures (build IDE, navigateurs, antivirus tiers),
                    // évite la perte d'événements liée à un overflow buffer kernel.
                    InternalBufferSize = 64 * 1024,
                };

                watcher.Created += OnFileChanged;
                watcher.Changed += OnFileChanged;
                watcher.Renamed += OnFileRenamed;
                watcher.Error += OnWatcherError;

                watcher.EnableRaisingEvents = true;
                _watchers.Add(watcher);
            }
            catch (Exception ex)
            {
                WriteLog($"Impossible de surveiller {path} : {ex.Message}");
            }
        }

        // CRITIQUE : ces deux handlers sont async void (imposé par la signature
        // FileSystemEventHandler). Toute exception non gérée crashe le process.
        // Un fichier crafté qui déclenche une exception suffirait à désactiver la
        // protection temps réel. On enrobe donc TOUT le corps en try/catch global.
        private async void OnFileChanged(object sender, FileSystemEventArgs e)
        {
            try
            {
                // Ignorer les dossiers
                if (Directory.Exists(e.FullPath)) return;

                // Vérifier l'extension
                var ext = Path.GetExtension(e.FullPath);
                if (!WatchedExtensions.Contains(ext)) return;

                // Éviter les scans trop fréquents du même fichier
                if (_recentlyScanned.TryGetValue(e.FullPath, out var lastScan) &&
                    (DateTime.Now - lastScan) < TimeSpan.FromSeconds(30))
                    return;

                // Attendre que le fichier soit stabilisé
                await Task.Delay(StabilizationDelay);

                // Vérifier que le fichier existe toujours
                if (!File.Exists(e.FullPath)) return;

                _recentlyScanned[e.FullPath] = DateTime.Now;

                // Nettoyer les entrées anciennes
                CleanupRecentCache();

                await _scanSemaphore.WaitAsync();
                try
                {
                    await ScanFileAsync(e.FullPath, e.ChangeType);
                }
                finally
                {
                    _scanSemaphore.Release();
                }
            }
            catch (Exception ex)
            {
                // Logger sans propager — protection temps réel ne doit JAMAIS crasher.
                WriteLog($"[RTP] OnFileChanged exception ({e.FullPath}): {ex.Message}");
            }
        }

        private async void OnFileRenamed(object sender, RenamedEventArgs e)
        {
            try
            {
                if (Directory.Exists(e.FullPath)) return;

                var ext = Path.GetExtension(e.FullPath);
                if (!WatchedExtensions.Contains(ext)) return;

                await Task.Delay(StabilizationDelay);
                if (!File.Exists(e.FullPath)) return;

                await _scanSemaphore.WaitAsync();
                try
                {
                    await ScanFileAsync(e.FullPath, WatcherChangeTypes.Renamed);
                }
                finally
                {
                    _scanSemaphore.Release();
                }
            }
            catch (Exception ex)
            {
                WriteLog($"[RTP] OnFileRenamed exception ({e.FullPath}): {ex.Message}");
            }
        }

        private void OnWatcherError(object sender, ErrorEventArgs e)
        {
            WriteLog($"Erreur FileSystemWatcher : {e.GetException()?.Message}");
        }

        private async Task ScanFileAsync(string filePath, WatcherChangeTypes changeType)
        {
            try
            {
                // Ne pas rescanner un fichier individuellement exclu
                if (ExclusionSettings.Current.IsFileExcluded(filePath))
                {
                    WriteLog($"[RTP] Fichier exclu, ignoré : {filePath}");
                    return;
                }

                var result = await _orchestrator.ScanFileAsync(filePath);

                if (result.ThreatsFound > 0)
                {
                    foreach (var threat in result.Threats)
                    {
                        // Notification toast
                        _notifications.ShowThreatDetected(threat);

                        if (ExclusionSettings.Current.AutoQuarantineEnabled)
                        {
                            // Quarantaine automatique activée par l'utilisateur
                            if (_quarantineManager.Quarantine(threat))
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
                WriteLog($"[RTP] Erreur scan {filePath} : {ex.Message}");
            }
        }

        private void CleanupRecentCache()
        {
            var threshold = DateTime.Now.AddMinutes(-5);
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

        public void Dispose()
        {
            if (_disposed) return;
            Stop();
            _scanSemaphore.Dispose();
            _disposed = true;
        }
    }
}
