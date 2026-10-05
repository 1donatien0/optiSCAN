using optiSCAN.Models;
using System.Collections.Concurrent;
using System.IO;
using System.Management;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;

namespace optiSCAN.Services
{
    /// <summary>
    /// Surveillance des créations de processus (WMI) — complète la RTP fichier
    /// en analysant les exécutables et hôtes de scripts au lancement.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public sealed class ProcessStartMonitor : IDisposable
    {
        private static readonly Regex QuotedPathRegex = new(
            @"[""']([^""']+\.(?:exe|dll|scr|com|msi|bat|cmd|ps1|vbs|js|hta|wsf|jar))[""']",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

        private readonly ScanOrchestrator _orchestrator;
        private readonly QuarantineManager _quarantineManager;
        private readonly NotificationService _notifications;
        private readonly ConcurrentDictionary<string, DateTime> _recentScans = new(StringComparer.OrdinalIgnoreCase);
        private readonly SemaphoreSlim _scanSemaphore = new(2, 2);
        private readonly Func<bool> _isSuspended;

        private ManagementEventWatcher? _watcher;
        private bool _enabled;
        private volatile bool _disposed;

        public event EventHandler<ThreatInfo>? ThreatDetected;

        private readonly IUserPreferencesAccessor _prefs;
        private readonly IExclusionSettingsAccessor _exclusions;
        private readonly ScanLogManager? _logger;
        private readonly IUiEventBus? _uiEvents;

        public ProcessStartMonitor(
            ScanOrchestrator orchestrator,
            QuarantineManager quarantineManager,
            NotificationService notifications,
            Func<bool>? isSuspended = null,
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
            _isSuspended = isSuspended ?? (() => false);
        }

        public void Start()
        {
            if (_enabled)
                return;

            try
            {
                var query = new WqlEventQuery(
                    "SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'");
                _watcher = new ManagementEventWatcher(query);
                _watcher.EventArrived += SurProcessDemarre;
                _watcher.Start();
                _enabled = true;
                AppLogger.Info("ProcessStartMonitor", "Surveillance des processus activée");
            }
            catch (Exception ex)
            {
                AppLogger.Warn("ProcessStartMonitor", "Start", ex);
            }
        }

        public void Stop()
        {
            if (!_enabled)
                return;

            try
            {
                if (_watcher != null)
                {
                    _watcher.EventArrived -= SurProcessDemarre;
                    _watcher.Stop();
                    _watcher.Dispose();
                    _watcher = null;
                }
            }
            catch (Exception ex)
            {
                AppLogger.Warn("ProcessStartMonitor", "Stop", ex);
            }

            _recentScans.Clear();
            _enabled = false;
            AppLogger.Info("ProcessStartMonitor", "Surveillance des processus désactivée");
        }

        private void SurProcessDemarre(object sender, EventArrivedEventArgs e)
        {
            if (_isSuspended())
                return;

            try
            {
                if (e.NewEvent?["TargetInstance"] is not ManagementBaseObject target)
                    return;

                var processName = target["Name"]?.ToString();
                if (string.IsNullOrWhiteSpace(processName))
                    return;

                var pid = Convert.ToInt32(target["ProcessId"]);
                var paths = ResolvePathsToScan(processName, pid, target["CommandLine"]?.ToString());
                foreach (var path in paths)
                    Track(HandlePathAsync(path, pid));
            }
            catch (Exception ex)
            {
                AppLogger.Warn("ProcessStartMonitor", "SurProcessDemarre", ex);
            }
        }

        private IEnumerable<string> ResolvePathsToScan(string processName, int pid, string? commandLine)
        {
            var results = new List<string>();

            var image = TryGetExecutablePath(pid);
            if (!string.IsNullOrWhiteSpace(image) && File.Exists(image) && RiskyFileExtensions.IsRisky(image))
                results.Add(image);

            if (RiskyFileExtensions.IsScriptHostProcess(processName) && !string.IsNullOrWhiteSpace(commandLine))
            {
                foreach (var candidate in ExtractCommandLineCandidates(commandLine))
                {
                    if (File.Exists(candidate) && RiskyFileExtensions.IsRisky(candidate))
                        results.Add(candidate);
                }
            }

            return results.Distinct(StringComparer.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Chemins candidats dans la ligne de commande d'un hôte de scripts : chemins entre
        /// guillemets (avec espaces) et jetons séparés par des espaces. Sans accès disque.
        /// </summary>
        internal static IReadOnlyList<string> ExtractCommandLineCandidates(string commandLine)
        {
            var candidates = new List<string>();
            foreach (Match match in QuotedPathRegex.Matches(commandLine))
                candidates.Add(match.Groups[1].Value);
            foreach (var token in commandLine.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            {
                var trimmed = token.Trim('"', '\'');
                if (trimmed.Length > 0)
                    candidates.Add(trimmed);
            }
            return candidates.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        }

        private static string? TryGetExecutablePath(int processId)
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    $"SELECT ExecutablePath FROM Win32_Process WHERE ProcessId = {processId}");
                foreach (ManagementObject obj in searcher.Get())
                    return obj["ExecutablePath"]?.ToString();
            }
            catch
            {
                /* accès refusé ou processus terminé */
            }

            return null;
        }

        private static readonly TimeSpan DedupWindow = TimeSpan.FromSeconds(45);
        private const long MaxProcessImageScanBytes = 256L * 1024 * 1024;

        /// <summary>Au-delà, les entrées expirées sont purgées (le service tourne des semaines).</summary>
        internal const int RecentScansPruneThreshold = 512;

        /// <summary>
        /// Plafond absolu : même si toutes les entrées sont récentes (rafale de lancements), le
        /// dictionnaire ne dépasse pas cette taille. Les plus anciennes sont alors retirées ;
        /// au pire, un fichier évincé est réanalysé à son prochain lancement.
        /// </summary>
        internal const int MaxRecentScans = 2048;

        /// <summary>Retire les entrées expirées, puis les plus anciennes au-delà de <see cref="MaxRecentScans"/>.</summary>
        internal void PruneRecentScans(DateTime nowUtc)
        {
            if (_recentScans.Count < RecentScansPruneThreshold)
                return;
            foreach (var kvp in _recentScans)
            {
                if (nowUtc - kvp.Value >= DedupWindow)
                    _recentScans.TryRemove(kvp.Key, out _);
            }

            if (_recentScans.Count <= MaxRecentScans)
                return;
            // Rafale : on redescend à la moitié du plafond en gardant les plus récentes.
            var excess = _recentScans.Count - MaxRecentScans / 2;
            foreach (var kvp in _recentScans.ToArray().OrderBy(k => k.Value).Take(excess))
                _recentScans.TryRemove(kvp.Key, out _);
        }

        internal int RecentScansCount => _recentScans.Count;

        internal void RecordRecentScanForTest(string path, DateTime whenUtc) => _recentScans[path] = whenUtc;

        // Tâches lancées par les événements WMI, attendues par Dispose avant de libérer le
        // sémaphore : sinon une tâche en cours appelait Release() sur un objet libéré.
        private readonly ConcurrentDictionary<Task, byte> _inflight = new();
        private readonly CancellationTokenSource _lifetime = new();

        private void Track(Task task)
        {
            _inflight.TryAdd(task, 0);
            _ = task.ContinueWith(t => _inflight.TryRemove(t, out _), TaskScheduler.Default);
        }

        internal int InflightCount => _inflight.Count;

        private async Task HandlePathAsync(string filePath, int processId)
        {
            if (_disposed)
                return;
            var lifetime = _lifetime.Token;
            var now = DateTime.UtcNow;
            if (_recentScans.TryGetValue(filePath, out var last) && (now - last) < DedupWindow)
                return;
            _recentScans[filePath] = now;
            PruneRecentScans(now);

            try
            {
                await Task.Delay(400, lifetime).ConfigureAwait(false);
                if (_exclusions.Current.IsFileExcluded(filePath))
                    return;
                await _scanSemaphore.WaitAsync(lifetime).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException)
            {
                return; // arrêt en cours : rien n'a été réservé
            }

            try
            {
                ScanResult result;
                string? analyzedSha256 = null;
                using (var source = NamedPipeClientAccess.OpenForProcess(processId, filePath))
                {
                    if (source == null)
                        return;
                    if (source.Length > MaxProcessImageScanBytes)
                    {
                        AppLogger.Info("ProcessStartMonitor", "Fichier trop volumineux pour le scan depuis le processus : " + PathRedaction.RedactPath(filePath));
                        return;
                    }

                    using var staged = ScanStaging.Stage(source, Path.GetFileName(filePath));
                    analyzedSha256 = staged.Sha256;
                    result = await _orchestrator.ScanFileAsync(staged.Path).ConfigureAwait(false);
                    result.TargetPath = filePath;
                    foreach (var threat in result.Threats)
                    {
                        threat.FilePath = filePath;
                        if (source.CanSeek)
                            threat.FileSize = source.Length;
                    }
                }

                DetectionHistoryRecorder.Record(_logger, _uiEvents, result, filePath);
                foreach (var threat in result.Threats)
                {
                    _notifications.ShowThreatDetected(threat);
                    if (_exclusions.Current.AutoQuarantineEnabled)
                    {
                        if (_quarantineManager.Quarantine(threat, result.SessionId, analyzedSha256))
                            _notifications.ShowQuarantined(threat);
                    }

                    ThreatDetected?.Invoke(this, threat);
                }
            }
            catch (Exception ex)
            {
                AppLogger.Warn("ProcessStartMonitor", $"Scan {PathRedaction.RedactPath(filePath)}", ex);
            }
            finally
            {
                _scanSemaphore.Release();
            }
        }

        public void Dispose()
        {
            if (_disposed)
                return;
            _disposed = true;
            Stop();

            // Les tâches en attente abandonnent ; celles qui scannent vont jusqu'au bout et
            // libèrent leur place. Le sémaphore n'est libéré qu'une fois toutes terminées.
            _lifetime.Cancel();
            var pending = _inflight.Keys.ToArray();
            var drained = pending.Length == 0;
            if (!drained)
            {
                try { drained = Task.WaitAll(pending, TimeSpan.FromSeconds(10)); }
                catch (AggregateException) { drained = pending.All(t => t.IsCompleted); }
            }

            // _lifetime n'est pas libéré : une tâche lancée pendant l'arrêt peut encore lire son jeton.
            if (drained)
                _scanSemaphore.Dispose();
            else
            {
                AppLogger.Warn("ProcessStartMonitor", "Arrêt : un scan est encore en cours, sémaphore laissé en place");
            }
        }
    }
}
