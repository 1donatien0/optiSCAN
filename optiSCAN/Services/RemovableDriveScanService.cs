using System.IO;
using System.Management;
using System.Runtime.Versioning;
using optiSCAN.Localization;
using optiSCAN.Models;

namespace optiSCAN.Services
{
    /// <summary>
    /// Détecte le branchement de lecteurs amovibles (USB, carte SD…) et lance un scan
    /// en arrière-plan via <see cref="ScanOrchestrator"/>.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public sealed class RemovableDriveScanService : IDisposable
    {
        private const int MountSettleDelayMs = 2000;
        private const int QuickScanMaxRiskyFiles = 4000;
        private const int PollIntervalMs = 4000;
        private const int WmiDeviceArrival = 2;
        private const int WmiDeviceRemoval = 3;

        private readonly ScanOrchestrator _orchestrator;
        private readonly QuarantineManager _quarantine;
        private readonly NotificationService _notifications;
        private readonly ScanLogManager _logger;
        private readonly HashSet<string> _knownRoots = new(StringComparer.OrdinalIgnoreCase);
        private readonly SemaphoreSlim _scanLock = new(1, 1);
        private readonly object _lifecycleLock = new();

        private ManagementEventWatcher? _volumeWatcher;
        private System.Threading.Timer? _pollTimer;
        private bool _started;
        private bool _disposed;

        public event EventHandler<ThreatInfo>? ThreatDetected;

        public RemovableDriveScanService(
            ScanOrchestrator orchestrator,
            QuarantineManager quarantine,
            NotificationService notifications,
            ScanLogManager logger)
        {
            _orchestrator = orchestrator;
            _quarantine = quarantine;
            _notifications = notifications;
            _logger = logger;
        }

        public void Start()
        {
            lock (_lifecycleLock)
            {
                if (_started || _disposed) return;
                SeedKnownRemovableRoots();
                TryStartVolumeWatcher();
                _pollTimer = new System.Threading.Timer(
                    _ => PollForNewDrives(),
                    null,
                    PollIntervalMs,
                    PollIntervalMs);
                _started = true;
                AppLogger.Info("RemovableDriveScan", "Surveillance des lecteurs amovibles démarrée.");
            }
        }

        public void Stop()
        {
            lock (_lifecycleLock)
            {
                if (!_started) return;
                _volumeWatcher?.Stop();
                _volumeWatcher?.Dispose();
                _volumeWatcher = null;
                _pollTimer?.Dispose();
                _pollTimer = null;
                _started = false;
            }
        }

        public void Dispose()
        {
            if (_disposed) return;
            Stop();
            _scanLock.Dispose();
            _disposed = true;
        }

        private void SeedKnownRemovableRoots()
        {
            foreach (var root in RemovableDriveDiscovery.GetReadyRemovableRoots())
                _knownRoots.Add(root);
        }

        private void TryStartVolumeWatcher()
        {
            try
            {
                var query = new WqlEventQuery(
                    "SELECT * FROM Win32_VolumeChangeEvent WHERE EventType = 2 OR EventType = 3");
                _volumeWatcher = new ManagementEventWatcher(query);
                _volumeWatcher.EventArrived += (_, e) => OnVolumeChange(e);
                _volumeWatcher.Start();
            }
            catch (Exception ex)
            {
                AppLogger.Warn("RemovableDriveScan", "WMI Win32_VolumeChangeEvent indisponible — repli sur polling.", ex);
            }
        }

        private void OnVolumeChange(EventArrivedEventArgs e)
        {
            try
            {
                var props = e.NewEvent?.Properties;
                if (props == null) return;

                var eventType = Convert.ToInt32(props["EventType"]?.Value ?? 0);
                var driveName = props["DriveName"]?.Value as string;

                if (eventType == WmiDeviceRemoval && !string.IsNullOrWhiteSpace(driveName))
                {
                    var root = RemovableDriveDiscovery.NormalizeRootFromDriveName(driveName);
                    if (root != null)
                        _knownRoots.Remove(root);
                    return;
                }

                if (eventType == WmiDeviceArrival)
                    _ = ScheduleScanNewDrivesAsync();
            }
            catch (Exception ex)
            {
                AppLogger.Warn("RemovableDriveScan", "OnVolumeChange", ex);
            }
        }

        private void PollForNewDrives() =>
            _ = ScheduleScanNewDrivesAsync();

        private async Task ScheduleScanNewDrivesAsync()
        {
            if (!UserPreferences.Current.RemovableDriveScanEnabled)
                return;

            try
            {
                await Task.Delay(MountSettleDelayMs).ConfigureAwait(false);
                var newRoots = RemovableDriveDiscovery.FindNewRemovableRoots(_knownRoots);
                foreach (var root in newRoots)
                {
                    _knownRoots.Add(root);
                    await ScanRootIfEligibleAsync(root).ConfigureAwait(false);
                }
            }
            catch (Exception ex)
            {
                AppLogger.Warn("RemovableDriveScan", "ScheduleScanNewDrivesAsync", ex);
            }
        }

        private async Task ScanRootIfEligibleAsync(string root)
        {
            if (!UserPreferences.Current.RemovableDriveScanEnabled)
                return;

            if (!RemovableDriveDiscovery.TryGetDriveInfo(root, out var drive))
                return;

            if (!RemovableDriveDiscovery.IsWithinSizeLimit(drive.TotalSize, UserPreferences.Current.RemovableDriveMaxSizeGb))
            {
                AppLogger.Info("RemovableDriveScan", $"Lecteur ignoré (taille) : {root}");
                return;
            }

            if (ExclusionSettings.Current.IsFolderExcluded(root))
            {
                AppLogger.Info("RemovableDriveScan", $"Lecteur exclu : {root}");
                return;
            }

            if (!_orchestrator.IsClamAvAvailable && !_orchestrator.IsYaraAvailable)
            {
                AppLogger.Warn("RemovableDriveScan", "Aucun moteur disponible — scan USB ignoré.");
                return;
            }

            await _scanLock.WaitAsync().ConfigureAwait(false);
            try
            {
                await RunScanAsync(root).ConfigureAwait(false);
            }
            finally
            {
                _scanLock.Release();
            }
        }

        private async Task RunScanAsync(string root)
        {
            AppLogger.Info("RemovableDriveScan", $"Analyse du lecteur {root}…");
            var detailed = UserPreferences.Current.RemovableDriveScanDetailed;
            ScanResult result;
            try
            {
                result = detailed
                    ? await ScanDetailedAsync(root).ConfigureAwait(false)
                    : await ScanQuickAsync(root).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                AppLogger.Error("RemovableDriveScan", $"Échec scan {root}", ex);
                return;
            }

            _logger.SaveScanResult(result);
            UserPreferences.Current.IncrementScanCount(ScanType.RemovableDrive);
            ServiceContainer.Default.RequestScanHistoryViewsRefresh();

            if (result.Threats.Count > 0)
            {
                if (ExclusionSettings.Current.AutoQuarantineEnabled)
                {
                    var n = _quarantine.QuarantineAll(result.Threats);
                    if (n > 0)
                        AppLogger.Info("RemovableDriveScan", $"{n} fichier(s) mis en quarantaine sur {root}.");
                }

                foreach (var threat in result.Threats)
                {
                    _notifications.ShowThreatDetected(threat);
                    ThreatDetected?.Invoke(this, threat);
                }
            }

            if (UserPreferences.Current.ActionNotificationsEnabled)
                _notifications.ShowScanCompleted(result.Threats.Count, result.FilesScanned);
        }

        private async Task<ScanResult> ScanDetailedAsync(string root)
        {
            var result = await _orchestrator.ScanFolderAsync(root).ConfigureAwait(false);
            result.Type = ScanType.RemovableDrive;
            return result;
        }

        private async Task<ScanResult> ScanQuickAsync(string root)
        {
            var files = RemovableDriveDiscovery.EnumerateAllFiles(root, QuickScanMaxRiskyFiles).ToList();
            if (files.Count == 0)
            {
                AppLogger.Info("RemovableDriveScan", $"Aucun fichier lisible sur {root} — repli analyse complète du volume.");
                return await ScanDetailedAsync(root).ConfigureAwait(false);
            }

            var merged = new ScanResult
            {
                Type = ScanType.RemovableDrive,
                TargetPath = root,
                StartedAt = DateTime.Now,
                Status = ScanStatus.Running,
            };

            foreach (var file in files)
            {
                if (ExclusionSettings.Current.IsFileExcluded(file))
                {
                    merged.FilesSkipped++;
                    continue;
                }

                var sub = await _orchestrator.ScanFileAsync(file).ConfigureAwait(false);
                merged.FilesScanned += sub.FilesScanned > 0 ? sub.FilesScanned : 1;
                merged.FilesSkipped += sub.FilesSkipped;
                merged.TotalBytesScanned += sub.TotalBytesScanned;
                foreach (var t in sub.Threats)
                    ScanThreatMerger.AddOrMergeThreat(merged.Threats, t);
            }

            merged.FinishedAt = DateTime.Now;
            merged.Status = ScanStatus.Completed;
            return merged;
        }
    }

    /// <summary>Détection et filtrage des lecteurs amovibles (testable).</summary>
    internal static class RemovableDriveDiscovery
    {
        public static IReadOnlyList<string> GetReadyRemovableRoots()
        {
            var list = new List<string>();
            foreach (var d in DriveInfo.GetDrives())
            {
                if (TryNormalizeRoot(d, out var root))
                    list.Add(root);
            }
            return list;
        }

        public static IReadOnlyList<string> FindNewRemovableRoots(ISet<string> knownRoots)
        {
            var list = new List<string>();
            foreach (var d in DriveInfo.GetDrives())
            {
                if (!TryNormalizeRoot(d, out var root))
                    continue;
                if (!knownRoots.Contains(root))
                    list.Add(root);
            }
            return list;
        }

        public static string? NormalizeRootFromDriveName(string driveName)
        {
            if (string.IsNullOrWhiteSpace(driveName))
                return null;
            var trimmed = driveName.Trim().TrimEnd('\\');
            if (trimmed.Length == 2 && trimmed[1] == ':')
                return trimmed + "\\";
            return null;
        }

        public static bool IsWithinSizeLimit(long totalBytes, int maxSizeGb)
        {
            if (maxSizeGb <= 0)
                return true;
            if (totalBytes <= 0)
                return true;
            return totalBytes <= (long)maxSizeGb * 1024L * 1024L * 1024L;
        }

        public static bool TryGetDriveInfo(string root, out DriveInfo drive)
        {
            drive = null!;
            try
            {
                var letter = root.TrimEnd('\\');
                if (letter.Length < 2)
                    return false;
                drive = new DriveInfo(letter);
                return drive.IsReady && IsEligibleForAutoScan(drive);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>Tous les fichiers du volume (pas seulement les extensions RTP), plafonnés.</summary>
        public static IEnumerable<string> EnumerateAllFiles(string root, int maxFiles)
        {
            if (!Directory.Exists(root))
                yield break;

            var stack = new Stack<string>();
            stack.Push(root);
            var count = 0;

            while (stack.Count > 0 && count < maxFiles)
            {
                var dir = stack.Pop();
                IEnumerable<string> subDirs;
                IEnumerable<string> files;
                try
                {
                    subDirs = Directory.EnumerateDirectories(dir);
                    files = Directory.EnumerateFiles(dir);
                }
                catch
                {
                    continue;
                }

                foreach (var sub in subDirs)
                {
                    try
                    {
                        if ((File.GetAttributes(sub) & FileAttributes.ReparsePoint) != 0)
                            continue;
                    }
                    catch { continue; }
                    stack.Push(sub);
                }

                foreach (var file in files)
                {
                    yield return file;
                    count++;
                    if (count >= maxFiles)
                        yield break;
                }
            }
        }

        /// <summary>
        /// Lecteur amovible classique ou clé USB souvent exposée en <see cref="DriveType.Fixed"/> par Windows.
        /// </summary>
        internal static bool IsEligibleForAutoScan(DriveInfo drive)
        {
            if (!drive.IsReady)
                return false;
            if (drive.DriveType is DriveType.Network or DriveType.CDRom or DriveType.NoRootDirectory)
                return false;
            if (drive.DriveType == DriveType.Removable)
                return true;
            if (IsSystemVolume(drive))
                return false;
            if (drive.DriveType == DriveType.Fixed)
                return IsUsbOrRemovableBackingDisk(drive.Name);
            return false;
        }

        private static bool IsSystemVolume(DriveInfo drive)
        {
            try
            {
                var sys = Environment.GetFolderPath(Environment.SpecialFolder.System);
                if (sys.Length >= 3)
                {
                    var sysRoot = sys[..3];
                    if (drive.Name.Equals(sysRoot, StringComparison.OrdinalIgnoreCase))
                        return true;
                }
            }
            catch { /* ignore */ }
            return false;
        }

        private static bool IsUsbOrRemovableBackingDisk(string driveName)
        {
            var deviceId = driveName.TrimEnd('\\');
            if (deviceId.Length < 2)
                return false;

            try
            {
                using var logical = new ManagementObjectSearcher(
                    $"SELECT DriveType FROM Win32_LogicalDisk WHERE DeviceID='{deviceId}'");
                foreach (ManagementObject obj in logical.Get())
                {
                    if (obj["DriveType"] is uint dt && dt == 2)
                        return true;
                }

                using var parts = new ManagementObjectSearcher(
                    $"ASSOCIATORS OF {{Win32_LogicalDisk.DeviceID='{deviceId}'}} WHERE AssocClass=Win32_LogicalDiskToPartition");
                foreach (ManagementObject partition in parts.Get())
                {
                    var partId = partition["DeviceID"]?.ToString();
                    if (string.IsNullOrEmpty(partId))
                        continue;

                    var escaped = partId.Replace(@"\", @"\\");
                    using var disks = new ManagementObjectSearcher(
                        $"ASSOCIATORS OF {{Win32_DiskPartition.DeviceID='{escaped}'}} WHERE AssocClass=Win32_DiskDriveToDiskPartition");
                    foreach (ManagementObject disk in disks.Get())
                    {
                        var iface = disk["InterfaceType"]?.ToString() ?? string.Empty;
                        var media = disk["MediaType"]?.ToString() ?? string.Empty;
                        var pnp = disk["PNPDeviceID"]?.ToString() ?? string.Empty;
                        if (iface.Equals("USB", StringComparison.OrdinalIgnoreCase))
                            return true;
                        if (media.Contains("Removable", StringComparison.OrdinalIgnoreCase))
                            return true;
                        if (pnp.Contains("USB", StringComparison.OrdinalIgnoreCase))
                            return true;
                    }
                }
            }
            catch (Exception ex)
            {
                AppLogger.Warn("RemovableDriveDiscovery", $"WMI lecteur {deviceId}", ex);
            }

            return false;
        }

        private static bool TryNormalizeRoot(DriveInfo drive, out string root)
        {
            root = string.Empty;
            try
            {
                if (!IsEligibleForAutoScan(drive))
                    return false;
                root = drive.RootDirectory.FullName;
                if (!root.EndsWith('\\'))
                    root += '\\';
                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}
