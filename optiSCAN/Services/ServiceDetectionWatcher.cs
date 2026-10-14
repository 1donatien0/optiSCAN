using System.Security.Principal;
using optiSCAN.Models;
using optiSCAN.Platform;

namespace optiSCAN.Services;

/// <summary>
/// Côté interface : relève périodiquement les détections du service SYSTEM (opération
/// <see cref="ProtectionPipeOperations.RecentDetections"/>), les inscrit dans l'historique de
/// l'utilisateur et les notifie. Sans cela, une menace trouvée ou mise en quarantaine par le
/// service n'apparaissait nulle part pour l'utilisateur.
/// </summary>
public sealed class ServiceDetectionWatcher : IDisposable
{
    internal static readonly TimeSpan Interval = TimeSpan.FromSeconds(30);

    /// <summary>Au tout premier relevé, les détections des dernières 24 h sont montrées.</summary>
    internal static readonly TimeSpan FirstLookBack = TimeSpan.FromHours(24);

    /// <summary>Au-delà, une seule notification récapitulative.</summary>
    internal const int MaxIndividualToasts = 3;

    private readonly IUserPreferencesAccessor _prefs;
    private readonly NotificationService _notifications;
    private readonly ScanLogManager _logger;
    private readonly IUiEventBus? _uiEvents;
    private readonly Func<long, ProtectionPipeResponse> _query;
    private System.Threading.Timer? _timer;
    private int _polling;
    private volatile bool _unsupported;

    public ServiceDetectionWatcher(
        IUserPreferencesAccessor preferences,
        NotificationService notifications,
        ScanLogManager logger,
        IUiEventBus? uiEvents,
        Func<long, ProtectionPipeResponse>? query = null)
    {
        _prefs = preferences;
        _notifications = notifications;
        _logger = logger;
        _uiEvents = uiEvents;
        _query = query ?? QueryService;
    }

    public void Start()
    {
        if (_timer != null || IsSystem())
            return;
        _timer = new System.Threading.Timer(_ => Poll(), null, TimeSpan.FromSeconds(5), Interval);
    }

    /// <summary>Un relevé. Rend le nombre de nouvelles détections traitées.</summary>
    internal int Poll()
    {
        if (_unsupported || !_prefs.Current.UsePlatformProtectionService)
            return 0;
        if (Interlocked.Exchange(ref _polling, 1) == 1)
            return 0;

        try
        {
            var since = _prefs.Current.LastSeenServiceDetection;
            if (since <= 0)
                since = (DateTime.UtcNow - FirstLookBack).Ticks;

            ProtectionPipeResponse response;
            try
            {
                response = _query(since);
            }
            catch (Exception ex)
            {
                AppLogger.Debug("ServiceDetectionWatcher", "Service injoignable : " + ex.Message);
                return 0;
            }

            if (!response.Ok)
            {
                // Service plus ancien : l'opération n'existe pas, inutile de redemander.
                if (response.Message?.StartsWith("Opération inconnue", StringComparison.Ordinal) == true)
                    _unsupported = true;
                return 0;
            }

            UpdateServiceRealTimeHealth(response.RealTimeDegradedFolders);

            var items = (response.Detections ?? new List<ServiceDetectionItem>())
                .Where(d => d.Sequence > since)
                .OrderBy(d => d.Sequence)
                .ToList();
            if (items.Count == 0)
                return 0;

            var threats = items.Select(ToThreat).ToList();
            foreach (var threat in threats)
            {
                var result = new ScanResult
                {
                    Type = ScanType.RealTime,
                    TargetPath = threat.FilePath,
                    StartedAt = threat.DetectedAt,
                    FinishedAt = threat.DetectedAt,
                    Status = ScanStatus.Completed,
                    FilesScanned = 1,
                };
                result.Threats.Add(threat);
                DetectionHistoryRecorder.Record(_logger, _uiEvents, result, threat.FilePath);
            }

            if (threats.Count <= MaxIndividualToasts)
            {
                foreach (var threat in threats)
                    _notifications.ShowServiceThreat(threat);
            }
            else
            {
                _notifications.ShowServiceThreatsSummary(threats.Count);
            }

            _prefs.Current.LastSeenServiceDetection = items[^1].Sequence;
            _prefs.Current.Save();
            return threats.Count;
        }
        finally
        {
            Interlocked.Exchange(ref _polling, 0);
        }
    }

    private static int _serviceRealTimeDegraded = -1;

    /// <summary>
    /// Dossiers en défaut dans le temps réel du service au dernier relevé ; -1 si inconnu
    /// (service plus ancien, temps réel arrêté ou jamais joint).
    /// </summary>
    public static int ServiceRealTimeDegradedFolders => Volatile.Read(ref _serviceRealTimeDegraded);

    private void UpdateServiceRealTimeHealth(int? degraded)
    {
        var value = degraded ?? -1;
        var previous = Interlocked.Exchange(ref _serviceRealTimeDegraded, value);
        if (previous == value)
            return;
        _uiEvents?.RequestProtectionStateRefresh();
        if (value > 0 && previous <= 0)
            _notifications.ShowRealTimeDegraded(value);
    }

    internal static void ResetServiceHealthForTests() => Volatile.Write(ref _serviceRealTimeDegraded, -1);

    internal static ThreatInfo ToThreat(ServiceDetectionItem item) => new()
    {
        FilePath = string.IsNullOrWhiteSpace(item.FullPath) ? item.FileName : item.FullPath,
        VirusName = item.VirusName,
        DetectedAt = DateTime.SpecifyKind(item.DetectedAtUtc, DateTimeKind.Utc).ToLocalTime(),
        DetectedBy = string.IsNullOrWhiteSpace(item.Engine) ? "ClamAV" : item.Engine,
        Status = item.Quarantined ? ThreatStatus.Quarantined : ThreatStatus.Detected,
    };

    private static ProtectionPipeResponse QueryService(long since)
    {
        using var client = new ProtectionPipeClient(timeout: TimeSpan.FromSeconds(5));
        return client.GetRecentDetectionsAsync(since).GetAwaiter().GetResult();
    }

    private static bool IsSystem()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return identity.IsSystem;
        }
        catch
        {
            return false;
        }
    }

    public void Dispose()
    {
        _timer?.Dispose();
        _timer = null;
    }
}
