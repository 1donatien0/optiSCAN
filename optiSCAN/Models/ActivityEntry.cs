using optiSCAN.Localization;
using System.Globalization;

namespace optiSCAN.Models
{
    public enum ActivityKind { Scan, Clean }

    /// <summary>
    /// Entree unifiee de la timeline (scan antivirus ou nettoyage systeme).
    /// Permet un historique chronologique sans tabs ni listes separees.
    /// </summary>
    public sealed class ActivityEntry
    {
        public ActivityKind Kind { get; init; }
        public DateTime StartedAt { get; init; }
        public DateTime? FinishedAt { get; init; }
        public string TypeDisplay { get; init; } = string.Empty;
        public string ResultSummary { get; init; } = string.Empty;
        public bool HasThreats { get; init; }
        public bool IsClean => Kind == ActivityKind.Scan && !HasThreats;
        public string DurationDisplay { get; init; } = string.Empty;
        public ScanSession? ScanSession { get; init; }
        public CleanSession? CleanSession { get; init; }
        public IReadOnlyList<ThreatInfo> Threats =>
            ScanSession?.Threats is { Count: > 0 } t ? t : Array.Empty<ThreatInfo>();
        public int ThreatsFound => ScanSession?.ThreatsFound ?? 0;
        public Guid ScanSessionId => ScanSession?.SessionId ?? Guid.Empty;

        public static ActivityEntry FromScan(ScanSession session)
        {
            string result = session.ThreatsFound > 0
                ? LocalizationService.Format("Hist_InfoThreats", session.ThreatsFound)
                : LocalizationService.GetString("Hist_InfoClean");

            return new ActivityEntry
            {
                Kind = ActivityKind.Scan,
                StartedAt = session.StartedAt,
                FinishedAt = session.FinishedAt,
                TypeDisplay = session.TypeDisplay,
                ResultSummary = result,
                HasThreats = session.ThreatsFound > 0,
                DurationDisplay = session.DurationDisplay,
                ScanSession = session,
            };
        }

        public static ActivityEntry FromClean(CleanSession session)
        {
            return new ActivityEntry
            {
                Kind = ActivityKind.Clean,
                StartedAt = session.StartedAt,
                FinishedAt = session.FinishedAt,
                TypeDisplay = LocalizationService.GetString("Hist_TabCleans"),
                ResultSummary = session.BytesDisplay,
                HasThreats = false,
                DurationDisplay = session.DurationDisplay,
                CleanSession = session,
            };
        }

        public string IconKind => Kind switch
        {
            ActivityKind.Clean => "Broom",
            _ when HasThreats  => "ShieldAlert",
            _                  => "ShieldCheck",
        };

        public string IconBrushKey => Kind switch
        {
            ActivityKind.Clean => "TextAccent",
            _ when HasThreats  => "DangerRed",
            _                  => "SuccessGreen",
        };

        public string DateDisplay =>
            StartedAt.ToString("dd/MM/yyyy HH:mm", CultureInfo.CurrentCulture);
    }
}
