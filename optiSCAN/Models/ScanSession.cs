using System.Text.Json.Serialization;

namespace optiSCAN.Models
{
    /// <summary>
    /// Entrée d'historique d'un scan — sérialisable en JSON pour la persistance locale.
    /// </summary>
    public class ScanSession
    {
        public Guid SessionId { get; set; }
        public DateTime StartedAt { get; set; }
        public DateTime? FinishedAt { get; set; }
        public string TypeDisplay { get; set; } = string.Empty;
        public string TargetPath { get; set; } = string.Empty;
        public int FilesScanned { get; set; }
        public int ThreatsFound { get; set; }
        public string StatusDisplay { get; set; } = string.Empty;

        [JsonIgnore]
        public string DurationDisplay =>
            FinishedAt.HasValue
                ? $"{(FinishedAt.Value - StartedAt).TotalSeconds:F0}s"
                : "—";

        [JsonIgnore]
        public string ThreatsBadge =>
            ThreatsFound == 0 ? "✅ Propre" : $"⚠️ {ThreatsFound} menace(s)";

        /// <summary>Convertit un ScanResult complet en entrée d'historique légère.</summary>
        public static ScanSession FromResult(ScanResult result) => new ScanSession
        {
            SessionId = result.SessionId,
            StartedAt = result.StartedAt,
            FinishedAt = result.FinishedAt,
            TypeDisplay = result.TypeDisplay,
            TargetPath = result.TargetPath,
            FilesScanned = result.FilesScanned,
            ThreatsFound = result.ThreatsFound,
            StatusDisplay = result.Status.ToString()
        };
    }
}
