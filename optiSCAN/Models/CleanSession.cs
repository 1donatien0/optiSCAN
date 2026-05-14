using System.Globalization;
using System.Text.Json.Serialization;

namespace optiSCAN.Models
{
    /// <summary>Entrée d'historique d'une session de nettoyage système (fichiers temp, caches, corbeille).</summary>
    public sealed class CleanSession
    {
        public DateTime StartedAt { get; set; }
        public DateTime FinishedAt { get; set; }

        /// <summary>Résumé des cibles cochées (ex. « Temp Windows, Corbeille, Edge »).</summary>
        public string TargetsSummary { get; set; } = "";

        public long BytesFreed { get; set; }

        [JsonIgnore]
        public string DateDisplay =>
            StartedAt.ToString("dd/MM/yyyy HH:mm", CultureInfo.CurrentCulture);

        [JsonIgnore]
        public string DurationDisplay
        {
            get
            {
                var d = FinishedAt - StartedAt;
                if (d < TimeSpan.Zero) d = TimeSpan.Zero;
                return ScanDisplayFormatter.FormatDuration(d);
            }
        }

        [JsonIgnore]
        public string BytesDisplay
        {
            get
            {
                if (BytesFreed >= 1_073_741_824) return $"{BytesFreed / 1_073_741_824.0:F1} Go";
                if (BytesFreed >= 1_048_576) return $"{BytesFreed / 1_048_576.0:F1} Mo";
                if (BytesFreed >= 1_024) return $"{BytesFreed / 1_024.0:F0} Ko";
                return $"{BytesFreed} o";
            }
        }
    }
}
