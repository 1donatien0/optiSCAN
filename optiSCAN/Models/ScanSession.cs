using System.Text.Json.Serialization;

namespace optiSCAN.Models
{
    /// <summary>
    /// Entrée d'historique d'un scan — version allégée de <see cref="ScanResult"/>,
    /// sérialisable en JSON pour la persistance locale.
    /// </summary>
    public class ScanSession
    {
        /// <summary>Identifiant unique de la session (correspondant au <see cref="ScanResult"/> d'origine).</summary>
        public Guid SessionId { get; set; }

        /// <summary>Date et heure de démarrage du scan.</summary>
        public DateTime StartedAt { get; set; }

        /// <summary>Date et heure de fin du scan (<c>null</c> si non encore terminé).</summary>
        public DateTime? FinishedAt { get; set; }

        /// <summary>Libellé du type de scan (ex. « Analyse rapide »), tel que stocké dans l'historique.</summary>
        public string TypeDisplay { get; set; } = string.Empty;

        /// <summary>Chemin ou identifiant de la cible analysée.</summary>
        public string TargetPath { get; set; } = string.Empty;

        /// <summary>Nombre de fichiers parcourus pendant le scan.</summary>
        public int FilesScanned { get; set; }

        /// <summary>Nombre de menaces détectées.</summary>
        public int ThreatsFound { get; set; }

        /// <summary>Libellé du statut final (ex. « Completed », « Cancelled »).</summary>
        public string StatusDisplay { get; set; } = string.Empty;

        /// <summary>Durée formatée en français (ex. « 2 min 34 s ») ; « — » si la session n'est pas terminée.</summary>
        [JsonIgnore]
        public string DurationDisplay =>
            FinishedAt.HasValue
                ? ScanDisplayFormatter.FormatDuration(FinishedAt.Value - StartedAt)
                : "—";

        /// <summary>Badge d'état (ex. « Aucune menace » ou « Attention : 2 menaces »).</summary>
        [JsonIgnore]
        public string ThreatsBadge =>
            ThreatsFound == 0
                ? "Aucune menace"
                : $"Attention : {ThreatsFound} menace{(ThreatsFound > 1 ? "s" : "")}";

        /// <summary>Convertit un <see cref="ScanResult"/> complet en entrée d'historique légère.</summary>
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
