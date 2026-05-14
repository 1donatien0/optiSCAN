namespace optiSCAN.Models
{
    /// <summary>
    /// Résultat complet d'une session de scan ClamAV.
    /// </summary>
    public class ScanResult
    {
        // ── Identité de la session ──────────────────────────────────────────────
        public Guid SessionId { get; set; } = Guid.NewGuid();
        public DateTime StartedAt { get; set; } = DateTime.Now;
        public DateTime? FinishedAt { get; set; }
        public ScanType Type { get; set; }
        public string TargetPath { get; set; } = string.Empty;

        // ── Statistiques ────────────────────────────────────────────────────────
        public int FilesScanned { get; set; }
        public int ThreatsFound => Threats.Count;
        public int FilesSkipped { get; set; }
        public long TotalBytesScanned { get; set; }

        // ── Résultats ───────────────────────────────────────────────────────────
        public List<ThreatInfo> Threats { get; set; } = new();
        public ScanStatus Status { get; set; } = ScanStatus.Running;
        public string? ErrorMessage { get; set; }

        // ── Propriétés calculées ────────────────────────────────────────────────
        public TimeSpan Duration =>
            FinishedAt.HasValue ? FinishedAt.Value - StartedAt : DateTime.Now - StartedAt;

        public bool IsClean => Status == ScanStatus.Completed && ThreatsFound == 0;

        public string SummaryDisplay =>
            Status switch
            {
                ScanStatus.Running => $"Scan en cours… ({FilesScanned} fichiers analysés)",
                ScanStatus.Completed => ThreatsFound == 0
                    ? $"✅ Aucune menace — {FilesScanned} fichiers analysés en {Duration.TotalSeconds:F1}s"
                    : $"⚠️ {ThreatsFound} menace(s) détectée(s) sur {FilesScanned} fichiers",
                ScanStatus.Cancelled => $"⛔ Scan annulé ({FilesScanned} fichiers parcourus)",
                ScanStatus.Error => $"❌ Erreur : {ErrorMessage}",
                _ => "Inconnu"
            };

        public string TypeDisplay => Type switch
        {
            ScanType.File => "Fichier",
            ScanType.Folder => "Dossier",
            ScanType.FullScan => "Scan complet",
            ScanType.QuickScan => "Scan rapide",
            _ => "Scan"
        };

        public string DurationDisplay
        {
            get
            {
                var d = Duration;
                if (d.TotalSeconds < 1) return "< 1s";
                if (d.TotalMinutes < 1) return $"{d.Seconds}s";
                if (d.TotalHours < 1) return $"{d.Minutes}m {d.Seconds:D2}s";
                return $"{(int)d.TotalHours}h {d.Minutes:D2}m";
            }
        }

        public string ThreatsBadge => Status switch
        {
            ScanStatus.Running => "En cours…",
            ScanStatus.Cancelled => "Annulé",
            ScanStatus.Error => "Erreur",
            _ => ThreatsFound == 0
                                        ? "✅ Propre"
                                        : $"⚠️ {ThreatsFound} menace{(ThreatsFound > 1 ? "s" : "")}"
        };
    }

    /// <summary>Type de scan lancé.</summary>
    public enum ScanType
    {
        File,
        Folder,
        QuickScan,
        FullScan
    }

    /// <summary>État d'avancement du scan.</summary>
    public enum ScanStatus
    {
        Running,
        Completed,
        Cancelled,
        Error
    }
}
