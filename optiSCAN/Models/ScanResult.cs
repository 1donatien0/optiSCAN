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
                ScanStatus.Running => $"Analyse en cours… ({FilesScanned:N0} fichier(s) déjà parcourus)",
                ScanStatus.Completed => ThreatsFound == 0
                    ? $"Aucune menace — {FilesScanned:N0} fichier(s) en {ScanDisplayFormatter.FormatDuration(Duration)}"
                    : $"Attention : {ThreatsFound} menace(s) sur {FilesScanned:N0} fichier(s)",
                ScanStatus.Cancelled => $"Analyse interrompue ({FilesScanned:N0} fichier(s) parcourus)",
                ScanStatus.Error => $"Erreur : {ErrorMessage}",
                _ => "État inconnu"
            };

        public string TypeDisplay => Type switch
        {
            ScanType.File => "Fichier",
            ScanType.Folder => "Dossier",
            ScanType.FullScan => "Analyse complète",
            ScanType.QuickScan => "Analyse rapide",
            _ => "Analyse"
        };

        public string DurationDisplay => ScanDisplayFormatter.FormatDuration(Duration);

        public string ThreatsBadge => Status switch
        {
            ScanStatus.Running => "En cours…",
            ScanStatus.Cancelled => "Interrompu",
            ScanStatus.Error => "Erreur",
            _ => ThreatsFound == 0
                ? "Aucune menace"
                : $"Attention : {ThreatsFound} menace{(ThreatsFound > 1 ? "s" : "")}"
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
