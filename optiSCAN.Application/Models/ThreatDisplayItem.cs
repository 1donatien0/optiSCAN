using optiSCAN.Services;

namespace optiSCAN.Models;

/// <summary>Menace avec évaluation de risque pour l'affichage en liste.</summary>
public sealed class ThreatDisplayItem
{
    public ThreatInfo Threat { get; }
    public RiskAssessment Risk { get; }
    public string FilePath => Threat.FilePath;
    public string VirusName => Threat.VirusName;
    public string RiskSeverity => Risk.Severity;
    public string RiskBrushKey => Risk.BrushKey;

    public static ThreatDisplayItem Create(ThreatInfo threat) =>
        new(threat, RiskScoringService.Assess(threat));

    private ThreatDisplayItem(ThreatInfo threat, RiskAssessment risk)
    {
        Threat = threat;
        Risk = risk;
    }
}
