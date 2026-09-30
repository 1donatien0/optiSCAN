using optiSCAN.Models;
using optiSCAN.Services;

namespace optiSCAN.ViewModels
{
    /// <summary>Ligne menace dans le détail Historique — état fichier / quarantaine pour les actions.</summary>
    public sealed class HistoryThreatRow
    {
        public HistoryThreatRow(ThreatInfo threat, HistoryViewModel vm)
        {
            Threat = threat;
            Risk = RiskScoringService.Assess(threat);
            IsQuarantined = vm.IsFileStillQuarantined(threat.FilePath);
            IsFileAccessible = vm.IsThreatFileAccessible(threat.FilePath);
        }

        public ThreatInfo Threat { get; }
        public RiskAssessment Risk { get; }
        public string FilePath => Threat.FilePath;
        public string VirusName => Threat.VirusName;
        public string RiskBrushKey => Risk.BrushKey;
        public bool IsQuarantined { get; }
        public bool IsFileAccessible { get; }
        public bool CanQuarantine => IsFileAccessible && !IsQuarantined;
        public bool CanViewInQuarantine => IsQuarantined;
        public bool CanDismiss => !IsFileAccessible && !IsQuarantined;
    }
}