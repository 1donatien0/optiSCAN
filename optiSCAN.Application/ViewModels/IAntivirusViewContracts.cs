using optiSCAN.Models;

namespace optiSCAN.ViewModels;

/// <summary>Contrat pour appliquer l'état des signatures antivirus (couche Application, sans ViewModel WinUI).</summary>
public interface IAntivirusSignatureState
{
    string DbVersion { get; set; }
    string RulesPackVersion { get; set; }
    string LastUpdateDisplay { get; set; }
    string RulesLastUpdateDisplay { get; set; }
    int YaraRulesCount { get; set; }
    string YaraStatus { get; set; }

    void RefreshProtectionStatus();
}

/// <summary>Menaces temps réel (RTP) remontées dans le shell antivirus.</summary>
public interface ILiveThreatSink
{
    void AppendLiveThreat(ThreatInfo threat);
}
