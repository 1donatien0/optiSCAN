namespace optiSCAN.Views;

/// <summary>Onglet Signatures antivirus (implémenté par la page Antivirus du shell).</summary>
public interface IAntivirusSignaturesPanel
{
    void UpdateSignaturesPanel(
        string yaraVersion,
        string yaraLastMaj,
        string clamVersion,
        string clamLastMaj);
}
