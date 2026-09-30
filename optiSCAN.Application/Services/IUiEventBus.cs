using optiSCAN.Models;

namespace optiSCAN.Services;

/// <summary>
/// Bus de messages UI (export, navigation contextuelle, rafraîchissement des vues).
/// <see cref="ServiceContainer"/> l'implémente ; les vues peuvent dépendre de cette interface
/// plutôt que du conteneur complet.
/// </summary>
public interface IUiEventBus
{
    event EventHandler? RequestSignatureUpdate;
    void TriggerSignatureUpdate();

    event EventHandler? FocusAntivirusSignaturesRequested;
    void RequestFocusAntivirusSignaturesTab();

    /// <summary>Demande de lancement d'une analyse (rapide/complète) depuis n'importe quelle vue.</summary>
    event EventHandler<ScanType>? ScanRequested;
    void RequestScan(ScanType type);

    event EventHandler? FocusAntivirusScanTabRequested;
    void RequestFocusAntivirusScanTab();

    event EventHandler? ScanHistoryViewsRefreshRequested;
    void RequestScanHistoryViewsRefresh();

    event EventHandler? ExportScanHistoryHtmlRequested;
    void RequestExportScanHistoryHtml();

    event EventHandler<ScanSession>? ExportScanSessionPdfRequested;
    void RequestExportScanSessionPdf(ScanSession session);

    event EventHandler<ScanSession>? ReviewHistorySessionRequested;
    void RequestReviewHistorySession(ScanSession session);

    event EventHandler? OpenQuarantineTabRequested;
    void RequestOpenQuarantineTab();

    event EventHandler? ProtectionStateRefreshRequested;
    void RequestProtectionStateRefresh();
}
