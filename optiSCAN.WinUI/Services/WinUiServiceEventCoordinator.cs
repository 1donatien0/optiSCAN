using optiSCAN.Coordinators;
using optiSCAN.Models;
using optiSCAN.Services;
using optiSCAN.ViewModels;
using optiSCAN.WinUI.ViewModels;

namespace optiSCAN.WinUI.Services;

/// <summary>Branche événements UI/toasts/protection pour le shell WinUI optiSCAN.</summary>
public sealed class WinUiServiceEventCoordinator
{
    private ServiceContainer? _container;
    private IUiEventBus? _ui;
    private EventHandler? _onSignatureUpdate;
    private EventHandler? _onFocusSignaturesTab;
    private EventHandler? _onFocusScanTab;
    private EventHandler? _onHistoryRefresh;
    private EventHandler? _onExportHtml;
    private EventHandler<ScanSession>? _onExportPdf;
    private EventHandler<ScanSession>? _onReviewSession;
    private EventHandler? _onOpenQuarantine;
    private EventHandler<ThreatInfo>? _onThreatDetected;
    private EventHandler<RemovableDriveScanStatusEventArgs>? _onUsbScanStatus;
    private EventHandler<ToastActivationEventArgs>? _onToastActivated;
    private EventHandler<ActionResult>? _onActionCompleted;

    public void Attach(
        ServiceContainer container,
        IUiEventBus ui,
        EventHandler onSignatureUpdate,
        EventHandler onFocusSignaturesTab,
        EventHandler onFocusScanTab,
        EventHandler onHistoryRefresh,
        EventHandler onExportHtml,
        EventHandler<ScanSession> onExportPdf,
        EventHandler<ScanSession> onReviewSession,
        EventHandler onOpenQuarantine,
        EventHandler<ThreatInfo> onThreatDetected,
        EventHandler<RemovableDriveScanStatusEventArgs> onUsbScanStatus,
        EventHandler<ToastActivationEventArgs> onToastActivated,
        EventHandler<ActionResult> onActionCompleted)
    {
        Detach();

        _container = container;
        _ui = ui;
        _onSignatureUpdate = onSignatureUpdate;
        _onFocusSignaturesTab = onFocusSignaturesTab;
        _onFocusScanTab = onFocusScanTab;
        _onHistoryRefresh = onHistoryRefresh;
        _onExportHtml = onExportHtml;
        _onExportPdf = onExportPdf;
        _onReviewSession = onReviewSession;
        _onOpenQuarantine = onOpenQuarantine;
        _onThreatDetected = onThreatDetected;
        _onUsbScanStatus = onUsbScanStatus;
        _onToastActivated = onToastActivated;
        _onActionCompleted = onActionCompleted;

        ui.RequestSignatureUpdate += onSignatureUpdate;
        ui.FocusAntivirusSignaturesRequested += onFocusSignaturesTab;
        ui.FocusAntivirusScanTabRequested += onFocusScanTab;
        ui.ScanHistoryViewsRefreshRequested += onHistoryRefresh;
        ui.ExportScanHistoryHtmlRequested += onExportHtml;
        ui.ExportScanSessionPdfRequested += onExportPdf;
        ui.ReviewHistorySessionRequested += onReviewSession;
        ui.OpenQuarantineTabRequested += onOpenQuarantine;

        container.RealTimeProtection.ThreatDetected += onThreatDetected;
        container.ProcessStartMonitor.ThreatDetected += onThreatDetected;
        container.RemovableDriveScan.ThreatDetected += onThreatDetected;
        container.RemovableDriveScan.ScanStatusChanged += onUsbScanStatus;
        container.Notifications.ToastActivated -= onToastActivated;
        container.Notifications.ToastActivated += onToastActivated;
        container.Notifications.SyncFromUserPreferences();
        container.Actions.ActionCompleted -= onActionCompleted;
        container.Actions.ActionCompleted += onActionCompleted;
    }

    public void Detach()
    {
        if (_ui == null || _container == null)
            return;

        _ui.RequestSignatureUpdate -= _onSignatureUpdate!;
        _ui.FocusAntivirusSignaturesRequested -= _onFocusSignaturesTab!;
        _ui.FocusAntivirusScanTabRequested -= _onFocusScanTab!;
        _ui.ScanHistoryViewsRefreshRequested -= _onHistoryRefresh!;
        _ui.ExportScanHistoryHtmlRequested -= _onExportHtml!;
        _ui.ExportScanSessionPdfRequested -= _onExportPdf!;
        _ui.ReviewHistorySessionRequested -= _onReviewSession!;
        _ui.OpenQuarantineTabRequested -= _onOpenQuarantine!;

        _container.RealTimeProtection.ThreatDetected -= _onThreatDetected!;
        _container.ProcessStartMonitor.ThreatDetected -= _onThreatDetected!;
        _container.RemovableDriveScan.ThreatDetected -= _onThreatDetected!;
        _container.RemovableDriveScan.ScanStatusChanged -= _onUsbScanStatus!;
        _container.Notifications.ToastActivated -= _onToastActivated!;
        _container.Actions.ActionCompleted -= _onActionCompleted!;

        _container = null;
        _ui = null;
    }
}
