using optiSCAN.Localization;
using optiSCAN.Models;
using optiSCAN.Services;

namespace optiSCAN.WinUI.Services;

/// <summary>Export HTML/PDF via la boîte « Enregistrer sous » Win32 (synchrone, compatible mode administrateur).</summary>
public sealed class WinUiHistoryExportService : IHistoryExportService
{
    private readonly IUserPreferencesAccessor _prefs;

    /// <param name="getHwnd">Conservé pour compatibilité : la fenêtre propriétaire est résolue par <see cref="WinUiNativeDialogs"/>.</param>
    public WinUiHistoryExportService(Func<IntPtr> getHwnd, IUserPreferencesAccessor? preferences = null)
    {
        _ = getHwnd;
        _prefs = preferences ?? new DefaultUserPreferencesAccessor();
    }

    public HistoryExportResult TryExportHtml(
        ScanLogManager? logManager,
        IEnumerable<ThreatInfo> threats,
        IEnumerable<QuarantineEntry> quarantine)
    {
        try
        {
            // Ancien code : FileSavePicker attendu en synchrone (.GetAwaiter().GetResult()) sur le
            // thread UI → interblocage, l'application se figeait au clic sur « Exporter ».
            var path = PickSaveFile(
                LocalizationService.GetString("Export_HtmlFilter"),
                $"optiSCAN_rapport_{DateTime.Now:yyyyMMdd_HHmm}.html",
                ".html");

            if (path == null)
                return HistoryExportResult.UserCancelled;

            var html = new HtmlExportService();
            var hist = logManager?.GetHistory() ?? Array.Empty<ScanSession>();
            html.ExportFullReport(hist, threats, quarantine, _prefs.Current, path);
            return HistoryExportResult.Succeeded(LocalizationService.Format("Status_HtmlSaved", path));
        }
        catch (Exception ex)
        {
            AppLogger.Error("WinUiHistoryExportService", "Export HTML", ex);
            return HistoryExportResult.Failed(LocalizationService.Format("Status_HtmlFailed", ex.Message));
        }
    }

    public HistoryExportResult TryExportSessionPdf(ScanSession session)
    {
        try
        {
            var path = PickSaveFile(
                LocalizationService.GetString("Export_PdfFilter"),
                $"optiSCAN_scan_{session.StartedAt:yyyyMMdd_HHmm}.pdf",
                ".pdf");

            if (path == null)
                return HistoryExportResult.UserCancelled;

            var gen = new PdfReportGenerator();
            gen.GenerateReportFromSession(session, path);
            return HistoryExportResult.Succeeded(LocalizationService.Format("Status_PdfSaved", path));
        }
        catch (Exception ex)
        {
            AppLogger.Error("WinUiHistoryExportService", "Export PDF", ex);
            return HistoryExportResult.Failed(LocalizationService.Format("Status_PdfFailed", ex.Message));
        }
    }

    private static string? PickSaveFile(string filter, string suggestedName, string defaultExt)
    {
        // Les ressources Export_*Filter sont au format WinForms « Libellé|*.ext » : on garde le libellé.
        var label = filter.Split('|')[0].Trim();
        return WinUiNativeDialogs.PickSaveFile(suggestedName, label, defaultExt);
    }
}
