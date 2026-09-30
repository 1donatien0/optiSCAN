using optiSCAN.Models;
using optiSCAN.Services;

namespace optiSCAN.Coordinators;

/// <summary>Export HTML/PDF déclenché depuis le bus UI (<see cref="IUiEventBus"/>).</summary>
public sealed class ExportCoordinator
{
    private readonly IHistoryExportService _export;

    public ExportCoordinator(IHistoryExportService export)
    {
        _export = export ?? throw new ArgumentNullException(nameof(export));
    }

    public void TryExportHtml(ExportContext ctx)
    {
        var result = _export.TryExportHtml(ctx.Log, ctx.Threats, ctx.Quarantine);
        Report(ctx, result);
    }

    public void TryExportSessionPdf(ExportContext ctx, ScanSession session)
    {
        var result = _export.TryExportSessionPdf(session);
        Report(ctx, result);
    }

    private static void Report(ExportContext ctx, HistoryExportResult result)
    {
        if (!result.WasCancelled && !string.IsNullOrEmpty(result.Message))
            ctx.SetStatus(result.Message, result.IsError, false);
    }
}
