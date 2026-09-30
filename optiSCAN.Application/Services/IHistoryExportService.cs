using optiSCAN.Models;

namespace optiSCAN.Services;

/// <summary>Contrat testable pour l'export HTML/PDF de l'historique (agnostique UI).</summary>
public interface IHistoryExportService
{
    HistoryExportResult TryExportHtml(
        ScanLogManager? logManager,
        IEnumerable<ThreatInfo> threats,
        IEnumerable<QuarantineEntry> quarantine);

    HistoryExportResult TryExportSessionPdf(ScanSession session);
}

public readonly struct HistoryExportResult
{
    public bool WasCancelled { get; init; }
    public bool Success { get; init; }
    public string Message { get; init; }
    public bool IsError { get; init; }

    public static HistoryExportResult UserCancelled => new() { WasCancelled = true };

    public static HistoryExportResult Succeeded(string message) =>
        new() { Success = true, Message = message };

    public static HistoryExportResult Failed(string message) =>
        new() { Success = false, IsError = true, Message = message };
}
