using optiSCAN.Models;
using optiSCAN.Services;
using optiSCAN.ViewModels;

namespace optiSCAN.Coordinators;

/// <summary>Remédiation des menaces depuis l'historique (injectable — façade DI du coordinateur statique).</summary>
public sealed class HistoryThreatRemediationService
{
    public void QuarantineAllThreats(IHistoryServices history, HistoryViewModel vm, ScanSession session, Action refreshTimeline) =>
        HistoryThreatRemediationCoordinator.QuarantineAllThreats(history, vm, session, refreshTimeline);

    public void QuarantineThreat(IHistoryServices history, HistoryViewModel vm, ScanSession session, string filePath, Action refreshTimeline) =>
        HistoryThreatRemediationCoordinator.QuarantineThreat(history, vm, session, filePath, refreshTimeline);

    public void DismissThreat(IHistoryServices history, ScanSession session, string filePath, Action refreshTimeline) =>
        HistoryThreatRemediationCoordinator.DismissThreat(history, session, filePath, refreshTimeline);

    public void IgnoreThreat(IHistoryServices history, ScanSession session, string filePath, Action refreshTimeline) =>
        HistoryThreatRemediationCoordinator.IgnoreThreat(history, session, filePath, refreshTimeline);

    public void DeleteThreat(IHistoryServices history, ScanSession session, string filePath, Action refreshTimeline) =>
        HistoryThreatRemediationCoordinator.DeleteThreat(history, session, filePath, refreshTimeline);
}
