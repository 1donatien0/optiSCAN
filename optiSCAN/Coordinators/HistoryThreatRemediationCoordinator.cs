using optiSCAN.Models;
using optiSCAN.Services;
using optiSCAN.ViewModels;

namespace optiSCAN.Coordinators;

/// <summary>Actions de remédiation des menaces depuis l'historique (quarantaine, ignore, delete).</summary>
public sealed class HistoryThreatRemediationCoordinator
{
    public void QuarantineAllThreats(IHistoryServices history, HistoryViewModel vm, ScanSession session, Action refreshTimeline)
    {
        if (session.Threats.Count == 0)
            return;

        int count = 0;
        foreach (var t in session.Threats.ToList())
        {
            if (!vm.IsThreatFileAccessible(t.FilePath))
                continue;
            if (history.Quarantine.Quarantine(t, session.SessionId))
            {
                count++;
                history.Logger.TryRemoveThreatFromSession(session.SessionId, t.FilePath);
            }
        }

        if (count > 0)
            refreshTimeline();
    }

    public void QuarantineThreat(
        IHistoryServices history,
        HistoryViewModel vm,
        ScanSession session,
        string filePath,
        Action refreshTimeline)
    {
        if (vm.IsFileStillQuarantined(filePath))
        {
            history.Logger.TryRemoveThreatFromSession(session.SessionId, filePath);
            refreshTimeline();
            return;
        }

        if (history.Actions.QuarantineThreat(filePath, session.SessionId).Success)
        {
            history.Logger.TryRemoveThreatFromSession(session.SessionId, filePath);
            refreshTimeline();
        }
    }

    public void DismissThreat(IHistoryServices history, ScanSession session, string filePath, Action refreshTimeline)
    {
        history.Logger.TryRemoveThreatFromSession(session.SessionId, filePath);
        refreshTimeline();
    }

    public void IgnoreThreat(
        IHistoryServices history,
        ScanSession session,
        string filePath,
        Action refreshTimeline)
    {
        history.Actions.IgnoreThreat(filePath);
        history.Logger.TryRemoveThreatFromSession(session.SessionId, filePath);
        refreshTimeline();
    }

    public void DeleteThreat(
        IHistoryServices history,
        ScanSession session,
        string filePath,
        Action refreshTimeline)
    {
        if (history.Actions.DeleteThreatFile(filePath).Success)
        {
            history.Logger.TryRemoveThreatFromSession(session.SessionId, filePath);
            refreshTimeline();
        }
    }
}
