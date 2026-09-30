using optiSCAN.Localization;
using optiSCAN.Models;
using optiSCAN.Services;
using optiSCAN.Strings;
using optiSCAN.ViewModels;
using System.Linq;

namespace optiSCAN.WinUI.ViewModels
{
    public partial class AntivirusViewModel
    {
        private void QuarantineAllThreats()
        {
            if (Threats.Count == 0) return;
            if (!_confirm.ConfirmYesNo(
                    OptiscanStrings.Confirmations.QuarantineAll(Threats.Count),
                    OptiscanStrings.Confirmations.Title))
                return;

            var sessionId = ActiveScanSessionId;
            int count = _quarantine.QuarantineAll(Threats, sessionId);
            foreach (var threat in Threats.ToList())
            {
                if (IsPathCurrentlyQuarantined(threat.FilePath))
                    _quarantinedDuringScanPaths.Add(threat.FilePath);
            }
            LoadQuarantine();
            // Retirer de la liste les menaces effectivement isolées (comme pour la quarantaine
            // unitaire) : sinon elles restaient affichées et leurs boutons agissaient sur des
            // fichiers déjà déplacés.
            foreach (var threat in Threats.ToList())
            {
                if (!IsPathCurrentlyQuarantined(threat.FilePath))
                    continue;
                threat.Status = ThreatStatus.Quarantined;
                Threats.Remove(threat);
            }
            ThreatsFound = Threats.Count;
            OnPropertyChanged(nameof(SummaryDisplay));
            ((RelayCommand)QuarantineAllCommand).NotifyCanExecuteChanged();
            StatusMessage = LocalizationService.Format("Vm_QuarantineBatch", count);
            _uiEvents.RequestScanHistoryViewsRefresh();
        }

        /// <summary>Appelé après une quarantaine réussie pendant un scan en cours.</summary>
        public void NotifyThreatQuarantinedDuringScan(string filePath)
        {
            if (string.IsNullOrWhiteSpace(filePath)) return;
            _quarantinedDuringScanPaths.Add(filePath);
            LoadQuarantine();
            _uiEvents.RequestScanHistoryViewsRefresh();
        }

        private bool IsPathCurrentlyQuarantined(string filePath) =>
            !string.IsNullOrWhiteSpace(filePath)
            && _quarantine.GetEntries().Any(e =>
                string.Equals(e.OriginalPath, filePath, StringComparison.OrdinalIgnoreCase));

        private void RestoreFromQuarantine(string? id)
        {
            if (string.IsNullOrEmpty(id)) return;
            bool ok = _quarantine.Restore(id);
            LoadQuarantine();
            StatusMessage = ok ? LocalizationService.GetString("Vm_RestoreOk") : LocalizationService.GetString("Vm_RestoreFail");
        }

        private void DeleteFromQuarantine(string? id)
        {
            if (string.IsNullOrEmpty(id)) return;
            bool ok = _quarantine.DeletePermanently(id);
            LoadQuarantine();
            StatusMessage = ok ? LocalizationService.GetString("Vm_DeleteOk") : LocalizationService.GetString("Vm_DeleteFail");
        }

        private void PurgeAll()
        {
            int total = _quarantine.Count;
            if (total == 0) return;
            if (!_confirm.ConfirmYesNo(
                    OptiscanStrings.Confirmations.PurgeQuarantine(total),
                    OptiscanStrings.Confirmations.Title))
                return;

            int count = _quarantine.PurgeAll();
            LoadQuarantine();
            StatusMessage = LocalizationService.Format("Vm_PurgeCount", count);
        }

        public void LoadQuarantine(bool reset = true)
        {
            _ui.Invoke(() =>
            {
                QuarantineTotalCount = _quarantine.Count;
                if (reset)
                    QuarantineEntries.Clear();
                var offset = QuarantineEntries.Count;
                foreach (var e in _quarantine.GetEntriesPaged(offset, QuarantinePageSize))
                    QuarantineEntries.Add(e);
                NotifyQuarantinePaging();
            });
        }

        private void LoadMoreQuarantinePage() => LoadQuarantine(reset: false);

        private void NotifyQuarantinePaging()
        {
            OnPropertyChanged(nameof(QuarantineHasMore));
            OnPropertyChanged(nameof(QuarantinePagingStatus));
            ((RelayCommand)LoadMoreQuarantineCommand).NotifyCanExecuteChanged();
            ((RelayCommand)PurgeQuarantineCommand).NotifyCanExecuteChanged();
        }

        private void MigrateScanCountFromHistoryIfNeeded()
        {
            var prefs = _prefs.Current;
            if (prefs.TotalScansCount > 0) return;
            int n = _logger.GetHistory().Count;
            if (n <= 0) return;
            prefs.TotalScansCount = n;
            prefs.Save();
        }

        private void LoadHistory()
        {
            _ui.Invoke(() =>
            {
                History.Clear();
                foreach (var s in _logger.GetHistory())
                    History.Add(s);
            });
        }

        public void AppendLiveThreat(ThreatInfo threat)
        {
            if (string.IsNullOrWhiteSpace(threat.FilePath)) return;
            _ui.Invoke(() =>
            {
                if (Threats.Any(t => string.Equals(t.FilePath, threat.FilePath, StringComparison.OrdinalIgnoreCase)))
                    return;
                Threats.Add(threat);
                ThreatsFound = Threats.Count;
                OnPropertyChanged(nameof(SummaryDisplay));
            });
        }

        public void RemoveDetectedThreat(string? filePath)
        {
            if (string.IsNullOrWhiteSpace(filePath)) return;
            _ui.Invoke(() =>
            {
                var removed = Threats
                    .Where(t => string.Equals(t.FilePath, filePath, StringComparison.OrdinalIgnoreCase))
                    .ToList();
                if (removed.Count == 0)
                    return;
                foreach (var t in removed)
                    Threats.Remove(t);
                ThreatsFound = Threats.Count;
                OnPropertyChanged(nameof(SummaryDisplay));
            });
        }

        public void RefreshQuarantineList() => LoadQuarantine(reset: true);

        public void RefreshHistory()
        {
            LoadHistory();
            RefreshRecentTargets();
        }

        /// <summary>Recharge la liste des menaces depuis une session d'historique pour traitement dans Analyse.</summary>
        public void LoadThreatsFromHistorySession(ScanSession session)
        {
            if (session == null) return;
            _ui.Invoke(() =>
            {
                Threats.Clear();
                foreach (var t in session.Threats)
                    Threats.Add(t.Clone());
                ThreatsFound = Threats.Count;
                OnPropertyChanged(nameof(SummaryDisplay));
                StatusMessage = ThreatsFound > 0
                    ? LocalizationService.Format("Vm_HistReviewLoaded", session.StartedAt, ThreatsFound)
                    : LocalizationService.GetString("Scan_Ready");
            });
        }

        public void RefreshRecentTargets()
        {
            _ui.Invoke(() =>
            {
                RecentTargets.Clear();
                foreach (var t in _prefs.Current.RecentTargets)
                    RecentTargets.Add(t);
            });
        }
    }
}
