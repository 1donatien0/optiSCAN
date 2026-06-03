using optiSCAN.Localization;
using optiSCAN.Models;
using optiSCAN.Services;
using optiSCAN.Strings;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Brush = System.Windows.Media.Brush;
using Button = System.Windows.Controls.Button;

namespace optiSCAN.Views
{
    /// <summary>
    /// Historique unifié (scans + nettoyages) avec filtres chips et traitement des menaces.
    /// </summary>
    public partial class HistoryControl : System.Windows.Controls.UserControl
    {
        private readonly AntivirusActions _actions = ServiceContainer.Default.Actions;
        private readonly ScanLogManager _logger = ServiceContainer.Default.Logger;

        private List<ActivityEntry> _allFeed = new();
        private object? _selectionKey;

        public HistoryControl()
        {
            InitializeComponent();
            ShowNoSelectionHint();
        }

        /// <summary>Alimente la timeline depuis <see cref="ScanLogManager.GetActivityFeed"/>.</summary>
        public void UpdateActivityHistory(IEnumerable<ActivityEntry> feed)
        {
            Dispatcher.InvokeAsync(() =>
            {
                _allFeed = feed.ToList();
                ApplyFilters();
            });
        }

        private void Chip_Checked(object sender, RoutedEventArgs e) => ApplyFilters();
        private void Search_Changed(object sender, TextChangedEventArgs e) => ApplyFilters();

        private void ApplyFilters()
        {
            if (dgTimeline == null) return;

            IEnumerable<ActivityEntry> query = _allFeed;

            if (chipThreats?.IsChecked == true)
                query = query.Where(e => e.Kind == ActivityKind.Scan && e.HasThreats);
            else if (chipClean?.IsChecked == true)
                query = query.Where(e => e.Kind == ActivityKind.Scan && !e.HasThreats);
            else if (chipSweep?.IsChecked == true)
                query = query.Where(e => e.Kind == ActivityKind.Clean);

            var search = txtSearch?.Text?.Trim();
            if (!string.IsNullOrEmpty(search))
            {
                query = query.Where(e =>
                    (e.TypeDisplay?.Contains(search, StringComparison.OrdinalIgnoreCase) ?? false)
                    || (e.ResultSummary?.Contains(search, StringComparison.OrdinalIgnoreCase) ?? false)
                    || (e.ScanSession?.TargetPath?.Contains(search, StringComparison.OrdinalIgnoreCase) ?? false)
                    || (e.CleanSession?.TargetsSummary?.Contains(search, StringComparison.OrdinalIgnoreCase) ?? false));
            }

            var list = query.ToList();
            dgTimeline.ItemsSource = list;

            if (list.Count == 0)
            {
                dgTimeline.SelectedIndex = -1;
                if (emptyState != null)
                    emptyState.Visibility = Visibility.Visible;
                UpdateDetail();
                return;
            }

            if (emptyState != null)
                emptyState.Visibility = Visibility.Collapsed;

            var idx = FindSelectionIndex(list);
            dgTimeline.SelectedIndex = idx >= 0 ? idx : 0;
            UpdateDetail();
        }

        private int FindSelectionIndex(IReadOnlyList<ActivityEntry> list)
        {
            if (_selectionKey == null) return -1;
            for (int i = 0; i < list.Count; i++)
            {
                if (Equals(SelectionKey(list[i]), _selectionKey))
                    return i;
            }
            return -1;
        }

        private static object SelectionKey(ActivityEntry entry) =>
            entry.Kind == ActivityKind.Scan
                ? (object)(entry.ScanSession?.SessionId ?? Guid.Empty)
                : entry.StartedAt;

        private void DgTimeline_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            _selectionKey = SelectedEntry != null ? SelectionKey(SelectedEntry) : null;
            UpdateDetail();
        }

        private ActivityEntry? SelectedEntry =>
            dgTimeline?.SelectedItem as ActivityEntry;

        private ScanSession? SelectedScanSession =>
            SelectedEntry?.ScanSession;

        private void UpdateDetail()
        {
            var entry = SelectedEntry;
            if (entry == null)
            {
                ShowNoSelectionHint();
                HideDetailPanels();
                return;
            }

            if (txtNoSelHint != null)
                txtNoSelHint.Visibility = Visibility.Collapsed;
            if (sessionInfoBar != null)
                sessionInfoBar.Visibility = Visibility.Visible;

            ShowEntryInfo(entry);

            if (entry.Kind == ActivityKind.Clean)
                ShowCleanDetail(entry.CleanSession);
            else
                ShowScanDetail(entry.ScanSession);
        }

        private void ShowNoSelectionHint()
        {
            if (sessionInfoBar != null)
                sessionInfoBar.Visibility = Visibility.Collapsed;
            if (txtNoSelHint != null)
                txtNoSelHint.Visibility = Visibility.Visible;
            if (scanActionBar != null)
                scanActionBar.Visibility = Visibility.Collapsed;
            HideDetailPanels();
        }

        private void HideDetailPanels()
        {
            if (dgHistoryThreats != null)
            {
                dgHistoryThreats.ItemsSource = null;
                dgHistoryThreats.Visibility = Visibility.Collapsed;
            }
            if (cleanLogPanel != null)
                cleanLogPanel.Visibility = Visibility.Collapsed;
            if (noThreatsState != null)
                noThreatsState.Visibility = Visibility.Collapsed;
            if (txtHistThreatsLegacy != null)
                txtHistThreatsLegacy.Visibility = Visibility.Collapsed;
        }

        private void ShowEntryInfo(ActivityEntry entry)
        {
            var cult = CultureInfo.CurrentCulture;

            if (txtSessionDate != null)
                txtSessionDate.Text = entry.StartedAt.ToString("dd/MM/yyyy HH:mm", cult);

            if (txtSessionMeta != null)
            {
                txtSessionMeta.Text = entry.Kind == ActivityKind.Clean
                    ? (entry.CleanSession?.TargetsSummary ?? string.Empty)
                    : entry.ScanSession != null
                        ? LocalizationService.Format("Hist_InfoFiles", entry.ScanSession.FilesScanned.ToString("N0", cult))
                        : string.Empty;
            }

            if (txtSessionResult != null)
            {
                txtSessionResult.Text = entry.ResultSummary;
                if (entry.HasThreats)
                {
                    txtSessionResult.Foreground = TryFindBrush("DangerRed") ?? txtSessionResult.Foreground;
                    if (resultChip != null)
                        resultChip.Background = TryFindBrush("RiskMinor") ?? resultChip.Background;
                }
                else if (entry.Kind == ActivityKind.Clean)
                {
                    txtSessionResult.Foreground = TryFindBrush("TextAccent") ?? txtSessionResult.Foreground;
                    if (resultChip != null)
                        resultChip.Background = TryFindBrush("InfoBg") ?? resultChip.Background;
                }
                else
                {
                    txtSessionResult.Foreground = TryFindBrush("SuccessGreen") ?? txtSessionResult.Foreground;
                    if (resultChip != null)
                        resultChip.Background = TryFindBrush("SuccessBg") ?? resultChip.Background;
                }
            }
        }

        private void ShowScanDetail(ScanSession? session)
        {
            if (cleanLogPanel != null)
                cleanLogPanel.Visibility = Visibility.Collapsed;
            if (scanActionBar != null)
                scanActionBar.Visibility = Visibility.Visible;

            var hasStoredThreats = session?.Threats.Count > 0;
            var sessionSelected = session != null;
            var legacyOnly = sessionSelected && session!.ThreatsFound > 0 && session.Threats.Count == 0;

            if (dgHistoryThreats != null)
            {
                dgHistoryThreats.ItemsSource = hasStoredThreats ? session!.Threats : null;
                dgHistoryThreats.Visibility = hasStoredThreats ? Visibility.Visible : Visibility.Collapsed;
            }

            if (noThreatsState != null)
                noThreatsState.Visibility = (sessionSelected && !hasStoredThreats && !legacyOnly)
                    ? Visibility.Visible : Visibility.Collapsed;

            if (txtHistThreatsLegacy != null)
                txtHistThreatsLegacy.Visibility = legacyOnly ? Visibility.Visible : Visibility.Collapsed;

            var canTreat = hasStoredThreats;
            if (btnTreatInAntivirus != null)
                btnTreatInAntivirus.IsEnabled = canTreat;
            if (btnHistQuarantineAll != null)
                btnHistQuarantineAll.IsEnabled = canTreat;
        }

        private void ShowCleanDetail(CleanSession? session)
        {
            if (scanActionBar != null)
                scanActionBar.Visibility = Visibility.Collapsed;
            if (dgHistoryThreats != null)
                dgHistoryThreats.Visibility = Visibility.Collapsed;
            if (noThreatsState != null)
                noThreatsState.Visibility = Visibility.Collapsed;
            if (txtHistThreatsLegacy != null)
                txtHistThreatsLegacy.Visibility = Visibility.Collapsed;

            if (cleanLogPanel == null || txtCleanLog == null)
                return;

            cleanLogPanel.Visibility = Visibility.Visible;
            if (session == null)
            {
                txtCleanLog.Text = LocalizationService.GetString("Hist_DetailSelectClean");
                return;
            }

            txtCleanLog.Text = !string.IsNullOrWhiteSpace(session.OperationLog)
                ? session.OperationLog
                : LocalizationService.Format(
                    "Hist_DetailCleanSummary",
                    session.TargetsSummary ?? string.Empty,
                    session.BytesDisplay ?? string.Empty,
                    session.DurationDisplay ?? string.Empty);
        }

        private static string? FilePathFromSender(object sender) =>
            sender is Button { Tag: string path } && !string.IsNullOrEmpty(path) ? path : null;

        private Brush? TryFindBrush(string key)
        {
            try { return TryFindResource(key) as Brush; }
            catch { return null; }
        }

        private void BtnTreatInAntivirus_Click(object sender, RoutedEventArgs e)
        {
            if (SelectedScanSession is not { Threats.Count: > 0 } session) return;
            ServiceContainer.Default.RequestReviewHistorySession(session);
        }

        private void BtnHistQuarantineAll_Click(object sender, RoutedEventArgs e)
        {
            if (SelectedScanSession is not ScanSession session || session.Threats.Count == 0) return;
            int count = ServiceContainer.Default.Quarantine.QuarantineAll(session.Threats);
            if (count > 0)
            {
                foreach (var t in session.Threats.ToList())
                    _logger.TryRemoveThreatFromSession(session.SessionId, t.FilePath);
                ApplyFilters();
            }
        }

        private void BtnHistQuarantine_Click(object sender, RoutedEventArgs e)
        {
            if (FilePathFromSender(sender) is not string filePath ||
                SelectedScanSession is not ScanSession session) return;
            if (_actions.QuarantineThreat(filePath).Success)
            {
                _logger.TryRemoveThreatFromSession(session.SessionId, filePath);
                ApplyFilters();
            }
        }

        private void BtnHistIgnore_Click(object sender, RoutedEventArgs e)
        {
            if (FilePathFromSender(sender) is not string filePath ||
                SelectedScanSession is not ScanSession session) return;
            _actions.IgnoreThreat(filePath);
            _logger.TryRemoveThreatFromSession(session.SessionId, filePath);
            ApplyFilters();
        }

        private void BtnHistDelete_Click(object sender, RoutedEventArgs e)
        {
            if (FilePathFromSender(sender) is not string filePath ||
                SelectedScanSession is not ScanSession session) return;
            if (_actions.DeleteThreatFile(filePath).Success)
            {
                _logger.TryRemoveThreatFromSession(session.SessionId, filePath);
                ApplyFilters();
            }
        }

        private void BtnOpenAntivirus_Click(object sender, RoutedEventArgs e) =>
            ServiceContainer.Default.Navigation?.NavigateTo(OptiscanStrings.PanelIds.Antivirus);

        private void BtnExportHtml_Click(object sender, RoutedEventArgs e) =>
            ServiceContainer.Default.RequestExportScanHistoryHtml();

        private void BtnExportSelectedPdf_Click(object sender, RoutedEventArgs e)
        {
            if (SelectedScanSession is ScanSession session)
                ServiceContainer.Default.RequestExportScanSessionPdf(session);
        }
    }
}
