using optiSCAN.Localization;
using optiSCAN.Models;
using optiSCAN.Services;
using optiSCAN.Strings;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;

namespace optiSCAN.Views
{
    /// <summary>
    /// Vue historique — affiche les sessions de scan et de nettoyage passées,
    /// permet de traiter les menaces enregistrées et d'exporter les rapports.
    /// </summary>
    public partial class HistoryControl : System.Windows.Controls.UserControl
    {
        private readonly AntivirusActions _actions = ServiceContainer.Default.Actions;
        private readonly ScanLogManager _logger = ServiceContainer.Default.Logger;

        private List<ScanSession> _allScanSessions = new();
        private List<CleanSession> _allCleanSessions = new();
        private bool _filterUiReady;

        public HistoryControl()
        {
            InitializeComponent();
            InitFilterControls();
            if (txtScanDetail != null)
                txtScanDetail.Text = LocalizationService.GetString("Hist_DetailSelectScan");
            if (txtCleanDetail != null)
                txtCleanDetail.Text = LocalizationService.GetString("Hist_DetailSelectClean");
        }

        private void InitFilterControls()
        {
            if (_filterUiReady || cmbScanFilter == null) return;
            _filterUiReady = true;

            cmbScanFilter.Items.Clear();
            cmbScanFilter.Items.Add(new ComboBoxItem { Content = LocalizationService.GetString("Hist_FilterAll"), Tag = "all" });
            cmbScanFilter.Items.Add(new ComboBoxItem { Content = LocalizationService.GetString("Hist_FilterWithThreats"), Tag = "threats" });
            cmbScanFilter.Items.Add(new ComboBoxItem { Content = LocalizationService.GetString("Hist_FilterNoThreats"), Tag = "clean" });
            cmbScanFilter.SelectedIndex = 0;
        }

        /// <summary>Alimente le DataGrid avec les sessions de scan.</summary>
        public void UpdateScanHistory(IEnumerable<ScanSession> sessions)
        {
            Dispatcher.InvokeAsync(() =>
            {
                _allScanSessions = sessions.ToList();
                ApplyScanFilters();
            });
        }

        /// <summary>Alimente le DataGrid avec les sessions de nettoyage.</summary>
        public void UpdateCleanHistory(IEnumerable<CleanSession> sessions)
        {
            Dispatcher.InvokeAsync(() =>
            {
                _allCleanSessions = sessions.ToList();
                ApplyCleanFilters();
            });
        }

        private void ScanFilter_Changed(object sender, RoutedEventArgs e) => ApplyScanFilters();

        private void CleanFilter_Changed(object sender, RoutedEventArgs e) => ApplyCleanFilters();

        private void ApplyScanFilters()
        {
            if (dgScanHistory == null) return;

            IEnumerable<ScanSession> query = _allScanSessions;

            var filterTag = (cmbScanFilter?.SelectedItem as ComboBoxItem)?.Tag as string ?? "all";
            query = filterTag switch
            {
                "threats" => query.Where(s => s.ThreatsFound > 0),
                "clean" => query.Where(s => s.ThreatsFound == 0),
                _ => query
            };

            var search = txtScanSearch?.Text?.Trim();
            if (!string.IsNullOrEmpty(search))
            {
                query = query.Where(s =>
                    (s.TargetPath?.Contains(search, StringComparison.OrdinalIgnoreCase) ?? false)
                    || (s.TypeDisplay?.Contains(search, StringComparison.OrdinalIgnoreCase) ?? false));
            }

            var list = query.OrderByDescending(s => s.StartedAt).ToList();
            dgScanHistory.ItemsSource = list;
            dgScanHistory.SelectedIndex = list.Count > 0 ? 0 : -1;
            if (emptyScanState != null)
                emptyScanState.Visibility = list.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            UpdateScanDetail();
        }

        private void ApplyCleanFilters()
        {
            if (dgCleanHistory == null) return;

            IEnumerable<CleanSession> query = _allCleanSessions;
            var search = txtCleanSearch?.Text?.Trim();
            if (!string.IsNullOrEmpty(search))
            {
                query = query.Where(s =>
                    s.TargetsSummary?.Contains(search, StringComparison.OrdinalIgnoreCase) == true);
            }

            var list = query.OrderByDescending(s => s.StartedAt).ToList();
            dgCleanHistory.ItemsSource = list;
            dgCleanHistory.SelectedIndex = list.Count > 0 ? 0 : -1;
            if (emptyCleanState != null)
                emptyCleanState.Visibility = list.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            UpdateCleanDetail();
        }

        private void DgScanHistory_SelectionChanged(object sender, SelectionChangedEventArgs e) =>
            UpdateScanDetail();

        private void DgCleanHistory_SelectionChanged(object sender, SelectionChangedEventArgs e) =>
            UpdateCleanDetail();

        private void UpdateScanDetail()
        {
            if (txtScanDetail == null) return;

            if (dgScanHistory?.SelectedItem is not ScanSession session)
            {
                txtScanDetail.Text = LocalizationService.GetString("Hist_DetailSelectScan");
                BindThreatsPanel(null);
                return;
            }

            txtScanDetail.Text = ScanLogManager.FormatScanDetail(session);
            BindThreatsPanel(session);
        }

        private void BindThreatsPanel(ScanSession? session)
        {
            var hasStoredThreats = session?.Threats.Count > 0;
            var legacyOnly = session != null && session.ThreatsFound > 0 && session.Threats.Count == 0;

            if (dgHistoryThreats != null)
            {
                dgHistoryThreats.ItemsSource = hasStoredThreats ? session!.Threats : null;
                dgHistoryThreats.Visibility = hasStoredThreats ? Visibility.Visible : Visibility.Collapsed;
            }

            if (txtHistThreatsLegacy != null)
                txtHistThreatsLegacy.Visibility = legacyOnly ? Visibility.Visible : Visibility.Collapsed;

            var canTreat = hasStoredThreats;
            if (btnTreatInAntivirus != null)
                btnTreatInAntivirus.IsEnabled = canTreat;
            if (btnHistQuarantineAll != null)
                btnHistQuarantineAll.IsEnabled = canTreat;
        }

        private ScanSession? SelectedScanSession =>
            dgScanHistory?.SelectedItem as ScanSession;

        private static ThreatInfo? ThreatFromSender(object sender) =>
            sender is System.Windows.Controls.Button { Tag: ThreatInfo threat } ? threat : null;

        private void BtnTreatInAntivirus_Click(object sender, RoutedEventArgs e)
        {
            if (SelectedScanSession is not { Threats.Count: > 0 } session)
                return;
            ServiceContainer.Default.RequestReviewHistorySession(session);
        }

        private void BtnHistQuarantineAll_Click(object sender, RoutedEventArgs e)
        {
            if (SelectedScanSession is not ScanSession session || session.Threats.Count == 0)
                return;

            if (System.Windows.MessageBox.Show(
                    OptiscanStrings.Confirmations.QuarantineAll(session.Threats.Count),
                    OptiscanStrings.Confirmations.Title,
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Question) != MessageBoxResult.Yes)
                return;

            foreach (var threat in session.Threats.ToList())
            {
                var result = _actions.QuarantineThreat(threat.Clone());
                if (result.Success)
                    _logger.TryRemoveThreatFromSession(session.SessionId, threat.FilePath);
            }

            session.ThreatsFound = session.Threats.Count;
            BindThreatsPanel(session);
            UpdateScanDetail();
            ApplyScanFilters();
            ServiceContainer.Default.RequestScanHistoryViewsRefresh();
        }

        private void BtnHistQuarantine_Click(object sender, RoutedEventArgs e)
        {
            var threat = ThreatFromSender(sender);
            if (threat == null) return;

            var result = _actions.QuarantineThreat(threat.Clone());
            if (result.Success)
                OnHistoryThreatHandled(threat.FilePath);
        }

        private void BtnHistIgnore_Click(object sender, RoutedEventArgs e)
        {
            var threat = ThreatFromSender(sender);
            if (threat == null) return;

            var result = _actions.IgnoreThreat(threat.FilePath);
            if (result.Success)
                OnHistoryThreatHandled(threat.FilePath);
        }

        private void BtnHistDelete_Click(object sender, RoutedEventArgs e)
        {
            var threat = ThreatFromSender(sender);
            if (threat == null) return;

            if (System.Windows.MessageBox.Show(
                    LocalizationService.GetString("Av_ConfirmDeleteFile"),
                    OptiscanStrings.Confirmations.Title,
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Warning) != MessageBoxResult.Yes)
                return;

            var result = _actions.DeleteThreatFile(threat.FilePath);
            if (result.Success)
                OnHistoryThreatHandled(threat.FilePath);
        }

        private void OnHistoryThreatHandled(string filePath)
        {
            if (SelectedScanSession is not ScanSession session || string.IsNullOrWhiteSpace(filePath))
                return;

            _logger.TryRemoveThreatFromSession(session.SessionId, filePath);
            session.ThreatsFound = session.Threats.Count;
            BindThreatsPanel(session);
            UpdateScanDetail();
            ApplyScanFilters();
            ServiceContainer.Default.RequestScanHistoryViewsRefresh();
        }

        private void UpdateCleanDetail()
        {
            if (txtCleanDetail == null) return;
            if (dgCleanHistory?.SelectedItem is not CleanSession session)
            {
                txtCleanDetail.Text = LocalizationService.GetString("Hist_DetailSelectClean");
                return;
            }

            if (!string.IsNullOrWhiteSpace(session.OperationLog))
            {
                txtCleanDetail.Text = session.OperationLog;
                return;
            }

            txtCleanDetail.Text = LocalizationService.Format(
                "Hist_DetailCleanSummary",
                session.TargetsSummary,
                session.BytesDisplay,
                session.DurationDisplay);
        }

        private void BtnOpenAntivirus_Click(object sender, RoutedEventArgs e)
        {
            Services.ServiceContainer.Default.Navigation?.NavigateTo(OptiscanStrings.PanelIds.Antivirus);
        }

        private void BtnExportHtml_Click(object sender, RoutedEventArgs e) =>
            Services.ServiceContainer.Default.RequestExportScanHistoryHtml();

        private void BtnExportSelectedPdf_Click(object sender, RoutedEventArgs e)
        {
            if (dgScanHistory?.SelectedItem is ScanSession session)
                Services.ServiceContainer.Default.RequestExportScanSessionPdf(session);
            else
                System.Windows.MessageBox.Show(
                    LocalizationService.GetString("Hist_ExportPdfSelect"),
                    LocalizationService.GetString("Hist_Title"),
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
        }
    }
}
