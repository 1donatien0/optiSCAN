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
    /// et permet d'exporter les rapports en HTML ou PDF.
    /// </summary>
    public partial class HistoryControl : System.Windows.Controls.UserControl
    {
        private List<ScanSession> _allScanSessions = new();
        private List<CleanSession> _allCleanSessions = new();
        private bool _filterUiReady;

        public HistoryControl()
        {
            InitializeComponent();
            if (txtScanDetail != null)
                txtScanDetail.Text = LocalizationService.GetString("Hist_DetailSelectScan");
            if (txtCleanDetail != null)
                txtCleanDetail.Text = LocalizationService.GetString("Hist_DetailSelectClean");
            Loaded += (_, _) => InitFilterControls();
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
                return;
            }

            var text = ScanLogManager.FormatScanDetail(session);
            if (session.ThreatsFound > 0 && session.Threats.Count == 0)
                text += Environment.NewLine + Environment.NewLine
                    + LocalizationService.GetString("Hist_DetailThreatsLegacy");
            txtScanDetail.Text = text;
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

        private void BtnExportPdf_Click(object sender, RoutedEventArgs e) =>
            Services.ServiceContainer.Default.RequestExportLastScanPdf();

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
