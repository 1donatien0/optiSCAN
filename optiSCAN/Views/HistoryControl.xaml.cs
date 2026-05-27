using optiSCAN.Localization;
using optiSCAN.Models;
using optiSCAN.Strings;
using System.Windows;

namespace optiSCAN.Views
{
    /// <summary>
    /// Vue historique — affiche les sessions de scan et de nettoyage passées,
    /// et permet d'exporter les rapports en HTML ou PDF.
    /// </summary>
    public partial class HistoryControl : System.Windows.Controls.UserControl
    {
        public HistoryControl()
        {
            InitializeComponent();
        }

        /// <summary>Alimente le DataGrid avec les sessions de scan.</summary>
        public void UpdateScanHistory(IEnumerable<ScanSession> sessions)
        {
            Dispatcher.InvokeAsync(() =>
            {
                if (dgScanHistory != null)
                    dgScanHistory.ItemsSource = sessions;
                RefreshScanJournal();
            });
        }

        private void RefreshScanJournal()
        {
            if (txtScanJournal == null) return;
            var lines = Services.ServiceContainer.Default.Logger.ReadLastLogLines(80);
            txtScanJournal.Text = lines.Length == 0
                ? "Aucune entrée dans le journal des analyses."
                : string.Join(Environment.NewLine, lines);
        }

        /// <summary>Alimente le DataGrid avec les sessions de nettoyage.</summary>
        public void UpdateCleanHistory(IEnumerable<CleanSession> sessions)
        {
            Dispatcher.InvokeAsync(() =>
            {
                if (dgCleanHistory != null)
                    dgCleanHistory.ItemsSource = sessions;
            });
        }

        private void BtnOpenAntivirus_Click(object sender, RoutedEventArgs e)
        {
            // Navigation via le container (INavigationService), sans référencer MainWindow.
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
