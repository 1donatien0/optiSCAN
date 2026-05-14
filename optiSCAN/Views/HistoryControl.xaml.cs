using optiSCAN.Models;
using System.Windows;

namespace optiSCAN.Views
{
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
            });
        }

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
            Services.ServiceContainer.Default.Navigation?.NavigateTo("Antivirus");
        }

        private void BtnExportHtml_Click(object sender, RoutedEventArgs e) =>
            Services.ServiceContainer.Default.RequestExportScanHistoryHtml();

        private void BtnExportPdf_Click(object sender, RoutedEventArgs e) =>
            Services.ServiceContainer.Default.RequestExportLastScanPdf();
    }
}
