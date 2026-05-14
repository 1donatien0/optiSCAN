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

        private void BtnOpenAntivirus_Click(object sender, RoutedEventArgs e)
        {
            // Audit A2 : navigation via le service exposé par le container,
            // plus de cast vers MainWindow. Cette vue compile et fonctionne
            // indépendamment du host (testable, design-time).
            Services.ServiceContainer.Default.Navigation?.NavigateTo("Antivirus");
        }
    }
}
