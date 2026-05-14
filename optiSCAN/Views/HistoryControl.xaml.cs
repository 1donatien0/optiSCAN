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
                {
                    dgScanHistory.ItemsSource = sessions;

                    // D�bogage : affiche les propri�t�s disponibles
                    if (sessions != null && sessions.Any())
                    {
                        var first = sessions.First();
                        var properties = first.GetType().GetProperties();
                        var propNames = string.Join(", ", properties.Select(p => p.Name));
                        System.Diagnostics.Debug.WriteLine($"Propri�t�s disponibles: {propNames}");
                    }
                }
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