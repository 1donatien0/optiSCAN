using optiSCAN.Localization;
using optiSCAN.Platform;
using optiSCAN.Services;
using System.Windows.Input;
using WpfApp = System.Windows.Application;

namespace optiSCAN.ViewModels
{
    /// <summary>
    /// Quarantaine du service SYSTEM : l'onglet Quarantaine en affiche le résumé (nombre, taille),
    /// ouvert à tout compte. Consulter, restaurer ou supprimer passe par une fenêtre
    /// d'administration élevée (<see cref="Views.ServiceQuarantineWindow"/>).
    /// </summary>
    public partial class ScanViewModel
    {
        private int _serviceQuarantineCount;
        private string _serviceQuarantineSummary = string.Empty;
        private ICommand? _manageServiceQuarantineCommand;
        private int _serviceQuarantineRefreshing;

        public int ServiceQuarantineCount
        {
            get => _serviceQuarantineCount;
            private set
            {
                _serviceQuarantineCount = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(HasServiceQuarantine));
            }
        }

        public bool HasServiceQuarantine => ServiceQuarantineCount > 0;

        public string ServiceQuarantineSummary
        {
            get => _serviceQuarantineSummary;
            private set { _serviceQuarantineSummary = value; OnPropertyChanged(); }
        }

        public ICommand ManageServiceQuarantineCommand =>
            _manageServiceQuarantineCommand ??= new RelayCommand(_ => ManageServiceQuarantine());

        /// <summary>Interroge le service (résumé seulement) sans bloquer l'interface.</summary>
        public void RefreshServiceQuarantineSummary()
        {
            if (Interlocked.Exchange(ref _serviceQuarantineRefreshing, 1) == 1)
                return;
            _ = Task.Run(async () =>
            {
                try
                {
                    using var client = new ProtectionPipeClient(timeout: TimeSpan.FromSeconds(3));
                    var response = await client.GetServiceQuarantineSummaryAsync().ConfigureAwait(false);
                    var count = response.Ok ? response.Count ?? 0 : 0;
                    var text = count > 0
                        ? LocalizationService.Format(
                            "SvcQ_Banner",
                            count,
                            ServiceQuarantineFormatting.FormatBytes(response.TotalBytes ?? 0),
                            response.RetentionDays ?? ServiceQuarantineStore.RetentionDays)
                        : string.Empty;
                    WpfApp.Current?.Dispatcher.BeginInvoke(() =>
                    {
                        ServiceQuarantineSummary = text;
                        ServiceQuarantineCount = count;
                    });
                }
                catch (Exception ex)
                {
                    // Service absent (installation sans service) ou ancien service : rien à afficher.
                    AppLogger.Debug("ScanViewModel", "Résumé quarantaine du service : " + ex.Message);
                }
                finally
                {
                    Volatile.Write(ref _serviceQuarantineRefreshing, 0);
                }
            });
        }

        private void ManageServiceQuarantine()
        {
            if (ElevationHelper.IsRunningElevated())
            {
                var window = new Views.ServiceQuarantineWindow { Owner = WpfApp.Current?.MainWindow };
                window.ShowDialog();
                RefreshServiceQuarantineSummary();
                return;
            }

            // Une invite UAC ; l'instance élevée n'ouvre que cette fenêtre.
            if (!ElevationHelper.RelaunchElevated(HeadlessScanArguments.ServiceQuarantine))
                StatusMessage = LocalizationService.GetString("SvcQ_ElevationRefused");
        }
    }
}
