using optiSCAN.Strings;
using System.Windows.Threading;

namespace optiSCAN.Services
{
    /// <summary>
    /// Coordonne les rafraîchissements de données déclenchés à chaque changement de vue.
    /// Extrait de MainWindow pour améliorer la testabilité et réduire la taille de la fenêtre principale.
    ///
    /// Pattern : <see cref="INavigationService.Navigated"/> → dispatch sur le Dispatcher WPF →
    /// appel des actions de rafraîchissement correspondantes.
    /// </summary>
    public sealed class NavigationRefreshCoordinator
    {
        private readonly INavigationService _navigation;
        private readonly Dispatcher _dispatcher;

        // Actions de rafraîchissement injectées par MainWindow.
        // Chaque action correspond à un bloc de données à recharger.
        private readonly Action _refreshHistory;
        private readonly Action _refreshAntivirusStatus;
        private readonly Action _refreshSignatures;
        private readonly Action _refreshAntivirusData;

        /// <summary>
        /// Initialise le coordinateur et s'abonne à l'événement <see cref="INavigationService.Navigated"/>.
        /// </summary>
        /// <param name="navigation">Service de navigation à observer.</param>
        /// <param name="dispatcher">Dispatcher WPF pour repasser sur le thread UI.</param>
        /// <param name="refreshHistory">Recharge l'historique des scans.</param>
        /// <param name="refreshAntivirusStatus">Recharge le statut ClamAV / YARA sidebar.</param>
        /// <param name="refreshSignatures">Recharge les versions de signatures (avec cache TTL).</param>
        /// <param name="refreshAntivirusData">Recharge l'ensemble des données Antivirus.</param>
        public NavigationRefreshCoordinator(
            INavigationService navigation,
            Dispatcher dispatcher,
            Action refreshHistory,
            Action refreshAntivirusStatus,
            Action refreshSignatures,
            Action refreshAntivirusData)
        {
            _navigation            = navigation;
            _dispatcher            = dispatcher;
            _refreshHistory        = refreshHistory;
            _refreshAntivirusStatus = refreshAntivirusStatus;
            _refreshSignatures     = refreshSignatures;
            _refreshAntivirusData  = refreshAntivirusData;

            _navigation.Navigated += OnNavigated;
        }

        /// <summary>Désinscrit le coordinateur du service de navigation.</summary>
        public void Detach() => _navigation.Navigated -= OnNavigated;

        private void OnNavigated(object? sender, string panelName)
        {
            _dispatcher.BeginInvoke(() => ApplyRefreshes(panelName), DispatcherPriority.Background);
        }

        /// <summary>Exposé aux tests unitaires (sans passer par le Dispatcher).</summary>
        internal void ApplyRefreshesForPanel(string panelName) => ApplyRefreshes(panelName);

        private void ApplyRefreshes(string panelName)
        {
            switch (panelName)
            {
                case OptiscanStrings.PanelIds.Overview:
                    _refreshHistory();
                    _refreshAntivirusStatus();
                    _refreshSignatures();
                    break;

                case OptiscanStrings.PanelIds.Antivirus:
                    _refreshAntivirusData();
                    break;

                case OptiscanStrings.PanelIds.History:
                    _refreshHistory();
                    break;
                // Clean et Options : aucun rafraîchissement nécessaire à la navigation.
            }
        }
    }
}
