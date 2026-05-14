using System.Runtime.Versioning;

namespace optiSCAN.Services
{
    /// <summary>
    /// Container DI minimaliste — singleton statique pour éviter d'ajouter
    /// une dépendance Microsoft.Extensions.DependencyInjection sur ce projet.
    ///
    /// Problème résolu (audit A1) : MainWindow et ScanViewModel construisaient
    /// CHACUN leurs propres instances de ClamAvEngine, YaraEngine, etc. via
    /// `new`. Conséquences :
    ///   - Double consommation mémoire
    ///   - Vérifications dupliquées (version ClamAV lue 2×)
    ///   - Caches divergents (RulesCount calculé deux fois)
    ///   - Logs en double dans freshclam, abonnements aux events doublés
    ///
    /// Solution : tous les services lifetime-long passent par <see cref="Default"/>.
    /// Les VM et la fenêtre principale obtiennent leurs dépendances via les
    /// propriétés exposées ici.
    ///
    /// Resté volontairement simple : pas de scopes, pas de lazy resolution
    /// par type, pas de constructor injection automatique. Suffisant pour
    /// la dizaine de services à durée de vie applicative qu'optiSCAN gère.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public sealed class ServiceContainer
    {
        private static readonly Lazy<ServiceContainer> _default =
            new(() => new ServiceContainer(), LazyThreadSafetyMode.ExecutionAndPublication);

        public static ServiceContainer Default => _default.Value;

        // ── Services singleton ───────────────────────────────────────────────────
        public ClamAvEngine ClamAv { get; }
        public YaraEngine Yara { get; }
        public ScanOrchestrator Orchestrator { get; }
        public FreshclamUpdater FreshclamUpdater { get; }
        public YaraForgeUpdater RulesUpdater { get; }
        public QuarantineManager Quarantine { get; }
        public ScanLogManager Logger { get; }
        public NotificationService Notifications { get; }

        // Adapters interfaces — à utiliser pour les futurs tests ou substitutions
        public IScanEngine ScanEngine { get; }

        /// <summary>Actions UI antivirus (quarantaine, suppression, stop updates).</summary>
        public AntivirusActions Actions { get; }

        // Navigation entre panneaux. Initialisé par MainWindow.OnLoaded une fois
        // que tous les UserControls sont créés (RegisterPanel a besoin de leur
        // référence). Les vues peuvent alors appeler Navigation.NavigateTo("...")
        // sans connaître MainWindow.
        public INavigationService? Navigation { get; set; }

        /// <summary>
        /// Émis par une vue qui veut déclencher une mise à jour manuelle des
        /// signatures (ex. OverviewControl, carte "Update"). Écouté par MainWindow.
        /// Évite que les vues appellent directement BtnManualUpdateSignatures_Click.
        /// </summary>
        public event EventHandler? RequestSignatureUpdate;

        public void TriggerSignatureUpdate() =>
            RequestSignatureUpdate?.Invoke(this, EventArgs.Empty);

        // Audit A3 : événements + méthodes Request* (plus de Action? mutables
        // assignées après coup — pas de NRE silencieuse si un service appelait
        // avant l’init UI ; les handlers sont simplement absents).

        private EventHandler? _focusAntivirusSignaturesHandlers;
        /// <summary>Demande d’afficher l’onglet Signatures (écouteur : <see cref="optiSCAN.MainWindow"/>).</summary>
        public event EventHandler? FocusAntivirusSignaturesRequested
        {
            add => _focusAntivirusSignaturesHandlers += value;
            remove => _focusAntivirusSignaturesHandlers -= value;
        }

        /// <summary>Demande d’afficher l’onglet Signatures dans Analyser (panneau Antivirus).</summary>
        public void RequestFocusAntivirusSignaturesTab() =>
            _focusAntivirusSignaturesHandlers?.Invoke(this, EventArgs.Empty);

        private EventHandler? _scanHistoryViewsRefreshHandlers;
        /// <summary>Synchronise grilles d’historique et libellé « dernière analyse » (vues multiples).</summary>
        public event EventHandler? ScanHistoryViewsRefreshRequested
        {
            add => _scanHistoryViewsRefreshHandlers += value;
            remove => _scanHistoryViewsRefreshHandlers -= value;
        }

        /// <summary>Demande un rafraîchissement des vues d’historique (thread UI : écouteur).</summary>
        public void RequestScanHistoryViewsRefresh() =>
            _scanHistoryViewsRefreshHandlers?.Invoke(this, EventArgs.Empty);

        private ServiceContainer()
        {
            // Ordre de construction : du plus indépendant au plus dépendant.
            ClamAv = new ClamAvEngine();
            Yara = new YaraEngine();
            FreshclamUpdater = new FreshclamUpdater();
            RulesUpdater = new YaraForgeUpdater();
            Quarantine = new QuarantineManager();
            Logger = new ScanLogManager();
            Notifications = new NotificationService();

            Orchestrator = new ScanOrchestrator(ClamAv, Yara);
            ScanEngine = new ClamAvScanEngineAdapter(ClamAv);
            Actions = new AntivirusActions(this);

            // MAJ silencieuses alignées sur le guide produit (Options peut les couper).
            FreshclamUpdater.EnableAutoUpdate(TimeSpan.FromHours(4));
            RulesUpdater.EnableAutoUpdate(TimeSpan.FromHours(24));

            AppLogger.Info("ServiceContainer", "Services initialisés");

            var yara = Yara;
            _ = Task.Run(async () =>
            {
                try
                {
                    if (!await yara.CompileRulesAsync().ConfigureAwait(false) && yara.IsAvailable)
                    {
                        AppLogger.Warn("ServiceContainer",
                            "Précompilation YARA (.yarc) absente ou échouée au démarrage — sera retentée au premier scan.");
                    }
                }
                catch (Exception ex)
                {
                    AppLogger.Warn("ServiceContainer", "Précompilation YARA au démarrage", ex);
                }
            });
        }

        /// <summary>
        /// Libère proprement tous les services disposables.
        /// Appelé depuis App.OnExit.
        /// </summary>
        public void Shutdown()
        {
            _focusAntivirusSignaturesHandlers = null;
            _scanHistoryViewsRefreshHandlers = null;
            try { FreshclamUpdater.DisableAutoUpdate(); }
            catch (Exception ex) { AppLogger.Warn("ServiceContainer", "FreshclamUpdater.DisableAutoUpdate", ex); }
            try { RulesUpdater.DisableAutoUpdate(); }
            catch (Exception ex) { AppLogger.Warn("ServiceContainer", "RulesUpdater.DisableAutoUpdate", ex); }
            (ClamAv as IDisposable)?.Dispose();
            (Yara as IDisposable)?.Dispose();
            AppLogger.Info("ServiceContainer", "Services fermés");
        }
    }
}
