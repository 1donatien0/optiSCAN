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

        /// <summary>
        /// Sélectionne l'onglet « Signatures » dans Analyser (panneau Antivirus).
        /// Renseigné par <see cref="MainWindow"/> après <c>RegisterPanels</c>.
        /// </summary>
        public Action? FocusAntivirusSignaturesTab { get; set; }

        /// <summary>
        /// Renseigné par <see cref="MainWindow"/> : synchronise grilles d’historique
        /// et libellé « dernière analyse » (vue d’ensemble + panneau Antivirus).
        /// </summary>
        public Action? RefreshScanHistoryViews { get; set; }

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
        }

        /// <summary>
        /// Libère proprement tous les services disposables.
        /// Appelé depuis App.OnExit.
        /// </summary>
        public void Shutdown()
        {
            FocusAntivirusSignaturesTab = null;
            RefreshScanHistoryViews = null;
            try { FreshclamUpdater.DisableAutoUpdate(); } catch { }
            try { RulesUpdater.DisableAutoUpdate(); } catch { }
            (ClamAv as IDisposable)?.Dispose();
            (Yara as IDisposable)?.Dispose();
            AppLogger.Info("ServiceContainer", "Services fermés");
        }
    }
}
