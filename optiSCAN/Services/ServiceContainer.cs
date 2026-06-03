using System.Runtime.Versioning;

namespace optiSCAN.Services
{
    /// <summary>
    /// Regroupe les services à longue durée de vie (singleton <see cref="Default"/>).
    /// MainWindow et <see cref="optiSCAN.ViewModels.ScanViewModel"/> s’appuient sur les mêmes
    /// instances (moteurs, journaux, quarantaine) pour éviter double charge mémoire, caches
    /// divergents et abonnements dupliqués.
    /// </summary>
    /// <remarks>
    /// Pas de Microsoft.Extensions.DependencyInjection : choix volontaire pour une app WPF
    /// desktop à cycle de vie unique (singleton <see cref="Default"/>, construction explicite
    /// dans le constructeur privé). Un conteneur DI n’apporterait pas de scopes ici ; les tests
    /// peuvent substituer via <see cref="IScanEngine"/> / instances passées à <see cref="ScanOrchestrator"/>.
    /// </remarks>
    [SupportedOSPlatform("windows")]
    public sealed class ServiceContainer
    {
        private static readonly Lazy<ServiceContainer> _default =
            new(() => new ServiceContainer(), LazyThreadSafetyMode.ExecutionAndPublication);

        public static ServiceContainer Default => _default.Value;

        private bool _shutdownDone;

        // ── Services singleton ───────────────────────────────────────────────────
        public ClamAvEngine ClamAv { get; }

        /// <summary>Moteur Clam effectif (clamd avec repli clamscan).</summary>
        internal CompositeClamAvBackend ClamAvBackend { get; }

        /// <summary><c>clamd</c> ou <c>clamscan</c> selon le dernier scan.</summary>
        public string ClamActiveEngine => ClamAvBackend.ActiveEngine;
        public YaraEngine Yara { get; }
        public ScanOrchestrator Orchestrator { get; }
        public FreshclamUpdater FreshclamUpdater { get; }
        public YaraForgeUpdater RulesUpdater { get; }
        public QuarantineManager Quarantine { get; }
        public ScanLogManager Logger { get; }
        public NotificationService Notifications { get; }
        /// <summary>Surveillance fichiers sensibles (désactivable via Options / exclusions).</summary>
        public RealTimeProtection RealTimeProtection { get; }

        /// <summary>Tâche planifiée Windows (schtasks) — instance partagée pour Options et diagnostics.</summary>
        public ScheduledScanService ScheduledScan { get; }

        // Adapters interfaces — à utiliser pour les futurs tests ou substitutions
        public IScanEngine ScanEngine { get; }

        /// <summary>Actions UI antivirus (quarantaine, suppression, stop updates).</summary>
        public AntivirusActions Actions { get; }

        public ThreatReputationService ThreatReputation { get; }

        public ISecurityPostureService SecurityPosture { get; }

        // Navigation entre panneaux. Initialisé par MainWindow.OnLoaded une fois
        // que tous les UserControls sont créés (RegisterPanel a besoin de leur
        // référence). Les vues peuvent alors appeler Navigation.NavigateTo("...")
        // sans connaître MainWindow.
        public INavigationService? Navigation { get; set; }

        /// <summary>Résout une menace connue par chemin (liste live du ViewModel, enregistrée par MainWindow).</summary>
        public Func<string, Models.ThreatInfo?>? ThreatLookup { get; set; }

        public Models.ThreatInfo? FindKnownThreat(string filePath) =>
            string.IsNullOrEmpty(filePath) ? null : ThreatLookup?.Invoke(filePath);

        /// <summary>
        /// Émis par une vue qui veut déclencher une mise à jour manuelle des
        /// signatures (ex. carte « Mise à jour » de l’accueil). Écouté par MainWindow.
        /// Évite que les vues appellent directement BtnManualUpdateSignatures_Click.
        /// </summary>
        public event EventHandler? RequestSignatureUpdate;

        public void TriggerSignatureUpdate() =>
            RequestSignatureUpdate?.Invoke(this, EventArgs.Empty);

        /// <summary>Active ou arrête la protection temps réel et persiste dans <see cref="ExclusionSettings"/>.</summary>
        public void ApplyRealtimeProtection(bool enabled)
        {
            ExclusionSettings.Current.RealTimeEnabled = enabled;
            ExclusionSettings.Current.Save();
            if (enabled) RealTimeProtection.Start();
            else RealTimeProtection.Stop();
            RequestProtectionStateRefresh();
        }

        /// <summary>Persiste la quarantaine automatique (RTP + mode headless).</summary>
        public void ApplyAutoQuarantine(bool enabled)
        {
            ExclusionSettings.Current.AutoQuarantineEnabled = enabled;
            ExclusionSettings.Current.Save();
        }

        /// <summary>Active ou coupe les timers freshclam / règles YARA.</summary>
        public void ApplySignatureAutoUpdate(bool enabled)
        {
            if (enabled)
            {
                FreshclamUpdater.EnableAutoUpdate(TimeSpan.FromHours(4));
                RulesUpdater.EnableAutoUpdate(TimeSpan.FromHours(24));
            }
            else
            {
                FreshclamUpdater.DisableAutoUpdate();
                RulesUpdater.DisableAutoUpdate();
            }

            UserPreferences.Current.SignatureAutoUpdateEnabled = enabled;
            UserPreferences.Current.Save();
            RequestProtectionStateRefresh();
        }

        private EventHandler? _protectionStateRefreshHandlers;

        /// <summary>Demande aux vues bindées de recalculer le badge de protection.</summary>
        public event EventHandler? ProtectionStateRefreshRequested
        {
            add => _protectionStateRefreshHandlers += value;
            remove => _protectionStateRefreshHandlers -= value;
        }

        public void RequestProtectionStateRefresh() =>
            _protectionStateRefreshHandlers?.Invoke(this, EventArgs.Empty);

        /// <summary>Restaure RTP et MAJ auto selon les préférences persistées (appel au démarrage UI).</summary>
        public void ApplyPreferencesOnStartup()
        {
            ApplySignatureAutoUpdate(UserPreferences.Current.SignatureAutoUpdateEnabled);
            if (ExclusionSettings.Current.RealTimeEnabled)
                RealTimeProtection.Start();
            else
                RealTimeProtection.Stop();

            if (UserPreferences.Current.GameModeAutoEnabled)
                DistractionFreeMonitor.Start();
            else
                DistractionFreeMonitor.Stop();

            if (UserPreferences.Current.UseClamdEngine)
            {
                _ = Task.Run(async () =>
                {
                    try { await ClamdHost.Shared.EnsureRunningAsync().ConfigureAwait(false); }
                    catch (Exception ex) { AppLogger.Warn("ServiceContainer", "Préchauffage clamd", ex); }
                });
            }
        }

        // Demandes UI (export, onglet Signatures, etc.) : événements nommés plutôt que des
        // callbacks assignables après coup — si personne n’est abonné, l’appel est simplement ignoré.

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

        private EventHandler? _exportScanHistoryHtmlHandlers;
        /// <summary>Demande l’export HTML du rapport (écouteur : <see cref="optiSCAN.MainWindow"/>).</summary>
        public event EventHandler? ExportScanHistoryHtmlRequested
        {
            add => _exportScanHistoryHtmlHandlers += value;
            remove => _exportScanHistoryHtmlHandlers -= value;
        }

        public void RequestExportScanHistoryHtml() =>
            _exportScanHistoryHtmlHandlers?.Invoke(this, EventArgs.Empty);

        private EventHandler<Models.ScanSession>? _exportScanSessionPdfHandlers;
        /// <summary>Export PDF d'une session d'historique précise (pas seulement la dernière).</summary>
        public event EventHandler<Models.ScanSession>? ExportScanSessionPdfRequested
        {
            add => _exportScanSessionPdfHandlers += value;
            remove => _exportScanSessionPdfHandlers -= value;
        }

        public void RequestExportScanSessionPdf(Models.ScanSession session) =>
            _exportScanSessionPdfHandlers?.Invoke(this, session);

        private EventHandler<Models.ScanSession>? _reviewHistorySessionHandlers;
        /// <summary>Charge les menaces d'une session historique dans Analyse (écouteur : MainWindow).</summary>
        public event EventHandler<Models.ScanSession>? ReviewHistorySessionRequested
        {
            add => _reviewHistorySessionHandlers += value;
            remove => _reviewHistorySessionHandlers -= value;
        }

        public void RequestReviewHistorySession(Models.ScanSession session) =>
            _reviewHistorySessionHandlers?.Invoke(this, session);

        private ServiceContainer()
        {
            // Ordre de construction : du plus indépendant au plus dépendant.
            ClamAv = new ClamAvEngine();
            var clamdEngine = new ClamdEngine();
            ClamAvBackend = new CompositeClamAvBackend(clamdEngine, ClamAv);
            Yara = new YaraEngine();
            FreshclamUpdater = new FreshclamUpdater();
            RulesUpdater = new YaraForgeUpdater();
            Quarantine = new QuarantineManager();
            Logger = new ScanLogManager();
            Notifications = new NotificationService();

            Orchestrator = new ScanOrchestrator(ClamAvBackend, Yara);
            ScanEngine = new ClamAvScanEngineAdapter(ClamAv);
            Actions = new AntivirusActions(this);
            ThreatReputation = new ThreatReputationService();
            SecurityPosture = new SecurityPostureService();
            RealTimeProtection = new RealTimeProtection(Orchestrator, Quarantine, Notifications);
            ScheduledScan = new ScheduledScanService();

            // Timers MAJ signatures : état restauré depuis UserPreferences (ApplyPreferencesOnStartup).
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
            if (_shutdownDone)
                return;
            _shutdownDone = true;
            _focusAntivirusSignaturesHandlers = null;
            _scanHistoryViewsRefreshHandlers = null;
            _exportScanHistoryHtmlHandlers = null;
            _exportScanSessionPdfHandlers = null;
            try { RealTimeProtection.Dispose(); }
            catch (Exception ex) { AppLogger.Warn("ServiceContainer", "RealTimeProtection.Dispose", ex); }
            try { FreshclamUpdater.DisableAutoUpdate(); }
            catch (Exception ex) { AppLogger.Warn("ServiceContainer", "FreshclamUpdater.DisableAutoUpdate", ex); }
            try { RulesUpdater.DisableAutoUpdate(); }
            catch (Exception ex) { AppLogger.Warn("ServiceContainer", "RulesUpdater.DisableAutoUpdate", ex); }
            try { ClamdHost.Shared.Stop(); }
            catch (Exception ex) { AppLogger.Warn("ServiceContainer", "ClamdHost.Stop", ex); }
            try { DistractionFreeMonitor.Stop(); }
            catch (Exception ex) { AppLogger.Warn("ServiceContainer", "DistractionFreeMonitor.Stop", ex); }
            (ClamAv as IDisposable)?.Dispose();
            (Yara as IDisposable)?.Dispose();
            AppLogger.Info("ServiceContainer", "Services fermés");
        }
    }
}
