using MaterialDesignThemes.Wpf;
using optiSCAN.Localization;
using optiSCAN.Models;
using optiSCAN.Services;
using optiSCAN.Strings;
using optiSCAN.ViewModels;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.Versioning;
using System.Text;
using System.Windows.Forms;
using System.Windows;
using System.Windows.Media;
using System.Windows.Threading;
using System.Windows.Input;
using System.Windows.Media.Animation;
using Button = System.Windows.Controls.Button;
using MediaColor = System.Windows.Media.Color;

namespace optiSCAN
{
    /// <summary>
    /// Fenêtre principale d'optiSCAN. Orchestre la navigation entre les 5 panneaux,
    /// coordonne les mises à jour de signatures, les exports et la protection temps réel
    /// en s'appuyant sur <see cref="Services.ServiceContainer"/> et <see cref="ViewModels.ScanViewModel"/>.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public partial class MainWindow : Window
    {
        // ── Services & ViewModel ─────────────────────────────────────────────────
        /// <summary>ViewModel partagé (scan, quarantaine, progression). DataContext de la fenêtre.</summary>
        public ScanViewModel? ViewModel { get; private set; }

        private SystemTrayHost? _trayHost;

        private ClamAvEngine? _clamAvEngine;
        private YaraEngine? _yaraEngine;
        private ScanOrchestrator? _antivirusOrchestrator;
        private ScanLogManager? _logManager;
        private QuarantineManager? _quarantineManager;
        private readonly HistoryExportService _historyExport = new();
        private FreshclamUpdater? _freshclamUpdater;
        private YaraForgeUpdater? _rulesUpdater;

        private readonly Services.NavigationService _navigationService = new();
        private Services.NavigationRefreshCoordinator? _navRefreshCoordinator;
        private readonly SignatureUpdateUiRunner _signatureUpdateRunner = new();
        private readonly RoutedCommand _quickScanShortcutCommand = new();
        private bool _isClosing = false;
        private bool _wasScanning;
        private bool _isSyncingSidebarSelection;
        private string? _lastStatusText;
        private bool _lastStatusIsError;
        private bool _lastStatusIsWarning;
        private string? _lastStatusIconKind;

        // ── Cache TTL signatures (évite de relire le disque à chaque navigation) ──
        private DateTime _lastSigRefreshAt = DateTime.MinValue;
        private static readonly TimeSpan SigCacheTtl = TimeSpan.FromSeconds(30);
        private (string ClamVer, string ClamWhen, string YaraVer, string YaraWhen)? _sigCache;

        // Après InitializeComponent / RegisterPanels, le constructeur assigne
        // ServiceContainer.Default.Navigation : les vues naviguent sans référencer MainWindow.

        public MainWindow()
        {
            InitializeComponent();
            // Avant toute navigation (ex. RadioButton coché), enregistrer les panneaux.
            RegisterPanels();
            if (navOverview != null)
                navOverview.IsChecked = true;
            else
                _navigationService.NavigateTo(OptiscanStrings.PanelIds.Overview);

            ApplyVersionLabels();

            try
            {
                _trayHost = new SystemTrayHost();
                _trayHost.Initialize(
                    () => Dispatcher.Invoke(ShowWindowFromTray),
                    () => Dispatcher.Invoke(ExitFromTray));

                // Services partagés via le singleton applicatif (mêmes instances que ScanViewModel).
                var c = ServiceContainer.Default;
                _clamAvEngine = c.ClamAv;
                _yaraEngine = c.Yara;
                _logManager = c.Logger;
                _quarantineManager = c.Quarantine;
                _antivirusOrchestrator = c.Orchestrator;
                _freshclamUpdater = c.FreshclamUpdater;
                _rulesUpdater = c.RulesUpdater;

                _freshclamUpdater.UpdateOutput += SurSortieFreshclam;
                _rulesUpdater.UpdateOutput += SurSortieMisesAJourRegles;
                _freshclamUpdater.UpdateOutput += (_, _) => Dispatcher.InvokeAsync(RefreshLiveFooter);
                _rulesUpdater.UpdateOutput += (_, _) => Dispatcher.InvokeAsync(RefreshLiveFooter);
                _freshclamUpdater.UpdateCompleted += (_, _) =>
                    Dispatcher.InvokeAsync(async () =>
                    {
                        InvalidateSigCache();
                        await RefreshSignaturesDisplayAsync(forceRefresh: true);
                        RefreshLiveFooter();
                    });
                _rulesUpdater.UpdateCompleted += (_, _) =>
                    Dispatcher.InvokeAsync(async () =>
                    {
                        InvalidateSigCache();
                        await RefreshSignaturesDisplayAsync(forceRefresh: true);
                        RefreshLiveFooter();
                    });

                // ViewModel partage le même container : pas de re-instanciation.
                ViewModel = new ScanViewModel(c);
                ViewModel.PropertyChanged -= SurChangementProprieteScanViewModel;
                ViewModel.PropertyChanged += SurChangementProprieteScanViewModel;
                _wasScanning = ViewModel.IsScanning;
                Dispatcher.InvokeAsync(RefreshLiveFooter);
                c.ThreatLookup = path => ViewModel?.Threats.FirstOrDefault(t =>
                    string.Equals(t.FilePath, path, StringComparison.OrdinalIgnoreCase));
                this.DataContext = ViewModel;

                // Les vues utilisent c.Navigation (INavigationService) au lieu de caster MainWindow.
                c.Navigation = _navigationService;

                // Écoute les demandes de mise à jour émises par les vues
                // (ex. carte "Update" d'OverviewControl).
                c.RequestSignatureUpdate += SurDemandeMiseAJourSignatures;
                c.ScanHistoryViewsRefreshRequested += SurDemandeRafraichissementHistorique;
                c.ExportScanHistoryHtmlRequested += SurDemandeExportHistoriqueHtml;
                c.ExportScanSessionPdfRequested += SurDemandeExportSessionScanPdf;
                c.ReviewHistorySessionRequested += SurDemandeRevueSessionHistorique;
                c.RealTimeProtection.ThreatDetected += SurMenaceTempsReelDetectee;
                c.Notifications.ToastActivated -= SurActivationToast;
                c.Notifications.ToastActivated += SurActivationToast;
                c.Notifications.SyncFromUserPreferences();
                c.Actions.ActionCompleted -= SurActionAntivirusTerminee;
                c.Actions.ActionCompleted += SurActionAntivirusTerminee;

                // Abonnement aux événements
                this.Loaded += async (s, e) => await SurChargementFenetrePrincipale();
                this.Closing += SurFermetureFenetre;
                this.StateChanged += SurChangementEtatFenetre;

                // IPC : une seconde instance envoie un message Windows pour réafficher cette fenêtre (IpcManager).
                IpcManager.HookShowMessage(this, ShowWindow);

                ThemeManager.ThemeChanged += SurChangementTheme;
                UpdateThemeToggleTooltip(ThemeManager.IsDarkTheme);

                // Raccourcis Ctrl+1..Ctrl+5 : une seule RoutedCommand, le paramètre est le nom du panneau.
                KeyboardShortcuts.Register(this,
                    new[] { OptiscanStrings.PanelIds.Overview, OptiscanStrings.PanelIds.Clean, OptiscanStrings.PanelIds.Antivirus, OptiscanStrings.PanelIds.History, OptiscanStrings.PanelIds.Options },
                    SwitchPanel);
                RegisterScanShortcuts();
            }
            catch (Exception ex)
            {
                AppLogger.Error("MainWindow", "Initialisation fenêtre principale", ex);
                SetStatus(LocalizationService.Format("Status_Error", ex.Message), isError: true);
            }
        }

        private void RegisterScanShortcuts()
        {
            CommandBindings.Add(new CommandBinding(_quickScanShortcutCommand, (_, _) =>
            {
                if (ViewModel?.QuickScanCommand?.CanExecute(null) == true)
                    ViewModel.QuickScanCommand.Execute(null);
            }));

            // F5 : raccourci d'analyse rapide indiqué dans l'interface Antivirus.
            InputBindings.Add(new KeyBinding(_quickScanShortcutCommand, Key.F5, ModifierKeys.None));
        }

        private void ShowWindowFromTray()
        {
            ShowWindow();
        }

        private void ExitFromTray()
        {
            _isClosing = true;
            Close();
        }

        // ── Initialisation ───────────────────────────────────────────────────────
        /// <summary>
        /// Orchestration principale au chargement de la fenêtre.
        /// Initialise les panneaux, évalue la disponibilité des moteurs (ClamAV/YARA),
        /// rafraîchit l'état de l'UI et branche les protections temps réel.
        /// </summary>
        /// <remarks>
        /// Cette méthode est appelée une seule fois dans l'exécution normale, mais la logique
        /// reste idempotente côté navigation (panneaux enregistrés sans duplication).
        /// En cas d'exception, l'UI affiche un statut d'erreur et continue sans crasher.
        /// </remarks>
        private async Task SurChargementFenetrePrincipale()
        {
            try
            {
                // ── Enregistrement des panneaux de navigation ────────────────────
                RegisterPanels();

                RuntimeDependencies.LogReportIfIncomplete();
                var runtimeReport = RuntimeDependencies.Evaluate();

                bool clamAvOk = _clamAvEngine?.IsClamAvInstalled() ?? false;
                if (!runtimeReport.IsClamAvReady)
                    SetStatus(runtimeReport.BuildSummaryLine() + LocalizationService.GetString("Main_RuntimeHint"), isWarning: true);
                else
                    SetStatus(clamAvOk ? LocalizationService.GetString("Main_ClamOperational") : LocalizationService.GetString("Main_ClamNotFound"), isWarning: !clamAvOk);

                RefreshAntivirusStatus();
                RefreshQuarantineList();
                RefreshHistory();
                await RefreshSignaturesDisplayAsync();
                // Bandeau élévation : affiché si optiSCAN tourne sans droits admin.
                (panelOverview as Views.OverviewControl)?.ApplyElevationBanner();
                try
                {
                    ServiceContainer.Default.ApplyPreferencesOnStartup();
                }
                catch (Exception ex)
                {
                    AppLogger.Warn("MainWindow", "ApplyPreferencesOnStartup", ex);
                }
                ViewModel?.RefreshProtectionStatus();
                RefreshOverviewProtectionAndRecommendations();

                // Afficher la vue d'accueil par défaut
                _navigationService.NavigateTo(OptiscanStrings.PanelIds.Overview);

                SetStatus(OptiscanStrings.UiMessages.ProtectionActive);
                OnboardingService.ShowIfNeeded(this);
            }
            catch (Exception ex)
            {
                AppLogger.Error("MainWindow", "SurChargementFenetrePrincipale", ex);
                SetStatus(LocalizationService.Format("Status_Error", ex.Message), isError: true);
            }
            await Task.CompletedTask;
        }

        /// <summary>
        /// Enregistre les 5 panneaux auprès du NavigationService.
        /// Appelé juste après <see cref="InitializeComponent"/> (avant tout <c>Checked</c> de la sidebar)
        /// et à nouveau dans <see cref="SurChargementFenetrePrincipale"/> (idempotent).
        /// </summary>
        private void RegisterPanels()
        {
            // Vérifications null : les éléments nommés existent forcément après InitializeComponent.
            if (panelOverview != null) _navigationService.RegisterPanel(OptiscanStrings.PanelIds.Overview, panelOverview);
            if (panelAntivirus != null) _navigationService.RegisterPanel(OptiscanStrings.PanelIds.Antivirus, panelAntivirus);
            if (panelClean != null) _navigationService.RegisterPanel(OptiscanStrings.PanelIds.Clean, panelClean);
            if (panelHistory != null) _navigationService.RegisterPanel(OptiscanStrings.PanelIds.History, panelHistory);
            if (panelOptions != null) _navigationService.RegisterPanel(OptiscanStrings.PanelIds.Options, panelOptions);

            ServiceContainer.Default.FocusAntivirusSignaturesRequested -= SurDemandeFocusSignaturesAntivirus;
            ServiceContainer.Default.FocusAntivirusSignaturesRequested += SurDemandeFocusSignaturesAntivirus;

            // Le coordinateur gère les rafraîchissements par vue (extrait de MainWindow).
            _navRefreshCoordinator?.Detach();
            _navRefreshCoordinator = new Services.NavigationRefreshCoordinator(
                _navigationService,
                Dispatcher,
                refreshHistory:         RefreshHistoryAsync,
                refreshAntivirusStatus: RefreshAntivirusStatusCoreAsync,
                refreshSignatures:      () => RefreshSignaturesDisplayAsync(),
                refreshAntivirusData:   RefreshAntivirusDataAsync);

            // SyncSidebarSelection reste dans MainWindow (manipulation UI directe).
            _navigationService.Navigated -= SurNavigationNaviguee;
            _navigationService.Navigated += SurNavigationNaviguee;
        }

        private void SurNavigationNaviguee(object? sender, string panelName) =>
            Dispatcher.BeginInvoke(() => SyncSidebarSelection(panelName), DispatcherPriority.Background);

        private void SyncSidebarSelection(string panelName)
        {
            _isSyncingSidebarSelection = true;
            try
            {
                switch (panelName)
                {
                    case OptiscanStrings.PanelIds.Overview:
                        if (navOverview != null) navOverview.IsChecked = true;
                        break;
                    case OptiscanStrings.PanelIds.Clean:
                        if (navClean != null) navClean.IsChecked = true;
                        break;
                    case OptiscanStrings.PanelIds.Antivirus:
                        if (navAntivirus != null) navAntivirus.IsChecked = true;
                        break;
                    case OptiscanStrings.PanelIds.History:
                        if (navHistory != null) navHistory.IsChecked = true;
                        break;
                    case OptiscanStrings.PanelIds.Options:
                        if (navOptions != null) navOptions.IsChecked = true;
                        break;
                }
            }
            finally
            {
                _isSyncingSidebarSelection = false;
            }
        }

        private void SurDemandeMiseAJourSignatures(object? sender, EventArgs e) =>
            BtnManualUpdateSignatures_Click(this, new RoutedEventArgs());

        private void SurDemandeRafraichissementHistorique(object? sender, EventArgs e) =>
            Dispatcher.BeginInvoke(RefreshHistory, GetHistoryRefreshPriority());

        private void SurChangementProprieteScanViewModel(object? sender, PropertyChangedEventArgs e)
        {
            if (ViewModel == null) return;

            if (e.PropertyName == nameof(ScanViewModel.IsScanning))
            {
                if (_wasScanning && !ViewModel.IsScanning)
                    Dispatcher.BeginInvoke(RefreshHistory, GetHistoryRefreshPriority());

                _wasScanning = ViewModel.IsScanning;
            }

            if (e.PropertyName is nameof(ScanViewModel.IsScanning)
                or nameof(ScanViewModel.ScanProgressDetail)
                or nameof(ScanViewModel.IsUpdating))
                Dispatcher.InvokeAsync(RefreshLiveFooter);
        }

        private DispatcherPriority GetHistoryRefreshPriority() =>
            string.Equals(_navigationService.CurrentView, OptiscanStrings.PanelIds.Overview, StringComparison.OrdinalIgnoreCase)
                ? DispatcherPriority.Normal
                : DispatcherPriority.Background;

        private void SurDemandeFocusSignaturesAntivirus(object? sender, EventArgs e)
        {
            if (panelAntivirus is Views.AntivirusView av)
                av.SelectSignaturesTab();
        }

        private void SurDemandeRevueSessionHistorique(object? sender, ScanSession session)
        {
            ViewModel?.LoadThreatsFromHistorySession(session);
            _navigationService.NavigateTo(OptiscanStrings.PanelIds.Antivirus);
            if (panelAntivirus is Views.AntivirusView av)
                av.SelectScanTab();
        }

        private void UnhookServiceContainerEvents()
        {
            var c = ServiceContainer.Default;
            c.RequestSignatureUpdate -= SurDemandeMiseAJourSignatures;
            c.ScanHistoryViewsRefreshRequested -= SurDemandeRafraichissementHistorique;
            c.ExportScanHistoryHtmlRequested -= SurDemandeExportHistoriqueHtml;
            c.ExportScanSessionPdfRequested -= SurDemandeExportSessionScanPdf;
            c.ReviewHistorySessionRequested -= SurDemandeRevueSessionHistorique;
            c.FocusAntivirusSignaturesRequested -= SurDemandeFocusSignaturesAntivirus;
            c.RealTimeProtection.ThreatDetected -= SurMenaceTempsReelDetectee;
            c.Notifications.ToastActivated -= SurActivationToast;
            c.Actions.ActionCompleted -= SurActionAntivirusTerminee;
        }

        // ── Navigation ───────────────────────────────────────────────────────────

        /// <summary>Déclenché par un RadioButton NavItem coché dans la sidebar.</summary>
        private void NavItem_Checked(object sender, RoutedEventArgs e)
        {
            if (_isSyncingSidebarSelection)
                return;

            if (sender is System.Windows.Controls.Primitives.ToggleButton tb
                && tb.Tag is string panelName)
            {
                SwitchPanel(panelName);
            }
        }

        /// <summary>Bascule le thème sombre/clair.</summary>
        private void BtnModesSombre_Click(object sender, RoutedEventArgs e)
        {
            ThemeManager.Toggle();
        }

        /// <summary>Ouvre la page du projet optiSCAN sur SourceForge dans le navigateur par défaut.</summary>
        private void BtnWebsite_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                {
                    FileName = OptiscanStrings.Urls.OptiscanWebsite,
                    UseShellExecute = true
                });
            }
            catch (Exception ex)
            {
                AppLogger.Warn("MainWindow", "Ouverture du site web (Process.Start)", ex);
            }
        }

        // Ancien handler Button conservé pour compatibilité
        private void MenuButton_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is string target)
                SwitchPanel(target);
        }

        /// <summary>
        /// Navigue vers le panneau identifié par <paramref name="panelName"/> et déclenche
        /// les rafraîchissements de données associés.
        /// </summary>
        public void SwitchPanel(string panelName) =>
            _navigationService.NavigateTo(panelName);

        // Les rafraîchissements de navigation sont maintenant gérés par NavigationRefreshCoordinator.

        // ── Rafraîchissement ─────────────────────────────────────────────────────
        // RefreshYaraStatus() est intentionnellement supprimé : YaraRulesCount et
        // YaraStatus sont désormais synchronisés dans RefreshSignaturesDisplay()
        // via le ViewModel, et UpdateYaraStatus() de AntivirusView est supprimée.

        private void RefreshAntivirusStatus()
        {
            _ = RefreshAntivirusStatusCoreAsync();
        }

        private async Task RefreshAntivirusStatusCoreAsync()
        {
            bool clamAvOk = await Task.Run(() => _clamAvEngine?.IsClamAvInstalled() ?? false).ConfigureAwait(true);
            int yaraRules = _yaraEngine?.RulesCount ?? 0;

            if (txtSidebarClamAvBadge != null)
            {
                txtSidebarClamAvBadge.Text = clamAvOk ? LocalizationService.GetString("Main_ClamBadgeActive") : LocalizationService.GetString("Main_ClamBadgeMissing");
                txtSidebarClamAvBadge.Foreground = clamAvOk
                    ? ThemeUiBrushes.Get("SuccessGreen", txtSidebarClamAvBadge)
                    : ThemeUiBrushes.Get("DangerRed", txtSidebarClamAvBadge);
            }

            if (icoSidebarClamAv != null)
            {
                icoSidebarClamAv.Kind = clamAvOk ? PackIconKind.ShieldCheck : PackIconKind.ShieldOff;
                icoSidebarClamAv.Foreground = clamAvOk
                    ? ThemeUiBrushes.Get("SuccessGreen", icoSidebarClamAv)
                    : ThemeUiBrushes.Get("DangerRed", icoSidebarClamAv);
            }

            var clamMode = ServiceContainer.Default.ClamActiveEngine;
            (panelOverview as Views.OverviewControl)?.UpdateAntivirusCardStatus(clamAvOk, yaraRules, clamMode);
        }

        private void RefreshQuarantineList()
        {
            ViewModel?.RefreshQuarantineList();
        }

        private Task RefreshHistoryAsync()
        {
            RefreshHistory();
            return Task.CompletedTask;
        }

        private void RefreshHistory()
        {
            var sessions = _logManager?.GetHistory() ?? Array.Empty<ScanSession>();
            var cleanSessions = _logManager?.GetCleanHistory() ?? Array.Empty<CleanSession>();
            (panelHistory as Views.HistoryControl)?.UpdateScanHistory(sessions);
            (panelHistory as Views.HistoryControl)?.UpdateCleanHistory(cleanSessions);
            ApplyLastScanSummary(sessions);
            (panelOverview as Views.OverviewControl)?.UpdateProtectionStatistics(sessions);
            RefreshOverviewProtectionAndRecommendations();
        }

        /// <summary>Synchronise « Dernière analyse » (vue d’ensemble + colonne Antivirus) avec l’historique réel.</summary>
        private void ApplyLastScanSummary(IReadOnlyList<ScanSession> sessions)
        {
            ScanSession? last = sessions.Count == 0
                ? null
                : sessions.OrderByDescending(s => s.StartedAt).First();
            (panelOverview as Views.OverviewControl)?.UpdateLastScanSummary(last);
            (panelAntivirus as Views.AntivirusView)?.UpdateLastScanDisplay(last?.StartedAt);
        }

        private void SurMenaceTempsReelDetectee(object? sender, ThreatInfo threat)
        {
            Dispatcher.BeginInvoke(new Action(() =>
            {
                ViewModel?.AppendLiveThreat(threat);
                RefreshQuarantineList();
                RefreshOverviewProtectionAndRecommendations();
            }), DispatcherPriority.Background);
        }

        private void SurActionAntivirusTerminee(object? sender, ActionResult result)
        {
            Dispatcher.BeginInvoke(() =>
            {
                SetStatus(result.Message, isError: result.IsError, isWarning: result.IsWarning);
                if (result.Success)
                {
                    RefreshQuarantineList();
                    (panelAntivirus as Views.AntivirusView)?.RefreshAllData();
                }
            }, DispatcherPriority.Normal);
        }

        private void SurActivationToast(object? sender, ToastActivationEventArgs e)
        {
            Dispatcher.BeginInvoke(new Action(() => HandleToastActivation(e)), DispatcherPriority.Normal);
        }

        /// <summary>
        /// Traite l'action reçue via un toast Windows (quarantaine, ignorer, navigation…).
        /// </summary>
        /// <remarks>
        /// Le toast peut déclencher des changements d'UI et/ou de données. On route donc l'action
        /// vers les services applicatifs, puis on rafraîchit l'état de la fenêtre (quarantaine,
        /// vue Antivirus, synthèse d'onglet, etc.).
        /// </remarks>
        private void HandleToastActivation(ToastActivationEventArgs e)
        {
            var c = ServiceContainer.Default;
            switch (e.Action.ToLowerInvariant())
            {
                case "quarantine":
                    if (!string.IsNullOrEmpty(e.FilePath))
                    {
                        var result = c.Actions.QuarantineThreat(e.FilePath);
                        SetStatus(result.Message, isError: result.IsError, isWarning: result.IsWarning);
                        if (result.Success)
                        {
                            RefreshQuarantineList();
                            (panelAntivirus as Views.AntivirusView)?.RefreshAllData();
                        }
                    }
                    ShowWindow();
                    _navigationService.NavigateTo(OptiscanStrings.PanelIds.Antivirus);
                    break;

                case "ignore":
                    if (!string.IsNullOrEmpty(e.FilePath))
                    {
                        var result = c.Actions.IgnoreThreat(e.FilePath);
                        SetStatus(result.Message, isError: result.IsError, isWarning: result.IsWarning);
                        (panelAntivirus as Views.AntivirusView)?.RefreshAllData();
                    }
                    break;

                case "openav":
                    ShowWindow();
                    _navigationService.NavigateTo(OptiscanStrings.PanelIds.Antivirus);
                    (panelAntivirus as Views.AntivirusView)?.SelectScanTab();
                    break;

                case "open":
                case "threat":
                    ShowWindow();
                    _navigationService.NavigateTo(OptiscanStrings.PanelIds.Antivirus);
                    (panelAntivirus as Views.AntivirusView)?.SelectScanTab();
                    break;

                case "showquarantine":
                    ShowWindow();
                    _navigationService.NavigateTo(OptiscanStrings.PanelIds.Antivirus);
                    (panelAntivirus as Views.AntivirusView)?.SelectQuarantineTab();
                    RefreshQuarantineList();
                    break;

                case "history":
                case "scanthreats":
                    ShowWindow();
                    _navigationService.NavigateTo(OptiscanStrings.PanelIds.History);
                    break;

                case "update":
                    ShowWindow();
                    _navigationService.NavigateTo(OptiscanStrings.PanelIds.Antivirus);
                    (panelAntivirus as Views.AntivirusView)?.SelectSignaturesTab();
                    BtnManualUpdateSignatures_Click(this, new RoutedEventArgs());
                    break;
            }
        }

        /// <summary>Titre de protection, recommandations hygiène et activité (vue d’ensemble).</summary>
        private void RefreshOverviewProtectionAndRecommendations()
        {
            var overview = panelOverview as Views.OverviewControl;
            if (overview == null) return;

            bool clam = _clamAvEngine?.IsClamAvInstalled() ?? false;
            int yaraRules = _yaraEngine?.RulesCount ?? 0;
            bool yaraAvail = _yaraEngine?.IsAvailable ?? false;
            bool protectedOk = clam && (!yaraAvail || yaraRules > 0);

            overview.UpdateProtectionHeadline(protectedOk);

            // Déléguer la logique de calcul à OverviewRecommendationsBuilder (testable sans UI).
            var cleanHist = _logManager?.GetCleanHistory() ?? Array.Empty<CleanSession>();
            var sessions = _logManager?.GetHistory() ?? Array.Empty<ScanSession>();

            var rec = OverviewRecommendationsBuilder.Build(new OverviewRecommendationsBuilder.Context
            {
                ClamInstalled = clam,
                LastFreshclamUpdate = _freshclamUpdater?.GetLastSignatureUpdateTime(),
                LastCleanAt = cleanHist.Count > 0 ? cleanHist[0].StartedAt : null,
                ScanSessions = sessions,
            });

            overview.UpdateRecommendations(
                rec.HygieneLine, rec.HygieneSeverity,
                rec.ActivityLine, rec.ActivitySeverity,
                rec.ShowSigUpdateLink);

            var lastScan = sessions.Count > 0 ? sessions[0].StartedAt : (DateTime?)null;
            bool rtpOn = ExclusionSettings.Current.RealTimeEnabled;
            bool rtpRun = ServiceContainer.Default.RealTimeProtection.IsEnabled;

            var posture = ServiceContainer.Default.SecurityPosture.Evaluate(new SecurityPostureContext
            {
                ClamInstalled = clam,
                YaraAvailable = yaraAvail,
                YaraRulesCount = yaraRules,
                RealTimeProtectionEnabled = rtpOn,
                RealTimeProtectionRunning = rtpRun,
                LastScanAt = lastScan,
                SignatureAutoUpdateEnabled = UserPreferences.Current.SignatureAutoUpdateEnabled,
            });
            overview.UpdateSecurityPosture(posture);
        }

        public async Task RefreshAntivirusDataAsync()
        {
            RefreshAntivirusStatus();
            RefreshQuarantineList();
            RefreshHistory();
            await RefreshSignaturesDisplayAsync();
        }

        /// <summary>
        /// Invalide le cache TTL des signatures (à appeler après une MAJ effective).
        /// </summary>
        private void InvalidateSigCache()
        {
            _lastSigRefreshAt = DateTime.MinValue;
            _sigCache = null;
        }

        /// <summary>Rafraîchit les versions de signatures (onglet Antivirus + ViewModel).</summary>
        private async Task RefreshSignaturesDisplayAsync(bool forceRefresh = false)
        {
            // Cache TTL : on relit le disque seulement si le cache est expiré ou forcé.
            string clamVer, clamWhen, yaraVer, yaraWhen;
            if (!forceRefresh && _sigCache.HasValue && (DateTime.UtcNow - _lastSigRefreshAt) < SigCacheTtl)
            {
                (clamVer, clamWhen, yaraVer, yaraWhen) = _sigCache.Value;
            }
            else
            {
                clamVer  = _freshclamUpdater != null
                    ? await _freshclamUpdater.GetLocalDatabaseVersionAsync().ConfigureAwait(true)
                    : "—";
                clamWhen = _freshclamUpdater?.GetLastSignatureChangeDisplay()  ?? "—";
                yaraVer  = _rulesUpdater?.GetRulesPackVersionDisplay()         ?? "—";
                yaraWhen = _rulesUpdater?.GetRulesLastUpdateDisplay()          ?? "—";
                _sigCache = (clamVer, clamWhen, yaraVer, yaraWhen);
                _lastSigRefreshAt = DateTime.UtcNow;
            }

            (panelAntivirus as Views.AntivirusView)?.UpdateSignaturesPanel(yaraVer, yaraWhen, clamVer, clamWhen);
            (panelOverview as Views.OverviewControl)?.UpdateSignaturesSummary(yaraVer, yaraWhen, clamVer, clamWhen);

            if (ViewModel != null)
            {
                ViewModel.DbVersion = clamVer;
                ViewModel.RulesPackVersion = yaraVer;
                ViewModel.LastUpdateDisplay = clamWhen == "—" ? LocalizationService.GetString("Vm_Never") : clamWhen;
                ViewModel.RulesLastUpdateDisplay = yaraWhen == "—" ? LocalizationService.GetString("Vm_Never") : yaraWhen;
                // Synchronise YaraRulesCount et YaraStatus : omis auparavant, ce qui
                // laissait le VM avec des valeurs obsolètes après une MAJ manuelle.
                var rulesCount = _yaraEngine?.RulesCount ?? 0;
                ViewModel.YaraRulesCount = rulesCount;
                ViewModel.YaraStatus = (_yaraEngine?.IsAvailable ?? false)
                    ? LocalizationService.Format("Vm_YaraOperational", rulesCount)
                    : LocalizationService.GetString("Vm_YaraUnavailable");
                ViewModel.RefreshProtectionStatus();
            }

            RefreshOverviewProtectionAndRecommendations();
        }

        private void SurDemandeExportHistoriqueHtml(object? sender, EventArgs e) =>
            Dispatcher.BeginInvoke(new Action(TryExportScanReportHtml), DispatcherPriority.Background);

        private void SurDemandeExportSessionScanPdf(object? sender, ScanSession session) =>
            Dispatcher.BeginInvoke(new Action(() => TryExportScanSessionPdf(session)), DispatcherPriority.Background);

        private void TryExportScanReportHtml()
        {
            var result = _historyExport.TryExportHtml(
                this,
                _logManager,
                ViewModel?.Threats ?? Enumerable.Empty<ThreatInfo>(),
                _quarantineManager?.GetEntries() ?? Array.Empty<QuarantineEntry>());
            if (!result.WasCancelled && !string.IsNullOrEmpty(result.Message))
                SetStatus(result.Message, isError: result.IsError);
        }

        private void TryExportScanSessionPdf(ScanSession session)
        {
            var result = _historyExport.TryExportSessionPdf(this, session);
            if (!result.WasCancelled && !string.IsNullOrEmpty(result.Message))
                SetStatus(result.Message, isError: result.IsError);
        }

        // ── Statut ───────────────────────────────────────────────────────────────
        private void UpdateThemeToggleTooltip(bool isDark)
        {
            if (btnModesSombre == null) return;
            btnModesSombre.ToolTip = LocalizationService.GetString(
                isDark ? "Nav_TooltipThemeLight" : "Nav_TooltipThemeDark");
        }

        private void SurChangementTheme(object? sender, bool isDark)
        {
            Dispatcher.InvokeAsync(() =>
            {
                UpdateThemeToggleTooltip(isDark);
                panelOptions.SyncThemeControls();

                RefreshAntivirusStatus();
                RefreshOverviewProtectionAndRecommendations();
                if (_lastStatusText != null)
                {
                    if (!IsLiveFooterActive())
                        ApplyPinnedFooter();
                    else
                        RefreshLiveFooter();
                }
            });
        }

        private void SetStatus(string text, bool isError = false, bool isWarning = false, string? iconKindName = null)
        {
            _lastStatusText = text;
            _lastStatusIsError = isError;
            _lastStatusIsWarning = isWarning;
            _lastStatusIconKind = iconKindName;

            Dispatcher.InvokeAsync(() =>
            {
                if (!IsLiveFooterActive())
                    ApplyPinnedFooter();
                AppLogger.Debug("MainWindow", $"Statut: {text}");
            });
        }

        private bool IsLiveFooterActive()
        {
            if (ViewModel?.IsScanning == true)
                return true;
            if (IsSignatureUpdateRunning())
                return true;
            return ViewModel?.IsUpdating == true;
        }

        private bool IsSignatureUpdateRunning() =>
            (_freshclamUpdater?.IsUpdating ?? false) || (_rulesUpdater?.IsUpdating ?? false);

        private void RefreshLiveFooter()
        {
            if (ViewModel == null) return;

            if (ViewModel.IsScanning)
            {
                if (statusFooterSpinner != null)
                    statusFooterSpinner.Visibility = Visibility.Visible;
                if (statusFooterIcon != null)
                    statusFooterIcon.Visibility = Visibility.Collapsed;
                StopRefreshSpin();

                var detail = ViewModel.ScanProgressDetail;
                if (lblStatus != null)
                {
                    lblStatus.Text = string.IsNullOrWhiteSpace(detail)
                        ? LocalizationService.GetString("Main_StatusScanning")
                        : detail;
                    var textBrush = ThemeUiBrushes.Get("TextMedium", lblStatus);
                    if (textBrush != null)
                        lblStatus.Foreground = textBrush;
                }
                return;
            }

            if (statusFooterSpinner != null)
                statusFooterSpinner.Visibility = Visibility.Collapsed;
            if (statusFooterIcon != null)
                statusFooterIcon.Visibility = Visibility.Visible;

            if (IsSignatureUpdateRunning() || ViewModel.IsUpdating)
            {
                if (lblStatus != null)
                {
                    lblStatus.Text = LocalizationService.GetString("Main_StatusUpdating");
                    var textBrush = ThemeUiBrushes.Get("TextMedium", lblStatus);
                    if (textBrush != null)
                        lblStatus.Foreground = textBrush;
                }

                if (statusFooterIcon != null)
                {
                    if (Enum.TryParse<PackIconKind>(UiIconKinds.Refresh, ignoreCase: false, out var kind))
                        statusFooterIcon.Kind = kind;
                    var accent = ThemeUiBrushes.Get("AccentBlue", statusFooterIcon);
                    if (accent != null)
                        statusFooterIcon.Foreground = accent;
                    StartRefreshSpin();
                }
                return;
            }

            StopRefreshSpin();
            ApplyPinnedFooter();
        }

        private void ApplyPinnedFooter()
        {
            if (_lastStatusText == null) return;

            var textKey = _lastStatusIsError ? "DangerRed" : _lastStatusIsWarning ? "AlertGold" : "TextMedium";
            var iconKey = _lastStatusIsError ? "DangerRed" : _lastStatusIsWarning ? "WarningOrange" : "SuccessGreen";
            var textBrush = ThemeUiBrushes.Get(textKey, lblStatus) ?? lblStatus?.Foreground;
            var iconBrush = ThemeUiBrushes.Get(iconKey, statusFooterIcon) ?? statusFooterIcon?.Foreground;

            if (lblStatus != null)
            {
                lblStatus.Text = _lastStatusText;
                if (textBrush != null)
                    lblStatus.Foreground = textBrush;
            }

            if (statusFooterIcon != null)
            {
                var kindName = _lastStatusIconKind ?? UiIconKinds.ForStatusFooter(_lastStatusIsError, _lastStatusIsWarning);
                if (Enum.TryParse<PackIconKind>(kindName, ignoreCase: false, out var kind))
                    statusFooterIcon.Kind = kind;
                if (iconBrush != null)
                    statusFooterIcon.Foreground = iconBrush;
            }
        }

        private void StartRefreshSpin()
        {
            if (statusFooterIcon == null) return;

            statusFooterIcon.RenderTransformOrigin = new System.Windows.Point(0.5, 0.5);
            if (statusFooterIcon.RenderTransform is not RotateTransform rotate)
            {
                rotate = new RotateTransform();
                statusFooterIcon.RenderTransform = rotate;
            }

            rotate.BeginAnimation(RotateTransform.AngleProperty, new DoubleAnimation(0, 360, TimeSpan.FromSeconds(1.1))
            {
                RepeatBehavior = RepeatBehavior.Forever
            });
        }

        private void StopRefreshSpin()
        {
            if (statusFooterIcon?.RenderTransform is RotateTransform rotate)
                rotate.BeginAnimation(RotateTransform.AngleProperty, null);
        }

        private void ApplyVersionLabels()
        {
            // Nomenclature : vM.m (README, v8.0) + M.m.p (assembly / installateur).
            var release = ProductVersionInfo.ReleaseLabel;
            var semver = ProductVersionInfo.SemVer;
            if (txtSidebarVersion != null)
                txtSidebarVersion.Text = $"{release} ({semver})";
        }

        // ── Ré-affichage depuis la systray ou IPC ────────────────────────────────
        // WM_SHOWME et le hook WndProc sont implémentés dans IpcManager.
        private void ShowWindow()
        {
            if (WindowState == WindowState.Minimized)
                WindowState = WindowState.Normal;
            Show();
            Activate();
            Topmost = true;
            Topmost = false;
        }

        // Raccourcis clavier : voir Services.KeyboardShortcuts.

        // ── Gestion de l'état de la fenêtre (minimize → systray) ────────────────
        private void SurChangementEtatFenetre(object? sender, EventArgs e)
        {
            if (WindowState == WindowState.Minimized)
            {
                Hide();
                SetStatus(OptiscanStrings.UiMessages.ProtectionReducedTray);
            }
        }

        // ── Fermeture ────────────────────────────────────────────────────────────
        private void SurFermetureFenetre(object? sender, CancelEventArgs e)
        {
            if (!_isClosing)
            {
                e.Cancel = true;
                Hide();
                SetStatus(OptiscanStrings.UiMessages.ProtectionReducedTray);
            }
            else
            {
                PerformCleanShutdown();
            }
        }

        private void PerformCleanShutdown()
        {
            try
            {
                _trayHost?.Dispose();
                _trayHost = null;

                // Désabonnement local des events branchés ici
                if (_freshclamUpdater != null) _freshclamUpdater.UpdateOutput -= SurSortieFreshclam;
                if (_rulesUpdater != null) _rulesUpdater.UpdateOutput -= SurSortieMisesAJourRegles;

                UnhookServiceContainerEvents();

                if (ViewModel != null)
                    ViewModel.PropertyChanged -= SurChangementProprieteScanViewModel;
                _navigationService.Navigated -= SurNavigationNaviguee;

                // Dispose du ViewModel (CTS, abonnements, timers)
                ViewModel?.Dispose();

                // Container partagé : c'est lui qui possède les services maintenant.
                ServiceContainer.Default.Shutdown();
            }
            catch (Exception ex)
            {
                AppLogger.Warn("MainWindow", "PerformCleanShutdown", ex);
            }
        }

        // ── Quarantaine ──────────────────────────────────────────────────────────

        // ── Mise à jour des signatures ───────────────────────────────────────────

        // Handlers nommés — souscrits une seule fois à l'init pour éviter
        // l'accumulation de lambdas anonymes à chaque clic.
        private void SurSortieFreshclam(object? sender, string line)
            => (panelAntivirus as Views.AntivirusView)?.AppendSignatureLog($"[ClamAV] {line}");

        private void SurSortieMisesAJourRegles(object? sender, string line)
            => (panelAntivirus as Views.AntivirusView)?.AppendSignatureLog($"{LocalizationService.GetString("Status_SigLogRules")} {line}");

        private async void BtnManualUpdateSignatures_Click(object sender, RoutedEventArgs e)
        {
            // Deux déclenchements rapprochés (carte Vue d'ensemble + bouton, ou double-clic)
            // lançaient un second flux qui voyait « déjà en cours » et dont le finally
            // remettait l'UI à l'état « terminé » pendant que le premier flux continuait.
            if (!_signatureUpdateRunner.TryEnterUpdate())
            {
                SetStatus(OptiscanStrings.StatusUpdates.SignaturesUpdateAlreadyRunning, isWarning: true);
                return;
            }

            SetStatus(OptiscanStrings.StatusUpdates.FullSignaturesUpdateStarting, iconKindName: UiIconKinds.Refresh);
            RefreshLiveFooter();
            var antivirusView = panelAntivirus as Views.AntivirusView;
            var completedOk = true;

            try
            {
                await Task.Yield();

                if (antivirusView != null)
                    antivirusView.SetSignatureUpdating(true);

                completedOk = await _signatureUpdateRunner.RunFullUpdateAsync(
                    _freshclamUpdater,
                    _rulesUpdater,
                    line => antivirusView?.AppendSignatureLog(line)).ConfigureAwait(true);

                InvalidateSigCache();
                await RefreshSignaturesDisplayAsync(forceRefresh: true);
            }
            catch (Exception ex)
            {
                completedOk = false;
                AppLogger.Error("MainWindow", "BtnManualUpdateSignatures_Click", ex);
                antivirusView?.AppendSignatureLog(UiLogText.Error($"Erreur : {ex.Message}"));
                SetStatus(LocalizationService.Format("Status_UpdateError", ex.Message), isError: true);
            }
            finally
            {
                antivirusView?.SetSignatureUpdating(false);
                await RefreshSignaturesDisplayAsync(); // inclut désormais YaraRulesCount + YaraStatus
                if (completedOk)
                    SetStatus(OptiscanStrings.StatusUpdates.FullSignaturesUpdateFinished);
                else
                    SetStatus(OptiscanStrings.StatusUpdates.FullSignaturesUpdateFinishedWithErrors, isWarning: true);

                RefreshLiveFooter();
                _signatureUpdateRunner.ReleaseUpdate();
            }
        }

        /// <summary>Annule la mise à jour de signatures en cours (freshclam.exe + règles YARA).</summary>
        public void BtnStopUpdateSignatures_Click(object sender, RoutedEventArgs e)
        {
            SetStatus(OptiscanStrings.StatusUpdates.SignaturesUpdateStopping, iconKindName: UiIconKinds.Stop);
            var antivirusView = panelAntivirus as Views.AntivirusView;

            // Annulation effective des process en cours (freshclam.exe + règles YARA).
            // Sans cet appel, le bouton ne faisait que masquer le spinner pendant
            // que freshclam continuait à tourner en arrière-plan.
            try { _freshclamUpdater?.CancelUpdate(); }
            catch (Exception ex) { AppLogger.Warn("MainWindow", "CancelUpdate ClamAV", ex); }

            try { _rulesUpdater?.CancelUpdate(); }
            catch (Exception ex) { AppLogger.Warn("MainWindow", "CancelUpdate règles", ex); }

            antivirusView?.AppendSignatureLog(LocalizationService.GetString("Status_SigInterrupted"));
            antivirusView?.SetSignatureUpdating(false);
        }
    }
}
