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

        private NotifyIcon? _trayIcon;
        private ContextMenuStrip? _trayMenu;

        private ClamAvEngine? _clamAvEngine;
        private YaraEngine? _yaraEngine;
        private ScanOrchestrator? _antivirusOrchestrator;
        private ScanLogManager? _logManager;
        private QuarantineManager? _quarantineManager;
        private FreshclamUpdater? _freshclamUpdater;
        private YaraForgeUpdater? _rulesUpdater;

        private readonly Services.NavigationService _navigationService = new();
        private readonly SemaphoreSlim _manualSignatureUpdateLock = new(1, 1);
        private readonly RoutedCommand _quickScanShortcutCommand = new();
        private bool _isClosing = false;
        private bool _wasScanning;
        private bool _isSyncingSidebarSelection;
        private string? _lastStatusText;
        private bool _lastStatusIsError;
        private bool _lastStatusIsWarning;
        private string? _lastStatusIconKind;

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
                InitializeTrayIcon();

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
                _freshclamUpdater.UpdateCompleted += (_, _) =>
                    Dispatcher.InvokeAsync(RefreshSignaturesDisplay);
                _rulesUpdater.UpdateCompleted += (_, _) =>
                    Dispatcher.InvokeAsync(RefreshSignaturesDisplay);

                // ViewModel partage le même container : pas de re-instanciation.
                ViewModel = new ScanViewModel(c);
                ViewModel.PropertyChanged -= SurChangementProprieteScanViewModel;
                ViewModel.PropertyChanged += SurChangementProprieteScanViewModel;
                _wasScanning = ViewModel.IsScanning;
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
                c.ExportLastScanPdfRequested += SurDemandeExportDernierScanPdf;
                c.ExportScanSessionPdfRequested += SurDemandeExportSessionScanPdf;
                c.RealTimeProtection.ThreatDetected += SurMenaceTempsReelDetectee;
                c.Notifications.ToastActivated -= SurActivationToast;
                c.Notifications.ToastActivated += SurActivationToast;
                c.Notifications.SyncFromUserPreferences();

                // Abonnement aux événements
                this.Loaded += async (s, e) => await SurChargementFenetrePrincipale();
                this.Closing += SurFermetureFenetre;
                this.StateChanged += SurChangementEtatFenetre;

                // IPC : une seconde instance envoie un message Windows pour réafficher cette fenêtre (IpcManager).
                IpcManager.HookShowMessage(this, ShowWindow);

                ThemeManager.ThemeChanged += SurChangementTheme;

                // Raccourcis Ctrl+1..Ctrl+5 : une seule RoutedCommand, le paramètre est le nom du panneau.
                KeyboardShortcuts.Register(this,
                    new[] { OptiscanStrings.PanelIds.Overview, OptiscanStrings.PanelIds.Antivirus, OptiscanStrings.PanelIds.Clean, OptiscanStrings.PanelIds.History, OptiscanStrings.PanelIds.Options },
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

        private void InitializeTrayIcon()
        {
            // Si la fenêtre est recréée (rare), éviter de dupliquer l'icône tray.
            if (_trayIcon != null)
                return;

            _trayMenu = new ContextMenuStrip();
            _trayMenu.Items.Add(LocalizationService.GetString("Tray_Open"), null, (_, _) => Dispatcher.Invoke(ShowWindowFromTray));
            _trayMenu.Items.Add(new ToolStripSeparator());
            _trayMenu.Items.Add(LocalizationService.GetString("Tray_Exit"), null, (_, _) => Dispatcher.Invoke(ExitFromTray));

            // Priorité 1 : icône embarquée dans optiSCAN.exe (toujours présente après publish).
            // Priorité 2 : optiSCAN.ico à côté de l'exécutable.
            // Repli final : icône système.
            var icon = ResolveTrayIcon();

            _trayIcon = new NotifyIcon
            {
                Text = "optiSCAN",
                Icon = icon,
                Visible = true,
                ContextMenuStrip = _trayMenu
            };

            _trayIcon.MouseClick += (_, e) =>
            {
                if (e.Button == MouseButtons.Left)
                    Dispatcher.Invoke(ShowWindowFromTray);
            };
            _trayIcon.DoubleClick += (_, _) => Dispatcher.Invoke(ShowWindowFromTray);
        }

        private static System.Drawing.Icon ResolveTrayIcon()
        {
            try
            {
                var processPath = Environment.ProcessPath;
                if (!string.IsNullOrWhiteSpace(processPath) && File.Exists(processPath))
                {
                    var embedded = System.Drawing.Icon.ExtractAssociatedIcon(processPath);
                    if (embedded != null)
                        return embedded;
                }
            }
            catch
            {
                // Continue vers fallback fichier.
            }

            try
            {
                var iconPath = Path.Combine(AppContext.BaseDirectory, "optiSCAN.ico");
                if (File.Exists(iconPath))
                    return new System.Drawing.Icon(iconPath);
            }
            catch
            {
                // Continue vers fallback système.
            }

            return System.Drawing.SystemIcons.Application;
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
                RefreshSignaturesDisplay();
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

            _navigationService.Navigated -= SurNavigationNaviguee;
            _navigationService.Navigated += SurNavigationNaviguee;
        }

        private void SurNavigationNaviguee(object? sender, string panelName) =>
            Dispatcher.BeginInvoke(() =>
            {
                SyncSidebarSelection(panelName);
                ApplyNavigationSideEffects(panelName);
            }, DispatcherPriority.Background);

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
            if (e.PropertyName != nameof(ScanViewModel.IsScanning) || ViewModel == null)
                return;

            if (_wasScanning && !ViewModel.IsScanning)
                Dispatcher.BeginInvoke(RefreshHistory, GetHistoryRefreshPriority());

            _wasScanning = ViewModel.IsScanning;
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

        private void UnhookServiceContainerEvents()
        {
            var c = ServiceContainer.Default;
            c.RequestSignatureUpdate -= SurDemandeMiseAJourSignatures;
            c.ScanHistoryViewsRefreshRequested -= SurDemandeRafraichissementHistorique;
            c.ExportScanHistoryHtmlRequested -= SurDemandeExportHistoriqueHtml;
            c.ExportLastScanPdfRequested -= SurDemandeExportDernierScanPdf;
            c.ExportScanSessionPdfRequested -= SurDemandeExportSessionScanPdf;
            c.FocusAntivirusSignaturesRequested -= SurDemandeFocusSignaturesAntivirus;
            c.RealTimeProtection.ThreatDetected -= SurMenaceTempsReelDetectee;
            c.Notifications.ToastActivated -= SurActivationToast;
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

        /// <summary>
        /// Rafraîchissements déclenchés à chaque <see cref="NavigationService.NavigateTo"/>,
        /// y compris depuis les cartes Vue d'ensemble ou la fin d'analyse (pas seulement la sidebar).
        /// </summary>
        private void ApplyNavigationSideEffects(string panelName)
        {
            if (_logManager == null)
                return;

            switch (panelName)
            {
                case OptiscanStrings.PanelIds.Overview:
                    RefreshHistory();
                    RefreshAntivirusStatus();
                    RefreshSignaturesDisplay();
                    break;
                case OptiscanStrings.PanelIds.Antivirus:
                    RefreshAntivirusData();
                    break;
                case OptiscanStrings.PanelIds.History:
                    RefreshHistory();
                    break;
            }
        }

        // ── Rafraîchissement ─────────────────────────────────────────────────────
        // RefreshYaraStatus() est intentionnellement supprimé : YaraRulesCount et
        // YaraStatus sont désormais synchronisés dans RefreshSignaturesDisplay()
        // via le ViewModel, et UpdateYaraStatus() de AntivirusView est supprimée.

        private void RefreshAntivirusStatus()
        {
            bool clamAvOk = _clamAvEngine?.IsClamAvInstalled() ?? false;
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

            // Mettre à jour la carte État Antivirus dans la vue d'ensemble
            (panelOverview as Views.OverviewControl)?.UpdateAntivirusCardStatus(clamAvOk, yaraRules);
        }

        private void RefreshQuarantineList()
        {
            ViewModel?.RefreshQuarantineList();
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
            DateTime? last = sessions.Count == 0 ? null : sessions.Max(s => s.StartedAt);
            (panelOverview as Views.OverviewControl)?.UpdateLastScanTime(last);
            (panelAntivirus as Views.AntivirusView)?.UpdateLastScanDisplay(last);
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

                case "open":
                case "threat":
                    ShowWindow();
                    _navigationService.NavigateTo(OptiscanStrings.PanelIds.Antivirus);
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

        /// <summary>Bannière + recommandations de la vue d’ensemble (données réelles).</summary>
        /// <remarks>
        /// Construit la synthèse en combinant l'état des moteurs (ClamAV/YARA) et l'historique
        /// (proposition de nettoyage basé sur la date du dernier nettoyage).
        /// </remarks>
        private void RefreshOverviewProtectionAndRecommendations()
        {
            var overview = panelOverview as Views.OverviewControl;
            if (overview == null) return;

            bool clam = _clamAvEngine?.IsClamAvInstalled() ?? false;
            int yaraRules = _yaraEngine?.RulesCount ?? 0;
            bool yaraAvail = _yaraEngine?.IsAvailable ?? false;
            bool protectedOk = clam && (!yaraAvail || yaraRules > 0);

            var clamVer = _freshclamUpdater?.GetLocalDatabaseVersion() ?? "—";
            var clamWhen = _freshclamUpdater?.GetLastSignatureChangeDisplay() ?? "—";
            var yaraPack = _rulesUpdater?.GetRulesPackVersionDisplay() ?? "—";
            var yaraWhen = _rulesUpdater?.GetRulesLastUpdateDisplay() ?? "—";

            var statusSb = new StringBuilder();
            if (clam)
                statusSb.AppendLine(LocalizationService.Format("Rec_StatusClamOk", clamVer, clamWhen));
            else
                statusSb.AppendLine(LocalizationService.GetString("Rec_StatusClamMissing"));
            statusSb.Append(LocalizationService.Format("Rec_StatusYara", yaraRules, yaraPack, yaraWhen));
            overview.UpdateProtectionStatus(protectedOk, statusSb.ToString().Trim());

            string sig = !clam
                ? LocalizationService.GetString("Rec_SigClamMissing")
                : (!yaraAvail || yaraRules == 0
                    ? LocalizationService.GetString("Rec_SigNoYara")
                    : LocalizationService.Format("Rec_SigReady", yaraRules));
            int sigSev = !clam || !yaraAvail || yaraRules == 0 ? 1 : 0;

            var cleanHist = _logManager?.GetCleanHistory() ?? Array.Empty<CleanSession>();
            DateTime? lastClean = cleanHist.Count > 0 ? cleanHist[0].StartedAt : null;
            bool suggestClean = !lastClean.HasValue || (DateTime.Now - lastClean.Value).TotalDays > 14;
            string hyp = suggestClean
                ? LocalizationService.GetString("Rec_CleanSuggest")
                : LocalizationService.Format("Rec_CleanRecent", lastClean!.Value.ToString("d", LocalizationService.CurrentCulture));
            int hypSev = suggestClean ? 1 : 0;

            var sessions = _logManager?.GetHistory() ?? Array.Empty<ScanSession>();
            var cutoff = DateTime.Now.AddDays(-30);
            int threats30 = sessions.Where(s => s.StartedAt >= cutoff).Sum(s => s.ThreatsFound);
            string act = sessions.Count == 0
                ? LocalizationService.GetString("Rec_ActNone")
                : threats30 > 0
                    ? LocalizationService.Format("Rec_ActThreats", threats30)
                    : LocalizationService.GetString("Rec_ActOk");
            int actSev = threats30 > 0 ? 1 : (sessions.Count == 0 ? 1 : 2);

            overview.UpdateRecommendations(sig, sigSev, hyp, hypSev, act, actSev);
        }

        public void RefreshAntivirusData()
        {
            RefreshAntivirusStatus();
            RefreshQuarantineList();
            RefreshHistory();
            RefreshSignaturesDisplay();
        }

        /// <summary>Rafraîchit les blocs YARA | ClamAV (Signatures + Vue d'ensemble + VM).</summary>
        private void RefreshSignaturesDisplay()
        {
            var clamVer = _freshclamUpdater?.GetLocalDatabaseVersion() ?? "—";
            var clamWhen = _freshclamUpdater?.GetLastSignatureChangeDisplay() ?? "—";
            var yaraVer = _rulesUpdater?.GetRulesPackVersionDisplay() ?? "—";
            var yaraWhen = _rulesUpdater?.GetRulesLastUpdateDisplay() ?? "—";

            (panelAntivirus as Views.AntivirusView)?.UpdateSignaturesPanel(yaraVer, yaraWhen, clamVer, clamWhen);
            (panelOverview as Views.OverviewControl)?.UpdateSignaturesSummary(yaraVer, yaraWhen, clamVer, clamWhen);

            if (ViewModel != null)
            {
                ViewModel.DbVersion = clamVer;
                ViewModel.RulesPackVersion = yaraVer;
                ViewModel.LastUpdateDisplay = clamWhen == "—" ? "Jamais" : clamWhen;
                ViewModel.RulesLastUpdateDisplay = yaraWhen == "—" ? "Jamais" : yaraWhen;
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

        private void SurDemandeExportDernierScanPdf(object? sender, EventArgs e) =>
            Dispatcher.BeginInvoke(new Action(TryExportLastScanPdf), DispatcherPriority.Background);

        private void SurDemandeExportSessionScanPdf(object? sender, ScanSession session) =>
            Dispatcher.BeginInvoke(new Action(() => TryExportScanSessionPdf(session)), DispatcherPriority.Background);

        private void TryExportScanReportHtml()
        {
            try
            {
                var dlg = new Microsoft.Win32.SaveFileDialog
                {
                    Filter = "Page web HTML (*.html)|*.html|Tous les fichiers (*.*)|*.*",
                    FileName = $"optiSCAN_rapport_{DateTime.Now:yyyyMMdd_HHmm}.html",
                    DefaultExt = ".html",
                    AddExtension = true
                };
                if (dlg.ShowDialog(this) != true) return;

                var html = new HtmlExportService();
                var hist = _logManager?.GetHistory() ?? Array.Empty<ScanSession>();
                var threats = ViewModel?.Threats ?? Enumerable.Empty<ThreatInfo>();
                var quar = _quarantineManager?.GetEntries() ?? Array.Empty<QuarantineEntry>();
                html.ExportFullReport(hist, threats, quar, UserPreferences.Current, dlg.FileName);
                SetStatus(LocalizationService.Format("Status_HtmlSaved", dlg.FileName));
            }
            catch (Exception ex)
            {
                AppLogger.Error("MainWindow", "Export HTML", ex);
                SetStatus(LocalizationService.Format("Status_HtmlFailed", ex.Message), isError: true);
            }
        }

        private void TryExportLastScanPdf()
        {
            var sessions = _logManager?.GetHistory() ?? Array.Empty<ScanSession>();
            if (sessions.Count == 0)
            {
                System.Windows.MessageBox.Show(this,
                    LocalizationService.GetString("Status_ExportNoHistory"),
                    LocalizationService.GetString("Hist_ExportPdfTitle"),
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
                return;
            }
            TryExportScanSessionPdf(sessions[0]);
        }

        private void TryExportScanSessionPdf(ScanSession session)
        {
            try
            {
                var dlg = new Microsoft.Win32.SaveFileDialog
                {
                    Filter = "Document PDF (*.pdf)|*.pdf|Tous les fichiers (*.*)|*.*",
                    FileName = $"optiSCAN_scan_{session.StartedAt:yyyyMMdd_HHmm}.pdf",
                    DefaultExt = ".pdf",
                    AddExtension = true
                };
                if (dlg.ShowDialog(this) != true) return;

                var gen = new PdfReportGenerator();
                gen.GenerateReportFromSession(session, dlg.FileName);
                SetStatus(LocalizationService.Format("Status_PdfSaved", dlg.FileName));
            }
            catch (Exception ex)
            {
                AppLogger.Error("MainWindow", "Export PDF", ex);
                SetStatus(LocalizationService.Format("Status_PdfFailed", ex.Message), isError: true);
            }
        }

        // ── Statut ───────────────────────────────────────────────────────────────
        private void SurChangementTheme(object? sender, bool isDark)
        {
            Dispatcher.InvokeAsync(() =>
            {
                RefreshAntivirusStatus();
                RefreshOverviewProtectionAndRecommendations();
                if (_lastStatusText != null)
                    SetStatus(_lastStatusText, _lastStatusIsError, _lastStatusIsWarning, _lastStatusIconKind);
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
                var textKey = isError ? "DangerRed" : isWarning ? "AlertGold" : "TextMedium";
                var iconKey = isError ? "DangerRed" : isWarning ? "WarningOrange" : "SuccessGreen";
                var textBrush = ThemeUiBrushes.Get(textKey, lblStatus) ?? lblStatus?.Foreground;
                var iconBrush = ThemeUiBrushes.Get(iconKey, statusFooterIcon) ?? statusFooterIcon?.Foreground;

                if (lblStatus != null)
                {
                    lblStatus.Text = text;
                    if (textBrush != null)
                        lblStatus.Foreground = textBrush;
                }

                if (statusFooterIcon != null)
                {
                    var kindName = iconKindName ?? UiIconKinds.ForStatusFooter(isError, isWarning);
                    if (Enum.TryParse<PackIconKind>(kindName, ignoreCase: false, out var kind))
                        statusFooterIcon.Kind = kind;
                    if (iconBrush != null)
                        statusFooterIcon.Foreground = iconBrush;
                }

                AppLogger.Debug("MainWindow", $"Statut: {text}");
            });
        }

        private void ApplyVersionLabels()
        {
            // Nomenclature : vM.m (README, v6.0) + M.m.p (assembly / installateur).
            var release = ProductVersionInfo.ReleaseLabel;
            var semver = ProductVersionInfo.SemVer;
            if (txtSidebarVersion != null)
                txtSidebarVersion.Text = $"{release} ({semver})";
            if (txtFooterVersion != null)
                txtFooterVersion.Text = LocalizationService.Format("Main_FooterVersion", release);
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
                // Retirer l'icône tray pour éviter qu'elle reste "fantôme" (explorer).
                if (_trayIcon != null)
                {
                    _trayIcon.Visible = false;
                    _trayIcon.Dispose();
                    _trayIcon = null;
                }
                _trayMenu?.Dispose();
                _trayMenu = null;

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

        /// <summary>Met le fichier identifié par <c>btn.Tag</c> en quarantaine chiffrée.</summary>
        public void BtnQuarantineThreat_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is string filePath)
            {
                var c = ServiceContainer.Default;
                var known = c.FindKnownThreat(filePath);
                var result = known != null
                    ? c.Actions.QuarantineThreat(known.Clone())
                    : c.Actions.QuarantineThreat(filePath);
                SetStatus(result.Message, isError: result.IsError);
                if (result.Success)
                {
                    RefreshQuarantineList();
                    ((Views.AntivirusView)panelAntivirus)?.RefreshAllData();
                }
            }
        }

        /// <summary>Ajoute le fichier identifié par <c>btn.Tag</c> aux exclusions (ignoré lors des futurs scans).</summary>
        public void BtnIgnoreThreat_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is string filePath)
            {
                ExclusionSettings.Current.AddFile(filePath);
                SetStatus(LocalizationService.Format("Status_FileIgnored", System.IO.Path.GetFileName(filePath)), isWarning: true);
                ((Views.AntivirusView)panelAntivirus)?.RefreshAllData();
            }
        }

        /// <summary>Supprime définitivement le fichier identifié par <c>btn.Tag</c>.</summary>
        public void BtnDeleteThreat_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is string filePath)
            {
                try
                {
                    if (System.IO.File.Exists(filePath))
                    {
                        System.IO.File.Delete(filePath);
                        SetStatus(LocalizationService.Format("Status_FileDeleted", System.IO.Path.GetFileName(filePath)), iconKindName: UiIconKinds.Delete);
                    }
                    ((Views.AntivirusView)panelAntivirus)?.RefreshAllData();
                }
                catch (Exception ex)
                {
                    SetStatus(LocalizationService.Format("Status_DeleteFailed", ex.Message), isError: true);
                }
            }
        }

        /// <summary>Restaure un fichier depuis la quarantaine vers son emplacement d'origine.</summary>
        public void BtnRestoreFromQuarantine_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is string quarantineId)
            {
                if (_quarantineManager?.Restore(quarantineId) == true)
                {
                    SetStatus(OptiscanStrings.UiMessages.RestoreFromQuarantineSuccess);
                    RefreshQuarantineList();
                    ((Views.AntivirusView)panelAntivirus)?.RefreshAllData();
                }
                else
                {
                    SetStatus(OptiscanStrings.UiMessages.RestoreFromQuarantineError, isError: true);
                }
            }
        }

        /// <summary>Supprime définitivement un fichier de la quarantaine (pas de restauration possible).</summary>
        public void BtnDeleteFromQuarantine_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is string quarantineId)
            {
                if (_quarantineManager?.DeletePermanently(quarantineId) == true)
                {
                    SetStatus(OptiscanStrings.UiMessages.DeleteThreatPermanentlySuccess, iconKindName: UiIconKinds.Delete);
                    RefreshQuarantineList();
                    ((Views.AntivirusView)panelAntivirus)?.RefreshAllData();
                }
                else
                {
                    SetStatus(OptiscanStrings.UiMessages.DeleteThreatPermanentlyError, isError: true);
                }
            }
        }

        // ── Mise à jour des signatures ───────────────────────────────────────────

        // Handlers nommés — souscrits une seule fois à l'init pour éviter
        // l'accumulation de lambdas anonymes à chaque clic.
        private void SurSortieFreshclam(object? sender, string line)
            => (panelAntivirus as Views.AntivirusView)?.AppendSignatureLog($"[ClamAV] {line}");

        private void SurSortieMisesAJourRegles(object? sender, string line)
            => (panelAntivirus as Views.AntivirusView)?.AppendSignatureLog($"{LocalizationService.GetString("Status_SigLogRules")} {line}");

        public async void BtnManualUpdateSignatures_Click(object sender, RoutedEventArgs e)
        {
            // Deux déclenchements rapprochés (carte Vue d'ensemble + bouton, ou double-clic)
            // lançaient un second flux qui voyait « déjà en cours » et dont le finally
            // remettait l'UI à l'état « terminé » pendant que le premier flux continuait.
            if (!await _manualSignatureUpdateLock.WaitAsync(0))
            {
                SetStatus(OptiscanStrings.StatusUpdates.SignaturesUpdateAlreadyRunning, isWarning: true);
                return;
            }

            SetStatus(OptiscanStrings.StatusUpdates.FullSignaturesUpdateStarting, iconKindName: UiIconKinds.Refresh);
            var antivirusView = panelAntivirus as Views.AntivirusView;
            var completedOk = true;

            try
            {
                await Task.Yield();

                if (antivirusView != null)
                    antivirusView.SetSignatureUpdating(true);

                // Travail réseau / sous-processus hors thread UI pour garder la fenêtre réactive.
                completedOk = await Task.Run(async () =>
                    await SignatureUpdateCoordinator.RunFullSignatureUpdateAsync(
                        _freshclamUpdater,
                        _rulesUpdater,
                        line => antivirusView?.AppendSignatureLog(line)).ConfigureAwait(false)).ConfigureAwait(true);

                RefreshSignaturesDisplay();
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
                RefreshSignaturesDisplay(); // inclut désormais YaraRulesCount + YaraStatus
                if (completedOk)
                    SetStatus(OptiscanStrings.StatusUpdates.FullSignaturesUpdateFinished);
                else
                    SetStatus(OptiscanStrings.StatusUpdates.FullSignaturesUpdateFinishedWithErrors, isWarning: true);

                _manualSignatureUpdateLock.Release();
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

        // ── Accès aux services ───────────────────────────────────────────────────
        /// <summary>Retourne le gestionnaire de quarantaine partagé.</summary>
        public QuarantineManager? GetQuarantineManager() => _quarantineManager;
        /// <summary>Retourne le gestionnaire de journaux de scan.</summary>
        public ScanLogManager? GetLogManager() => _logManager;
        /// <summary>Retourne l'orchestrateur ClamAV + YARA partagé.</summary>
        public ScanOrchestrator? GetOrchestrator() => _antivirusOrchestrator;
        /// <summary>Retourne le service de mise à jour des signatures ClamAV.</summary>
        public FreshclamUpdater? GetFreshclamUpdater() => _freshclamUpdater;
        /// <summary>Retourne le service de mise à jour des règles YARA.</summary>
        public YaraForgeUpdater? GetRulesUpdater() => _rulesUpdater;
    }
}
