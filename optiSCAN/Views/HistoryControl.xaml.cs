using optiSCAN.Localization;

using optiSCAN.Models;

using optiSCAN.Services;

using optiSCAN.Strings;

using optiSCAN.ViewModels;

using System.Globalization;

using System.Windows;

using System.Windows.Controls;

using System.Windows.Media;

using System.Windows.Threading;

using Brush = System.Windows.Media.Brush;

using Button = System.Windows.Controls.Button;

using RadioButton = System.Windows.Controls.RadioButton;



namespace optiSCAN.Views

{

    /// <summary>

    /// Historique unifié (journal d'activité) avec filtres chips et traitement des menaces.

    /// </summary>

    public partial class HistoryControl : System.Windows.Controls.UserControl

    {

        private ServiceContainer? _services;
        private IUiEventBus _uiEvents = ServiceContainer.UiEvents;
        private AntivirusActions? _actions;
        private ScanLogManager? _logger;
        private bool _bound;
        private bool _syncingFilterChips;

        public HistoryViewModel VM { get; private set; } = null!;

        private AntivirusActions Actions => _actions ?? throw new InvalidOperationException("HistoryControl.Bind() must be called before use.");
        private ScanLogManager Logger => _logger ?? throw new InvalidOperationException("HistoryControl.Bind() must be called before use.");

        public HistoryControl()
        {
            InitializeComponent();
            Loaded += OnLoaded;
            Unloaded += OnUnloaded;
        }

        /// <summary>Branche les services partagés (appelé par <see cref="optiSCAN.MainWindow"/> au démarrage).</summary>
        public void Bind(ServiceContainer services)
        {
            if (_bound)
                return;
            _bound = true;
            _services = services;
            _uiEvents = services;
            _actions = services.Actions;
            _logger = services.Logger;
            VM = new HistoryViewModel(services);
            DataContext = VM;
            VM.PropertyChanged += OnViewModelPropertyChanged;
        }



        public void RefreshTimeline()

        {

            VM.Refresh();

            SyncFilterChips();

            UpdateDetailPanels();

        }



        private void OnLoaded(object sender, RoutedEventArgs e)

        {

            _uiEvents.ScanHistoryViewsRefreshRequested += OnExternalRefreshRequested;

            RefreshTimeline();

        }



        private void OnUnloaded(object sender, RoutedEventArgs e)

        {

            _uiEvents.ScanHistoryViewsRefreshRequested -= OnExternalRefreshRequested;

        }



        private void OnExternalRefreshRequested(object? sender, EventArgs e)

        {

            if (!IsLoaded) return;

            Dispatcher.BeginInvoke(RefreshTimeline, DispatcherPriority.Background);

        }



        private void OnViewModelPropertyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)

        {

            switch (e.PropertyName)

            {

                case nameof(HistoryViewModel.SelectedEntry):

                case nameof(HistoryViewModel.ShowScanActions):

                case nameof(HistoryViewModel.ShowQuarantineReadOnly):

                case nameof(HistoryViewModel.HasQuarantineSourceScan):

                    UpdateDetailPanels();

                    break;

                case nameof(HistoryViewModel.SelectedFilter):

                    SyncFilterChips();

                    break;

            }

        }



        private void SyncFilterChips()

        {

            if (!IsLoaded) return;



            var tag = VM.SelectedFilter switch

            {

                HistoryFilter.Threats => "Threats",

                HistoryFilter.CleanScans => "CleanScans",

                HistoryFilter.Cleans => "Cleans",

                HistoryFilter.Quarantine => "Quarantine",

                _ => "All",

            };



            _syncingFilterChips = true;

            try

            {

                if (chipAll != null) chipAll.IsChecked = tag == "All";

                if (chipThreats != null) chipThreats.IsChecked = tag == "Threats";

                if (chipClean != null) chipClean.IsChecked = tag == "CleanScans";

                if (chipSweep != null) chipSweep.IsChecked = tag == "Cleans";

                if (chipQuarantine != null) chipQuarantine.IsChecked = tag == "Quarantine";

            }

            finally

            {

                _syncingFilterChips = false;

            }

        }



        private void Chip_Checked(object sender, RoutedEventArgs e)

        {

            if (_syncingFilterChips || sender is not RadioButton { Tag: string tag } || !IsLoaded) return;

            VM.SelectedFilter = tag switch

            {

                "Threats" => HistoryFilter.Threats,

                "CleanScans" => HistoryFilter.CleanScans,

                "Cleans" => HistoryFilter.Cleans,

                "Quarantine" => HistoryFilter.Quarantine,

                _ => HistoryFilter.All,

            };

        }



        private void UpdateDetailPanels()

        {

            var entry = VM.SelectedEntry;

            if (entry == null)

            {

                ShowNoSelectionHint();

                HideDetailPanels();

                return;

            }



            if (txtNoSelHint != null)

                txtNoSelHint.Visibility = Visibility.Collapsed;

            if (sessionInfoBar != null)

                sessionInfoBar.Visibility = Visibility.Visible;



            ShowEntryInfo(entry);



            if (entry.Kind == ActivityKind.Quarantine)

                ShowQuarantineDetail(entry);

            else if (entry.Kind == ActivityKind.Clean)

                ShowCleanDetail(entry.CleanSession);

            else

                ShowScanDetail(entry.ScanSession);

        }



        private void ShowNoSelectionHint()

        {

            if (sessionInfoBar != null)

                sessionInfoBar.Visibility = Visibility.Collapsed;

            if (txtNoSelHint != null)

                txtNoSelHint.Visibility = Visibility.Visible;

            HideDetailPanels();

        }



        private void HideDetailPanels()

        {

            if (dgHistoryThreats != null)

            {

                dgHistoryThreats.ItemsSource = null;

                dgHistoryThreats.Visibility = Visibility.Collapsed;

            }

            if (cleanLogPanel != null)

                cleanLogPanel.Visibility = Visibility.Collapsed;

            if (quarantineDetailPanel != null)

                quarantineDetailPanel.Visibility = Visibility.Collapsed;

            if (noThreatsState != null)

                noThreatsState.Visibility = Visibility.Collapsed;

            if (txtHistThreatsLegacy != null)

                txtHistThreatsLegacy.Visibility = Visibility.Collapsed;

        }



        private void ShowEntryInfo(ActivityEntry entry)

        {

            var cult = CultureInfo.CurrentCulture;



            if (txtSessionDate != null)

                txtSessionDate.Text = entry.StartedAt.ToString("dd/MM/yyyy HH:mm", cult);



            if (txtSessionMeta != null)

            {

                txtSessionMeta.Text = entry.Kind switch

                {

                    ActivityKind.Clean => entry.CleanSession?.TargetsSummary ?? entry.TargetDisplay,

                    ActivityKind.Quarantine => entry.DetailDisplay,

                    _ => entry.ScanSession != null

                        ? LocalizationService.Format("Hist_InfoFiles", entry.ScanSession.FilesScanned.ToString("N0", cult))

                        : string.Empty,

                };

            }



            if (txtSessionResult != null)

            {

                txtSessionResult.Text = entry.ResultSummary;

                ApplyResultChipStyle(entry);

            }

        }



        private void ApplyResultChipStyle(ActivityEntry entry)

        {

            if (txtSessionResult == null) return;



            if (entry.HasThreats)

            {

                txtSessionResult.Foreground = TryFindBrush("DangerRed") ?? txtSessionResult.Foreground;

                if (resultChip != null)

                    resultChip.Background = TryFindBrush("RiskMinor") ?? resultChip.Background;

            }

            else if (entry.Kind == ActivityKind.Clean)

            {

                txtSessionResult.Foreground = TryFindBrush("TextAccent") ?? txtSessionResult.Foreground;

                if (resultChip != null)

                    resultChip.Background = TryFindBrush("InfoBg") ?? resultChip.Background;

            }

            else if (entry.Kind == ActivityKind.Quarantine)

            {

                txtSessionResult.Foreground = TryFindBrush("WarningOrange") ?? txtSessionResult.Foreground;

                if (resultChip != null)

                    resultChip.Background = TryFindBrush("SurfaceBg") ?? resultChip.Background;

            }

            else

            {

                txtSessionResult.Foreground = TryFindBrush("SuccessGreen") ?? txtSessionResult.Foreground;

                if (resultChip != null)

                    resultChip.Background = TryFindBrush("SuccessBg") ?? resultChip.Background;

            }

        }



        private void ShowScanDetail(ScanSession? session)

        {

            if (cleanLogPanel != null)

                cleanLogPanel.Visibility = Visibility.Collapsed;

            if (quarantineDetailPanel != null)

                quarantineDetailPanel.Visibility = Visibility.Collapsed;



            var hasStoredThreats = session?.Threats.Count > 0;

            var sessionSelected = session != null;

            var legacyOnly = sessionSelected && session!.ThreatsFound > 0 && session.Threats.Count == 0;



            if (dgHistoryThreats != null)

            {

                dgHistoryThreats.ItemsSource = hasStoredThreats
                    ? VM.BuildThreatRows(session!.Threats)
                    : null;

                dgHistoryThreats.Visibility = hasStoredThreats ? Visibility.Visible : Visibility.Collapsed;

            }



            if (noThreatsState != null)

                noThreatsState.Visibility = (sessionSelected && !hasStoredThreats && !legacyOnly)

                    ? Visibility.Visible : Visibility.Collapsed;



            if (txtHistThreatsLegacy != null)

                txtHistThreatsLegacy.Visibility = legacyOnly ? Visibility.Visible : Visibility.Collapsed;

        }



        private void ShowQuarantineDetail(ActivityEntry entry)

        {

            if (dgHistoryThreats != null)

                dgHistoryThreats.Visibility = Visibility.Collapsed;

            if (cleanLogPanel != null)

                cleanLogPanel.Visibility = Visibility.Collapsed;

            if (noThreatsState != null)

                noThreatsState.Visibility = Visibility.Collapsed;

            if (txtHistThreatsLegacy != null)

                txtHistThreatsLegacy.Visibility = Visibility.Collapsed;



            if (quarantineDetailPanel == null)

                return;



            quarantineDetailPanel.Visibility = Visibility.Visible;

            var q = entry.QuarantineEntry;



            if (txtQuarTitle != null)

                txtQuarTitle.Text = q?.FileName ?? entry.TypeDisplay;

            if (txtQuarPath != null)

                txtQuarPath.Text = q != null

                    ? LocalizationService.Format("Hist_DetailQuarantinePath", q.OriginalPath)

                    : entry.TargetDisplay;

            if (txtQuarMeta != null && q != null)

                txtQuarMeta.Text = LocalizationService.Format("Hist_DetailQuarantineMeta", q.VirusName, q.SizeDisplay);

            if (txtQuarStatus != null)

            {

                txtQuarStatus.Text = entry.IsStillQuarantined

                    ? LocalizationService.GetString("Hist_QuarantineStillActive")

                    : LocalizationService.GetString("Hist_QuarantineHistorical");

            }

            if (btnManageInAv != null)

                btnManageInAv.IsEnabled = entry.IsStillQuarantined;

        }



        private void ShowCleanDetail(CleanSession? session)

        {

            if (dgHistoryThreats != null)

                dgHistoryThreats.Visibility = Visibility.Collapsed;

            if (quarantineDetailPanel != null)

                quarantineDetailPanel.Visibility = Visibility.Collapsed;

            if (noThreatsState != null)

                noThreatsState.Visibility = Visibility.Collapsed;

            if (txtHistThreatsLegacy != null)

                txtHistThreatsLegacy.Visibility = Visibility.Collapsed;



            if (cleanLogPanel == null || txtCleanLog == null)

                return;



            cleanLogPanel.Visibility = Visibility.Visible;

            if (session == null)

            {

                txtCleanLog.Text = LocalizationService.GetString("Hist_DetailSelectClean");

                return;

            }



            txtCleanLog.Text = !string.IsNullOrWhiteSpace(session.OperationLog)

                ? session.OperationLog

                : LocalizationService.Format(

                    "Hist_DetailCleanSummary",

                    session.TargetsSummary ?? string.Empty,

                    session.BytesDisplay ?? string.Empty,

                    session.DurationDisplay ?? string.Empty);

        }



        private static string? FilePathFromSender(object sender) =>

            sender is Button { Tag: string path } && !string.IsNullOrEmpty(path) ? path : null;



        private Brush? TryFindBrush(string key)

        {

            try { return TryFindResource(key) as Brush; }

            catch { return null; }

        }



        private ScanSession? SelectedScanSession => VM.SelectedEntry?.ScanSession;



        private void BtnTreatInAntivirus_Click(object sender, RoutedEventArgs e)

        {

            if (SelectedScanSession is not { Threats.Count: > 0 } session) return;

            _uiEvents.RequestReviewHistorySession(session);

        }



        private void BtnHistQuarantineAll_Click(object sender, RoutedEventArgs e)
        {
            if (SelectedScanSession is not ScanSession session || session.Threats.Count == 0) return;

            int count = 0;
            foreach (var t in session.Threats.ToList())
            {
                if (!VM.IsThreatFileAccessible(t.FilePath))
                    continue;
                if (_services!.Quarantine.Quarantine(t, session.SessionId))
                {
                    count++;
                    Logger.TryRemoveThreatFromSession(session.SessionId, t.FilePath);
                }
            }

            if (count > 0)
                RefreshTimeline();
        }



        private void BtnHistQuarantine_Click(object sender, RoutedEventArgs e)
        {
            if (FilePathFromSender(sender) is not string filePath ||
                SelectedScanSession is not ScanSession session) return;

            if (VM.IsFileStillQuarantined(filePath))
            {
                Logger.TryRemoveThreatFromSession(session.SessionId, filePath);
                RefreshTimeline();
                return;
            }

            if (Actions.QuarantineThreat(filePath, session.SessionId).Success)
            {
                Logger.TryRemoveThreatFromSession(session.SessionId, filePath);
                RefreshTimeline();
            }
        }

        private void BtnHistDismiss_Click(object sender, RoutedEventArgs e)
        {
            if (FilePathFromSender(sender) is not string filePath ||
                SelectedScanSession is not ScanSession session) return;
            Logger.TryRemoveThreatFromSession(session.SessionId, filePath);
            RefreshTimeline();
        }



        private void BtnHistIgnore_Click(object sender, RoutedEventArgs e)

        {

            if (FilePathFromSender(sender) is not string filePath ||

                SelectedScanSession is not ScanSession session) return;

            Actions.IgnoreThreat(filePath);

            Logger.TryRemoveThreatFromSession(session.SessionId, filePath);

            RefreshTimeline();

        }



        private void BtnHistDelete_Click(object sender, RoutedEventArgs e)

        {

            if (FilePathFromSender(sender) is not string filePath ||

                SelectedScanSession is not ScanSession session) return;

            if (Actions.DeleteThreatFile(filePath).Success)

            {

                Logger.TryRemoveThreatFromSession(session.SessionId, filePath);

                RefreshTimeline();

            }

        }



        private void BtnViewInQuarantine_Click(object sender, RoutedEventArgs e)

        {

            if (FilePathFromSender(sender) is not string filePath) return;

            if (!VM.IsFileStillQuarantined(filePath)) return;

            OpenAntivirusQuarantineTab();

        }



        private void BtnViewSourceScan_Click(object sender, RoutedEventArgs e)

        {

            var sessionId = VM.SelectedEntry?.QuarantineEntry?.SourceSessionId;

            if (sessionId is not { } id || id == Guid.Empty) return;

            if (!VM.TrySelectScanSession(id)) return;

            SyncFilterChips();

            UpdateDetailPanels();

        }



        private void BtnManageInAv_Click(object sender, RoutedEventArgs e) =>

            OpenAntivirusQuarantineTab();



        private static void OpenAntivirusQuarantineTab() =>
            ServiceContainer.UiEvents.RequestOpenQuarantineTab();



        private void BtnOpenAntivirus_Click(object sender, RoutedEventArgs e) =>

            ServiceContainer.Views.Navigation?.NavigateTo(OptiscanStrings.PanelIds.Antivirus);



        private void BtnExportHtml_Click(object sender, RoutedEventArgs e) =>

            _uiEvents.RequestExportScanHistoryHtml();



        private void BtnExportSelectedPdf_Click(object sender, RoutedEventArgs e)

        {

            if (SelectedScanSession is ScanSession session)

                _uiEvents.RequestExportScanSessionPdf(session);

        }

    }

}


