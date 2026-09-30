using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using optiSCAN.Coordinators;
using optiSCAN.Localization;
using optiSCAN.Models;
using optiSCAN.Services;
using optiSCAN.Strings;
using optiSCAN.ViewModels;
using optiSCAN.WinUI.Services;
using System.Globalization;

namespace optiSCAN.WinUI.Views;

public sealed partial class HistoryPage : UserControl
{
    private readonly ServiceContainer _container;
    private readonly IUserConfirmService _confirm;
    private bool _syncingChips;

    public HistoryViewModel ViewModel { get; }

    public HistoryPage(HistoryViewModel viewModel, IUserConfirmService? confirm = null)
    {
        ViewModel = viewModel;
        _confirm = confirm ?? DeclineUserConfirmService.Instance;
        _container = WinUiServiceHost.Instance.Container;
        InitializeComponent();
        TimelineList.ItemsSource = ViewModel.FilteredEntries;
        ApplyStaticLabels();
        ViewModel.PropertyChanged += (_, e) => DispatcherQueue.TryEnqueue(() =>
        {
            SyncUi();
            if (e.PropertyName is nameof(HistoryViewModel.SelectedEntry)
                or nameof(HistoryViewModel.HasQuarantineSourceScan)
                or nameof(HistoryViewModel.ShowScanActions)
                or null)
                UpdateDetail();
        });
        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
        SyncUi();
    }

    public void Refresh() => ViewModel.Refresh();

    private void ApplyStaticLabels()
    {
        PageTitle.Text = LocalizationService.GetString("Hist_Title");
        PageSubtitle.Text = LocalizationService.GetString("Hist_Sub");
        SearchBox.PlaceholderText = LocalizationService.GetString("Hist_SearchScan");
        ExportHtmlButton.Content = LocalizationService.GetString("Hist_ExportHtml");
        ExportPdfButton.Content = LocalizationService.GetString("Hist_ExportPdf");
        TreatInAvButton.Content = LocalizationService.GetString("Hist_TreatInAv");
        OpenAvButton.Content = LocalizationService.GetString("Hist_OpenAv");
        ManageInAvButton.Content = LocalizationService.GetString("Hist_ManageInAv");
        ViewSourceScanButton.Content = LocalizationService.GetString("Hist_ViewSourceScan");
        QuarantineAllButton.Content = LocalizationService.GetString("Hist_QuarantineAll");
        ThreatsLegacyPanel.Text = LocalizationService.GetString("Hist_ThreatsLegacy");

        ToolTipService.SetToolTip(ExportHtmlButton, LocalizationService.GetString("Hist_TooltipExportHtml"));
        ToolTipService.SetToolTip(ExportPdfButton, LocalizationService.GetString("Hist_TooltipExportPdf"));
        ToolTipService.SetToolTip(TreatInAvButton, LocalizationService.GetString("Hist_TooltipTreatInAv"));
        ToolTipService.SetToolTip(QuarantineAllButton, LocalizationService.GetString("Hist_TooltipQuarantineAll"));
        ToolTipService.SetToolTip(ManageInAvButton, LocalizationService.GetString("Hist_TooltipManageInAv"));
        ToolTipService.SetToolTip(ViewSourceScanButton, LocalizationService.GetString("Hist_TooltipViewSourceScan"));
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        ServiceContainer.UiEvents.ScanHistoryViewsRefreshRequested += OnExternalRefresh;
        ViewModel.Refresh();
    }

    private void OnUnloaded(object sender, RoutedEventArgs e) =>
        ServiceContainer.UiEvents.ScanHistoryViewsRefreshRequested -= OnExternalRefresh;

    private void OnExternalRefresh(object? sender, EventArgs e) =>
        DispatcherQueue.TryEnqueue(ViewModel.Refresh);

    private void SyncUi()
    {
        ChipAll.Content = ViewModel.ChipAllLabel;
        ChipThreats.Content = ViewModel.ChipThreatsLabel;
        ChipCleanScans.Content = ViewModel.ChipCleanScansLabel;
        ChipCleans.Content = ViewModel.ChipCleansLabel;
        ChipQuarantine.Content = ViewModel.ChipQuarantineLabel;

        EmptyState.Visibility = ViewModel.IsEmpty ? Visibility.Visible : Visibility.Collapsed;
        TimelineList.Visibility = ViewModel.IsEmpty ? Visibility.Collapsed : Visibility.Visible;
        EmptyTitleText.Text = ViewModel.EmptyTitle;
        EmptySubtitleText.Text = ViewModel.EmptySubtitle;
        ExportPdfButton.IsEnabled = ViewModel.CanExportPdf;

        SyncChips();
        SyncTimelineSelection();
        UpdateDetail();
    }

    private void SyncChips()
    {
        _syncingChips = true;
        try
        {
            var tag = ViewModel.SelectedFilter switch
            {
                HistoryFilter.Threats => "Threats",
                HistoryFilter.CleanScans => "CleanScans",
                HistoryFilter.Cleans => "Cleans",
                HistoryFilter.Quarantine => "Quarantine",
                _ => "All",
            };
            ChipAll.IsChecked = tag == "All";
            ChipThreats.IsChecked = tag == "Threats";
            ChipCleanScans.IsChecked = tag == "CleanScans";
            ChipCleans.IsChecked = tag == "Cleans";
            ChipQuarantine.IsChecked = tag == "Quarantine";
        }
        finally
        {
            _syncingChips = false;
        }
    }

    private void SyncTimelineSelection()
    {
        var entry = ViewModel.SelectedEntry;
        if (entry != null && !ReferenceEquals(TimelineList.SelectedItem, entry))
            TimelineList.SelectedItem = entry;
    }

    private void Chip_Click(object sender, RoutedEventArgs e)
    {
        if (_syncingChips || sender is not ToggleButton { Tag: string tag })
            return;

        ViewModel.SelectedFilter = tag switch
        {
            "Threats" => HistoryFilter.Threats,
            "CleanScans" => HistoryFilter.CleanScans,
            "Cleans" => HistoryFilter.Cleans,
            "Quarantine" => HistoryFilter.Quarantine,
            _ => HistoryFilter.All,
        };
    }

    private void SearchBox_TextChanged(object sender, TextChangedEventArgs e) =>
        ViewModel.SearchText = SearchBox.Text;

    private void TimelineList_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (TimelineList.SelectedItem is ActivityEntry entry)
            ViewModel.SelectedEntry = entry;
    }

    private void UpdateDetail()
    {
        var entry = ViewModel.SelectedEntry;
        TreatInAvButton.Visibility = Visibility.Collapsed;
        QuarantineAllButton.Visibility = Visibility.Collapsed;
        ViewSourceScanButton.Visibility = Visibility.Collapsed;
        ThreatsLegacyPanel.Visibility = Visibility.Collapsed;

        if (entry == null)
        {
            SessionInfoText.Text = LocalizationService.GetString("Hist_SelectScanHint");
            DetailText.Text = string.Empty;
            ThreatsList.Visibility = Visibility.Collapsed;
            NoThreatsPanel.Visibility = Visibility.Collapsed;
            CleanLogPanel.Visibility = Visibility.Collapsed;
            QuarantineDetailPanel.Visibility = Visibility.Collapsed;
            return;
        }

        var cult = CultureInfo.CurrentCulture;
        SessionInfoText.Text = $"{entry.TypeDisplay} — {entry.StartedAt.ToString("g", cult)}";
        DetailText.Text = entry.ResultSummary ?? entry.TargetDisplay ?? string.Empty;

        if (entry.Kind == ActivityKind.Scan && entry.ScanSession is ScanSession session)
        {
            var rows = ViewModel.BuildThreatRows(session.Threats);
            var legacyOnly = session.ThreatsFound > 0 && session.Threats.Count == 0;

            ThreatsList.ItemsSource = rows;
            ThreatsList.Visibility = rows.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
            NoThreatsPanel.Visibility = rows.Count == 0 && !legacyOnly ? Visibility.Visible : Visibility.Collapsed;
            NoThreatsPanel.Text = LocalizationService.GetString("Hist_NoThreatsInSession");
            ThreatsLegacyPanel.Visibility = legacyOnly ? Visibility.Visible : Visibility.Collapsed;
            CleanLogPanel.Visibility = Visibility.Collapsed;
            QuarantineDetailPanel.Visibility = Visibility.Collapsed;

            var showActions = ViewModel.ShowScanActions;
            TreatInAvButton.Visibility = showActions ? Visibility.Visible : Visibility.Collapsed;
            QuarantineAllButton.Visibility = showActions ? Visibility.Visible : Visibility.Collapsed;
            QuarantineAllButton.IsEnabled = showActions;
        }
        else if (entry.Kind == ActivityKind.Clean)
        {
            ThreatsList.Visibility = Visibility.Collapsed;
            NoThreatsPanel.Visibility = Visibility.Collapsed;
            QuarantineDetailPanel.Visibility = Visibility.Collapsed;
            CleanLogPanel.Visibility = Visibility.Visible;

            var clean = entry.CleanSession;
            CleanLogText.Text = clean != null && !string.IsNullOrWhiteSpace(clean.OperationLog)
                ? clean.OperationLog
                : clean != null
                    ? LocalizationService.Format(
                        "Hist_DetailCleanSummary",
                        clean.TargetsSummary ?? string.Empty,
                        clean.BytesDisplay ?? string.Empty,
                        clean.DurationDisplay ?? string.Empty)
                    : LocalizationService.GetString("Hist_DetailSelectClean");
        }
        else if (entry.Kind == ActivityKind.Quarantine)
        {
            ThreatsList.Visibility = Visibility.Collapsed;
            NoThreatsPanel.Visibility = Visibility.Collapsed;
            CleanLogPanel.Visibility = Visibility.Collapsed;
            QuarantineDetailPanel.Visibility = Visibility.Visible;
            var q = entry.QuarantineEntry;
            QuarTitleText.Text = q?.FileName ?? entry.TypeDisplay;
            QuarPathText.Text = q != null
                ? LocalizationService.Format("Hist_DetailQuarantinePath", q.OriginalPath)
                : entry.TargetDisplay ?? string.Empty;
            QuarMetaText.Text = q != null
                ? LocalizationService.Format("Hist_DetailQuarantineMeta", q.VirusName, q.SizeDisplay)
                : string.Empty;
            QuarStatusText.Text = entry.IsStillQuarantined
                ? LocalizationService.GetString("Hist_QuarantineStillActive")
                : LocalizationService.GetString("Hist_QuarantineHistorical");
            ManageInAvButton.IsEnabled = entry.IsStillQuarantined;
            ViewSourceScanButton.Visibility = ViewModel.HasQuarantineSourceScan
                ? Visibility.Visible
                : Visibility.Collapsed;
        }
        else
        {
            ThreatsList.Visibility = Visibility.Collapsed;
            NoThreatsPanel.Visibility = Visibility.Collapsed;
            CleanLogPanel.Visibility = Visibility.Collapsed;
            QuarantineDetailPanel.Visibility = Visibility.Collapsed;
        }
    }

    private ScanSession? SelectedScanSession =>
        ViewModel.SelectedEntry?.ScanSession;

    private static string? FilePathFromSender(object sender) =>
        sender is Button { Tag: string path } ? path : null;

    private void QuarantineAll_Click(object sender, RoutedEventArgs e)
    {
        if (SelectedScanSession is not ScanSession session || session.Threats.Count == 0)
            return;
        if (!_confirm.ConfirmYesNo(
                OptiscanStrings.Confirmations.QuarantineAll(session.Threats.Count),
                OptiscanStrings.Confirmations.Title))
            return;
        HistoryThreatRemediationCoordinator.QuarantineAllThreats((IHistoryServices)_container, ViewModel, session, Refresh);
    }

    private void QuarantineThreat_Click(object sender, RoutedEventArgs e)
    {
        if (FilePathFromSender(sender) is { } path && SelectedScanSession is ScanSession session)
            HistoryThreatRemediationCoordinator.QuarantineThreat((IHistoryServices)_container, ViewModel, session, path, Refresh);
    }

    private void DismissThreat_Click(object sender, RoutedEventArgs e)
    {
        if (FilePathFromSender(sender) is { } path && SelectedScanSession is ScanSession session)
            HistoryThreatRemediationCoordinator.DismissThreat((IHistoryServices)_container, session, path, Refresh);
    }

    private void IgnoreThreat_Click(object sender, RoutedEventArgs e)
    {
        if (FilePathFromSender(sender) is { } path && SelectedScanSession is ScanSession session)
            HistoryThreatRemediationCoordinator.IgnoreThreat((IHistoryServices)_container, session, path, Refresh);
    }

    private void DeleteThreat_Click(object sender, RoutedEventArgs e)
    {
        if (FilePathFromSender(sender) is not { } path || SelectedScanSession is not ScanSession session)
            return;

        // Suppression définitive du fichier : l'historique la faisait sans aucune confirmation.
        if (!_confirm.ConfirmYesNo(
                LocalizationService.GetString("Av_ConfirmDeleteFile"),
                OptiscanStrings.Confirmations.Title,
                warning: true))
            return;

        HistoryThreatRemediationCoordinator.DeleteThreat((IHistoryServices)_container, session, path, Refresh);
    }

    private void ViewInQuarantine_Click(object sender, RoutedEventArgs e)
    {
        if (FilePathFromSender(sender) is not { } path || !ViewModel.IsFileStillQuarantined(path))
            return;
        OpenQuarantineTab();
    }

    private void TreatInAv_Click(object sender, RoutedEventArgs e)
    {
        if (SelectedScanSession is not { Threats.Count: > 0 } session)
            return;
        ServiceContainer.UiEvents.RequestReviewHistorySession(session);
    }

    private void ViewSourceScan_Click(object sender, RoutedEventArgs e)
    {
        var sessionId = ViewModel.SelectedEntry?.QuarantineEntry?.SourceSessionId;
        if (sessionId is not { } id || id == Guid.Empty)
            return;
        if (!ViewModel.TrySelectScanSession(id))
            return;
        SyncChips();
        SyncTimelineSelection();
        UpdateDetail();
    }

    private void OpenQuarantineTab_Click(object sender, RoutedEventArgs e) => OpenQuarantineTab();

    private void OpenQuarantineTab() =>
        ServiceContainer.UiEvents.RequestOpenQuarantineTab();

    private void ExportHtml_Click(object sender, RoutedEventArgs e) =>
        ServiceContainer.UiEvents.RequestExportScanHistoryHtml();

    private void ExportPdf_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel.SelectedEntry?.ScanSession is ScanSession session)
            ServiceContainer.UiEvents.RequestExportScanSessionPdf(session);
    }
}
