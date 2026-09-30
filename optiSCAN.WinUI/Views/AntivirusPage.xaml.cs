using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using optiSCAN.Localization;
using optiSCAN.Models;
using optiSCAN.Services;
using optiSCAN.Strings;
using optiSCAN.ViewModels;
using optiSCAN.WinUI.ViewModels;
using optiSCAN.Views;
using optiSCAN.WinUI.Services;
using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Text;

namespace optiSCAN.WinUI.Views;

public sealed partial class AntivirusPage : UserControl, IAntivirusSignaturesPanel
{
    private readonly ServiceContainer _services;
    private readonly IUserConfirmService _confirm;
    private readonly ConcurrentQueue<string> _signatureLogQueue = new();
    private DispatcherQueueTimer? _signatureLogFlushTimer;
    private int _signatureLogArmPosted;
    private DateTime? _heroLastScan;
    private readonly ObservableCollection<ThreatDisplayItem> _threatDisplays = new();
    private bool _threatsDirty = true;
    private bool? _isNarrowLayout;
    private SelectorBarItem? _requestedSection;
    private bool _applyingSection;

    public AntivirusViewModel ViewModel { get; }

    public AntivirusPage(AntivirusViewModel viewModel, IUserConfirmService? confirm = null)
    {
        ViewModel = viewModel;
        _services = WinUiServiceHost.Instance.Container;
        _confirm = confirm ?? DeclineUserConfirmService.Instance;
        InitializeComponent();
        ApplyLocalizedLabels();
        ThreatsList.ItemsSource = _threatDisplays;
        QuarantineList.ItemsSource = ViewModel.QuarantineEntries;
        RecentList.ItemsSource = ViewModel.RecentTargets;
        ViewModel.PropertyChanged += (_, _) => DispatcherQueue.TryEnqueue(SyncUi);
        // Les collections ne lèvent pas PropertyChanged : puces « Récents » et état vide de la quarantaine.
        ViewModel.RecentTargets.CollectionChanged += (_, _) => DispatcherQueue.TryEnqueue(SyncUi);
        ViewModel.QuarantineEntries.CollectionChanged += (_, _) => DispatcherQueue.TryEnqueue(SyncUi);
        // La liste affichée est une projection de ViewModel.Threats : toute modification (ajout pendant le
        // scan, quarantaine, suppression, chargement depuis l'historique) doit la reconstruire. L'ancien test
        // sur le seul nombre d'éléments laissait des lignes périmées (ex. une menace retirée puis une autre ajoutée).
        ViewModel.Threats.CollectionChanged += (_, _) =>
        {
            _threatsDirty = true;
            DispatcherQueue.TryEnqueue(SyncUi);
        };
        ViewModel.DisplayScanProgressRequested += OnDisplayScanProgressRequested;
        MainTabs.SelectionChanged += (_, _) =>
        {
            if (!_applyingSection && MainTabs.SelectedItem is SelectorBarItem selected)
                _requestedSection = selected;
            ApplySectionVisibility();
            if (ReferenceEquals(MainTabs.SelectedItem, QuarantineTab))
                ViewModel.LoadQuarantine(reset: true);
        };
        Loaded += (_, _) =>
        {
            // La page est mise en cache : elle est déchargée/rechargée à chaque changement de section.
            // Se réabonner ici (l'ancien code se désabonnait à Unloaded sans jamais se réabonner :
            // après une première visite d'une autre section, un scan lancé depuis l'accueil ou le
            // menu contextuel ne ramenait plus l'onglet Analyse).
            ViewModel.DisplayScanProgressRequested -= OnDisplayScanProgressRequested;
            ViewModel.DisplayScanProgressRequested += OnDisplayScanProgressRequested;
            // Le modèle est réappliqué au rechargement : sans ça, le trait reste sur Analyse
            // alors que le panneau affiché est Signatures.
            ApplyRequestedSection();
            SyncUi();
            if (!_signatureLogQueue.IsEmpty)
                DispatcherQueue.TryEnqueue(DispatcherQueuePriority.Low, ArmSignatureLogFlush);
        };
        Unloaded += (_, _) =>
        {
            ViewModel.DisplayScanProgressRequested -= OnDisplayScanProgressRequested;
            // Ne pas vider la file du journal : une mise à jour des signatures peut continuer
            // pendant que l'utilisateur consulte une autre section.
            _signatureLogFlushTimer?.Stop();
            Interlocked.Exchange(ref _signatureLogArmPosted, 0);
        };
        SyncUi();
    }

    public void UpdateSignaturesPanel(string yaraVersion, string yaraLastMaj, string clamVersion, string clamLastMaj)
    {
        DispatcherQueue.TryEnqueue(() =>
        {
            YaraVersionText.Text = VersionDisplayHelper.NormalizeForDisplay(yaraVersion);
            YaraUpdateText.Text = yaraLastMaj;
            ClamVersionText.Text = VersionDisplayHelper.NormalizeForDisplay(clamVersion);
            ClamUpdateText.Text = clamLastMaj;
        });
    }

    public void UpdateSignatureInfo(string version, string date) =>
        UpdateSignaturesPanel("—", "—", version, date);

    public void UpdateLastScanDisplay(DateTime? lastScan)
    {
        _heroLastScan = lastScan;
        DispatcherQueue.TryEnqueue(DispatcherQueuePriority.Low, () =>
            LastScanText.Text = FormatHeroLastScan(lastScan));
    }

    public void UpdateQuarantineList(IEnumerable<QuarantineEntry>? entries = null) =>
        DispatcherQueue.TryEnqueue(() => ViewModel.LoadQuarantine(reset: true));

    private void OnDisplayScanProgressRequested(object? sender, EventArgs e) =>
        DispatcherQueue.TryEnqueue(SelectScanTab);

    public void SelectScanTab() => SelectSection(ScanTab);

    public void SelectQuarantineTab()
    {
        SelectSection(QuarantineTab);
        ViewModel.LoadQuarantine(reset: true);
    }

    public void SelectSignaturesTab() => SelectSection(SignaturesTab);

    private void SelectSection(SelectorBarItem item)
    {
        _requestedSection = item;
        if (IsLoaded)
            ApplyRequestedSection();
    }

    /// <summary>
    /// SelectedItem seul ne déplace pas le surlignage du SelectorBar.
    /// IsSelected est posé sur chaque onglet, et rejoué au Loaded.
    /// </summary>
    private void ApplyRequestedSection()
    {
        var item = _requestedSection ?? ScanTab;
        if (_applyingSection)
            return;

        _applyingSection = true;
        try
        {
            item.IsSelected = true;
            if (!ReferenceEquals(ScanTab, item))
                ScanTab.IsSelected = false;
            if (!ReferenceEquals(QuarantineTab, item))
                QuarantineTab.IsSelected = false;
            if (!ReferenceEquals(SignaturesTab, item))
                SignaturesTab.IsSelected = false;
            MainTabs.SelectedItem = item;
            ApplySectionVisibility();
        }
        finally
        {
            _applyingSection = false;
        }
    }

    /// <summary>SelectorBar ne porte pas de contenu : on affiche le panneau de la section choisie.</summary>
    private void ApplySectionVisibility()
    {
        var selected = MainTabs.SelectedItem ?? ScanTab;
        ScanPanel.Visibility = ReferenceEquals(selected, ScanTab) ? Visibility.Visible : Visibility.Collapsed;
        QuarantinePanel.Visibility = ReferenceEquals(selected, QuarantineTab) ? Visibility.Visible : Visibility.Collapsed;
        SignaturesPanel.Visibility = ReferenceEquals(selected, SignaturesTab) ? Visibility.Visible : Visibility.Collapsed;
        SyncScanPhaseUi(ViewModel.IsScanning, ViewModel.Threats.Count > 0, OnScanSection);
    }

    private bool OnScanSection => ReferenceEquals(MainTabs.SelectedItem ?? ScanTab, ScanTab);

    private void PageRoot_SizeChanged(object sender, SizeChangedEventArgs e) =>
        ApplyAdaptiveLayout(e.NewSize.Width);

    /// <summary>Fenêtre étroite : vignettes en 2×2, statistiques sous l'en-tête, cartes signatures empilées.</summary>
    private void ApplyAdaptiveLayout(double width)
    {
        var narrow = width < 760;
        if (_isNarrowLayout == narrow)
            return;
        _isNarrowLayout = narrow;

        Button[] tiles = [QuickScanButton, FullScanButton, FolderScanButton, FileScanButton];
        ScanTilesGrid.ColumnDefinitions.Clear();
        ScanTilesGrid.RowDefinitions.Clear();
        var columns = narrow ? 2 : 4;
        for (var c = 0; c < columns; c++)
            ScanTilesGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        for (var r = 0; r < tiles.Length / columns; r++)
            ScanTilesGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        for (var i = 0; i < tiles.Length; i++)
        {
            Grid.SetColumn(tiles[i], i % columns);
            Grid.SetRow(tiles[i], i / columns);
        }

        Grid.SetColumn(StatsPanel, narrow ? 0 : 2);
        Grid.SetRow(StatsPanel, narrow ? 1 : 0);
        Grid.SetColumnSpan(StatsPanel, narrow ? 3 : 1);

        var sigCards = SignatureCardsGrid.Children;
        SignatureCardsGrid.ColumnDefinitions.Clear();
        SignatureCardsGrid.RowDefinitions.Clear();
        SignatureCardsGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        if (!narrow)
            SignatureCardsGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        else
        {
            SignatureCardsGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            SignatureCardsGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        }
        for (var i = 0; i < sigCards.Count; i++)
        {
            if (sigCards[i] is not FrameworkElement card)
                continue;
            Grid.SetColumn(card, narrow ? 0 : i);
            Grid.SetRow(card, narrow ? i : 0);
        }
    }

    public void AppendSignatureLog(string message)
    {
        if (string.IsNullOrWhiteSpace(message))
            return;

        _signatureLogQueue.Enqueue(message);
        if (Interlocked.CompareExchange(ref _signatureLogArmPosted, 1, 0) != 0)
            return;

        DispatcherQueue.TryEnqueue(DispatcherQueuePriority.Low, ArmSignatureLogFlush);
    }

    public void SetSignatureUpdating(bool updating)
    {
        DispatcherQueue.TryEnqueue(() =>
        {
            SigUpdateProgress.Visibility = updating ? Visibility.Visible : Visibility.Collapsed;
            SigUpdateProgress.IsIndeterminate = updating;
            UpdateSignaturesButton.IsEnabled = !updating;
            StopUpdateButton.Visibility = updating ? Visibility.Visible : Visibility.Collapsed;
        });
    }

    private void ArmSignatureLogFlush()
    {
        Interlocked.Exchange(ref _signatureLogArmPosted, 0);

        _signatureLogFlushTimer ??= DispatcherQueue.CreateTimer();
        _signatureLogFlushTimer.Interval = TimeSpan.FromMilliseconds(110);
        _signatureLogFlushTimer.Tick -= SignatureLogFlushTimer_Tick;
        _signatureLogFlushTimer.Tick += SignatureLogFlushTimer_Tick;
        _signatureLogFlushTimer.Stop();
        _signatureLogFlushTimer.Start();
    }

    private void SignatureLogFlushTimer_Tick(DispatcherQueueTimer sender, object args)
    {
        sender.Stop();
        var sb = new StringBuilder(8192);
        for (var i = 0; i < 500 && _signatureLogQueue.TryDequeue(out var line); i++)
            sb.AppendLine(line);

        if (sb.Length > 0)
        {
            SignatureLogText.Text += sb.ToString();
            ScrollSignatureLogToEnd();
        }

        if (!_signatureLogQueue.IsEmpty)
            sender.Start();
    }

    // Force la mise en page avant de défiler : sinon ScrollableHeight reflète encore
    // l'ancien contenu et la dernière ligne (finalisation de la MAJ) reste sous le pli.
    private void ScrollSignatureLogToEnd()
    {
        SignatureLogScroll.UpdateLayout();
        SignatureLogScroll.ChangeView(null, SignatureLogScroll.ScrollableHeight, null, disableAnimation: true);

        // Second passage après le prochain cycle de rendu, au cas où l'extent
        // n'aurait pas encore été recalculé (ajout de plusieurs lignes d'un coup).
        DispatcherQueue.TryEnqueue(DispatcherQueuePriority.Low, () =>
            SignatureLogScroll.ChangeView(null, SignatureLogScroll.ScrollableHeight, null, disableAnimation: true));
    }

    private void RefreshAfterThreatAction()
    {
        ViewModel.RefreshProtectionStatus();
        ViewModel.LoadQuarantine(reset: true);
        SyncUi();
        _services.RequestScanHistoryViewsRefresh();
    }


    private void ApplyLocalizedLabels()
    {
        TitleText.Text = LocalizationService.GetString("Av_Title");

        QuickScanTitle.Text = LocalizationService.GetString("Av_Quick");
        QuickScanSub.Text = LocalizationService.GetString("Av_QuickSub");
        ToolTipService.SetToolTip(QuickScanButton, LocalizationService.GetString("Av_Tooltip_QuickScan"));
        FullScanTitle.Text = LocalizationService.GetString("Av_Full");
        FullScanSub.Text = LocalizationService.GetString("Av_FullSub");
        FolderScanTitle.Text = LocalizationService.GetString("Av_FolderTile");
        FolderScanSub.Text = LocalizationService.GetString("Av_FolderSub");
        ToolTipService.SetToolTip(FolderScanButton, LocalizationService.GetString("Av_Folder"));
        FileScanTitle.Text = LocalizationService.GetString("Av_FileTile");
        FileScanSub.Text = LocalizationService.GetString("Av_FileSub");
        ToolTipService.SetToolTip(FileScanButton, LocalizationService.GetString("Av_File"));
        RecentLabel.Text = LocalizationService.GetString("Av_Recent");

        FilesScannedLabel.Text = LocalizationService.GetString("Av_Analyzed");
        ThreatsFoundLabel.Text = LocalizationService.GetString("Av_Threats");
        QuarantineCountLabel.Text = LocalizationService.GetString("Av_TabQuarantine");

        ScanProgressTitle.Text = LocalizationService.GetString("Av_ScanInProgress");
        StopScanText.Text = LocalizationService.GetString("Av_Stop");

        ScanTab.Text = LocalizationService.GetString("Av_TabScan");
        QuarantineTab.Text = LocalizationService.GetString("Av_TabQuarantine");
        SignaturesTab.Text = LocalizationService.GetString("Av_TabSignatures");

        EmptyThreatsTitle.Text = LocalizationService.GetString("Av_NoThreats");
        EmptyThreatsSubtitle.Text = LocalizationService.GetString("Av_SystemClean");
        QuarantineAllText.Text = LocalizationService.GetString("Av_QuarantineAll");

        EmptyQuarantineTitle.Text = LocalizationService.GetString("Av_QuarantineEmpty");
        EmptyQuarantineSubtitle.Text = LocalizationService.GetString("Av_QuarantineEmptySub");
        LoadMoreQuarantineButton.Content = LocalizationService.GetString("Av_LoadMore");
        PurgeQuarantineText.Text = LocalizationService.GetString("Av_EmptyQuarantine");

        UpdateSignaturesText.Text = LocalizationService.GetString("Av_Update");
        ToolTipService.SetToolTip(UpdateSignaturesButton, LocalizationService.GetString("Av_Tooltip_UpdateSignatures"));
        StopUpdateText.Text = LocalizationService.GetString("Av_StopUpdate");
        InitText.Text = LocalizationService.GetString("Av_Init");
    }

    private void SyncUi()
    {
        if (_threatsDirty)
        {
            _threatsDirty = false;
            _threatDisplays.Clear();
            foreach (var t in ViewModel.Threats)
                _threatDisplays.Add(ThreatDisplayItem.Create(t));
        }
        BadgeText.Text = ViewModel.ProtectionBadgeText;
        var lastScan = _heroLastScan ?? (_services.Logger.GetHistory().Count == 0
            ? null
            : _services.Logger.GetHistory().Max(s => s.StartedAt));
        LastScanText.Text = FormatHeroLastScan(lastScan);
        StatusText.Text = ViewModel.StatusMessage;
        CurrentItemText.Text = ViewModel.CurrentScanItem;
        ScanProgressDetail.Text = ViewModel.ScanProgressDetail;
        FilesScannedValue.Text = ViewModel.FilesScanned.ToString("N0", CultureInfo.CurrentCulture);
        ThreatsFoundValue.Text = ViewModel.ThreatsFound.ToString("N0", CultureInfo.CurrentCulture);
        QuarantineCountValue.Text = ViewModel.QuarantineTotalCount.ToString("N0", CultureInfo.CurrentCulture);
        QuarantinePagingText.Text = ViewModel.QuarantinePagingStatus;

        var threatCount = ViewModel.Threats.Count;
        ThreatsHeaderText.Text = threatCount > 0
            ? $"{LocalizationService.GetString("Av_Threats")} ({threatCount.ToString("N0", CultureInfo.CurrentCulture)})"
            : LocalizationService.GetString("Av_ResultsTitle");
        QuarantineTab.Text = ViewModel.QuarantineTotalCount > 0
            ? $"{LocalizationService.GetString("Av_TabQuarantine")} ({ViewModel.QuarantineTotalCount.ToString("N0", CultureInfo.CurrentCulture)})"
            : LocalizationService.GetString("Av_TabQuarantine");
        var quarantineEmpty = ViewModel.QuarantineTotalCount == 0 && ViewModel.QuarantineEntries.Count == 0;
        EmptyQuarantineState.Visibility = quarantineEmpty ? Visibility.Visible : Visibility.Collapsed;
        QuarantineList.Visibility = quarantineEmpty ? Visibility.Collapsed : Visibility.Visible;
        RecentRow.Visibility = ViewModel.RecentTargets.Count > 0 ? Visibility.Visible : Visibility.Collapsed;

        var scanning = ViewModel.IsScanning;
        SyncScanPhaseUi(scanning, ViewModel.Threats.Count > 0, OnScanSection);
        ScanProgressBar.IsIndeterminate = ViewModel.IsIndeterminate;
        ScanProgressBar.Value = ViewModel.ProgressValue;
        StopScanButton.IsEnabled = ViewModel.CanStop;

        LoadMoreQuarantineButton.IsEnabled = ViewModel.QuarantineHasMore;
        PurgeQuarantineButton.IsEnabled = ViewModel.QuarantineTotalCount > 0;

        InitOverlay.Visibility = ViewModel.IsInitializing ? Visibility.Visible : Visibility.Collapsed;
        InitErrorText.Text = ViewModel.InitializationError ?? string.Empty;
        InitErrorText.Visibility = string.IsNullOrEmpty(ViewModel.InitializationError)
            ? Visibility.Collapsed
            : Visibility.Visible;
    }

    private void SyncScanPhaseUi(bool scanning, bool hasThreats, bool showScanLaunchers) =>
        UiPhaseVisibility.ApplyAntivirusScanPhase(
            scanning,
            hasThreats,
            ScanHubPanel,
            ScanProgressPanel,
            ThreatsList,
            EmptyThreatsState,
            QuarantineAllButton,
            showScanLaunchers);

    private static string FormatHeroLastScan(DateTime? lastScan)
    {
        if (!lastScan.HasValue)
            return LocalizationService.GetString("Av_LastScanNone");

        var diff = DateTime.Now - lastScan.Value;
        if (diff.TotalMinutes < 1)
            return LocalizationService.GetString("Av_LastScanInstant");
        if (diff.TotalMinutes < 60)
            return LocalizationService.Format("Av_LastScanMinutes", (int)diff.TotalMinutes);
        if (diff.TotalHours < 24)
            return LocalizationService.Format("Av_LastScanHours", (int)diff.TotalHours);
        if (diff.TotalDays < 7)
            return LocalizationService.Format("Av_LastScanDays", (int)diff.TotalDays);

        return LocalizationService.Format("Av_LastScanLabel", lastScan.Value.ToString("G", CultureInfo.CurrentCulture));
    }

    private async void QuickScan_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel.QuickScanCommand.CanExecute(null))
            ViewModel.QuickScanCommand.Execute(null);
        await Task.CompletedTask;
    }

    private async void FullScan_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel.FullScanCommand.CanExecute(null))
            ViewModel.FullScanCommand.Execute(null);
        await Task.CompletedTask;
    }

    private void StopScan_Click(object sender, RoutedEventArgs e) =>
        ViewModel.StopScanCommand.Execute(null);

    // Sélecteurs Win32 : les pickers WinRT échouent quand optiSCAN est relancé en administrateur.
    private void BrowseFolder_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var folder = WinUiNativeDialogs.PickFolder(LocalizationService.GetString("Av_Folder"));
            if (!string.IsNullOrWhiteSpace(folder) && ViewModel.ScanFolderCommand.CanExecute(folder))
                ViewModel.ScanFolderCommand.Execute(folder);
        }
        catch (Exception ex)
        {
            AppLogger.Warn("AntivirusPage", "BrowseFolder", ex);
            _confirm.Warn(ex.Message, LocalizationService.IsEnglish ? "Error" : "Erreur");
        }
    }

    private void BrowseFile_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var file = WinUiNativeDialogs.PickFile(LocalizationService.GetString("Av_File"));
            if (!string.IsNullOrWhiteSpace(file) && ViewModel.ScanFileCommand.CanExecute(file))
                ViewModel.ScanFileCommand.Execute(file);
        }
        catch (Exception ex)
        {
            AppLogger.Warn("AntivirusPage", "BrowseFile", ex);
            _confirm.Warn(ex.Message, LocalizationService.IsEnglish ? "Error" : "Erreur");
        }
    }

    private void RecentTarget_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: RecentScanTarget target }
            && ViewModel.ScanRecentCommand.CanExecute(target))
            ViewModel.ScanRecentCommand.Execute(target);
    }

    private void QuarantineAll_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel.QuarantineAllCommand.CanExecute(null))
            ViewModel.QuarantineAllCommand.Execute(null);
    }

    private void LoadMoreQuarantine_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel.LoadMoreQuarantineCommand.CanExecute(null))
            ViewModel.LoadMoreQuarantineCommand.Execute(null);
    }

    private void PurgeQuarantine_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel.PurgeQuarantineCommand.CanExecute(null))
            ViewModel.PurgeQuarantineCommand.Execute(null);
    }

    private void UpdateSignatures_Click(object sender, RoutedEventArgs e) =>
        _services.TriggerSignatureUpdate();

    private void StopUpdate_Click(object sender, RoutedEventArgs e) =>
        App.MainWindowInstance?.StopSignatureUpdate();

    private void QuarantineThreat_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: string filePath })
            return;

        var sessionId = ViewModel.ActiveScanSessionId;
        var known = _services.FindKnownThreat(filePath);
        var result = known != null
            ? _services.Actions.QuarantineThreat(known.Clone(), sessionId)
            : _services.Actions.QuarantineThreat(filePath, sessionId);

        if (result.Success)
        {
            ViewModel.RemoveDetectedThreat(filePath);
            ViewModel.NotifyThreatQuarantinedDuringScan(filePath);
        }

        RefreshAfterThreatAction();
    }

    private void IgnoreThreat_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: string filePath }
            && _services.Actions.IgnoreThreat(filePath).Success)
        {
            ViewModel.RemoveDetectedThreat(filePath);
            RefreshAfterThreatAction();
        }
    }

    private async void Reputation_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: string filePath } btn)
            return;

        btn.IsEnabled = false;
        try
        {
            var result = await _services.ThreatReputation.LookupFileAsync(filePath);
            var message = result.Summary;
            if (!string.IsNullOrEmpty(result.Permalink))
                message += Environment.NewLine + result.Permalink;

            if (result.IsError)
                _confirm.Warn(message, LocalizationService.GetString("Av_ReputationTitle"));
            else
                _confirm.Inform(message, LocalizationService.GetString("Av_ReputationTitle"));
        }
        catch (Exception ex)
        {
            // async void : une exception non gérée ici fermerait l'application.
            AppLogger.Warn("AntivirusPage", "Reputation", ex);
            _confirm.Warn(ex.Message, LocalizationService.GetString("Av_ReputationTitle"));
        }
        finally
        {
            btn.IsEnabled = true;
        }
    }

    private void DeleteThreat_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: string filePath })
            return;

        if (!_confirm.ConfirmYesNo(
                LocalizationService.GetString("Av_ConfirmDeleteFile"),
                OptiscanStrings.Confirmations.Title,
                warning: true))
            return;

        if (_services.Actions.DeleteThreatFile(filePath).Success)
        {
            ViewModel.RemoveDetectedThreat(filePath);
            RefreshAfterThreatAction();
        }
    }

    private void RestoreQuarantine_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: string id }
            && _services.Actions.RestoreFromQuarantine(id).Success)
            RefreshAfterThreatAction();
    }

    private void DeleteQuarantine_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: string id })
            return;

        if (!_confirm.ConfirmYesNo(
                LocalizationService.GetString("Av_ConfirmDeleteQuarantine"),
                OptiscanStrings.Confirmations.Title))
            return;

        if (_services.Actions.DeleteFromQuarantine(id).Success)
            RefreshAfterThreatAction();
    }
}
