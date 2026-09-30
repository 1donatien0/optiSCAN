using optiSCAN.Localization;
using optiSCAN.Models;
using optiSCAN.Services;
using optiSCAN.ViewModels;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace optiSCAN.WinUI.ViewModels;

/// <summary>Phase d'affichage de la page Nettoyer (journal, barre d'actions).</summary>
public enum CleanUiPhase
{
    Idle,
    Analyzing,
    Ready,
    Cleaning,
    EmptyResult,
}

/// <summary>ViewModel de la page Nettoyer — délègue l'analyse/nettoyage à <see cref="CleanEngine"/>.</summary>
public sealed class CleanViewModel : INotifyPropertyChanged
{
    private readonly ServiceContainer _container;
    private readonly ScanLogManager _logger;
    private readonly IUiThreadScheduler _ui;
    private readonly IUserConfirmService _confirm;
    private bool _analysed;

    private string _tempSizeDisplay = ByteSizeFormat.Format(0);
    private string _browserSizeDisplay = ByteSizeFormat.Format(0);
    private string _totalSizeDisplay = ByteSizeFormat.Format(0);
    private string _logText = string.Empty;
    private bool _showEmptyState;
    private bool _isCleanEnabled;
    private bool _isAnalyzeEnabled = true;
    private CleanUiPhase _phase = CleanUiPhase.Idle;

    public CleanViewModel(
        ServiceContainer container,
        IUiThreadScheduler? ui = null,
        IUserConfirmService? confirm = null)
    {
        _container = container;
        _logger = container.Logger;
        _ui = ui ?? SyncUiThreadScheduler.Instance;
        _confirm = confirm ?? DeclineUserConfirmService.Instance;
        Updates = new UpdatesViewModel(_ui, _confirm);
        Tweaks = new TweaksViewModel(_ui, _confirm);
        SystemItems = new ObservableCollection<CleanupItem>();
        BrowserItems = new ObservableCollection<CleanupItem>();
        BuildItemCatalog();
        AnalyzeCommand = new AsyncRelayCommand(_ => AnalyzeAsync());
        CleanCommand = new AsyncRelayCommand(_ => CleanAsync(), _ => _analysed && _isCleanEnabled);
        ResetLogHint();
    }

    /// <summary>Onglet « Mises à jour » du panneau Optimiser (winget).</summary>
    public UpdatesViewModel Updates { get; }

    /// <summary>Onglet « Tweaks » du panneau Optimiser.</summary>
    public TweaksViewModel Tweaks { get; }

    public ObservableCollection<CleanupItem> SystemItems { get; }
    public ObservableCollection<CleanupItem> BrowserItems { get; }
    public AsyncRelayCommand AnalyzeCommand { get; }
    public AsyncRelayCommand CleanCommand { get; }

    public string TempSizeDisplay { get => _tempSizeDisplay; private set => SetField(ref _tempSizeDisplay, value); }
    public string BrowserSizeDisplay { get => _browserSizeDisplay; private set => SetField(ref _browserSizeDisplay, value); }
    public string TotalSizeDisplay { get => _totalSizeDisplay; private set => SetField(ref _totalSizeDisplay, value); }
    public string LogText { get => _logText; private set => SetField(ref _logText, value); }
    public bool ShowEmptyState { get => _showEmptyState; private set => SetField(ref _showEmptyState, value); }
    public bool IsCleanEnabled { get => _isCleanEnabled; private set { if (SetField(ref _isCleanEnabled, value)) CleanCommand.NotifyCanExecuteChanged(); } }
    public bool IsAnalyzeEnabled { get => _isAnalyzeEnabled; private set => SetField(ref _isAnalyzeEnabled, value); }
    public CleanUiPhase Phase { get => _phase; private set => SetField(ref _phase, value); }

    public void ResetLogHint()
    {
        Phase = CleanUiPhase.Idle;
        SetLog(LocalizationService.GetString("Clean_LogHint"));
    }

    private void BuildItemCatalog()
    {
        SystemItems.Clear();
        BrowserItems.Clear();
        foreach (var entry in CleanEngine.GetCatalog())
        {
            var item = new CleanupItem
            {
                Id = entry.Id,
                DisplayName = LocalizationService.GetString(entry.NameKey),
                Details = entry.DetailsKey != null
                    ? LocalizationService.GetString(entry.DetailsKey)
                    : string.Empty,
                IsBrowser = entry.IsBrowser,
                IsSelected = entry.DefaultSelected,
            };
            if (entry.IsBrowser)
                BrowserItems.Add(item);
            else
                SystemItems.Add(item);
        }
    }

    private async Task AnalyzeAsync()
    {
        var sel = ReadSelection();
        if (!sel.HasSelection)
        {
            _confirm.Inform(
                LocalizationService.GetString("Clean_LogHint"),
                LocalizationService.GetString("Clean_Title"));
            return;
        }

        IsAnalyzeEnabled = false;
        IsCleanEnabled = false;
        _analysed = false;
        Phase = CleanUiPhase.Analyzing;
        CleanCommand.NotifyCanExecuteChanged();
        ShowEmptyState = false;
        SetLog(LocalizationService.GetString("Clean_LogAnalyzeStart"));

        var result = await Task.Run(() => CleanEngine.Analyze(sel)).ConfigureAwait(true);

        TempSizeDisplay = ByteSizeFormat.Format(result.SystemBytes);
        BrowserSizeDisplay = ByteSizeFormat.Format(result.BrowserBytes);
        TotalSizeDisplay = ByteSizeFormat.Format(result.SystemBytes + result.BrowserBytes);
        foreach (var line in result.LogLines)
            AppendLog(line);

        _analysed = true;
        IsCleanEnabled = result.CanClean;
        ShowEmptyState = result.ShowEmptyState;
        Phase = result.ShowEmptyState ? CleanUiPhase.EmptyResult : CleanUiPhase.Ready;
        CleanCommand.NotifyCanExecuteChanged();
        IsAnalyzeEnabled = true;
    }

    private async Task CleanAsync()
    {
        if (!_analysed)
            return;

        var sel = ReadSelection();
        IsAnalyzeEnabled = false;
        IsCleanEnabled = false;
        Phase = CleanUiPhase.Cleaning;
        CleanCommand.NotifyCanExecuteChanged();
        AppendLog(LocalizationService.GetString("Clean_LogCleanStart"));
        var cleanStarted = DateTime.Now;

        try
        {
            var result = await Task.Run(() => CleanEngine.Clean(sel)).ConfigureAwait(true);
            foreach (var line in result.LogLines)
                AppendLog(line);

            TempSizeDisplay = ByteSizeFormat.Format(0);
            BrowserSizeDisplay = ByteSizeFormat.Format(0);
            TotalSizeDisplay = ByteSizeFormat.Format(0);
            _analysed = false;
            IsCleanEnabled = false;
            Phase = CleanUiPhase.Idle;
            CleanCommand.NotifyCanExecuteChanged();

            try
            {
                _logger.SaveCleanSession(new CleanSession
                {
                    StartedAt = cleanStarted,
                    FinishedAt = DateTime.Now,
                    TargetsSummary = CleanEngine.BuildTargetsSummary(sel),
                    BytesFreed = result.BytesFreed,
                    OperationLog = CaptureOperationLog(),
                });
                _container.RequestScanHistoryViewsRefresh();
            }
            catch (Exception ex)
            {
                AppLogger.Warn("CleanViewModel", "SaveCleanSession", ex);
            }
        }
        catch (Exception ex)
        {
            AppLogger.Warn("CleanViewModel", "Clean", ex);
            AppendLog(LocalizationService.Format("Clean_ErrCleaning", ex.Message));
        }
        finally
        {
            IsAnalyzeEnabled = true;
            if (_analysed)
            {
                IsCleanEnabled = true;
                Phase = ShowEmptyState ? CleanUiPhase.EmptyResult : CleanUiPhase.Ready;
                CleanCommand.NotifyCanExecuteChanged();
            }
        }
    }

    private void SetLog(string text) => LogText = $"[{DateTime.Now:HH:mm:ss}] {text}\n";

    private void AppendLog(string line)
    {
        if (CleanEngine.IsHintLog(LogText))
            LogText = string.Empty;
        LogText += $"[{DateTime.Now:HH:mm:ss}] {line}\n";
    }

    private string CaptureOperationLog()
    {
        var t = LogText.Trim();
        return CleanEngine.IsHintLog(t) ? string.Empty : t;
    }

    private CleanEngine.CleanSelection ReadSelection()
    {
        var ids = SystemItems.Concat(BrowserItems)
            .Where(i => i.IsSelected)
            .Select(i => i.Id);
        return CleanEngine.SelectionFromIds(ids);
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    private void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

    private bool SetField<T>(ref T field, T value, [CallerMemberName] string? name = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value))
            return false;
        field = value;
        OnPropertyChanged(name);
        return true;
    }
}
