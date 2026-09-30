using Microsoft.Win32;
using optiSCAN.Localization;
using optiSCAN.Models;
using optiSCAN.Services;
using optiSCAN.Strings;
using optiSCAN.ViewModels;
using optiSCAN.WinUI.Services;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.CompilerServices;

namespace optiSCAN.WinUI.ViewModels;

/// <summary>ViewModel de la page Options — préférences, exclusions et scans planifiés.</summary>
public sealed class OptionsViewModel : INotifyPropertyChanged
{
    private readonly ServiceContainer _services;
    private readonly IUiThreadScheduler _ui;
    private readonly Action<bool>? _applyTheme;
    private readonly IUserConfirmService _confirm;
    private bool _suppressEvents;
    private string? _languageBeforeChange;
    private int _favoriteScanIndexBeforeChange;

    private bool _realtime;
    private bool _processMonitor;
    private bool _tamper;
    private bool _platform;
    private bool _platformEnabled = true;
    private bool _removable;
    private bool _removableDetailed;
    private bool _includeRemovableFullScan;
    private bool _autoQuarantine;
    private bool _backupBeforeQuarantine;
    private bool _autoUpdate;
    private bool _aggressive;
    private bool _useClamd;
    private bool _notifications;
    private bool _autoStart;
    private bool _gameMode;
    private bool _alternateTheme;
    private bool _highContrast;
    private bool _scheduled;
    private bool _scheduledEnabled = true;
    private bool _runScheduleEnabled;
    private bool _scheduleTimeEnabled = true;
    private int _languageIndex;
    private int _favoriteScanIndex;
    private int _scheduleHourIndex = 2;
    private int _scheduleMinuteIndex;
    private string _scheduleStatusText = string.Empty;
    private string _newExclusionPath = string.Empty;
    private string _virusTotalApiKey = string.Empty;
    private string _cleanThreshold = string.Empty;
    private string _sigThreshold = string.Empty;
    private string _alternateThemeTitle = string.Empty;
    private string _alternateThemeSub = string.Empty;
    private string _themePresetId = "donaby";
    private string _themeAccentColor = string.Empty;

    public OptionsViewModel(
        ServiceContainer services,
        Action<bool>? applyTheme = null,
        IUiThreadScheduler? ui = null,
        IUserConfirmService? confirm = null)
    {
        _services = services;
        _applyTheme = applyTheme;
        _ui = ui ?? SyncUiThreadScheduler.Instance;
        _confirm = confirm ?? DeclineUserConfirmService.Instance;
        Exclusions = new ObservableCollection<string>();
        ScheduleHours = new ObservableCollection<string>();
        ScheduleMinutes = new ObservableCollection<string>();
        InitScheduleCombos();
        RunScheduleNowCommand = new AsyncRelayCommand(_ => RunScheduleNowAsync(), _ => _runScheduleEnabled);
        RefreshThemeLabels();
        LoadPreferences();
        _ = LoadScheduledStateAsync();
    }

    public ObservableCollection<string> Exclusions { get; }
    public ObservableCollection<string> ScheduleHours { get; }
    public ObservableCollection<string> ScheduleMinutes { get; }
    public AsyncRelayCommand RunScheduleNowCommand { get; }

    public bool Realtime { get => _realtime; set { if (SetField(ref _realtime, value)) OnOptionChanged(nameof(Realtime)); } }
    public bool ProcessMonitor { get => _processMonitor; set { if (SetField(ref _processMonitor, value)) OnOptionChanged(nameof(ProcessMonitor)); } }
    public bool Tamper { get => _tamper; set { if (SetField(ref _tamper, value)) OnOptionChanged(nameof(Tamper)); } }
    public bool Platform { get => _platform; set { if (SetField(ref _platform, value)) OnOptionChanged(nameof(Platform)); } }
    public bool PlatformEnabled { get => _platformEnabled; private set => SetField(ref _platformEnabled, value); }
    public bool Removable { get => _removable; set { if (SetField(ref _removable, value)) OnOptionChanged(nameof(Removable)); } }
    public bool RemovableDetailed { get => _removableDetailed; set { if (SetField(ref _removableDetailed, value)) OnOptionChanged(nameof(RemovableDetailed)); } }
    public bool IncludeRemovableFullScan { get => _includeRemovableFullScan; set { if (SetField(ref _includeRemovableFullScan, value)) OnOptionChanged(nameof(IncludeRemovableFullScan)); } }
    public bool AutoQuarantine { get => _autoQuarantine; set { if (SetField(ref _autoQuarantine, value)) OnOptionChanged(nameof(AutoQuarantine)); } }
    public bool BackupBeforeQuarantine { get => _backupBeforeQuarantine; set { if (SetField(ref _backupBeforeQuarantine, value)) OnOptionChanged(nameof(BackupBeforeQuarantine)); } }
    public bool AutoUpdate { get => _autoUpdate; set { if (SetField(ref _autoUpdate, value)) OnOptionChanged(nameof(AutoUpdate)); } }
    public bool Aggressive { get => _aggressive; set { if (SetField(ref _aggressive, value)) OnOptionChanged(nameof(Aggressive)); } }
    public bool UseClamd { get => _useClamd; set { if (SetField(ref _useClamd, value)) OnOptionChanged(nameof(UseClamd)); } }
    public bool Notifications { get => _notifications; set { if (SetField(ref _notifications, value)) OnOptionChanged(nameof(Notifications)); } }
    public bool AutoStart { get => _autoStart; set { if (SetField(ref _autoStart, value)) OnOptionChanged(nameof(AutoStart)); } }
    public bool GameMode { get => _gameMode; set { if (SetField(ref _gameMode, value)) OnOptionChanged(nameof(GameMode)); } }
    public bool AlternateTheme { get => _alternateTheme; set { if (SetField(ref _alternateTheme, value)) OnOptionChanged(nameof(AlternateTheme)); } }
    public bool HighContrast { get => _highContrast; set { if (SetField(ref _highContrast, value)) OnOptionChanged(nameof(HighContrast)); } }
    public bool Scheduled
    {
        get => _scheduled;
        set
        {
            if (!SetField(ref _scheduled, value))
                return;
            OnOptionChanged(nameof(Scheduled));
        }
    }

    public bool ScheduledEnabled { get => _scheduledEnabled; private set => SetField(ref _scheduledEnabled, value); }
    public bool RunScheduleEnabled { get => _runScheduleEnabled; private set { if (SetField(ref _runScheduleEnabled, value)) RunScheduleNowCommand.NotifyCanExecuteChanged(); } }
    public bool ScheduleTimeEnabled { get => _scheduleTimeEnabled; private set => SetField(ref _scheduleTimeEnabled, value); }
    public int LanguageIndex { get => _languageIndex; set => SetField(ref _languageIndex, value); }
    public int FavoriteScanIndex { get => _favoriteScanIndex; set => SetField(ref _favoriteScanIndex, value); }
    public int ScheduleHourIndex { get => _scheduleHourIndex; set => SetField(ref _scheduleHourIndex, value); }
    public int ScheduleMinuteIndex { get => _scheduleMinuteIndex; set => SetField(ref _scheduleMinuteIndex, value); }
    public string ScheduleStatusText { get => _scheduleStatusText; private set => SetField(ref _scheduleStatusText, value); }
    public string NewExclusionPath { get => _newExclusionPath; set => SetField(ref _newExclusionPath, value); }
    public string VirusTotalApiKey { get => _virusTotalApiKey; set { if (SetField(ref _virusTotalApiKey, value)) OnOptionChanged(nameof(VirusTotalApiKey)); } }
    public string CleanThreshold { get => _cleanThreshold; set { if (SetField(ref _cleanThreshold, value)) OnOptionChanged(nameof(CleanThreshold)); } }
    public string SigThreshold { get => _sigThreshold; set { if (SetField(ref _sigThreshold, value)) OnOptionChanged(nameof(SigThreshold)); } }
    public string AlternateThemeTitle { get => _alternateThemeTitle; private set => SetField(ref _alternateThemeTitle, value); }
    public string AlternateThemeSub { get => _alternateThemeSub; private set => SetField(ref _alternateThemeSub, value); }
    public string ThemePresetId { get => _themePresetId; private set => SetField(ref _themePresetId, value); }
    public string ThemeAccentColor { get => _themeAccentColor; private set => SetField(ref _themeAccentColor, value); }

    public void SetThemePreset(string presetId)
    {
        ThemePresetId = presetId;
        WinUiThemeManager.SetThemePreset(presetId);
    }

    public void SetThemeAccentColor(string? hex)
    {
        ThemeAccentColor = hex ?? string.Empty;
        WinUiThemeManager.SetCustomAccentColor(ThemeAccentColor);
    }

    /// <summary>
    /// Resynchronise la case « thème alternatif » après un changement fait ailleurs (bouton du volet
    /// de navigation) : sans cela la case restait sur l'ancienne valeur et la cliquer inversait l'effet.
    /// </summary>
    public void RefreshThemeState()
    {
        _suppressEvents = true;
        try
        {
            AlternateTheme = WinUiThemeManager.IsAlternateThemeEnabled;
            HighContrast = _services.UserPreferencesAccessor.Current.HighContrastEnabled;
        }
        finally
        {
            _suppressEvents = false;
        }
        RefreshThemeLabels();
    }

    public void RefreshThemeLabels()
    {
        bool windowsDark = WinUiThemeManager.IsWindowsAppsDarkTheme();
        AlternateThemeTitle = LocalizationService.GetString(windowsDark ? "Opt_ThemeLight" : "Opt_ThemeDark");
        AlternateThemeSub = LocalizationService.GetString(windowsDark ? "Opt_ThemeLightSub" : "Opt_ThemeDarkSub");
    }

    public void OnLanguageDropDownOpened() =>
        _languageBeforeChange = LocalizationService.IsEnglish ? "en-US" : "fr-FR";

    public void OnLanguageDropDownClosed(string? tag)
    {
        if (_suppressEvents || string.IsNullOrWhiteSpace(tag))
            return;

        var selected = tag.StartsWith("en", StringComparison.OrdinalIgnoreCase) ? "en-US" : "fr-FR";
        if (_languageBeforeChange == null
            || string.Equals(selected, _languageBeforeChange, StringComparison.OrdinalIgnoreCase))
            return;

        LocalizationService.SetUserCulture(selected);
        LocalizationService.RestartApplication();
    }

    public void OnFavoriteScanDropDownOpened() => _favoriteScanIndexBeforeChange = FavoriteScanIndex;

    public void OnFavoriteScanDropDownClosed()
    {
        if (_suppressEvents || FavoriteScanIndex == _favoriteScanIndexBeforeChange)
            return;

        var prefs = _services.UserPreferencesAccessor.Current;
        prefs.FavoriteScanType = FavoriteScanIndex switch
        {
            1 => ScanType.FullScan,
            2 => ScanType.Folder,
            3 => ScanType.File,
            _ => ScanType.QuickScan,
        };
        prefs.Save();
    }

    public void AddExclusion(string path)
    {
        var trimmed = path.Trim();
        if (string.IsNullOrEmpty(trimmed) || !Directory.Exists(trimmed))
            return;

        if (_services.ExclusionSettingsAccessor.Current.AddFolder(trimmed) && !Exclusions.Contains(trimmed))
            Exclusions.Add(trimmed);
        NewExclusionPath = string.Empty;
    }

    public void RemoveExclusion(string path)
    {
        if (ExclusionSettings.IsMandatoryExcludedFolder(path))
            return;
        Exclusions.Remove(path);
        _services.ExclusionSettingsAccessor.Current.RemoveFolder(path);
    }

    public void CommitThreshold(string tag, string text)
    {
        if (_suppressEvents)
            return;

        if (!int.TryParse(text, out int value) || value is < 1 or > 365)
        {
            value = tag == "CleanThreshold"
                ? RecommendationThresholds.CleanSuggestThresholdDays
                : RecommendationThresholds.SignatureStaleThresholdDays;
            if (tag == "CleanThreshold")
                CleanThreshold = value.ToString(CultureInfo.InvariantCulture);
            else
                SigThreshold = value.ToString(CultureInfo.InvariantCulture);
        }

        var prefs = _services.UserPreferencesAccessor.Current;
        if (tag == "CleanThreshold")
            prefs.CleanSuggestThresholdDays = value;
        else if (tag == "SigThreshold")
            prefs.SignatureStaleThresholdDays = value;
        prefs.Save();
    }

    private void InitScheduleCombos()
    {
        for (int h = 0; h < 24; h++)
            ScheduleHours.Add(h.ToString("00", CultureInfo.InvariantCulture));
        for (int m = 0; m < 60; m += 15)
            ScheduleMinutes.Add(m.ToString("00", CultureInfo.InvariantCulture));
    }

    /// <summary>Relit les préférences (ex. après l'assistant de premier lancement qui les modifie).</summary>
    public void ReloadPreferences() => LoadPreferences();

    private void LoadPreferences()
    {
        _suppressEvents = true;
        try
        {
            var prefs = _services.UserPreferencesAccessor.Current;
            var excl = _services.ExclusionSettingsAccessor.Current;

            Notifications = prefs.ActionNotificationsEnabled;
            AutoStart = IsAutoStartRegistered();
            AutoUpdate = prefs.SignatureAutoUpdateEnabled;
            Aggressive = prefs.AggressiveSignatureUpdates;
            UseClamd = prefs.UseClamdEngine;
            GameMode = prefs.GameModeAutoEnabled;
            Realtime = excl.RealTimeEnabled;
            ProcessMonitor = prefs.ProcessMonitorEnabled;
            Tamper = prefs.TamperProtectionEnabled;
            Removable = prefs.RemovableDriveScanEnabled;
            RemovableDetailed = prefs.RemovableDriveScanDetailed;
            IncludeRemovableFullScan = prefs.IncludeRemovableInFullScan;
            AutoQuarantine = excl.AutoQuarantineEnabled;
            BackupBeforeQuarantine = prefs.BackupBeforeQuarantine;
            AlternateTheme = WinUiThemeManager.IsAlternateThemeEnabled;
            HighContrast = _services.UserPreferencesAccessor.Current.HighContrastEnabled;
            ThemePresetId = prefs.ThemePresetId;
            ThemeAccentColor = prefs.ThemeAccentColor ?? string.Empty;
            VirusTotalApiKey = prefs.VirusTotalApiKey ?? string.Empty;
            CleanThreshold = prefs.CleanSuggestThresholdDays.ToString(CultureInfo.InvariantCulture);
            SigThreshold = prefs.SignatureStaleThresholdDays.ToString(CultureInfo.InvariantCulture);
            LanguageIndex = prefs.UiCulture?.StartsWith("en", StringComparison.OrdinalIgnoreCase) == true ? 1 : 0;
            FavoriteScanIndex = prefs.FavoriteScanType switch
            {
                ScanType.FullScan => 1,
                ScanType.Folder => 2,
                ScanType.File => 3,
                _ => 0,
            };

            PlatformEnabled = PlatformProtectionFeatureGate.IsUserActivatable;
            Platform = PlatformEnabled && prefs.UsePlatformProtectionService;

            Exclusions.Clear();
            foreach (var path in excl.ExcludedFolders)
                Exclusions.Add(path);

            if (string.IsNullOrEmpty(ScheduleStatusText))
                ScheduleStatusText = LocalizationService.GetString("Opt_SchedLoading");
        }
        finally
        {
            _suppressEvents = false;
        }
    }

    private async Task LoadScheduledStateAsync()
    {
        ScheduledEnabled = false;
        try
        {
            bool exists = await Task.Run(() => _services.ScheduledScan.IsTaskExists());
            _suppressEvents = true;
            try { Scheduled = exists; }
            finally { _suppressEvents = false; }
            await RefreshScheduledStatusAsync();
        }
        finally
        {
            ScheduledEnabled = true;
        }
    }

    private async Task RefreshScheduledStatusAsync()
    {
        bool exists = await Task.Run(() => _services.ScheduledScan.IsTaskExists());
        if (!exists)
        {
            ScheduleStatusText = LocalizationService.GetString("Opt_SchedNone");
            RunScheduleEnabled = false;
            ScheduleTimeEnabled = true;
            return;
        }

        RunScheduleEnabled = true;
        ScheduleTimeEnabled = false;
        var next = await Task.Run(() => _services.ScheduledScan.GetNextRunTime());
        ScheduleStatusText = next.HasValue
            ? LocalizationService.Format("Opt_SchedNextRun", next.Value.ToString("f", LocalizationService.CurrentCulture))
            : LocalizationService.GetString("Opt_SchedActiveUnknown");
    }

    private void OnOptionChanged(string option)
    {
        if (_suppressEvents)
            return;

        switch (option)
        {
            case nameof(Notifications):
                var prefsN = _services.UserPreferencesAccessor.Current;
                prefsN.ActionNotificationsEnabled = Notifications;
                prefsN.Save();
                _services.Notifications.IsEnabled = Notifications;
                break;
            case nameof(AutoStart):
                SetAutoStart(AutoStart);
                break;
            case nameof(AutoUpdate):
                _services.ApplySignatureAutoUpdate(AutoUpdate);
                break;
            case nameof(UseClamd):
                var prefsC = _services.UserPreferencesAccessor.Current;
                prefsC.UseClamdEngine = UseClamd;
                prefsC.Save();
                if (UseClamd)
                    _ = Task.Run(async () => { try { await ClamdHost.Shared.EnsureRunningAsync(); } catch (Exception ex) { AppLogger.Warn("OptionsViewModel", "clamd", ex); } });
                else
                    ClamdHost.Shared.Stop();
                break;
            case nameof(GameMode):
                var prefsG = _services.UserPreferencesAccessor.Current;
                prefsG.GameModeAutoEnabled = GameMode;
                prefsG.Save();
                if (GameMode) DistractionFreeMonitor.Start();
                else DistractionFreeMonitor.Stop();
                break;
            case nameof(Realtime):
                _services.ApplyRealtimeProtection(Realtime);
                break;
            case nameof(ProcessMonitor):
                _services.ApplyProcessMonitor(ProcessMonitor);
                break;
            case nameof(Tamper):
                _services.ApplyTamperProtection(Tamper);
                break;
            case nameof(Platform) when PlatformEnabled:
                _services.ApplyPlatformProtectionService(Platform);
                break;
            case nameof(Removable):
                _services.ApplyRemovableDriveScan(Removable);
                break;
            case nameof(RemovableDetailed):
                var prefsRd = _services.UserPreferencesAccessor.Current;
                prefsRd.RemovableDriveScanDetailed = RemovableDetailed;
                prefsRd.Save();
                break;
            case nameof(IncludeRemovableFullScan):
                var prefsIr = _services.UserPreferencesAccessor.Current;
                prefsIr.IncludeRemovableInFullScan = IncludeRemovableFullScan;
                prefsIr.Save();
                break;
            case nameof(AutoQuarantine):
                _services.ApplyAutoQuarantine(AutoQuarantine);
                break;
            case nameof(BackupBeforeQuarantine):
                var prefsB = _services.UserPreferencesAccessor.Current;
                prefsB.BackupBeforeQuarantine = BackupBeforeQuarantine;
                prefsB.Save();
                break;
            case nameof(Aggressive):
                var prefsA = _services.UserPreferencesAccessor.Current;
                prefsA.AggressiveSignatureUpdates = Aggressive;
                prefsA.Save();
                if (prefsA.SignatureAutoUpdateEnabled)
                    _services.ApplySignatureAutoUpdate(true);
                break;
            case nameof(AlternateTheme):
                WinUiThemeManager.SetAlternateThemeEnabled(AlternateTheme);
                RefreshThemeLabels();
                _applyTheme?.Invoke(WinUiThemeManager.IsDarkTheme);
                break;
            case nameof(HighContrast):
                WinUiThemeManager.SetHighContrast(HighContrast);
                break;
            case nameof(VirusTotalApiKey):
                var prefsVt = _services.UserPreferencesAccessor.Current;
                prefsVt.VirusTotalApiKey = VirusTotalApiKey;
                prefsVt.Save();
                break;
            case nameof(Scheduled):
                ScheduledEnabled = false;
                ScheduleTimeEnabled = false;
                RunScheduleEnabled = false;
                _ = ApplyScheduledScanAsync(Scheduled, GetSelectedScheduleTime());
                break;
        }
    }

    private TimeSpan GetSelectedScheduleTime()
    {
        int h = ScheduleHourIndex >= 0 ? ScheduleHourIndex : 2;
        int m = 0;
        if (ScheduleMinuteIndex >= 0 && ScheduleMinuteIndex < ScheduleMinutes.Count
            && int.TryParse(ScheduleMinutes[ScheduleMinuteIndex], out var parsed))
            m = parsed;
        return new TimeSpan(h, m, 0);
    }

    private async Task ApplyScheduledScanAsync(bool enable, TimeSpan? schedTime)
    {
        try
        {
            bool ok = await Task.Run(() => ScheduledScanApply.SetEnabled(enable, schedTime, _services.ScheduledScan));
            if (enable && !ok)
            {
                _confirm.Warn(
                    LocalizationService.GetString("Opt_SchedTaskFailed"),
                    LocalizationService.GetString("Opt_SchedTaskTitle"));
            }
        }
        finally
        {
            _suppressEvents = true;
            try
            {
                bool exists = await Task.Run(() => _services.ScheduledScan.IsTaskExists());
                Scheduled = exists;
                ScheduledEnabled = true;
            }
            finally { _suppressEvents = false; }
            await RefreshScheduledStatusAsync();
        }
    }

    private async Task RunScheduleNowAsync()
    {
        bool exists = await Task.Run(() => _services.ScheduledScan.IsTaskExists());
        if (!exists)
            return;

        RunScheduleEnabled = false;
        try
        {
            await Task.Run(() => _services.ScheduledScan.RunNow());
            await RefreshScheduledStatusAsync();
        }
        finally
        {
            RunScheduleEnabled = true;
        }
    }

    public async Task CheckAppUpdateAsync()
    {
        AppUpdateCheckResult result;
        try
        {
            result = await new UpdateService().CheckForUpdatesAsync().ConfigureAwait(true);
        }
        catch (Exception ex)
        {
            AppLogger.Error("OptionsViewModel", "CheckForUpdatesAsync", ex);
            result = new AppUpdateCheckResult
            {
                Status = AppUpdateChannelStatus.StagingError,
                CurrentVersion = ProductVersionInfo.SemVer,
                ReleaseLabel = ProductVersionInfo.ReleaseLabel,
                UserMessage = LocalizationService.Format("Opt_AppUpdateCheckError", ex.Message),
            };
        }

        // Le message propose d'ouvrir la page de téléchargement : « Oui » l'ouvre.
        if (_confirm.ConfirmYesNo(
                result.UserMessage,
                LocalizationService.GetString("Opt_AppUpdateTitle"),
                warning: false))
        {
            OpenSourceForge();
        }
    }

    public void OpenSourceForge()
    {
        try
        {
            Process.Start(new ProcessStartInfo(OptiscanStrings.Urls.OptiscanSourceForge) { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            AppLogger.Warn("OptionsViewModel", "OpenSourceForge", ex);
        }
    }

    // ── Cohabitation Windows Defender ────────────────────────────────────────
    public DefenderCoexistenceStatus GetDefenderStatus() => _services.GetDefenderCoexistenceStatus();

    /// <summary>Opt-in : réapplique les exclusions Defender (pas d'application silencieuse au démarrage).</summary>
    public void RefreshDefenderExclusions() => _services.RefreshDefenderExclusions();

    // ── Documents légaux livrés avec l'application ───────────────────────────
    public void OpenBundledDocument(string relativePath)
    {
        var path = Path.Combine(AppContext.BaseDirectory, relativePath);
        if (!File.Exists(path))
        {
            _confirm.Warn(
                LocalizationService.Format("Opt_OpenDocError", path),
                LocalizationService.GetString("Opt_Title"));
            return;
        }

        try
        {
            Process.Start(new ProcessStartInfo { FileName = path, UseShellExecute = true });
        }
        catch (Exception ex)
        {
            AppLogger.Warn("OptionsViewModel", $"Open document {relativePath}", ex);
            _confirm.Warn(
                LocalizationService.Format("Opt_OpenDocError", ex.Message),
                LocalizationService.GetString("Opt_Title"));
        }
    }

    public void OpenLogsFolder()
    {
        try
        {
            if (!Directory.Exists(AppLogger.LogDirectory))
                Directory.CreateDirectory(AppLogger.LogDirectory);

            Process.Start(new ProcessStartInfo
            {
                FileName = AppLogger.LogDirectory,
                UseShellExecute = true,
            });
        }
        catch (Exception ex)
        {
            AppLogger.Warn("OptionsViewModel", "OpenLogsFolder", ex);
            _confirm.Warn(
                LocalizationService.Format("Opt_LogsOpenError", ex.Message),
                LocalizationService.GetString("Opt_DiagnosticsTitle"));
        }
    }

    private static bool IsAutoStartRegistered()
    {
        const string regKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
        const string appName = "optiSCAN";
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(regKey, writable: false);
            return key?.GetValue(appName) != null;
        }
        catch { return false; }
    }

    private static void SetAutoStart(bool enable)
    {
        const string regKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
        const string appName = "optiSCAN";
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(regKey, writable: true);
            if (key == null)
                return;
            if (enable)
            {
                var exe = Environment.ProcessPath ?? Path.Combine(AppContext.BaseDirectory, "optiSCAN.exe");
                key.SetValue(appName, $"\"{exe}\"");
            }
            else
                key.DeleteValue(appName, throwOnMissingValue: false);
        }
        catch (Exception ex)
        {
            AppLogger.Warn("OptionsViewModel", "SetAutoStart", ex);
        }
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
