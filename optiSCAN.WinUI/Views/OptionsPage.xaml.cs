using Microsoft.UI.Xaml;

using Microsoft.UI.Xaml.Controls;

using optiSCAN.Localization;

using optiSCAN.Services;

using optiSCAN.Strings;

using optiSCAN.WinUI.Services;

using optiSCAN.WinUI.ViewModels;

using System.Diagnostics;
using System.Linq;




namespace optiSCAN.WinUI.Views;



public sealed partial class OptionsPage : UserControl

{

    private bool _suppressUiSync;



    public OptionsViewModel ViewModel { get; }



    public OptionsPage(OptionsViewModel viewModel)

    {

        ViewModel = viewModel;

        InitializeComponent();

        ExclusionsList.ItemsSource = ViewModel.Exclusions;

        ScheduleHour.ItemsSource = ViewModel.ScheduleHours;

        ScheduleMinute.ItemsSource = ViewModel.ScheduleMinutes;

        InitFavoriteScanCombo();

        InitThemePresetCombo();

        ApplyLocalizedLabels();

        ViewModel.PropertyChanged += (_, _) => DispatcherQueue.TryEnqueue(SyncUi);

        Loaded += OnLoaded;

        Unloaded += OnUnloaded;

        RegisterPropertyChangedCallback(VisibilityProperty, (_, _) =>

        {

            if (Visibility == Visibility.Visible)

                ViewModel.RefreshThemeLabels();

        });

        SyncUi();

    }



    private void InitThemePresetCombo()
    {
        ThemePresetCombo.Items.Clear();
        foreach (var pack in WinUiThemePacks.All)
        {
            ThemePresetCombo.Items.Add(new ComboBoxItem
            {
                Content = LocalizationService.GetString(pack.NameKey),
                Tag = pack.Id,
            });
        }
    }

    private void InitFavoriteScanCombo()

    {

        FavoriteScanCombo.Items.Add(LocalizationService.GetString("Opt_FavQuick"));

        FavoriteScanCombo.Items.Add(LocalizationService.GetString("Opt_FavFull"));

        FavoriteScanCombo.Items.Add(LocalizationService.GetString("Opt_FavFolder"));

        FavoriteScanCombo.Items.Add(LocalizationService.GetString("Opt_FavFile"));

    }



    private void OnLoaded(object sender, RoutedEventArgs e)

    {

        WinUiThemeManager.ThemeChanged += OnThemeChanged;
        ServiceContainer.UiEvents.ProtectionStateRefreshRequested += OnProtectionStateRefreshRequested;
        RefreshDefenderStatus();

        ViewModel.RefreshThemeLabels();

    }



    private void OnUnloaded(object sender, RoutedEventArgs e) =>

        UnsubscribeOptionsEvents();



    private void UnsubscribeOptionsEvents()
    {
        WinUiThemeManager.ThemeChanged -= OnThemeChanged;
        ServiceContainer.UiEvents.ProtectionStateRefreshRequested -= OnProtectionStateRefreshRequested;
    }

    private void OnProtectionStateRefreshRequested(object? sender, EventArgs e) =>
        DispatcherQueue.TryEnqueue(RefreshDefenderStatus);

    // ── Cohabitation Windows Defender ────────────────────────────────────────
    private void RefreshDefenderStatus()
    {
        var status = ViewModel.GetDefenderStatus();
        if (!status.IsDefenderActive)
        {
            DefenderPanel.Visibility = Visibility.Collapsed;
            return;
        }

        DefenderPanel.Visibility = Visibility.Visible;
        DefenderModeText.Text = LocalizationService.GetString(status.StatusMessageKey);
        DefenderExclusionsText.Text = LocalizationService.GetString(status.ExclusionMessageKey);
    }

    private async void DefenderRefresh_Click(object sender, RoutedEventArgs e)
    {
        ViewModel.RefreshDefenderExclusions();
        // Retour asynchrone (PowerShell, éventuelle élévation) : on relit l'état après un court délai.
        await Task.Delay(2500);
        RefreshDefenderStatus();
    }

    // ── Documents légaux ─────────────────────────────────────────────────────
    private void PrivacyPolicy_Click(object sender, RoutedEventArgs e) =>
        ViewModel.OpenBundledDocument(@"docs\POLITIQUE_CONFIDENTIALITE.md");

    private void License_Click(object sender, RoutedEventArgs e) =>
        ViewModel.OpenBundledDocument("LICENSE.txt");

    private void OnThemeChanged(object? sender, bool _) => ViewModel.RefreshThemeLabels();



    private void ApplyLocalizedLabels()

    {

        PageTitle.Text = LocalizationService.GetString("Opt_Title");

        ProtectionTitle.Text = LocalizationService.GetString("Opt_Antivirus");

        UpdatesTitle.Text = LocalizationService.GetString("Opt_General");

        AppearanceTitle.Text = LocalizationService.GetString("Opt_General");

        AdvancedTitle.Text = LocalizationService.GetString("Opt_RecThresholds");

        ExclusionsTitle.Text = LocalizationService.GetString("Opt_Exclusions");

        ScheduleTitle.Text = LocalizationService.GetString("Opt_Scheduled");

        LanguageLabel.Text = LocalizationService.GetString("Opt_Language");

        FavoriteScanLabel.Text = LocalizationService.GetString("Opt_FavScan");

        FavoriteScanHint.Text = LocalizationService.GetString("Opt_FavHint");

        AddExclusionButton.Content = LocalizationService.GetString("Opt_Add");

        BrowseExclusionButton.Content = LocalizationService.GetString("Opt_Browse");

        RunScheduleNowButton.Content = LocalizationService.GetString("Opt_RunNow");

        ChkRealtime.Content = LocalizationService.GetString("Opt_Rtp");

        ChkProcessMonitor.Content = LocalizationService.GetString("Opt_ProcessMonitor");

        ChkTamper.Content = LocalizationService.GetString("Opt_TamperProtection");

        ChkPlatform.Content = LocalizationService.GetString("Opt_PlatformProtection");
        PlatformSubText.Text = LocalizationService.GetString("Opt_PlatformProtectionSub");

        ChkRemovable.Content = LocalizationService.GetString("Opt_RemovableScan");

        ChkRemovableDetailed.Content = LocalizationService.GetString("Opt_RemovableDetailed");

        ChkIncludeRemovableFullScan.Content = LocalizationService.GetString("Opt_IncludeRemovableFull");

        ChkAutoQuarantine.Content = LocalizationService.GetString("Opt_AutoQuarantine");

        ChkBackupBeforeQuarantine.Content = LocalizationService.GetString("Opt_BackupBeforeQuarantine");

        ChkAutoUpdate.Content = LocalizationService.GetString("Opt_AutoSig");

        ChkAggressive.Content = LocalizationService.GetString("Opt_AggressiveSignatures");

        ChkUseClamd.Content = LocalizationService.GetString("Opt_UseClamd");

        ChkNotifications.Content = LocalizationService.GetString("Opt_Notifications");

        ChkAutoStart.Content = LocalizationService.GetString("Opt_Startup");

        ChkGameMode.Content = LocalizationService.GetString("Opt_GameMode");

        ChkScheduled.Content = LocalizationService.GetString("Opt_Scheduled");

        VirusTotalLabel.Text = LocalizationService.GetString("Opt_VirusTotal");

        VirusTotalSub.Text = LocalizationService.GetString("Opt_VirusTotalSub");

        CleanThresholdLabel.Text = LocalizationService.GetString("Opt_CleanThreshold");

        SigThresholdLabel.Text = LocalizationService.GetString("Opt_SigThreshold");
        // Unité traduite (« j » était codé en dur en français, y compris en anglais).
        CleanThresholdUnit.Text = LocalizationService.GetString("Opt_Days");
        SigThresholdUnit.Text = LocalizationService.GetString("Opt_Days");

        AppUpdateTitle.Text = LocalizationService.GetString("Opt_AppUpdateTitle");

        AppUpdateHint.Text = LocalizationService.GetString("Opt_UpdateHint");

        CheckAppUpdateButton.Content = LocalizationService.GetString("Opt_AboutUpdates");
        PrivacyPolicyButton.Content = LocalizationService.GetString("Opt_PrivacyPolicy");
        LicenseButton.Content = LocalizationService.GetString("Opt_License");
        LegalHintText.Text = LocalizationService.GetString("Opt_LegalHint");
        DefenderTitle.Text = LocalizationService.GetString("Defender_Opt_Title");
        DefenderRefreshButton.Content = LocalizationService.GetString("Defender_Opt_RefreshExclusions");

        OpenSourceForgeButton.Content = LocalizationService.GetString("Opt_SourceForge");

        DiagnosticsTitle.Text = LocalizationService.GetString("Opt_DiagnosticsTitle");

        LogsHint.Text = LocalizationService.GetString("Opt_LogsHint");

        LogsPathLabel.Text = LocalizationService.GetString("Opt_LogsPathLabel");

        LogsPathText.Text = AppLogger.LogDirectory;

        OpenLogsFolderButton.Content = LocalizationService.GetString("Opt_OpenLogsFolder");

        HighContrastTitle.Text = LocalizationService.GetString("Opt_HighContrast");

        HighContrastSub.Text = LocalizationService.GetString("Opt_HighContrastSub");

        ThemePresetLabel.Text = LocalizationService.GetString("Opt_ThemePreset");
        ThemeAccentLabel.Text = LocalizationService.GetString("Opt_ThemeAccent");

        NewExclusionBox.PlaceholderText = LocalizationService.GetString("Opt_ExclusionPlaceholder");


    }



    private void SyncUi()

    {

        _suppressUiSync = true;

        try

        {

            ChkRealtime.IsChecked = ViewModel.Realtime;

            ChkProcessMonitor.IsChecked = ViewModel.ProcessMonitor;

            ChkTamper.IsChecked = ViewModel.Tamper;

            ChkPlatform.IsChecked = ViewModel.Platform;

            ChkPlatform.IsEnabled = ViewModel.PlatformEnabled;

            PlatformPanel.Opacity = ViewModel.PlatformEnabled ? 1.0 : 0.55;

            ChkRemovable.IsChecked = ViewModel.Removable;

            ChkRemovableDetailed.IsChecked = ViewModel.RemovableDetailed;

            ChkIncludeRemovableFullScan.IsChecked = ViewModel.IncludeRemovableFullScan;

            ChkAutoQuarantine.IsChecked = ViewModel.AutoQuarantine;

            ChkBackupBeforeQuarantine.IsChecked = ViewModel.BackupBeforeQuarantine;

            ChkAutoUpdate.IsChecked = ViewModel.AutoUpdate;

            ChkAggressive.IsChecked = ViewModel.Aggressive;

            ChkUseClamd.IsChecked = ViewModel.UseClamd;

            ChkNotifications.IsChecked = ViewModel.Notifications;

            ChkAutoStart.IsChecked = ViewModel.AutoStart;

            ChkGameMode.IsChecked = ViewModel.GameMode;

            ChkAlternateTheme.IsChecked = ViewModel.AlternateTheme;

            ChkHighContrast.IsChecked = ViewModel.HighContrast;

            ThemeAccentBox.Text = ViewModel.ThemeAccentColor;
            SelectThemePresetCombo(ViewModel.ThemePresetId);

            ChkScheduled.IsChecked = ViewModel.Scheduled;

            ChkScheduled.IsEnabled = ViewModel.ScheduledEnabled;

            LanguageCombo.SelectedIndex = ViewModel.LanguageIndex;

            FavoriteScanCombo.SelectedIndex = ViewModel.FavoriteScanIndex;

            ScheduleHour.SelectedIndex = ViewModel.ScheduleHourIndex;

            ScheduleMinute.SelectedIndex = ViewModel.ScheduleMinuteIndex;

            AlternateThemeTitle.Text = ViewModel.AlternateThemeTitle;

            AlternateThemeSub.Text = ViewModel.AlternateThemeSub;

            TxtCleanThreshold.Text = ViewModel.CleanThreshold;

            TxtSigThreshold.Text = ViewModel.SigThreshold;

            if (PwdVirusTotal.Password != ViewModel.VirusTotalApiKey)

                PwdVirusTotal.Password = ViewModel.VirusTotalApiKey;

        }

        finally

        {

            _suppressUiSync = false;

        }



        ScheduleStatusText.Text = ViewModel.ScheduleStatusText;

        RunScheduleNowButton.IsEnabled = ViewModel.RunScheduleEnabled;

        ScheduleHour.IsEnabled = ViewModel.ScheduleTimeEnabled;

        ScheduleMinute.IsEnabled = ViewModel.ScheduleTimeEnabled;

        ScheduleTimePanel.Opacity = ViewModel.ScheduleTimeEnabled ? 1.0 : 0.55;

    }



    private void Option_Changed(object sender, RoutedEventArgs e)

    {

        if (_suppressUiSync || sender is not CheckBox cb)

            return;



        bool isOn = cb.IsChecked == true;

        switch (cb.Tag as string)

        {

            case "RealtimeProtection": ViewModel.Realtime = isOn; break;

            case "ProcessMonitor": ViewModel.ProcessMonitor = isOn; break;

            case "TamperProtection": ViewModel.Tamper = isOn; break;

            case "PlatformProtection": ViewModel.Platform = isOn; break;

            case "RemovableDriveScan": ViewModel.Removable = isOn; break;

            case "RemovableDriveDetailed": ViewModel.RemovableDetailed = isOn; break;

            case "IncludeRemovableFullScan": ViewModel.IncludeRemovableFullScan = isOn; break;

            case "AutoQuarantine": ViewModel.AutoQuarantine = isOn; break;

            case "BackupBeforeQuarantine": ViewModel.BackupBeforeQuarantine = isOn; break;

            case "AutoUpdate": ViewModel.AutoUpdate = isOn; break;

            case "AggressiveSignatures": ViewModel.Aggressive = isOn; break;

            case "UseClamd": ViewModel.UseClamd = isOn; break;

            case "Notifications": ViewModel.Notifications = isOn; break;

            case "AutoStart": ViewModel.AutoStart = isOn; break;

            case "GameMode": ViewModel.GameMode = isOn; break;

            case "AlternateTheme": ViewModel.AlternateTheme = isOn; break;

            case "HighContrast": ViewModel.HighContrast = isOn; break;

            case "ScheduledScan": ViewModel.Scheduled = isOn; break;

        }

    }



    private void LanguageCombo_DropDownOpened(object sender, object e) =>

        ViewModel.OnLanguageDropDownOpened();



    private void LanguageCombo_DropDownClosed(object sender, object e)

    {

        if (_suppressUiSync || LanguageCombo.SelectedItem is not ComboBoxItem item)

            return;

        ViewModel.OnLanguageDropDownClosed(item.Tag as string);

    }



    private void FavoriteScanCombo_DropDownOpened(object sender, object e) =>

        ViewModel.OnFavoriteScanDropDownOpened();



    private void FavoriteScanCombo_DropDownClosed(object sender, object e)

    {

        if (_suppressUiSync)

            return;

        ViewModel.FavoriteScanIndex = FavoriteScanCombo.SelectedIndex;

        ViewModel.OnFavoriteScanDropDownClosed();

    }



    private void PwdVirusTotal_Changed(object sender, RoutedEventArgs e)

    {

        if (_suppressUiSync)

            return;

        ViewModel.VirusTotalApiKey = PwdVirusTotal.Password;

    }



    private void NumericOnly_BeforeTextChanging(TextBox sender, TextBoxBeforeTextChangingEventArgs args) =>

        args.Cancel = !args.NewText.All(char.IsDigit);



    private void ThresholdBox_LostFocus(object sender, RoutedEventArgs e)

    {

        if (_suppressUiSync || sender is not TextBox box || box.Tag is not string tag)

            return;

        ViewModel.CommitThreshold(tag, box.Text ?? string.Empty);

    }



    private void AddExclusion_Click(object sender, RoutedEventArgs e)
    {
        var path = (NewExclusionBox.Text ?? string.Empty).Trim();
        if (path.Length == 0)
            return;

        // L'ancien code ignorait silencieusement un chemin inexistant et ne vidait jamais la zone de saisie.
        if (!Directory.Exists(path))
        {
            App.MainWindowInstance?.ShowWarning(
                LocalizationService.GetString("Opt_ExclNeedFolder"),
                LocalizationService.GetString("Opt_Exclusions"));
            return;
        }

        ViewModel.AddExclusion(path);
        NewExclusionBox.Text = string.Empty;
    }



    private void BrowseExclusion_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            // Sélecteur Win32 : le FolderPicker WinRT échoue quand l'application tourne en administrateur.
            var folder = WinUiNativeDialogs.PickFolder(LocalizationService.GetString("Opt_ExclFolderPickerDesc"));
            if (!string.IsNullOrWhiteSpace(folder))
                ViewModel.AddExclusion(folder);
        }
        catch (Exception ex)
        {
            AppLogger.Warn("OptionsPage", "BrowseExclusion", ex);
        }
    }

    // Le libellé était fourni par une ressource « Opt_RemoveLabel » injectée au runtime dans
    // Application.Resources : si le modèle de ligne était réalisé avant, la ressource était introuvable.
    private void RemoveExclusionButton_Loaded(object sender, RoutedEventArgs e)
    {
        if (sender is Button button)
            button.Content = LocalizationService.GetString("Opt_Remove");
    }

    // Les listes Heure / Minute n'étaient jamais relues : l'heure choisie pour l'analyse planifiée
    // était ignorée (toujours 02:00).
    private void ScheduleTime_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_suppressUiSync)
            return;
        if (ScheduleHour.SelectedIndex >= 0)
            ViewModel.ScheduleHourIndex = ScheduleHour.SelectedIndex;
        if (ScheduleMinute.SelectedIndex >= 0)
            ViewModel.ScheduleMinuteIndex = ScheduleMinute.SelectedIndex;
    }



    private void RemoveExclusion_Click(object sender, RoutedEventArgs e)

    {

        if (sender is Button { Tag: string path })

            ViewModel.RemoveExclusion(path);

    }



    private void RunScheduleNow_Click(object sender, RoutedEventArgs e) =>

        ViewModel.RunScheduleNowCommand.Execute(null);



    private async void CheckAppUpdate_Click(object sender, RoutedEventArgs e) =>

        await ViewModel.CheckAppUpdateAsync();



    private void OpenSourceForge_Click(object sender, RoutedEventArgs e)

    {

        try

        {

            Process.Start(new ProcessStartInfo(OptiscanStrings.Urls.OptiscanSourceForge) { UseShellExecute = true });

        }

        catch (Exception ex)

        {

            AppLogger.Warn("OptionsPage", "OpenSourceForge", ex);

        }

    }



    private void OpenLogsFolder_Click(object sender, RoutedEventArgs e) =>
        ViewModel.OpenLogsFolder();

    private void SelectThemePresetCombo(string presetId)
    {
        for (int i = 0; i < ThemePresetCombo.Items.Count; i++)
        {
            if (ThemePresetCombo.Items[i] is ComboBoxItem item
                && string.Equals(item.Tag as string, presetId, StringComparison.OrdinalIgnoreCase))
            {
                ThemePresetCombo.SelectedIndex = i;
                return;
            }
        }
    }

    private void ThemePresetCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_suppressUiSync || ThemePresetCombo.SelectedItem is not ComboBoxItem item)
            return;
        var id = item.Tag as string ?? "donaby";
        ViewModel.SetThemePreset(id);
    }

    private void ThemeAccentBox_LostFocus(object sender, RoutedEventArgs e) =>
        ViewModel.SetThemeAccentColor(ThemeAccentBox.Text);

}


