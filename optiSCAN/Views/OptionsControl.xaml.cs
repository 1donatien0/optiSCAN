using Microsoft.Win32;
using optiSCAN.Localization;
using optiSCAN.Models;
using optiSCAN.Services;
using optiSCAN.Strings;
using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using WinForms = System.Windows.Forms;
using WpfButton = System.Windows.Controls.Button;
using WpfCheckBox = System.Windows.Controls.CheckBox;

namespace optiSCAN.Views
{
    /// <summary>
    /// Vue Options — exclusions, protection temps réel, scans planifiés, thème et préférences utilisateur.
    /// </summary>
    public partial class OptionsControl : System.Windows.Controls.UserControl
    {
        private readonly ObservableCollection<string> _exclusions = new();
        private ScheduledScanService ScheduledScan => ServiceContainer.Default.ScheduledScan;
        private bool _suppressPreferenceEvents;
        private string? _languageTagBeforeDropDown;
        private int _favoriteScanIndexBeforeDropDown;

        public OptionsControl()
        {
            InitializeComponent();
            lstExclusions.ItemsSource = _exclusions;
            InitScheduleTimeComboBoxes();
            LoadPreferences();
        }

        private void InitScheduleTimeComboBoxes()
        {
            if (cmbScheduleHour == null || cmbScheduleMinute == null) return;
            for (int h = 0; h < 24; h++)
                cmbScheduleHour.Items.Add(h.ToString("00", CultureInfo.InvariantCulture));
            for (int m = 0; m < 60; m += 15)
                cmbScheduleMinute.Items.Add(m.ToString("00", CultureInfo.InvariantCulture));
            cmbScheduleHour.SelectedIndex = 2;
            cmbScheduleMinute.SelectedIndex = 0;
        }

        private TimeSpan GetSelectedScheduleTime()
        {
            int h = cmbScheduleHour?.SelectedIndex ?? 2;
            int m = 0;
            if (cmbScheduleMinute?.SelectedItem is string ms && int.TryParse(ms, out var parsed))
                m = parsed;
            return new TimeSpan(h, m, 0);
        }

        private void LoadPreferences()
        {
            _suppressPreferenceEvents = true;
            try
            {
                var prefs = UserPreferences.Current;
                if (chkNotifications != null)
                    chkNotifications.IsChecked = prefs.ActionNotificationsEnabled;
                if (chkAutoStart != null)
                    chkAutoStart.IsChecked = IsAutoStartRegistered();
                if (chkDarkTheme != null)
                    chkDarkTheme.IsChecked = prefs.DarkTheme;
                if (chkSyncWindowsTheme != null)
                    chkSyncWindowsTheme.IsChecked = prefs.SyncWindowsTheme;
                if (chkDarkTheme != null)
                    chkDarkTheme.IsEnabled = prefs.SyncWindowsTheme != true;

                if (cmbUiLanguage != null)
                    SelectUiLanguageCombo(UserPreferences.Current.UiCulture);

                if (cmbFavoriteScan != null)
                {
                    cmbFavoriteScan.SelectedIndex = prefs.FavoriteScanType switch
                    {
                        ScanType.FullScan => 1,
                        ScanType.Folder => 2,
                        ScanType.File => 3,
                        _ => 0
                    };
                }

                var ex = ExclusionSettings.Current;
                if (chkRealtimeProtection != null)
                    chkRealtimeProtection.IsChecked = ex.RealTimeEnabled;
                if (chkAutoQuarantine != null)
                    chkAutoQuarantine.IsChecked = ex.AutoQuarantineEnabled;

                var c = ServiceContainer.Default;
                if (chkAutoUpdate != null)
                    chkAutoUpdate.IsChecked = prefs.SignatureAutoUpdateEnabled;

                if (chkScheduledScan != null)
                    chkScheduledScan.IsChecked = ScheduledScan.IsTaskExists();

                _exclusions.Clear();
                foreach (var path in ex.ExcludedFolders)
                    _exclusions.Add(path);

                RefreshScheduledStatus();
            }
            finally
            {
                _suppressPreferenceEvents = false;
            }
        }

        private void RefreshScheduledStatus()
        {
            if (txtScheduledNextRun == null) return;
            if (!ScheduledScan.IsTaskExists())
            {
                txtScheduledNextRun.Text = LocalizationService.GetString("Opt_SchedNone");
                if (btnScheduledRunNow != null) btnScheduledRunNow.IsEnabled = false;
                if (pnlScheduleTime != null) pnlScheduleTime.IsEnabled = true;
                return;
            }

            if (btnScheduledRunNow != null) btnScheduledRunNow.IsEnabled = true;
            if (pnlScheduleTime != null) pnlScheduleTime.IsEnabled = false;
            var next = ScheduledScan.GetNextRunTime();
            txtScheduledNextRun.Text = next.HasValue
                ? LocalizationService.Format("Opt_SchedNextRun", next.Value.ToString("f", LocalizationService.CurrentCulture))
                : LocalizationService.GetString("Opt_SchedActiveUnknown");
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

        private void CheckOption_Changed(object sender, RoutedEventArgs e)
        {
            if (_suppressPreferenceEvents) return;
            if (sender is not WpfCheckBox cb) return;
            bool isOn = cb.IsChecked == true;
            var prefs = UserPreferences.Current;
            var c = ServiceContainer.Default;

            switch (cb.Tag as string)
            {
                case "Notifications":
                    prefs.ActionNotificationsEnabled = isOn;
                    prefs.Save();
                    c.Notifications.IsEnabled = isOn;
                    break;

                case "AutoStart":
                    SetAutoStart(isOn);
                    break;

                case "AutoUpdate":
                    c.ApplySignatureAutoUpdate(isOn);
                    break;

                case "RealtimeProtection":
                    c.ApplyRealtimeProtection(isOn);
                    break;

                case "AutoQuarantine":
                    c.ApplyAutoQuarantine(isOn);
                    break;

                case "DarkTheme":
                    if (!prefs.SyncWindowsTheme)
                        ThemeManager.Apply(isOn);
                    break;

                case "SyncWindowsTheme":
                    ThemeManager.SetSyncWithWindows(isOn);
                    if (chkDarkTheme != null)
                    {
                        chkDarkTheme.IsEnabled = !isOn;
                        if (isOn)
                            chkDarkTheme.IsChecked = ThemeManager.IsDarkTheme;
                    }
                    break;

                case "ScheduledScan":
                    if (isOn)
                    {
                        if (!ScheduledScan.CreateDailyScan(GetSelectedScheduleTime()))
                            System.Windows.MessageBox.Show(
                                LocalizationService.GetString("Opt_SchedTaskFailed"),
                                LocalizationService.GetString("Opt_SchedTaskTitle"),
                                MessageBoxButton.OK,
                                MessageBoxImage.Warning);
                    }
                    else
                    {
                        ScheduledScan.DeleteTask();
                    }
                    _suppressPreferenceEvents = true;
                    try
                    {
                        if (chkScheduledScan != null)
                            chkScheduledScan.IsChecked = ScheduledScan.IsTaskExists();
                    }
                    finally { _suppressPreferenceEvents = false; }
                    RefreshScheduledStatus();
                    break;
            }
        }

        private void SelectUiLanguageCombo(string? culture)
        {
            if (cmbUiLanguage == null) return;

            var normalized = string.IsNullOrWhiteSpace(culture)
                ? LocalizationService.CurrentCulture.Name
                : culture;

            var wantEn = normalized.StartsWith("en", StringComparison.OrdinalIgnoreCase);
            cmbUiLanguage.SelectedIndex = wantEn ? 1 : 0;
        }

        private void ComboBox_PreviewMouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            if (sender is not System.Windows.Controls.ComboBox cb || cb.IsDropDownOpen)
                return;

            cb.Focus();
            cb.IsDropDownOpen = true;
            e.Handled = true;
        }

        private void ComboBox_DropDownOpened(object sender, EventArgs e)
        {
            if (sender == cmbUiLanguage)
            {
                _languageTagBeforeDropDown = GetSelectedLanguageTag();
            }
            else if (sender == cmbFavoriteScan)
            {
                _favoriteScanIndexBeforeDropDown = cmbFavoriteScan?.SelectedIndex ?? -1;
            }
        }

        private string? GetSelectedLanguageTag()
        {
            if (cmbUiLanguage?.SelectedItem is System.Windows.Controls.ComboBoxItem item)
                return item.Tag as string;
            return null;
        }

        private void CmbUiLanguage_DropDownClosed(object sender, EventArgs e)
        {
            if (_suppressPreferenceEvents)
                return;

            var tag = GetSelectedLanguageTag();
            if (string.IsNullOrWhiteSpace(tag))
                return;

            if (string.Equals(tag, _languageTagBeforeDropDown, StringComparison.OrdinalIgnoreCase))
                return;

            var selected = tag.StartsWith("en", StringComparison.OrdinalIgnoreCase) ? "en-US" : "fr-FR";
            var currentNormalized = LocalizationService.IsEnglish ? "en-US" : "fr-FR";

            if (string.Equals(selected, currentNormalized, StringComparison.OrdinalIgnoreCase))
                return;

            var confirm = System.Windows.MessageBox.Show(
                LocalizationService.GetString("Opt_LangRestartMessage"),
                LocalizationService.GetString("Opt_LangRestartTitle"),
                MessageBoxButton.OKCancel,
                MessageBoxImage.Information);

            if (confirm != MessageBoxResult.OK)
            {
                _suppressPreferenceEvents = true;
                try { SelectUiLanguageCombo(currentNormalized); }
                finally { _suppressPreferenceEvents = false; }
                return;
            }

            LocalizationService.SetUserCulture(selected);
            LocalizationService.RestartApplication();
        }

        private void CmbFavoriteScan_DropDownClosed(object sender, EventArgs e)
        {
            if (_suppressPreferenceEvents || cmbFavoriteScan == null)
                return;

            if (cmbFavoriteScan.SelectedIndex == _favoriteScanIndexBeforeDropDown)
                return;

            var prefs = UserPreferences.Current;
            prefs.FavoriteScanType = cmbFavoriteScan.SelectedIndex switch
            {
                1 => ScanType.FullScan,
                2 => ScanType.Folder,
                3 => ScanType.File,
                _ => ScanType.QuickScan
            };
            prefs.Save();
        }

        private void BtnScheduledRunNow_Click(object sender, RoutedEventArgs e)
        {
            if (!ScheduledScan.IsTaskExists())
            {
                System.Windows.MessageBox.Show(LocalizationService.GetString("Opt_SchedEnableFirst"), LocalizationService.GetString("App_TitleShort"), MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }
            if (!ScheduledScan.RunNow())
            {
                System.Windows.MessageBox.Show(LocalizationService.GetString("Opt_SchedRunFailed"), LocalizationService.GetString("App_TitleShort"),
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            System.Windows.MessageBox.Show(
                LocalizationService.GetString("Opt_SchedRunOk"),
                LocalizationService.GetString("App_TitleShort"),
                MessageBoxButton.OK,
                MessageBoxImage.Information);
            RefreshScheduledStatus();
        }

        private static void SetAutoStart(bool enable)
        {
            const string regKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
            const string appName = "optiSCAN";
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(regKey, writable: true);
                if (key == null) return;
                if (enable)
                    key.SetValue(appName, $"\"{System.Reflection.Assembly.GetExecutingAssembly().Location}\"");
                else
                    key.DeleteValue(appName, throwOnMissingValue: false);
            }
            catch (Exception ex)
            {
                AppLogger.Warn("OptionsControl", "SetAutoStart", ex);
            }
        }

        private void BtnAddTypedExclusion_Click(object sender, RoutedEventArgs e)
        {
            var path = txtNewExclusion?.Text?.Trim() ?? string.Empty;
            if (string.IsNullOrEmpty(path) || !Directory.Exists(path))
            {
                System.Windows.MessageBox.Show(LocalizationService.GetString("Opt_ExclNeedFolder"), LocalizationService.GetString("App_TitleShort"), MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }
            if (ExclusionSettings.Current.AddFolder(path) && !_exclusions.Contains(path))
                _exclusions.Add(path);
            if (txtNewExclusion != null) txtNewExclusion.Text = string.Empty;
        }

        private async void BtnCheckAppUpdate_Click(object sender, RoutedEventArgs e)
        {
            AppUpdateCheckResult result;
            try
            {
                result = await new UpdateService().CheckForUpdatesAsync().ConfigureAwait(true);
            }
            catch (Exception ex)
            {
                AppLogger.Error("OptionsControl", "CheckForUpdatesAsync", ex);
                result = new AppUpdateCheckResult
                {
                    Status = AppUpdateChannelStatus.StagingError,
                    CurrentVersion = ProductVersionInfo.SemVer,
                    ReleaseLabel = ProductVersionInfo.ReleaseLabel,
                    UserMessage = LocalizationService.Format("Opt_AppUpdateCheckError", ex.Message),
                };
            }

            System.Windows.MessageBox.Show(
                result.UserMessage,
                LocalizationService.GetString("Opt_AppUpdateTitle"),
                MessageBoxButton.OK,
                result.Success ? MessageBoxImage.Information : MessageBoxImage.Warning);
        }

        private async void BtnOpenSourceForge_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                {
                    FileName = OptiscanStrings.Urls.OptiscanSourceForge,
                    UseShellExecute = true
                });
            }
            catch (Exception ex)
            {
                AppLogger.Warn("OptionsControl", "Navigate SourceForge", ex);
            }
            await Task.CompletedTask;
        }

        private void BtnAddExclusion_Click(object sender, RoutedEventArgs e)
        {
            using var dlg = new WinForms.FolderBrowserDialog
            {
                Description = "Sélectionnez un dossier à exclure des analyses"
            };

            if (dlg.ShowDialog() == WinForms.DialogResult.OK)
            {
                var path = dlg.SelectedPath;
                if (!_exclusions.Contains(path))
                {
                    _exclusions.Add(path);
                    ExclusionSettings.Current.AddFolder(path);
                }
            }
        }

        private void BtnRemoveExclusion_Click(object sender, RoutedEventArgs e)
        {
            if (sender is WpfButton btn && btn.Tag is string path)
            {
                _exclusions.Remove(path);
                ExclusionSettings.Current.RemoveFolder(path);
            }
        }
    }
}
