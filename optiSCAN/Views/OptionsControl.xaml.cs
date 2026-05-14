using Microsoft.Win32;
using optiSCAN.Models;
using optiSCAN.Services;
using System.Collections.ObjectModel;
using System.IO;
using System.Windows;
using WinForms = System.Windows.Forms;
using WpfButton = System.Windows.Controls.Button;
using WpfCheckBox = System.Windows.Controls.CheckBox;

namespace optiSCAN.Views
{
    public partial class OptionsControl : System.Windows.Controls.UserControl
    {
        private readonly ObservableCollection<string> _exclusions = new();
        private readonly ScheduledScanService _scheduledScan = new();
        private bool _suppressPreferenceEvents;

        public OptionsControl()
        {
            InitializeComponent();
            lstExclusions.ItemsSource = _exclusions;
            LoadPreferences();
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

            var ex = ExclusionSettings.Current;
            if (chkRealtimeProtection != null)
                chkRealtimeProtection.IsChecked = ex.RealTimeEnabled;
            if (chkAutoQuarantine != null)
                chkAutoQuarantine.IsChecked = ex.AutoQuarantineEnabled;

            var c = ServiceContainer.Default;
            if (chkAutoUpdate != null)
                chkAutoUpdate.IsChecked = c.FreshclamUpdater.IsAutoUpdateEnabled && c.RulesUpdater.IsAutoUpdateEnabled;

            if (chkScheduledScan != null)
                chkScheduledScan.IsChecked = _scheduledScan.IsTaskExists();

            _exclusions.Clear();
            foreach (var path in ex.ExcludedFolders)
                _exclusions.Add(path);
            }
            finally
            {
                _suppressPreferenceEvents = false;
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

                case "ScheduledScan":
                    if (isOn)
                    {
                        if (!_scheduledScan.CreateDailyScan())
                            System.Windows.MessageBox.Show(
                                "Impossible de créer la tâche planifiée Windows (schtasks). Vérifiez les droits ou l’orthographe du nom d’utilisateur.",
                                "optiSCAN — Planification",
                                MessageBoxButton.OK,
                                MessageBoxImage.Warning);
                    }
                    else
                    {
                        _scheduledScan.DeleteTask();
                    }
                    _suppressPreferenceEvents = true;
                    try
                    {
                        if (chkScheduledScan != null)
                            chkScheduledScan.IsChecked = _scheduledScan.IsTaskExists();
                    }
                    finally { _suppressPreferenceEvents = false; }
                    break;
            }
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
                System.Windows.MessageBox.Show("Entrez un dossier existant ou utilisez « Parcourir… ».", "optiSCAN", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }
            if (ExclusionSettings.Current.AddFolder(path) && !_exclusions.Contains(path))
                _exclusions.Add(path);
            if (txtNewExclusion != null) txtNewExclusion.Text = string.Empty;
        }

        private void BtnCheckAppUpdate_Click(object sender, RoutedEventArgs e)
        {
            _ = Task.Run(async () =>
            {
                try
                {
                    var svc = new UpdateService();
                    await svc.CheckForUpdatesAsync().ConfigureAwait(false);
                }
                catch { /* ignoré */ }
            });

            System.Windows.MessageBox.Show(
                "optiSCAN ne télécharge pas encore les mises à jour de l’application en arrière-plan.\n\n" +
                "• Signatures ClamAV + règles YARA : onglet Antivirus → Signatures.\n" +
                "• Nouvelle version du programme : https://sourceforge.net/projects/optiscan/\n\n" +
                "Un dossier local de préparation des mises à jour a été vérifié / créé.",
                "Mise à jour applicative",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }

        private async void BtnOpenSourceForge_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "https://sourceforge.net/projects/optiscan/",
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
