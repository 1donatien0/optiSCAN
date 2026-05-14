using optiSCAN.Services;
using System.Collections.ObjectModel;
using System.Windows;
using WinForms = System.Windows.Forms;
using WpfCheckBox = System.Windows.Controls.CheckBox;
using WpfButton   = System.Windows.Controls.Button;

namespace optiSCAN.Views
{
    public partial class OptionsControl : System.Windows.Controls.UserControl
    {
        private readonly ObservableCollection<string> _exclusions = new();

        public OptionsControl()
        {
            InitializeComponent();
            lstExclusions.ItemsSource = _exclusions;
            LoadPreferences();
        }

        // ── Chargement des préférences ───────────────────────────────────────
        private void LoadPreferences()
        {
            var prefs = UserPreferences.Current;
            if (chkNotifications != null)
                chkNotifications.IsChecked = prefs.ActionNotificationsEnabled;

            // Exclusions
            _exclusions.Clear();
            foreach (var path in ExclusionSettings.Current.ExcludedFolders)
                _exclusions.Add(path);
        }

        // ── Changement d'option ──────────────────────────────────────────────
        private void CheckOption_Changed(object sender, RoutedEventArgs e)
        {
            if (sender is WpfCheckBox cb)
            {
                bool isOn  = cb.IsChecked == true;
                var prefs  = UserPreferences.Current;

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
                        // Audit A2 : on résout depuis le ServiceContainer plutôt que
                        // remonter vers MainWindow par cast. Ainsi cette vue compile
                        // et fonctionne même indépendamment du host (tests, design-time).
                        var updater = ServiceContainer.Default.FreshclamUpdater;
                        if (isOn) updater.EnableAutoUpdate(System.TimeSpan.FromHours(4));
                        else updater.DisableAutoUpdate();
                        break;

                    // RealtimeProtection, AutoQuarantine → futurs services
                    default:
                        break;
                }
            }
        }

        // ── Démarrage Windows (Registre) ─────────────────────────────────────
        private static void SetAutoStart(bool enable)
        {
            const string regKey  = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
            const string appName = "optiSCAN";
            try
            {
                using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(regKey, writable: true);
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

        // ── Exclusions ───────────────────────────────────────────────────────
        private void BtnAddExclusion_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new WinForms.FolderBrowserDialog
            {
                Description = "Sélectionnez un dossier à exclure des analyses"
            };

            if (dialog.ShowDialog() == WinForms.DialogResult.OK)
            {
                var path = dialog.SelectedPath;
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
