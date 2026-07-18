using optiSCAN.Localization;
using optiSCAN.Services;
using optiSCAN.Strings;
using System.Collections.Generic;
using System.Linq;
using System.Windows;

namespace optiSCAN.Views
{
    /// <summary>
    /// Panneau Optimiser — sous-onglet « Mises à jour » (applications via winget,
    /// lien Windows Update). Port C# de l'onglet Mises à jour d'OptiWin.
    /// </summary>
    public partial class CleanControl
    {
        private readonly WingetUpdateService _winget = new();
        private IReadOnlyList<WingetPackageUpdate> _availableUpdates = Array.Empty<WingetPackageUpdate>();
        private readonly List<System.Windows.Controls.CheckBox> _updateCheckBoxes = new();
        private bool _updateRunning;

        // ── Rechercher ───────────────────────────────────────────────────────
        private async void btnUpdScan_Click(object sender, RoutedEventArgs e)
        {
            if (_updateRunning) return;

            SetUpdateButtonsEnabled(scanning: true);
            pnlUpdateList.Children.Clear();
            _updateCheckBoxes.Clear();
            _availableUpdates = Array.Empty<WingetPackageUpdate>();
            emptyUpdateState.Visibility = Visibility.Collapsed;
            SetUpdateLog(LocalizationService.GetString("Upd_LogScanStart"));

            try
            {
                var wingetPath = _winget.ResolveWingetPath();
                if (wingetPath == null)
                {
                    AppendUpdateLog(LocalizationService.GetString("Upd_LogWingetMissing"));
                    return;
                }
                AppendUpdateLog(LocalizationService.Format("Upd_LogWinget", wingetPath));

                _availableUpdates = await _winget.GetAvailableUpdatesAsync();

                if (_availableUpdates.Count == 0)
                {
                    AppendUpdateLog(LocalizationService.GetString("Upd_LogNone"));
                    emptyUpdateState.Visibility = Visibility.Visible;
                    btnUpdAll.IsEnabled = true; // winget présent : « Tout mettre à jour » reste possible
                    return;
                }

                foreach (var u in _availableUpdates)
                {
                    var cb = new System.Windows.Controls.CheckBox
                    {
                        Content = $"{u.Name}   {u.InstalledVersion} → {u.AvailableVersion}",
                        IsChecked = true,
                        Margin = new Thickness(2, 3, 2, 3),
                        Tag = u,
                    };
                    _updateCheckBoxes.Add(cb);
                    pnlUpdateList.Children.Add(cb);
                }

                AppendUpdateLog(LocalizationService.Format("Upd_LogFound", _availableUpdates.Count));
                btnUpdSelected.IsEnabled = true;
                btnUpdAll.IsEnabled = true;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("CleanControl", "Recherche winget", ex);
                AppendUpdateLog(LocalizationService.Format("Upd_LogError", ex.Message));
            }
            finally
            {
                btnUpdScan.IsEnabled = true;
                _updateRunning = false;
            }
        }

        // ── Mettre à jour la sélection ───────────────────────────────────────
        private async void btnUpdSelected_Click(object sender, RoutedEventArgs e)
        {
            if (_updateRunning) return;

            var selected = _updateCheckBoxes
                .Where(cb => cb.IsChecked == true)
                .Select(cb => (WingetPackageUpdate)cb.Tag!)
                .ToList();

            if (selected.Count == 0)
            {
                AppendUpdateLog(LocalizationService.GetString("Upd_LogNoneChecked"));
                return;
            }

            var summary = string.Join("\n",
                selected.Select(u => $" •  {u.Name}  ({u.InstalledVersion} → {u.AvailableVersion})"));
            var confirm = System.Windows.MessageBox.Show(
                LocalizationService.Format("Upd_ConfirmBody", summary),
                OptiscanStrings.Confirmations.Title,
                MessageBoxButton.OKCancel,
                MessageBoxImage.Question);
            if (confirm != MessageBoxResult.OK)
                return;

            _updateRunning = true;
            SetUpdateButtonsEnabled(scanning: false);
            AppendUpdateLog(LocalizationService.Format("Upd_LogUpgradeStart", selected.Count));

            try
            {
                int ok = await _winget.UpgradePackagesAsync(
                    selected.Select(u => u.Id),
                    AppendWingetOutputLine);
                AppendUpdateLog(LocalizationService.Format("Upd_LogUpgradeDone", ok));
            }
            catch (Exception ex)
            {
                AppLogger.Warn("CleanControl", "Mise à jour winget (sélection)", ex);
                AppendUpdateLog(LocalizationService.Format("Upd_LogError", ex.Message));
            }
            finally
            {
                _updateRunning = false;
                btnUpdScan.IsEnabled = true;
                btnUpdSelected.IsEnabled = _updateCheckBoxes.Count > 0;
                btnUpdAll.IsEnabled = true;
                btnUpdWindows.IsEnabled = true;
            }
        }

        // ── Tout mettre à jour ───────────────────────────────────────────────
        private async void btnUpdAll_Click(object sender, RoutedEventArgs e)
        {
            if (_updateRunning) return;

            var confirm = System.Windows.MessageBox.Show(
                LocalizationService.GetString("Upd_ConfirmAllBody"),
                OptiscanStrings.Confirmations.Title,
                MessageBoxButton.OKCancel,
                MessageBoxImage.Question);
            if (confirm != MessageBoxResult.OK)
                return;

            _updateRunning = true;
            SetUpdateButtonsEnabled(scanning: false);
            AppendUpdateLog(LocalizationService.GetString("Upd_LogUpgradeAllStart"));

            try
            {
                await _winget.UpgradeAllAsync(AppendWingetOutputLine);
                AppendUpdateLog(LocalizationService.GetString("Upd_LogUpgradeAllDone"));
            }
            catch (Exception ex)
            {
                AppLogger.Warn("CleanControl", "Mise à jour winget (tout)", ex);
                AppendUpdateLog(LocalizationService.Format("Upd_LogError", ex.Message));
            }
            finally
            {
                _updateRunning = false;
                btnUpdScan.IsEnabled = true;
                btnUpdSelected.IsEnabled = _updateCheckBoxes.Count > 0;
                btnUpdAll.IsEnabled = true;
                btnUpdWindows.IsEnabled = true;
            }
        }

        // ── Windows Update ───────────────────────────────────────────────────
        private void btnUpdWindows_Click(object sender, RoutedEventArgs e)
        {
            if (SystemTweaksService.OpenWindowsUpdateSettings())
                AppendUpdateLog(LocalizationService.GetString("Upd_LogWindowsSettings"));
        }

        // ── Helpers ──────────────────────────────────────────────────────────
        private void SetUpdateButtonsEnabled(bool scanning)
        {
            _updateRunning = true;
            btnUpdScan.IsEnabled = false;
            btnUpdSelected.IsEnabled = false;
            btnUpdAll.IsEnabled = false;
            // btnUpdWindows reste actif : simple lien vers les paramètres.
            _ = scanning;
        }

        /// <summary>Filtre les lignes de progression winget (spinners, barres) avant journalisation.</summary>
        private void AppendWingetOutputLine(string line)
        {
            if (line.Length < 3) return;
            if (line.Contains('█') || line.Contains('▒') || line.Contains('░')) return;
            if (line.All(c => c is '-' or '\\' or '|' or '/' or ' ' or '.')) return;
            AppendUpdateLog(line);
        }

        private void SetUpdateLog(string text)
        {
            if (txtUpdateLog != null)
                txtUpdateLog.Text = $"[{DateTime.Now:HH:mm:ss}] {text}\n";
        }

        private void AppendUpdateLog(string line)
        {
            Dispatcher.InvokeAsync(() =>
            {
                if (txtUpdateLog == null) return;
                if (txtUpdateLog.Text.StartsWith("Cliquez", StringComparison.OrdinalIgnoreCase)
                    || txtUpdateLog.Text.StartsWith("Click", StringComparison.OrdinalIgnoreCase))
                    txtUpdateLog.Text = string.Empty;
                txtUpdateLog.Text += $"[{DateTime.Now:HH:mm:ss}] {line}\n";
                txtUpdateLog.ScrollToEnd();
            });
        }
    }
}
