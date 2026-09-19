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
        private readonly List<System.Windows.Controls.CheckBox> _updateCheckBoxes = new();
        private bool _updateRunning;
        private bool _updateScanPerformed;

        // ── Rechercher ───────────────────────────────────────────────────────
        private async void btnUpdScan_Click(object sender, RoutedEventArgs e)
        {
            if (_updateRunning) return;
            await RefreshUpdateListAsync();
        }

        /// <summary>
        /// Relance « winget upgrade » et reconstruit intégralement la liste.
        /// Extrait du gestionnaire de clic pour être réutilisable après une
        /// mise à jour globale.
        /// </summary>
        private async Task RefreshUpdateListAsync(bool resetLog = true)
        {
            _updateRunning = true;
            LockUpdateButtons();
            ClearUpdateList();
            emptyUpdateState.Visibility = Visibility.Collapsed;

            if (resetLog)
                SetUpdateLog(LocalizationService.GetString("Upd_LogScanStart"));
            else
                AppendUpdateLog(LocalizationService.GetString("Upd_LogScanStart"));

            try
            {
                var wingetPath = _winget.ResolveWingetPath();
                if (wingetPath == null)
                {
                    AppendUpdateLog(LocalizationService.GetString("Upd_LogWingetMissing"));
                    return;
                }
                AppendUpdateLog(LocalizationService.Format("Upd_LogWinget", wingetPath));

                var updates = await _winget.GetAvailableUpdatesAsync();
                _updateScanPerformed = true;

                foreach (var u in updates)
                    AddUpdateRow(u);

                if (_updateCheckBoxes.Count == 0)
                    AppendUpdateLog(LocalizationService.GetString("Upd_LogNone"));
                else
                    AppendUpdateLog(LocalizationService.Format("Upd_LogFound", _updateCheckBoxes.Count));
            }
            catch (Exception ex)
            {
                AppLogger.Warn("CleanControl", "Recherche winget", ex);
                AppendUpdateLog(LocalizationService.Format("Upd_LogError", ex.Message));
            }
            finally
            {
                _updateRunning = false;
                SyncUpdateListState();
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

            // Verrou posé avant la boîte de dialogue : sans cela, un second clic
            // pendant la confirmation lancerait un doublon de mise à jour.
            _updateRunning = true;
            try
            {
                var summary = string.Join("\n",
                    selected.Select(u => $" •  {u.Name}  ({u.InstalledVersion} → {u.AvailableVersion})"));
                var confirm = System.Windows.MessageBox.Show(
                    LocalizationService.Format("Upd_ConfirmBody", summary),
                    OptiscanStrings.Confirmations.Title,
                    MessageBoxButton.OKCancel,
                    MessageBoxImage.Question);
                if (confirm != MessageBoxResult.OK)
                    return;

                LockUpdateButtons();
                AppendUpdateLog(LocalizationService.Format("Upd_LogUpgradeStart", selected.Count));

                // Progress<T> est créé sur le thread UI : chaque rapport revient
                // donc sur ce thread et peut manipuler pnlUpdateList directement.
                var progress = new Progress<WingetUpgradeResult>(ApplyUpgradeResult);

                var results = await _winget.UpgradePackagesAsync(
                    selected,
                    AppendWingetOutputLine,
                    progress);

                int ok = results.Count(r => r.IsResolved);
                int ko = results.Count - ok;
                AppendUpdateLog(LocalizationService.Format("Upd_LogUpgradeSummary", ok, ko));
            }
            catch (Exception ex)
            {
                AppLogger.Warn("CleanControl", "Mise à jour winget (sélection)", ex);
                AppendUpdateLog(LocalizationService.Format("Upd_LogError", ex.Message));
            }
            finally
            {
                _updateRunning = false;
                SyncUpdateListState();
            }
        }

        // ── Tout mettre à jour ───────────────────────────────────────────────
        private async void btnUpdAll_Click(object sender, RoutedEventArgs e)
        {
            if (_updateRunning) return;

            // Verrou posé avant la boîte de dialogue (cf. btnUpdSelected_Click).
            _updateRunning = true;
            bool completed = false;
            try
            {
                var confirm = System.Windows.MessageBox.Show(
                    LocalizationService.GetString("Upd_ConfirmAllBody"),
                    OptiscanStrings.Confirmations.Title,
                    MessageBoxButton.OKCancel,
                    MessageBoxImage.Question);
                if (confirm != MessageBoxResult.OK)
                    return;

                LockUpdateButtons();
                AppendUpdateLog(LocalizationService.GetString("Upd_LogUpgradeAllStart"));

                await _winget.UpgradeAllAsync(
                    AppendWingetOutputLine,
                    _updateCheckBoxes
                        .Select(cb => (WingetPackageUpdate)cb.Tag!)
                        .ToList());
                AppendUpdateLog(LocalizationService.GetString("Upd_LogUpgradeAllDone"));
                completed = true;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("CleanControl", "Mise à jour winget (tout)", ex);
                AppendUpdateLog(LocalizationService.Format("Upd_LogError", ex.Message));
            }
            finally
            {
                _updateRunning = false;
                SyncUpdateListState();
            }

            if (!completed) return;

            // « upgrade --all » est un processus unique : aucun résultat par
            // paquet exploitable. La seule façon fiable de rafraîchir la liste
            // est de relancer une recherche.
            AppendUpdateLog(LocalizationService.GetString("Upd_LogRescan"));
            await RefreshUpdateListAsync(resetLog: false);
        }

        // ── Windows Update ───────────────────────────────────────────────────
        private void btnUpdWindows_Click(object sender, RoutedEventArgs e)
        {
            if (SystemTweaksService.OpenWindowsUpdateSettings())
                AppendUpdateLog(LocalizationService.GetString("Upd_LogWindowsSettings"));
        }

        // ── Gestion de la liste ──────────────────────────────────────────────
        private void ClearUpdateList()
        {
            foreach (var cb in _updateCheckBoxes)
                cb.Checked -= UpdateRow_Checked;
            pnlUpdateList.Children.Clear();
            _updateCheckBoxes.Clear();
        }

        private static string FormatUpdateRowLabel(WingetPackageUpdate u) =>
            $"{u.Name}   {u.InstalledVersion} → {u.AvailableVersion}";

        private void AddUpdateRow(WingetPackageUpdate update)
        {
            var cb = new System.Windows.Controls.CheckBox
            {
                Content = FormatUpdateRowLabel(update),
                IsChecked = true,
                Margin = new Thickness(2, 3, 2, 3),
                Tag = update,
            };
            // Recocher une ligne en échec efface son marquage : elle redevient
            // une mise à jour ordinaire à retenter.
            cb.Checked += UpdateRow_Checked;
            _updateCheckBoxes.Add(cb);
            pnlUpdateList.Children.Add(cb);
        }

        private void UpdateRow_Checked(object sender, RoutedEventArgs e)
        {
            if (sender is not System.Windows.Controls.CheckBox cb) return;
            if (cb.Tag is WingetPackageUpdate u)
                cb.Content = FormatUpdateRowLabel(u);
            cb.ToolTip = null;
            cb.ClearValue(ForegroundProperty);
        }

        /// <summary>
        /// Applique le résultat d'un paquet : la ligne disparaît si la mise à
        /// jour est acquise, sinon elle est décochée et marquée visuellement.
        /// Appelé sur le thread UI via <see cref="Progress{T}"/>.
        /// </summary>
        private void ApplyUpgradeResult(WingetUpgradeResult result)
        {
            // Recherche par référence : robuste même si deux paquets partagent
            // un identifiant vide ou identique.
            var cb = _updateCheckBoxes.FirstOrDefault(c => ReferenceEquals(c.Tag, result.Package));
            var pkg = result.Package;

            switch (result.Status)
            {
                case WingetUpgradeStatus.Succeeded:
                    RemoveUpdateRow(cb);
                    AppendUpdateLog(LocalizationService.Format(
                        "Upd_LogPkgSuccess", pkg.Name, pkg.AvailableVersion));
                    break;

                case WingetUpgradeStatus.AlreadyUpToDate:
                    RemoveUpdateRow(cb);
                    AppendUpdateLog(LocalizationService.Format("Upd_LogPkgAlready", pkg.Name));
                    break;

                case WingetUpgradeStatus.RebootRequired:
                    MarkUpdateRow(cb, "Upd_TagReboot", "WarningOrange");
                    AppendUpdateLog(LocalizationService.Format("Upd_LogPkgReboot", pkg.Name));
                    break;

                case WingetUpgradeStatus.CancelledByUser:
                    MarkUpdateRow(cb, "Upd_TagCancelled", "WarningOrange");
                    AppendUpdateLog(LocalizationService.Format("Upd_LogPkgCancelled", pkg.Name));
                    break;

                default:
                    MarkUpdateRow(cb, "Upd_TagFailed", "DangerRed");
                    AppendUpdateLog(LocalizationService.Format(
                        "Upd_LogPkgFailed", pkg.Name, $"0x{result.ExitCode:X8}"));
                    break;
            }

            SyncUpdateListState();
        }

        private void RemoveUpdateRow(System.Windows.Controls.CheckBox? cb)
        {
            if (cb == null) return;
            cb.Checked -= UpdateRow_Checked;
            pnlUpdateList.Children.Remove(cb);
            _updateCheckBoxes.Remove(cb);
        }

        /// <summary>
        /// Décoche la ligne et l'annote. Le décochage est le point important :
        /// il évite qu'un second clic sur « Mettre à jour la sélection » relance
        /// un paquet déjà traité.
        /// </summary>
        private void MarkUpdateRow(System.Windows.Controls.CheckBox? cb, string tagKey, string brushKey)
        {
            if (cb == null) return;
            cb.IsChecked = false;
            var label = LocalizationService.GetString(tagKey);
            if (cb.Tag is WingetPackageUpdate u)
                cb.Content = $"{FormatUpdateRowLabel(u)}   [{label}]";
            cb.ToolTip = label;
            // Qualification complète obligatoire : le projet active UseWindowsForms,
            // qui ajoute « global using System.Drawing » — « Brush » serait donc
            // ambigu entre System.Drawing.Brush et System.Windows.Media.Brush.
            if (TryFindResource(brushKey) is System.Windows.Media.Brush brush)
                cb.Foreground = brush;
        }

        /// <summary>Resynchronise l'état dérivé de la liste (état vide, boutons).</summary>
        private void SyncUpdateListState()
        {
            bool listEmpty = _updateCheckBoxes.Count == 0;
            emptyUpdateState.Visibility = listEmpty && _updateScanPerformed
                ? Visibility.Visible
                : Visibility.Collapsed;

            if (_updateRunning) return;

            btnUpdScan.IsEnabled = true;
            // Volontairement basé sur la présence de lignes, pas sur les cases
            // cochées : l'utilisateur peut recocher une ligne sans que l'état du
            // bouton soit recalculé.
            btnUpdSelected.IsEnabled = !listEmpty;
            btnUpdAll.IsEnabled = _winget.ResolveWingetPath() != null;
            btnUpdWindows.IsEnabled = true;
        }

        // ── Helpers ──────────────────────────────────────────────────────────
        /// <summary>
        /// Verrouille les boutons d'action pendant une opération.
        /// Le déverrouillage passe toujours par <see cref="SyncUpdateListState"/>,
        /// qui recalcule l'état réel de chaque bouton.
        /// </summary>
        private void LockUpdateButtons()
        {
            btnUpdScan.IsEnabled = false;
            btnUpdSelected.IsEnabled = false;
            btnUpdAll.IsEnabled = false;
            // btnUpdWindows reste actif : simple lien vers les paramètres.
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
