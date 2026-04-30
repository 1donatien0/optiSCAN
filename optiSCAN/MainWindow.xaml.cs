using System;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Media;
using optiSCAN.Models;
using optiSCAN.Services;
using WpfButton = System.Windows.Controls.Button;
using WpfColor = System.Windows.Media.Color;
using WpfMessageBox = System.Windows.MessageBox;
using FolderDialog = System.Windows.Forms.FolderBrowserDialog;

namespace optiSCAN
{
    public partial class MainWindow : Window
    {
        // Champs système
        private DirectoryInfo winTemp;
        private DirectoryInfo appTemp;
        private int _totalRemovedFiles;

        // Services
        private readonly ClamAvEngine _clamAvEngine;
        private readonly FreshclamUpdater _freshclamUpdater;
        private readonly YaraForgeUpdater _rulesUpdater;
        private readonly ScanLogManager _logManager;
        private readonly QuarantineManager _quarantineManager;
        private readonly YaraEngine _yaraEngine;

        // Antivirus intégré
        private ScanOrchestrator _antivirusOrchestrator = null!;
        private CancellationTokenSource? _antivirusCts;
        private ObservableCollection<ThreatInfo> _currentThreats = null!;

        // Index du panneau actif
        private int _currentPanel = 0;

        public MainWindow()
        {
            InitializeComponent();

            winTemp = new DirectoryInfo(@"C:\Windows\Temp");
            appTemp = new DirectoryInfo(Path.GetTempPath());

            _clamAvEngine = new ClamAvEngine();
            _freshclamUpdater = new FreshclamUpdater();
            _rulesUpdater = new YaraForgeUpdater();
            _logManager = new ScanLogManager();
            _quarantineManager = new QuarantineManager();
            _yaraEngine = new YaraEngine();
            _antivirusOrchestrator = new ScanOrchestrator(_clamAvEngine, _yaraEngine);
            _currentThreats = new ObservableCollection<ThreatInfo>();

            // Mise à jour auto
            _freshclamUpdater.EnableAutoUpdate(TimeSpan.FromHours(4));
            _rulesUpdater.EnableAutoUpdate(TimeSpan.FromHours(24));

            // Liaison des événements pour les logs de signatures
            _freshclamUpdater.UpdateOutput += OnFreshclamOutput;
            _freshclamUpdater.UpdateCompleted += OnFreshclamCompleted;

            Loaded += async (_, _) => await InitializeAsync();
        }

        private void OnFreshclamOutput(object? sender, string line)
        {
            Dispatcher.Invoke(() =>
            {
                signatureLog.Text += line + "\n";
                signatureLog.ScrollToEnd();
            });
        }

        private void OnFreshclamCompleted(object? sender, UpdateResult result)
        {
            Dispatcher.Invoke(() =>
            {
                signatureLog.Text += $"\n[COMPLETED] {result.Message}\n";
                signatureVersion.Text = _freshclamUpdater.GetLocalDatabaseVersion();
                signatureLastUpdate.Text = DateTime.Now.ToString("dd/MM/yyyy HH:mm");
                runSignatures.Text = _freshclamUpdater.IsDatabasePresent()
                    ? $"v{_freshclamUpdater.GetLocalDatabaseVersion()}"
                    : "Aucune base";
                UpdateOverviewHealthBanner();
            });
        }

        private async Task InitializeAsync()
        {
            // Statut ClamAV dans la sidebar
            bool clamAvOk = _clamAvEngine.IsClamAvInstalled();
            txtSidebarAntivirusStatus.Text = clamAvOk ? "ClamAV ✅" : "⚠ Non installé";
            txtSidebarAntivirusStatus.Foreground = clamAvOk
                ? new SolidColorBrush(WpfColor.FromRgb(80, 200, 120))
                : new SolidColorBrush(WpfColor.FromRgb(224, 90, 90));

            // Carte antivirus
            cardAntivirusSubtitle.Text = clamAvOk ? "ClamAV opérationnel" : "⚠ Non installé";
            cardAntivirusSubtitle.Foreground = clamAvOk
                ? new SolidColorBrush(WpfColor.FromRgb(39, 174, 96))
                : new SolidColorBrush(WpfColor.FromRgb(192, 57, 43));

            // Signatures
            string dbVersion = _freshclamUpdater.GetLocalDatabaseVersion();
            runSignatures.Text = _freshclamUpdater.IsDatabasePresent() ? $"v{dbVersion}" : "Aucune base";
            signatureVersion.Text = dbVersion;
            signatureLastUpdate.Text = _freshclamUpdater.LastUpdateTime?.ToString("dd/MM/yyyy HH:mm") ?? "Jamais";

            // Analyse initiale (délégué à RefreshCleanPanelAsync — indicateur santé 3 niveaux)
            await RefreshCleanPanelAsync();

            RefreshHistory();
            RefreshExclusionLists();
            RefreshQuarantineList();
            RefreshAntivirusHistory();
            RefreshYaraStatus();
            UpdateOverviewHealthBanner();
        }

        private void RefreshYaraStatus()
        {
            bool yaraOk = _yaraEngine.IsAvailable;
            string yaraStatusText = yaraOk
                ? $"YARA actif — {_yaraEngine.RulesCount} règle(s)"
                : "YARA non disponible";
            antivirusYaraStatus.Text = yaraStatusText;
            antivirusYaraStatus.Foreground = yaraOk
                ? new SolidColorBrush(WpfColor.FromRgb(80, 200, 120))
                : new SolidColorBrush(WpfColor.FromRgb(224, 90, 90));
            antivirusYaraCount.Text = _yaraEngine.RulesCount.ToString();
        }

        // Navigation
        private void ShowPanel(int index)
        {
            if (panelOverview is null) return;

            panelOverview.Visibility = index == 0 ? Visibility.Visible : Visibility.Collapsed;
            panelClean.Visibility = index == 1 ? Visibility.Visible : Visibility.Collapsed;
            panelHistory.Visibility = index == 2 ? Visibility.Visible : Visibility.Collapsed;
            panelOptions.Visibility = index == 3 ? Visibility.Visible : Visibility.Collapsed;
            panelAntivirus.Visibility = index == 4 ? Visibility.Visible : Visibility.Collapsed;
            _currentPanel = index;

            // Masquer le header (indicateur santé) quand on est sur l'antivirus
            if (index == 4)
            {
                headerBorder.Visibility = Visibility.Collapsed;
                RefreshAntivirusStatus();
                RefreshYaraStatus();
            }
            else
            {
                headerBorder.Visibility = Visibility.Visible;
            }
        }

        private void NavOverview_Checked(object sender, RoutedEventArgs e) => ShowPanel(0);
        private void NavClean_Checked(object sender, RoutedEventArgs e) { ShowPanel(1); _ = RefreshCleanPanelAsync(); }
        private void NavAntivirus_Checked(object sender, RoutedEventArgs e) { ShowPanel(4); RefreshAntivirusStatus(); }
        private void NavHistory_Checked(object sender, RoutedEventArgs e) { ShowPanel(2); RefreshHistory(); }
        private void NavOptions_Checked(object sender, RoutedEventArgs e) => ShowPanel(3);

        // Boutons des cartes
        private void Button_Analyser_Click(object sender, RoutedEventArgs e) { _ = RefreshCleanPanelAsync(); SetStatus("Analyse en cours…"); }
        private void Button_Nettoyer_Click(object sender, RoutedEventArgs e) => navClean.IsChecked = true;
        private void Button_Antivirus_Click(object sender, RoutedEventArgs e) => navAntivirus.IsChecked = true;
        private void Button_Histo_Click(object sender, RoutedEventArgs e) => navHistory.IsChecked = true;
        // Button_MAJ_Click → implémentation async avec overlay (voir section Mise à jour ci-dessous)

        private void Button_Web_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                Process.Start(new ProcessStartInfo("http://anthony-cardinale.fr/pc-cleaner") { UseShellExecute = true });
            }
            catch (Exception ex)
            {
                WpfMessageBox.Show($"Impossible d'ouvrir le navigateur : {ex.Message}", "Erreur", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        // Antivirus intégré
        private void RefreshAntivirusStatus()
        {
            bool clamAvOk = _clamAvEngine.IsClamAvInstalled();
            string dbVersion = _freshclamUpdater.GetLocalDatabaseVersion();

            signatureVersion.Text = dbVersion;
            signatureLastUpdate.Text = _freshclamUpdater.LastUpdateTime?.ToString("dd/MM/yyyy HH:mm") ?? "Jamais";
            antivirusStatusMessage.Text = clamAvOk ? "✅ ClamAV opérationnel, prêt à scanner." : "⚠ ClamAV non installé";
        }

        private async void BtnQuickScan_Click(object sender, RoutedEventArgs e) => await StartAntivirusScanAsync(ScanType.QuickScan);
        private async void BtnFullScan_Click(object sender, RoutedEventArgs e) => await StartAntivirusScanAsync(ScanType.FullScan);
        private async void BtnEicarTest_Click(object sender, RoutedEventArgs e) => await RunEicarTestAsync();

        private void BtnStopScan_Click(object sender, RoutedEventArgs e)
        {
            _antivirusCts?.Cancel();
            btnStopScan.IsEnabled = false;
        }

        private async void BtnManualUpdateSignatures_Click(object sender, RoutedEventArgs e)
        {
            antivirusStatusMessage.Text = "Mise à jour des signatures en cours…";
            signatureLog.Text = string.Empty;
            btnManualUpdateSignatures.IsEnabled = false;

            // ── 1. Signatures ClamAV ──────────────────────────────────────────
            // Les logs arrivent via l'événement UpdateOutput (déjà câblé dans le constructeur).
            var clamResult = await _freshclamUpdater.UpdateAsync();

            signatureVersion.Text   = _freshclamUpdater.GetLocalDatabaseVersion();
            signatureLastUpdate.Text = DateTime.Now.ToString("dd/MM/yyyy HH:mm");
            runSignatures.Text = _freshclamUpdater.IsDatabasePresent()
                ? $"v{_freshclamUpdater.GetLocalDatabaseVersion()}"
                : "Aucune base";

            // ── 2. Règles de détection comportementale ────────────────────────
            antivirusStatusMessage.Text = "Mise à jour des règles de détection…";
            var rulesResult = await _rulesUpdater.UpdateAsync(
                new Progress<string>(msg => Dispatcher.Invoke(() =>
                {
                    signatureLog.Text += msg + "\n";
                    signatureLog.ScrollToEnd();
                })));

            // Rafraîchir le statut YARA
            RefreshYaraStatus();

            // ── 3. Résumé ─────────────────────────────────────────────────────
            bool allOk = clamResult.Success && rulesResult.Success;
            antivirusStatusMessage.Text = allOk
                ? "✅ Mise à jour complète (signatures + règles de détection)"
                : "⚠ Mise à jour partielle — consultez le journal";

            signatureLog.Text += allOk
                ? "\n✅ Tout est à jour."
                : $"\n⚠ Signatures : {clamResult.Message}\n⚠ Règles : {rulesResult.Message}";
            signatureLog.ScrollToEnd();

            btnManualUpdateSignatures.IsEnabled = true;
        }

        private void BtnQuarantineAll_Click(object sender, RoutedEventArgs e)
        {
            int count = _quarantineManager.QuarantineAll(_currentThreats);
            RefreshQuarantineList();
            antivirusStatusMessage.Text = $"{count} fichier(s) placé(s) en quarantaine.";
            _currentThreats.Clear();
            antivirusThreatsGrid.ItemsSource = null;
            antivirusThreatsGrid.ItemsSource = _currentThreats;
            antivirusThreatsFound.Text = "0";
            threatsBadge.Visibility = Visibility.Collapsed;
        }

        // ── Actions par menace (ligne par ligne dans le DataGrid) ─────────────────

        /// <summary>
        /// Met en quarantaine le fichier d'une seule ligne du DataGrid des menaces.
        /// </summary>
        private void BtnQuarantineThreat_Click(object sender, RoutedEventArgs e)
        {
            var btn = sender as WpfButton;
            string? filePath = btn?.Tag as string;
            if (string.IsNullOrEmpty(filePath)) return;

            // Trouver la ThreatInfo correspondante
            var threat = _currentThreats.FirstOrDefault(t => t.FilePath == filePath);
            if (threat == null) return;

            bool ok = _quarantineManager.Quarantine(threat);
            if (ok)
            {
                _currentThreats.Remove(threat);
                RefreshQuarantineList();
                antivirusThreatsFound.Text = _currentThreats.Count.ToString();
                threatsBadge.Visibility = _currentThreats.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
                if (_currentThreats.Count > 0) threatsBadgeText.Text = $"{_currentThreats.Count} menace(s)";
                antivirusStatusMessage.Text = $"✅ {Path.GetFileName(filePath)} placé en quarantaine.";
            }
            else
            {
                antivirusStatusMessage.Text = $"⚠ Impossible de mettre en quarantaine : {Path.GetFileName(filePath)}";
            }
        }

        /// <summary>
        /// Supprime définitivement le fichier infecté (avec confirmation).
        /// </summary>
        private void BtnDeleteThreat_Click(object sender, RoutedEventArgs e)
        {
            var btn = sender as WpfButton;
            string? filePath = btn?.Tag as string;
            if (string.IsNullOrEmpty(filePath)) return;

            var answer = WpfMessageBox.Show(
                $"Supprimer définitivement ce fichier ?\n\n{filePath}\n\nCette action est irréversible.",
                "Confirmer la suppression",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);

            if (answer != MessageBoxResult.Yes) return;

            try
            {
                if (File.Exists(filePath))
                    File.Delete(filePath);

                var threat = _currentThreats.FirstOrDefault(t => t.FilePath == filePath);
                if (threat != null) _currentThreats.Remove(threat);

                antivirusThreatsFound.Text = _currentThreats.Count.ToString();
                threatsBadge.Visibility = _currentThreats.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
                if (_currentThreats.Count > 0) threatsBadgeText.Text = $"{_currentThreats.Count} menace(s)";
                antivirusStatusMessage.Text = $"🗑 {Path.GetFileName(filePath)} supprimé définitivement.";
            }
            catch (Exception ex)
            {
                antivirusStatusMessage.Text = $"⚠ Erreur suppression : {ex.Message}";
            }
        }

        private void BtnPurgeQuarantine_Click(object sender, RoutedEventArgs e)
        {
            if (WpfMessageBox.Show("Vider toute la quarantaine ?", "Confirmation",
                MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes)
            {
                _quarantineManager.PurgeAll();
                RefreshQuarantineList();
                antivirusStatusMessage.Text = "Quarantaine vidée.";
            }
        }

        private void BtnRestoreFromQuarantine_Click(object sender, RoutedEventArgs e)
        {
            var btn = sender as WpfButton;
            string? id = btn?.Tag as string;
            if (id != null)
            {
                _quarantineManager.Restore(id);
                RefreshQuarantineList();
                antivirusStatusMessage.Text = "Fichier restauré.";
            }
        }

        private void BtnDeleteFromQuarantine_Click(object sender, RoutedEventArgs e)
        {
            var btn = sender as WpfButton;
            string? id = btn?.Tag as string;
            if (id != null)
            {
                _quarantineManager.DeletePermanently(id);
                RefreshQuarantineList();
                antivirusStatusMessage.Text = "Fichier supprimé définitivement.";
            }
        }

        private async void BrowseFolder_Click(object sender, RoutedEventArgs e)
        {
            using var dialog = new FolderDialog { Description = "Sélectionnez le dossier à analyser", UseDescriptionForTitle = true };
            if (dialog.ShowDialog() == System.Windows.Forms.DialogResult.OK)
                await StartAntivirusScanAsync(ScanType.Folder, dialog.SelectedPath);
        }

        private async void BrowseFile_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new Microsoft.Win32.OpenFileDialog();
            if (dialog.ShowDialog() == true)
                await StartAntivirusScanAsync(ScanType.File, dialog.FileName);
        }

        private async Task StartAntivirusScanAsync(ScanType type, string? path = null)
        {
            _antivirusCts?.Cancel();
            _antivirusCts = new CancellationTokenSource();

            btnStopScan.IsEnabled = true;
            antivirusProgressBar.Visibility     = Visibility.Visible;
            antivirusProgressBar.IsIndeterminate = true;
            antivirusProgressBar.Value           = 0;

            _currentThreats.Clear();
            antivirusThreatsGrid.ItemsSource = null;
            antivirusThreatsGrid.ItemsSource = _currentThreats;
            antivirusFilesScanned.Text   = "0";
            antivirusThreatsFound.Text   = "0";
            antivirusRealtimeFiles.Text  = "0";
            antivirusRealtimeThreats.Text = "0";
            antivirusSummary.Text        = string.Empty;
            threatsBadge.Visibility      = Visibility.Collapsed;

            var progress = new Progress<ScanProgress>(p =>
            {
                Dispatcher.Invoke(() =>
                {
                    antivirusStatusMessage.Text = p.Message;
                    antivirusFilesScanned.Text = p.FilesScanned.ToString();
                    antivirusThreatsFound.Text = p.ThreatsFound.ToString();

                    if (p.Phase == ScanPhase.ThreatFound && p.ThreatInfo != null)
                    {
                        _currentThreats.Add(p.ThreatInfo);
                        threatsBadge.Visibility = Visibility.Visible;
                        threatsBadgeText.Text = $"{p.ThreatsFound} menace(s)";
                    }
                });
            });

            try
            {
                ScanResult result = type switch
                {
                    ScanType.QuickScan => await _antivirusOrchestrator.QuickScanAsync(progress, _antivirusCts.Token),
                    ScanType.FullScan => await _antivirusOrchestrator.FullScanAsync(progress, _antivirusCts.Token),
                    ScanType.Folder => await _antivirusOrchestrator.ScanFolderAsync(path!, progress, _antivirusCts.Token),
                    ScanType.File => await _antivirusOrchestrator.ScanFileAsync(path!, progress, _antivirusCts.Token),
                    _ => throw new InvalidOperationException()
                };

                antivirusSummary.Text = result.SummaryDisplay;
                antivirusStatusMessage.Text = result.SummaryDisplay;

                // Mise à jour des compteurs finaux
                antivirusFilesScanned.Text    = result.FilesScanned.ToString();
                antivirusRealtimeFiles.Text   = result.FilesScanned.ToString();
                antivirusThreatsFound.Text    = result.ThreatsFound.ToString();
                antivirusRealtimeThreats.Text = result.ThreatsFound.ToString();
                antivirusLastScan.Text        = DateTime.Now.ToString("HH:mm");

                if (result.ThreatsFound > 0)
                {
                    WpfMessageBox.Show(
                        $"{result.ThreatsFound} menace(s) détectée(s) !\n\nConsultez l'onglet « Scan en cours » pour les détails.",
                        "Menaces détectées", MessageBoxButton.OK, MessageBoxImage.Warning);
                }

                _logManager.SaveScanResult(result);
                RefreshHistory();
                RefreshAntivirusHistory();
            }
            catch (OperationCanceledException)
            {
                antivirusStatusMessage.Text = "Scan annulé";
                antivirusSummary.Text       = "Scan annulé par l'utilisateur";
            }
            catch (Exception ex)
            {
                antivirusStatusMessage.Text = $"Erreur : {ex.Message}";
            }
            finally
            {
                antivirusProgressBar.IsIndeterminate = false;
                antivirusProgressBar.Visibility      = Visibility.Collapsed;
                btnStopScan.IsEnabled = false;
            }
        }

        private async Task RunEicarTestAsync()
        {
            _antivirusCts?.Cancel();
            _antivirusCts = new CancellationTokenSource();

            btnStopScan.IsEnabled = true;
            antivirusProgressBar.Visibility      = Visibility.Visible;
            antivirusProgressBar.IsIndeterminate = true;
            _currentThreats.Clear();
            antivirusThreatsGrid.ItemsSource = _currentThreats;
            antivirusSummary.Text = string.Empty;

            var progress = new Progress<ScanProgress>(p =>
            {
                Dispatcher.Invoke(() =>
                {
                    antivirusStatusMessage.Text = p.Message;
                    if (p.Phase == ScanPhase.ThreatFound && p.ThreatInfo != null)
                        _currentThreats.Add(p.ThreatInfo);
                });
            });

            try
            {
                var result = await _antivirusOrchestrator.RunEicarTestAsync(progress, _antivirusCts.Token);
                antivirusSummary.Text       = result.SummaryDisplay;
                antivirusStatusMessage.Text = result.ThreatsFound > 0
                    ? "✅ Test EICAR réussi : menace détectée !"
                    : "⚠ Test EICAR : aucune détection — base ClamAV ou règles manquantes ?";
            }
            catch (Exception ex)
            {
                antivirusStatusMessage.Text = $"Erreur : {ex.Message}";
            }
            finally
            {
                antivirusProgressBar.IsIndeterminate = false;
                antivirusProgressBar.Visibility      = Visibility.Collapsed;
                btnStopScan.IsEnabled = false;
            }
        }

        private void RefreshQuarantineList()
        {
            quarantineGrid.ItemsSource = _quarantineManager.GetEntries();
            antivirusQuarantineCount.Text = _quarantineManager.GetEntries().Count().ToString();
        }

        private void RefreshAntivirusHistory()
        {
            antivirusHistoryGrid.ItemsSource = _logManager.GetHistory();
        }

        // ── Exclusions ────────────────────────────────────────────────────────────

        private void RefreshExclusionLists()
        {
            var excl = ExclusionSettings.Current;
            lstExcludedFolders.ItemsSource = null;
            lstExcludedFolders.ItemsSource = excl.ExcludedFolders;
            lstExcludedRules.ItemsSource   = null;
            lstExcludedRules.ItemsSource   = excl.ExcludedRuleNames;
        }

        private void BtnAddExcludedFolder_Click(object sender, RoutedEventArgs e)
        {
            using var dlg = new FolderDialog { Description = "Sélectionnez un dossier à exclure", UseDescriptionForTitle = true };
            if (dlg.ShowDialog() == System.Windows.Forms.DialogResult.OK)
            {
                ExclusionSettings.Current.AddFolder(dlg.SelectedPath);
                ExclusionSettings.Reload();
                RefreshExclusionLists();
            }
        }

        private void BtnRemoveExcludedFolder_Click(object sender, RoutedEventArgs e)
        {
            if (lstExcludedFolders.SelectedItem is string folder)
            {
                ExclusionSettings.Current.RemoveFolder(folder);
                ExclusionSettings.Reload();
                RefreshExclusionLists();
            }
        }

        private void BtnAddExcludedRule_Click(object sender, RoutedEventArgs e)
        {
            string rule = txtNewRule.Text.Trim();
            if (!string.IsNullOrEmpty(rule))
            {
                ExclusionSettings.Current.AddRule(rule);
                ExclusionSettings.Reload();
                txtNewRule.Text = string.Empty;
                RefreshExclusionLists();
            }
        }

        private void BtnRemoveExcludedRule_Click(object sender, RoutedEventArgs e)
        {
            if (lstExcludedRules.SelectedItem is string rule)
            {
                ExclusionSettings.Current.RemoveRule(rule);
                ExclusionSettings.Reload();
                RefreshExclusionLists();
            }
        }

        // ── Mise à jour — overlay in-app ──────────────────────────────────────────

        private async void Button_MAJ_Click(object sender, RoutedEventArgs e)
        {
            updateLog.Text          = $"=== Mise à jour du {DateTime.Now:dd/MM/yyyy à HH:mm} ===\n\n";
            updateSummary.Text      = "Connexion aux serveurs…";
            updateProgressBar.IsIndeterminate = true;
            updateCloseBtn.IsEnabled = false;
            updateOverlay.Visibility = Visibility.Visible;

            void OnOutput(object? s, string line) => Dispatcher.Invoke(() =>
            {
                updateLog.Text += line + "\n";
                updateLogScroll.ScrollToEnd();
            });

            // Détacher l'handler de l'auto-update (signatureLog) pendant la MAJ manuelle
            // pour que le flux aille uniquement dans l'overlay, pas en double.
            _freshclamUpdater.UpdateOutput -= OnFreshclamOutput;
            _freshclamUpdater.UpdateOutput += OnOutput;
            try
            {
                // 1. Signatures ClamAV
                updateLog.Text += "[ClamAV] Connexion à database.clamav.net…\n";
                var clamResult  = await _freshclamUpdater.UpdateAsync();
                string clamVer  = _freshclamUpdater.GetLocalDatabaseVersion();
                updateLog.Text += clamResult.Success
                    ? $"\n✅ ClamAV mis à jour — base v{clamVer}\n"
                    : $"\n⚠  ClamAV : {clamResult.Message}\n";

                // 2. Règles YARA
                updateLog.Text += "\n[YARA] Récupération des règles depuis YARA-Forge…\n";
                var yaraResult = await _rulesUpdater.UpdateAsync(
                    new Progress<string>(msg => Dispatcher.Invoke(() =>
                    {
                        updateLog.Text += msg + "\n";
                        updateLogScroll.ScrollToEnd();
                    })));
                updateLog.Text += yaraResult.Success
                    ? $"\n✅ Règles YARA — {_yaraEngine.RulesCount} règle(s) active(s)\n"
                    : $"\n⚠  YARA : {yaraResult.Message}\n";

                // Résumé
                bool allOk = clamResult.Success && yaraResult.Success;
                updateLog.Text    += "\n" + new string('─', 48) + "\n";
                updateLog.Text    += allOk ? "✅ Toutes les bases sont à jour." : "⚠  Mise à jour partielle.";
                updateSummary.Text = allOk
                    ? $"✅ ClamAV v{clamVer}  •  {_yaraEngine.RulesCount} règles YARA"
                    : "⚠ Mise à jour partielle — consultez le journal";

                // Mettre à jour le header
                runSignatures.Text       = _freshclamUpdater.IsDatabasePresent() ? $"v{clamVer}" : "Aucune base";
                signatureVersion.Text    = clamVer;
                signatureLastUpdate.Text = DateTime.Now.ToString("dd/MM/yyyy HH:mm");
                RefreshYaraStatus();
            }
            finally
            {
                _freshclamUpdater.UpdateOutput -= OnOutput;
                _freshclamUpdater.UpdateOutput += OnFreshclamOutput; // Rétablir pour les MAJ automatiques
                updateProgressBar.IsIndeterminate = false;
                updateProgressBar.Value = 100;
                updateCloseBtn.IsEnabled = true;
                updateLogScroll.ScrollToEnd();
                SetStatus("Mise à jour terminée.");
            }
        }

        private void UpdateOverlay_Close(object sender, RoutedEventArgs e)
        {
            updateOverlay.Visibility = Visibility.Collapsed;
            updateLog.Text           = string.Empty;
            updateSummary.Text       = string.Empty;
            updateProgressBar.Value  = 0;
        }

        // ── Nettoyage étendu (CCleaner-style) ────────────────────────────────────

        private async Task RefreshCleanPanelAsync()
        {
            SetStatus("Analyse des fichiers temporaires…");
            cleanProgress.Visibility = Visibility.Visible;

            long winSize = 0, userSize = 0, edgeSize = 0, chromeSize = 0, firefoxSize = 0;

            await Task.Run(() =>
            {
                winSize    = SafeDirSize(winTemp);
                userSize   = SafeDirSize(appTemp);
                edgeSize   = GetBrowserCacheSize(BrowserCacheEdge());
                chromeSize = GetBrowserCacheSize(BrowserCacheChrome());
                firefoxSize = GetBrowserCacheSize(BrowserCacheFirefox());
            });

            // Cartes de stats
            lblWinTempSize.Text  = FormatSize(winSize);
            lblUserTempSize.Text = FormatSize(userSize);
            long sysTotal    = winSize + userSize;
            long browserTotal = edgeSize + chromeSize + firefoxSize;
            long grandTotal   = sysTotal + browserTotal;
            lblSysTotal.Text     = FormatSize(sysTotal);
            lblBrowserTotal.Text = FormatSize(browserTotal);
            lblTotalSize.Text    = FormatSize(grandTotal);
            runEspace.Text       = $"{grandTotal / 1_000_000} Mo";

            // Labels de détail dans les checkboxes
            lblEdgeSize.Text    = FormatSize(edgeSize);
            lblChromeSize.Text  = FormatSize(chromeSize);
            lblFirefoxSize.Text = FormatSize(firefoxSize);

            // Log d'analyse
            cleanLog.Text = $"Analyse du {DateTime.Now:dd/MM/yyyy à HH:mm}\n\n" +
                            $"  Système :\n" +
                            $"    • C:\\Windows\\Temp   : {FormatSize(winSize)}\n" +
                            $"    • %TEMP% utilisateur : {FormatSize(userSize)}\n\n" +
                            $"  Navigateurs :\n" +
                            $"    • Edge   : {FormatSize(edgeSize)}\n" +
                            $"    • Chrome : {FormatSize(chromeSize)}\n" +
                            $"    • Firefox: {FormatSize(firefoxSize)}\n\n" +
                            $"  Total libérable : {FormatSize(grandTotal)}\n\n" +
                            "Cochez les cibles souhaitées puis cliquez sur « Nettoyer maintenant ».";

            cleanProgress.Visibility = Visibility.Collapsed;
            SetStatus($"Analyse terminée — {FormatSize(grandTotal)} à libérer.");
        }

        private async void BtnCleanNow_Click(object sender, RoutedEventArgs e)
        {
            if (WpfMessageBox.Show(
                    "Supprimer les fichiers temporaires sélectionnés ?\n\nCette action est irréversible.",
                    "Confirmation nettoyage", MessageBoxButton.YesNo, MessageBoxImage.Question)
                != MessageBoxResult.Yes) return;

            cleanProgress.Visibility = Visibility.Visible;
            SetStatus("Nettoyage en cours…");
            long bytesBefore = 0;
            var sb = new StringBuilder();
            sb.AppendLine($"=== Nettoyage du {DateTime.Now:dd/MM/yyyy HH:mm:ss} ===\n");
            _totalRemovedFiles = 0;

            // Lire les valeurs des CheckBox sur le thread UI avant d'entrer dans Task.Run
            bool cleanWin     = chkCleanWinTemp.IsChecked  == true;
            bool cleanUser    = chkCleanUserTemp.IsChecked == true;
            bool cleanEdge    = chkCleanEdge.IsChecked     == true;
            bool cleanChrome  = chkCleanChrome.IsChecked   == true;
            bool cleanFirefox = chkCleanFirefox.IsChecked  == true;
            bool cleanBin     = chkCleanBin.IsChecked      == true;

            await Task.Run(() =>
            {
                if (cleanWin)
                { bytesBefore += SafeDirSize(winTemp); ClearTempData(winTemp, sb); }
                if (cleanUser)
                { bytesBefore += SafeDirSize(appTemp); ClearTempData(appTemp, sb); }
                if (cleanEdge)
                    foreach (var d in BrowserCacheEdge().Where(Directory.Exists))
                    { bytesBefore += SafeDirSize(new DirectoryInfo(d)); ClearTempData(new DirectoryInfo(d), sb); }
                if (cleanChrome)
                    foreach (var d in BrowserCacheChrome().Where(Directory.Exists))
                    { bytesBefore += SafeDirSize(new DirectoryInfo(d)); ClearTempData(new DirectoryInfo(d), sb); }
                if (cleanFirefox)
                    foreach (var d in BrowserCacheFirefox().Where(Directory.Exists))
                    { bytesBefore += SafeDirSize(new DirectoryInfo(d)); ClearTempData(new DirectoryInfo(d), sb); }
                if (cleanBin)
                {
                    try
                    {
                        // SHEmptyRecycleBin via P/Invoke léger
                        NativeMethods.SHEmptyRecycleBin(IntPtr.Zero, null, 0x0007);
                        sb.AppendLine("  ✓ Corbeille vidée");
                        _totalRemovedFiles++;
                    }
                    catch (Exception ex) { sb.AppendLine($"  ✗ Corbeille : {ex.Message}"); }
                }
            });

            sb.AppendLine($"\n{_totalRemovedFiles} élément(s) supprimé(s).");
            cleanLog.Text = sb.ToString();

            // Enregistrer dans l'historique de nettoyage
            _cleanHistory.Insert(0, new CleanSession
            {
                Date          = DateTime.Now,
                ItemsRemoved  = _totalRemovedFiles,
                BytesFreed    = bytesBefore
            });
            RefreshCleanHistory();

            await RefreshCleanPanelAsync();
            SetStatus($"Nettoyage terminé — {_totalRemovedFiles} élément(s) supprimé(s).");
        }

        private void ClearTempData(DirectoryInfo di, StringBuilder log)
        {
            if (!di.Exists) return;
            foreach (FileInfo file in di.GetFiles())
            {
                try { file.Delete(); _totalRemovedFiles++; log.AppendLine($"  ✓ {file.FullName}"); }
                catch (Exception ex) { log.AppendLine($"  ✗ {file.Name} — {ex.Message}"); }
            }
            foreach (DirectoryInfo dir in di.GetDirectories())
            {
                try { dir.Delete(true); _totalRemovedFiles++; log.AppendLine($"  ✓ [dossier] {dir.FullName}"); }
                catch (Exception ex) { log.AppendLine($"  ✗ [dossier] {dir.Name} — {ex.Message}"); }
            }
        }

        // ── Historique de nettoyage ───────────────────────────────────────────────

        private readonly List<CleanSession> _cleanHistory = new();

        private void RefreshHistory()
        {
            var history = _logManager.GetHistory();
            historyGrid.ItemsSource         = history;
            cleanHistoryGrid.ItemsSource    = _cleanHistory;
            cardHistorySubtitle.Text = history.Count > 0
                ? $"{history.Count} scan(s) • {_cleanHistory.Count} nettoyage(s)"
                : "Aucune activité enregistrée";
            UpdateOverviewHealthBanner();
        }

        private void RefreshCleanHistory()
        {
            cleanHistoryGrid.ItemsSource = null;
            cleanHistoryGrid.ItemsSource = _cleanHistory;
        }

        // ── Helpers navigateurs (chemins de cache) ────────────────────────────────

        private static string[] BrowserCacheEdge()
        {
            string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            return new[]
            {
                Path.Combine(local, @"Microsoft\Edge\User Data\Default\Cache\Cache_Data"),
                Path.Combine(local, @"Microsoft\Edge\User Data\Default\Code Cache"),
                Path.Combine(local, @"Microsoft\Edge\User Data\Default\GPUCache"),
            };
        }

        private static string[] BrowserCacheChrome()
        {
            string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            return new[]
            {
                Path.Combine(local, @"Google\Chrome\User Data\Default\Cache\Cache_Data"),
                Path.Combine(local, @"Google\Chrome\User Data\Default\Code Cache"),
                Path.Combine(local, @"Google\Chrome\User Data\Default\GPUCache"),
            };
        }

        private static string[] BrowserCacheFirefox()
        {
            string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string profiles = Path.Combine(local, @"Mozilla\Firefox\Profiles");
            if (!Directory.Exists(profiles)) return Array.Empty<string>();
            return Directory.GetDirectories(profiles)
                .Select(p => Path.Combine(p, "cache2"))
                .ToArray();
        }

        private static long GetBrowserCacheSize(string[] paths)
        {
            long total = 0;
            foreach (var p in paths)
                if (Directory.Exists(p))
                    total += SafeDirSize(new DirectoryInfo(p));
            return total;
        }

        // ── Utilitaires ───────────────────────────────────────────────────────────

        private static long SafeDirSize(DirectoryInfo d)
        {
            if (!d.Exists) return 0;
            long size = 0;
            try
            {
                foreach (FileInfo f in d.GetFiles("*", SearchOption.AllDirectories))
                    try { size += f.Length; } catch { }
            }
            catch { }
            return size;
        }

        private static string FormatSize(long bytes)
        {
            if (bytes >= 1_073_741_824) return $"{bytes / 1_073_741_824.0:F1} Go";
            if (bytes >= 1_048_576)     return $"{bytes / 1_048_576.0:F1} Mo";
            if (bytes >= 1_024)         return $"{bytes / 1_024.0:F0} Ko";
            return $"{bytes} o";
        }

        private void UpdateOverviewHealthBanner()
        {
            bool defsReady = _freshclamUpdater.IsDatabasePresent();
            string defsText = defsReady ? "Les définitions sont à jour" : "Définitions indisponibles";

            var lastScan = _logManager.GetHistory().FirstOrDefault()?.StartedAt;
            string scanText = lastScan.HasValue
                ? $"Dernière analyse il y a {ToRelativeFrench(lastScan.Value)}."
                : "Dernière analyse : jamais.";

            overviewHealthTitle.Text = defsReady
                ? "Votre ordinateur est protégé"
                : "Protection à finaliser";
            overviewHealthSubtitle.Text = $"{defsText}. {scanText}";
        }

        private static string ToRelativeFrench(DateTime when)
        {
            TimeSpan elapsed = DateTime.Now - when;
            if (elapsed.TotalMinutes < 1) return "moins d'une minute";
            if (elapsed.TotalHours < 1) return $"{(int)elapsed.TotalMinutes} minute(s)";
            if (elapsed.TotalDays < 1) return $"{(int)elapsed.TotalHours} heure(s)";
            if (elapsed.TotalDays < 7) return $"{(int)elapsed.TotalDays} jour(s)";
            return when.ToString("dd/MM/yyyy HH:mm");
        }

        private void SetStatus(string message)
        {
            Dispatcher.InvokeAsync(() => lblStatus.Text = message);
        }
    }

    // ── Modèle session de nettoyage ───────────────────────────────────────────────

    public record CleanSession
    {
        public DateTime Date         { get; init; }
        public int      ItemsRemoved { get; init; }
        public long     BytesFreed   { get; init; }

        public string DateDisplay    => Date.ToString("dd/MM/yyyy HH:mm");
        public string FreedDisplay   => BytesFreed >= 1_048_576
            ? $"{BytesFreed / 1_048_576.0:F1} Mo"
            : $"{BytesFreed / 1_024.0:F0} Ko";
    }


    // ── P/Invoke pour vider la Corbeille ─────────────────────────────────────────

    internal static class NativeMethods
    {
        [System.Runtime.InteropServices.DllImport("shell32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
        internal static extern uint SHEmptyRecycleBin(IntPtr hwnd, string? pszRootPath, uint dwFlags);
    }
}
