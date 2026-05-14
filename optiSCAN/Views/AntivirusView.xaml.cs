using optiSCAN.Models;
using optiSCAN.Services;
using optiSCAN.ViewModels;
using System.Windows;
using System.Windows.Media;
using Color = System.Windows.Media.Color;
using DataFormats = System.Windows.DataFormats;
using DragDropEffects = System.Windows.DragDropEffects;
// Résoudre toutes les ambiguïtés
using DragEventArgs = System.Windows.DragEventArgs;
using FolderBrowserDialog = System.Windows.Forms.FolderBrowserDialog;
using OpenFileDialog = Microsoft.Win32.OpenFileDialog;

namespace optiSCAN.Views
{
    public partial class AntivirusView : System.Windows.Controls.UserControl
    {
        private ScanViewModel? _vmScanTabSubscription;

        public AntivirusView()
        {
            InitializeComponent();
            DataContextChanged += AntivirusView_DataContextChanged;
            Unloaded += AntivirusView_Unloaded;
        }

        private void AntivirusView_DataContextChanged(object sender, DependencyPropertyChangedEventArgs e)
        {
            if (_vmScanTabSubscription != null)
            {
                _vmScanTabSubscription.DisplayScanProgressRequested -= OnVmDisplayScanProgressRequested;
                _vmScanTabSubscription = null;
            }
            if (DataContext is ScanViewModel vm)
            {
                _vmScanTabSubscription = vm;
                vm.DisplayScanProgressRequested += OnVmDisplayScanProgressRequested;
            }
        }

        private void AntivirusView_Unloaded(object sender, RoutedEventArgs e)
        {
            if (_vmScanTabSubscription != null)
            {
                _vmScanTabSubscription.DisplayScanProgressRequested -= OnVmDisplayScanProgressRequested;
                _vmScanTabSubscription = null;
            }
        }

        private void OnVmDisplayScanProgressRequested(object? sender, EventArgs e)
        {
            Dispatcher.InvokeAsync(() =>
            {
                if (antivirusMainTabs is System.Windows.Controls.TabControl tc)
                {
                    tc.SelectedIndex = 0;
                    _ = tc.Focus();
                }
            });
        }

        private ScanViewModel? VM => DataContext as ScanViewModel;
        private MainWindow? Win => Window.GetWindow(this) as MainWindow;

        // ═══════════════════════════════════════════════════════════════════
        // MÉTHODES PUBLIQUES — appelées par MainWindow pour mettre à jour l'UI
        // ═══════════════════════════════════════════════════════════════════

        /// <summary>Met à jour l'indicateur de statut YARA dans la colonne gauche.</summary>
        public void UpdateYaraStatus(bool yaraOk, int rulesCount)
        {
            Dispatcher.InvokeAsync(() =>
            {
                if (antivirusYaraStatus != null)
                {
                    antivirusYaraStatus.Text = yaraOk
                        ? $"YARA : {rulesCount} règle{(rulesCount > 1 ? "s" : "")} active{(rulesCount > 1 ? "s" : "")}"
                        : "YARA : non disponible";
                    antivirusYaraStatus.Foreground = new SolidColorBrush(yaraOk
                        ? Color.FromRgb(80, 200, 120)
                        : Color.FromRgb(224, 90, 90));
                }
                if (antivirusYaraCount != null)
                    antivirusYaraCount.Text = rulesCount.ToString();
            });
        }

        /// <summary>Peuple le DataGrid de quarantaine et met à jour le compteur.</summary>
        public void UpdateQuarantineList(IEnumerable<QuarantineEntry> entries)
        {
            Dispatcher.InvokeAsync(() =>
            {
                var list = entries as IList<QuarantineEntry> ?? entries.ToList();
                if (quarantineGrid != null)
                    quarantineGrid.ItemsSource = list;
                if (antivirusQuarantineCount != null)
                    antivirusQuarantineCount.Text = list.Count.ToString();
            });
        }

        /// <summary>Peuple le DataGrid d'historique des scans.</summary>
        public void UpdateHistory(IEnumerable<ScanSession> historyList)
        {
            Dispatcher.InvokeAsync(() =>
            {
                if (antivirusHistoryGrid != null)
                    antivirusHistoryGrid.ItemsSource = historyList;
            });
        }

        /// <summary>Ajoute une ligne dans le journal de mise à jour des signatures.</summary>
        public void AppendSignatureLog(string message)
        {
            Dispatcher.InvokeAsync(() =>
            {
                if (signatureLog != null)
                {
                    signatureLog.AppendText(message + Environment.NewLine);
                    signatureLog.ScrollToEnd();
                }
            });
        }

        /// <summary>Affiche ou masque la barre de progression et les boutons pendant une MAJ.</summary>
        public void SetSignatureUpdating(bool updating)
        {
            Dispatcher.InvokeAsync(() =>
            {
                if (sigUpdateProgressBar != null)
                    sigUpdateProgressBar.Visibility = updating ? Visibility.Visible : Visibility.Collapsed;
                if (btnManualUpdateSignatures != null)
                    btnManualUpdateSignatures.IsEnabled = !updating;
                if (btnStopUpdateSignatures != null)
                    btnStopUpdateSignatures.Visibility = updating ? Visibility.Visible : Visibility.Collapsed;
            });
        }

        /// <summary>Sélectionne l'onglet « Signatures » (ordre des <c>TabItem</c> dans AntivirusView.xaml).</summary>
        public void SelectSignaturesTab()
        {
            const int signaturesTabIndex = 3;
            Dispatcher.InvokeAsync(() =>
            {
                if (antivirusMainTabs != null)
                    antivirusMainTabs.SelectedIndex = signaturesTabIndex;
            });
        }

        /// <summary>Met à jour le panneau YARA | ClamAV (versions + dernières MAJ).</summary>
        public void UpdateSignaturesPanel(string yaraVersion, string yaraLastMaj, string clamVersion, string clamLastMaj)
        {
            Dispatcher.InvokeAsync(() =>
            {
                if (sigYaraVersion != null)
                    sigYaraVersion.Text = string.IsNullOrWhiteSpace(yaraVersion) ? "—" : yaraVersion;
                if (sigYaraLastMaj != null)
                    sigYaraLastMaj.Text = string.IsNullOrWhiteSpace(yaraLastMaj) || yaraLastMaj == "—" ? "—" : yaraLastMaj;
                if (sigClamVersion != null)
                    sigClamVersion.Text = string.IsNullOrWhiteSpace(clamVersion) || clamVersion == "Inconnue" ? "—" : clamVersion;
                if (sigClamLastMaj != null)
                    sigClamLastMaj.Text = string.IsNullOrWhiteSpace(clamLastMaj) || clamLastMaj == "—" ? "—" : clamLastMaj;
            });
        }

        /// <summary>Compat : mappe sur ClamAV uniquement (YARA « — »).</summary>
        public void UpdateSignatureInfo(string version, string date)
            => UpdateSignaturesPanel("—", "—", version, date);

        /// <summary>Demande à MainWindow de recharger toutes les données antivirus.</summary>
        public void RefreshAllData() => Win?.RefreshAntivirusData();

        // ═══════════════════════════════════════════════════════════════════
        // DIALOGUES DE NAVIGATION (parcourir dossier / fichier)
        // ═══════════════════════════════════════════════════════════════════

        private async void BrowseFolder_Click(object sender, RoutedEventArgs e)
        {
            using var dlg = new FolderBrowserDialog
            {
                Description = "Sélectionnez le dossier à analyser",
                UseDescriptionForTitle = true
            };
            if (dlg.ShowDialog() == System.Windows.Forms.DialogResult.OK
                && VM?.ScanFolderCommand is { } cmd
                && cmd.CanExecute(dlg.SelectedPath))
            {
                cmd.Execute(dlg.SelectedPath);
            }
            await System.Threading.Tasks.Task.CompletedTask;
        }

        private void BrowseFile_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new OpenFileDialog();
            if (dlg.ShowDialog() == true
                && VM?.ScanFileCommand is { } cmd
                && cmd.CanExecute(dlg.FileName))
            {
                cmd.Execute(dlg.FileName);
            }
        }

        // ═══════════════════════════════════════════════════════════════════
        // DRAG & DROP
        // ═══════════════════════════════════════════════════════════════════

        private void AntivirusPanel_DragOver(object sender, DragEventArgs e)
        {
            e.Effects = e.Data.GetDataPresent(DataFormats.FileDrop)
                ? DragDropEffects.Copy
                : DragDropEffects.None;
            e.Handled = true;
        }

        private void AntivirusPanel_Drop(object sender, DragEventArgs e)
        {
            if (!e.Data.GetDataPresent(DataFormats.FileDrop)) return;
            var paths = (string[])e.Data.GetData(DataFormats.FileDrop);
            if (paths == null || paths.Length == 0) return;

            string target = paths[0];
            if (VM == null) return;

            if (System.IO.Directory.Exists(target) && VM.ScanFolderCommand.CanExecute(target))
                VM.ScanFolderCommand.Execute(target);
            else if (System.IO.File.Exists(target) && VM.ScanFileCommand.CanExecute(target))
                VM.ScanFileCommand.Execute(target);
        }

        // ═══════════════════════════════════════════════════════════════════
        // HANDLERS — appellent directement le service AntivirusActions du
        // ServiceContainer plutôt que de remonter vers MainWindow (audit A2).
        // ═══════════════════════════════════════════════════════════════════

        private static Services.AntivirusActions Actions => Services.ServiceContainer.Default.Actions;

        private void BtnQuarantineThreat_Click(object sender, RoutedEventArgs e)
        {
            if (sender is System.Windows.Controls.Button btn && btn.Tag is string filePath)
            {
                Actions.QuarantineThreat(filePath);
                RefreshAllData();
            }
        }

        private void BtnIgnoreThreat_Click(object sender, RoutedEventArgs e)
        {
            if (sender is System.Windows.Controls.Button btn && btn.Tag is string filePath)
                Actions.IgnoreThreat(filePath);
        }

        private void BtnDeleteThreat_Click(object sender, RoutedEventArgs e)
        {
            if (sender is System.Windows.Controls.Button btn && btn.Tag is string filePath)
            {
                Actions.DeleteThreatFile(filePath);
                RefreshAllData();
            }
        }

        private void BtnRestoreFromQuarantine_Click(object sender, RoutedEventArgs e)
        {
            if (sender is System.Windows.Controls.Button btn && btn.Tag is string quarantineId)
            {
                Actions.RestoreFromQuarantine(quarantineId);
                RefreshAllData();
            }
        }

        private void BtnDeleteFromQuarantine_Click(object sender, RoutedEventArgs e)
        {
            if (sender is System.Windows.Controls.Button btn && btn.Tag is string quarantineId)
            {
                Actions.DeleteFromQuarantine(quarantineId);
                RefreshAllData();
            }
        }

        private void BtnManualUpdateSignatures_Click(object sender, RoutedEventArgs e)
        {
            // La logique complète de MAJ (toast progress, log, etc.) reste dans
            // MainWindow car elle pilote l'UI de cette vue. On notifie via le
            // container — MainWindow écoute RequestSignatureUpdate.
            Services.ServiceContainer.Default.TriggerSignatureUpdate();
        }

        private void BtnStopUpdateSignatures_Click(object sender, RoutedEventArgs e)
        {
            Actions.StopAllUpdates();
            SetSignatureUpdating(false);
            AppendSignatureLog("Mise à jour interrompue par l'utilisateur");
        }
    }
}
