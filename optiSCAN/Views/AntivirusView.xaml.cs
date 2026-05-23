using optiSCAN.Models;
using optiSCAN.Services;
using optiSCAN.ViewModels;
using System.Collections.Concurrent;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using Color = System.Windows.Media.Color;
using DataFormats = System.Windows.DataFormats;
using DragDropEffects = System.Windows.DragDropEffects;
// Résoudre toutes les ambiguïtés
using DragEventArgs = System.Windows.DragEventArgs;
using FolderBrowserDialog = System.Windows.Forms.FolderBrowserDialog;
using OpenFileDialog = Microsoft.Win32.OpenFileDialog;

namespace optiSCAN.Views
{
    /// <summary>
    /// Vue principale de l'onglet Antivirus — scan, historique, signatures et quarantaine.
    /// Se connecte au <see cref="ViewModels.ScanViewModel"/> via DataContext.
    /// </summary>
    public partial class AntivirusView : System.Windows.Controls.UserControl
    {
        private ScanViewModel? _vmScanTabSubscription;

        // Journal MAJ signatures : file d'attente + timer pour ne pas poster une
        // opération dispatcher par ligne (freshclam peut en cracher des centaines
        // et geler toute l'UI avec ScrollToEnd à chaque fois).
        private readonly ConcurrentQueue<string> _signatureLogQueue = new();
        private DispatcherTimer? _signatureLogFlushTimer;
        private int _signatureLogArmPosted;
        /// <summary>ScrollViewer du template TextBox (mis en cache après ApplyTemplate).</summary>
        private ScrollViewer? _signatureLogScrollHost;

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

            _signatureLogFlushTimer?.Stop();
            _signatureLogFlushTimer = null;
            while (_signatureLogQueue.TryDequeue(out _)) { }
            Interlocked.Exchange(ref _signatureLogArmPosted, 0);
            _signatureLogScrollHost = null;
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

        /// <summary>Affiche la date du dernier enregistrement d’analyse (vue latérale).</summary>
        public void UpdateLastScanDisplay(DateTime? lastScan)
        {
            Dispatcher.InvokeAsync(() =>
            {
                if (antivirusLastScan == null) return;
                antivirusLastScan.Text = lastScan.HasValue
                    ? lastScan.Value.ToString("dd/MM/yyyy HH:mm", System.Globalization.CultureInfo.CurrentCulture)
                    : "—";
            });
        }

        /// <summary>
        /// Compatibilité : délègue au ViewModel (liste paginée liée au DataGrid).
        /// </summary>
        public void UpdateQuarantineList(IEnumerable<QuarantineEntry>? _ = null)
        {
            Dispatcher.InvokeAsync(() => VM?.LoadQuarantine(reset: true));
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
            _signatureLogQueue.Enqueue(message);
            if (Interlocked.CompareExchange(ref _signatureLogArmPosted, 1, 0) != 0)
                return;

            // Ne pas utiliser this.Dispatcher depuis un thread pool (freshclam OutputDataReceived) :
            // l'accès au Dispatcher du DO peut lever InvalidOperationException.
            var disp = System.Windows.Application.Current?.Dispatcher;
            if (disp == null) return;
            disp.BeginInvoke(new Action(ArmSignatureLogFlush), DispatcherPriority.Background);
        }

        private void ArmSignatureLogFlush()
        {
            Interlocked.Exchange(ref _signatureLogArmPosted, 0);

            _signatureLogFlushTimer ??= new DispatcherTimer(
                TimeSpan.FromMilliseconds(110),
                DispatcherPriority.Background,
                OnSignatureLogFlushTick,
                Dispatcher);

            _signatureLogFlushTimer.Stop();
            _signatureLogFlushTimer.Start();
        }

        private void OnSignatureLogFlushTick(object? sender, EventArgs e)
        {
            _signatureLogFlushTimer?.Stop();
            if (signatureLog == null)
                return;

            EnsureSignatureLogScrollHost();
            // Ne forcer le bas que si l'utilisateur y est déjà : sinon ScrollToEnd à chaque tick
            // empêche de faire défiler le journal pendant la MAJ (effet « qui remonte »).
            bool pinTail = IsSignatureLogPinnedToTail(_signatureLogScrollHost);

            var sb = new StringBuilder(8192);
            for (var i = 0; i < 500 && _signatureLogQueue.TryDequeue(out var line); i++)
                sb.AppendLine(line);

            if (sb.Length > 0)
            {
                signatureLog.AppendText(sb.ToString());
                if (pinTail)
                    signatureLog.ScrollToEnd();
            }

            if (!_signatureLogQueue.IsEmpty)
                _signatureLogFlushTimer?.Start();
        }

        private void EnsureSignatureLogScrollHost()
        {
            if (_signatureLogScrollHost != null || signatureLog == null)
                return;
            signatureLog.ApplyTemplate();
            _signatureLogScrollHost = FindChildScrollViewer(signatureLog);
        }

        private static ScrollViewer? FindChildScrollViewer(DependencyObject root)
        {
            var n = VisualTreeHelper.GetChildrenCount(root);
            for (var i = 0; i < n; i++)
            {
                var child = VisualTreeHelper.GetChild(root, i);
                if (child is ScrollViewer sv)
                    return sv;
                var nested = FindChildScrollViewer(child);
                if (nested != null)
                    return nested;
            }
            return null;
        }

        private static bool IsSignatureLogPinnedToTail(ScrollViewer? sv)
        {
            if (sv == null)
                return true;
            if (sv.ExtentHeight <= 0)
                return true;
            return sv.VerticalOffset + sv.ViewportHeight >= sv.ExtentHeight - 2.5;
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
        // HANDLERS — actions via ServiceContainer.AntivirusActions (sans remonter vers MainWindow).
        // ═══════════════════════════════════════════════════════════════════

        private static Services.AntivirusActions Actions => Services.ServiceContainer.Default.Actions;

        private void BtnQuarantineThreat_Click(object sender, RoutedEventArgs e)
        {
            if (sender is System.Windows.Controls.Button btn && btn.Tag is string filePath)
            {
                var known = Services.ServiceContainer.Default.FindKnownThreat(filePath);
                if (known != null)
                    Actions.QuarantineThreat(known.Clone());
                else
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
