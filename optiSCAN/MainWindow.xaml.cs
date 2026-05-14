using optiSCAN.Models;
using optiSCAN.Services;
using optiSCAN.ViewModels;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.Versioning;
using System.Threading;
using System.Windows;
using System.Windows.Media;
using Button = System.Windows.Controls.Button;
using MediaColor = System.Windows.Media.Color;

namespace optiSCAN
{
    [SupportedOSPlatform("windows")]
    public partial class MainWindow : Window
    {
        // ═══════════════════════════════════════════════════════════════════
        // SERVICES & VIEWMODEL
        // ═══════════════════════════════════════════════════════════════════
        public ScanViewModel? ViewModel { get; private set; }

        private ClamAvEngine? _clamAvEngine;
        private YaraEngine? _yaraEngine;
        private ScanOrchestrator? _antivirusOrchestrator;
        private ScanLogManager? _logManager;
        private QuarantineManager? _quarantineManager;
        private UpdateService? _updateService;
        private FreshclamUpdater? _freshclamUpdater;
        private YaraForgeUpdater? _rulesUpdater;

        private readonly Services.NavigationService _navigationService = new();
        private readonly SemaphoreSlim _manualSignatureUpdateLock = new(1, 1);
        private bool _isClosing = false;

        // Constructeur statique : enregistre l'instance NavigationService de
        // MainWindow dans le container pour que les vues y accèdent sans cast
        // (audit A2). Le set se fait dans le constructeur d'instance, mais on
        // doit attendre que _navigationService soit assigné.

        public MainWindow()
        {
            InitializeComponent();

            try
            {
                // Résolution depuis le ServiceContainer global : une seule
                // instance de chaque service partagée avec ScanViewModel
                // (cf. audit A1 — fini la double instanciation).
                var c = ServiceContainer.Default;
                _clamAvEngine = c.ClamAv;
                _yaraEngine = c.Yara;
                _logManager = c.Logger;
                _quarantineManager = c.Quarantine;
                _antivirusOrchestrator = c.Orchestrator;
                _freshclamUpdater = c.FreshclamUpdater;
                _rulesUpdater = c.RulesUpdater;

                // UpdateService reste local : il ne contient quasiment rien et
                // n'a pas vocation à être partagé.
                _updateService = new UpdateService();

                _freshclamUpdater.UpdateOutput += OnFreshclamOutput;
                _rulesUpdater.UpdateOutput += OnRulesUpdaterOutput;
                _freshclamUpdater.UpdateCompleted += (_, _) =>
                    Dispatcher.InvokeAsync(RefreshSignaturesDisplay);
                _rulesUpdater.UpdateCompleted += (_, _) =>
                    Dispatcher.InvokeAsync(RefreshSignaturesDisplay);

                // ViewModel partage le même container : pas de re-instanciation.
                ViewModel = new ScanViewModel(c);
                this.DataContext = ViewModel;

                // Expose le NavigationService au container — les vues peuvent
                // s'en servir sans cast (System.Windows.Application.Current.MainWindow as MainWindow).
                c.Navigation = _navigationService;

                // Écoute les demandes de mise à jour émises par les vues
                // (ex. carte "Update" d'OverviewControl).
                c.RequestSignatureUpdate += (s, e) =>
                    BtnManualUpdateSignatures_Click(this, new RoutedEventArgs());

                // Abonnement aux événements
                this.Loaded += async (s, e) => await OnMainWindowLoaded();
                this.Closing += OnWindowClosing;
                this.StateChanged += OnWindowStateChanged;

                // IPC : remontée de fenêtre lorsqu'une 2e instance est lancée
                // (audit A5 — extrait dans IpcManager).
                IpcManager.HookShowMessage(this, ShowWindow);

                // Raccourcis Ctrl+1..Ctrl+5 (audit A5/P10 — un seul RoutedCommand
                // paramétré par le tag du panneau, au lieu de 5 commandes).
                KeyboardShortcuts.Register(this,
                    new[] { "Overview", "Antivirus", "Clean", "History", "Options" },
                    SwitchPanel);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Erreur Initialisation : {ex.Message}");
                SetStatus($"Erreur: {ex.Message}", isError: true);
            }
        }

        // ═══════════════════════════════════════════════════════════════════
        // INITIALISATION
        // ═══════════════════════════════════════════════════════════════════
        private async Task OnMainWindowLoaded()
        {
            try
            {
                // ── Enregistrement des panneaux de navigation ────────────────────
                RegisterPanels();

                bool clamAvOk = _clamAvEngine?.IsClamAvInstalled() ?? false;
                SetStatus(clamAvOk ? "✅ ClamAV opérationnel" : "⚠️ ClamAV non installé", isWarning: !clamAvOk);

                if (_updateService != null)
                    _ = Task.Run(async () => await _updateService.CheckAndPrepareUpdatesAsync());

                RefreshYaraStatus();
                RefreshAntivirusStatus();
                RefreshQuarantineList();
                RefreshHistory();
                RefreshSignaturesDisplay();

                // Afficher la vue d'accueil par défaut
                _navigationService.NavigateTo("Overview");

                SetStatus("✅ Protection active");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Erreur : {ex.Message}");
                SetStatus($"Erreur: {ex.Message}", isError: true);
            }
            await Task.CompletedTask;
        }

        /// <summary>
        /// Enregistre les 5 panneaux auprès du NavigationService.
        /// Appelé une seule fois après InitializeComponent (via Loaded).
        /// </summary>
        private void RegisterPanels()
        {
            // Null-checks : les éléments nommés existent forcément après InitializeComponent.
            if (panelOverview != null) _navigationService.RegisterPanel("Overview", panelOverview);
            if (panelAntivirus != null) _navigationService.RegisterPanel("Antivirus", panelAntivirus);
            if (panelClean != null) _navigationService.RegisterPanel("Clean", panelClean);
            if (panelHistory != null) _navigationService.RegisterPanel("History", panelHistory);
            if (panelOptions != null) _navigationService.RegisterPanel("Options", panelOptions);

            ServiceContainer.Default.FocusAntivirusSignaturesTab = () =>
            {
                if (panelAntivirus is Views.AntivirusView av)
                    av.SelectSignaturesTab();
            };
        }

        // ═══════════════════════════════════════════════════════════════════
        // NAVIGATION
        // ═══════════════════════════════════════════════════════════════════

        /// <summary>Déclenché par un RadioButton NavItem coché dans la sidebar.</summary>
        private void NavItem_Checked(object sender, RoutedEventArgs e)
        {
            if (sender is System.Windows.Controls.Primitives.ToggleButton tb
                && tb.Tag is string panelName)
            {
                SwitchPanel(panelName);
            }
        }

        /// <summary>Bascule le thème sombre/clair.</summary>
        private void BtnModesSombre_Click(object sender, RoutedEventArgs e)
        {
            ThemeManager.Toggle();
        }

        /// <summary>Ouvre le site web optiSCAN dans le navigateur par défaut.</summary>
        private void BtnWebsite_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "https://github.com",
                    UseShellExecute = true
                });
            }
            catch { }
        }

        // Ancien handler Button conservé pour compatibilité
        private void MenuButton_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is string target)
                SwitchPanel(target);
        }

        public void SwitchPanel(string panelName)
        {
            // La visibilité est gérée intégralement par le NavigationService (SRP).
            // Les effets de bord métier (rafraîchissement des données) restent ici.
            _navigationService.NavigateTo(panelName);

            switch (panelName)
            {
                case "Antivirus":
                    RefreshAntivirusData();
                    break;
                case "History":
                    RefreshHistory();
                    break;
            }
        }

        // ═══════════════════════════════════════════════════════════════════
        // MÉTHODES DE RAFRAÎCHISSEMENT
        // ═══════════════════════════════════════════════════════════════════
        private void RefreshYaraStatus()
        {
            bool yaraOk = _yaraEngine?.IsAvailable ?? false;
            int rulesCount = _yaraEngine?.RulesCount ?? 0;

            var antivirusView = panelAntivirus as Views.AntivirusView;
            antivirusView?.UpdateYaraStatus(yaraOk, rulesCount);
        }

        private void RefreshAntivirusStatus()
        {
            bool clamAvOk = _clamAvEngine?.IsClamAvInstalled() ?? false;
            int yaraRules = _yaraEngine?.RulesCount ?? 0;

            if (txtSidebarAntivirusStatus != null)
            {
                txtSidebarAntivirusStatus.Text = clamAvOk ? "✅ ClamAV actif" : "⚠️ Non installé";
                txtSidebarAntivirusStatus.Foreground = clamAvOk
                    ? new SolidColorBrush(MediaColor.FromRgb(80, 200, 120))
                    : new SolidColorBrush(MediaColor.FromRgb(224, 90, 90));
            }

            // Mettre à jour la carte État Antivirus dans la vue d'ensemble
            (panelOverview as Views.OverviewControl)?.UpdateAntivirusCardStatus(clamAvOk, yaraRules);
        }

        private void RefreshQuarantineList()
        {
            var entries = _quarantineManager?.GetEntries() ?? new List<QuarantineEntry>();
            var antivirusView = panelAntivirus as Views.AntivirusView;
            antivirusView?.UpdateQuarantineList(entries);
        }

        private void RefreshHistory()
        {
            var sessions = _logManager?.GetHistory() ?? new List<ScanSession>();
            // Antivirus tab
            (panelAntivirus as Views.AntivirusView)?.UpdateHistory(sessions);
            // Panneau Historique dédié
            (panelHistory as Views.HistoryControl)?.UpdateScanHistory(sessions);
        }

        public void RefreshAntivirusData()
        {
            RefreshYaraStatus();
            RefreshAntivirusStatus();
            RefreshQuarantineList();
            RefreshHistory();
            RefreshSignaturesDisplay();
        }

        /// <summary>Rafraîchit les blocs YARA | ClamAV (Signatures + Vue d'ensemble + VM).</summary>
        private void RefreshSignaturesDisplay()
        {
            var clamVer = _freshclamUpdater?.GetLocalDatabaseVersion() ?? "—";
            var clamWhen = _freshclamUpdater?.GetLastSignatureChangeDisplay() ?? "—";
            var yaraVer = _rulesUpdater?.GetRulesPackVersionDisplay() ?? "—";
            var yaraWhen = _rulesUpdater?.GetRulesLastUpdateDisplay() ?? "—";

            (panelAntivirus as Views.AntivirusView)?.UpdateSignaturesPanel(yaraVer, yaraWhen, clamVer, clamWhen);
            (panelOverview as Views.OverviewControl)?.UpdateSignaturesSummary(yaraVer, yaraWhen, clamVer, clamWhen);

            if (ViewModel != null)
            {
                ViewModel.DbVersion = clamVer;
                ViewModel.RulesPackVersion = yaraVer;
                ViewModel.LastUpdateDisplay = clamWhen == "—" ? "Jamais" : clamWhen;
                ViewModel.RulesLastUpdateDisplay = yaraWhen == "—" ? "Jamais" : yaraWhen;
            }
        }

        // ═══════════════════════════════════════════════════════════════════
        // MÉTHODES DE STATUT
        // ═══════════════════════════════════════════════════════════════════
        private void SetStatus(string text, bool isError = false, bool isWarning = false)
        {
            Dispatcher.InvokeAsync(() =>
            {
                if (lblStatus != null)
                {
                    lblStatus.Text = text;
                    if (isError)
                        lblStatus.Foreground = new SolidColorBrush(MediaColor.FromRgb(239, 68, 68));
                    else if (isWarning)
                        lblStatus.Foreground = new SolidColorBrush(MediaColor.FromRgb(245, 158, 11));
                    else
                        lblStatus.Foreground = new SolidColorBrush(MediaColor.FromRgb(148, 163, 184));
                }
                Debug.WriteLine($"[{DateTime.Now:HH:mm:ss}] {text}");
            });
        }

        // ═══════════════════════════════════════════════════════════════════
        // MÉTHODE DE NETTOYAGE (appelée par CleanControl)
        // ═══════════════════════════════════════════════════════════════════
        public async void PerformCleanup()
        {
            SetStatus("🧹 Nettoyage en cours...");

            // Simulation de nettoyage (à remplacer par votre logique réelle)
            await Task.Run(async () =>
            {
                await Task.Delay(2000);
                Dispatcher.Invoke(() => SetStatus("✅ Nettoyage terminé - Espace libéré"));
            });
        }

        // ═══════════════════════════════════════════════════════════════════
        // RÉ-AFFICHAGE DEPUIS LA SYSTRAY OU IPC
        // ═══════════════════════════════════════════════════════════════════
        // (Le hook WM_SHOWME et la gestion ComponentDispatcher ont été extraits
        // dans Services.IpcManager — cf. audit A5.)
        private void ShowWindow()
        {
            if (WindowState == WindowState.Minimized)
                WindowState = WindowState.Normal;
            Show();
            Activate();
            Topmost = true;
            Topmost = false;
        }

        // RegisterKeyboardShortcuts retiré : extrait dans Services.KeyboardShortcuts
        // (audit A5/P10 — un seul RoutedCommand paramétré au lieu de 5).

        // ═══════════════════════════════════════════════════════════════════
        // GESTION DE L'ÉTAT DE LA FENÊTRE (minimize → systray)
        // ═══════════════════════════════════════════════════════════════════
        private void OnWindowStateChanged(object? sender, EventArgs e)
        {
            if (WindowState == WindowState.Minimized)
            {
                Hide();
                SetStatus("optiSCAN réduit dans la barre système");
            }
        }

        // ═══════════════════════════════════════════════════════════════════
        // GESTION DE LA FERMETURE
        // ═══════════════════════════════════════════════════════════════════
        private void OnWindowClosing(object? sender, CancelEventArgs e)
        {
            if (!_isClosing)
            {
                e.Cancel = true;
                Hide();
                SetStatus("optiSCAN réduit dans la barre système");
            }
            else
            {
                PerformCleanShutdown();
            }
        }

        private void PerformCleanShutdown()
        {
            try
            {
                // Désabonnement local des events branchés ici
                if (_freshclamUpdater != null) _freshclamUpdater.UpdateOutput -= OnFreshclamOutput;
                if (_rulesUpdater != null) _rulesUpdater.UpdateOutput -= OnRulesUpdaterOutput;

                // Dispose du ViewModel (CTS, abonnements, timers)
                ViewModel?.Dispose();

                // Container partagé : c'est lui qui possède les services maintenant.
                ServiceContainer.Default.Shutdown();
            }
            catch (Exception ex)
            {
                AppLogger.Warn("MainWindow", "PerformCleanShutdown", ex);
            }
        }

        // ═══════════════════════════════════════════════════════════════════
        // MÉTHODES DE QUARANTAINE
        // ═══════════════════════════════════════════════════════════════════
        public void BtnQuarantineThreat_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is string filePath)
            {
                var threat = new ThreatInfo
                {
                    FilePath = filePath,
                    VirusName = "Détecté",
                    DetectedAt = DateTime.Now,
                    Status = ThreatStatus.Detected,
                    FileSize = System.IO.File.Exists(filePath) ? new System.IO.FileInfo(filePath).Length : 0
                };

                if (_quarantineManager?.Quarantine(threat) == true)
                {
                    SetStatus($"✅ Fichier mis en quarantaine : {System.IO.Path.GetFileName(filePath)}");
                    RefreshQuarantineList();
                    ((Views.AntivirusView)panelAntivirus)?.RefreshAllData();
                }
                else
                {
                    SetStatus($"❌ Erreur lors de la mise en quarantaine", isError: true);
                }
            }
        }

        public void BtnIgnoreThreat_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is string filePath)
            {
                ExclusionSettings.Current.AddFile(filePath);
                SetStatus($"⚠️ Fichier ignoré : {System.IO.Path.GetFileName(filePath)}", isWarning: true);
                ((Views.AntivirusView)panelAntivirus)?.RefreshAllData();
            }
        }

        public void BtnDeleteThreat_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is string filePath)
            {
                try
                {
                    if (System.IO.File.Exists(filePath))
                    {
                        System.IO.File.Delete(filePath);
                        SetStatus($"🗑️ Fichier supprimé : {System.IO.Path.GetFileName(filePath)}");
                    }
                    ((Views.AntivirusView)panelAntivirus)?.RefreshAllData();
                }
                catch (Exception ex)
                {
                    SetStatus($"❌ Erreur suppression : {ex.Message}", isError: true);
                }
            }
        }

        public void BtnRestoreFromQuarantine_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is string quarantineId)
            {
                if (_quarantineManager?.Restore(quarantineId) == true)
                {
                    SetStatus($"✅ Fichier restauré depuis la quarantaine");
                    RefreshQuarantineList();
                    ((Views.AntivirusView)panelAntivirus)?.RefreshAllData();
                }
                else
                {
                    SetStatus($"❌ Erreur lors de la restauration", isError: true);
                }
            }
        }

        public void BtnDeleteFromQuarantine_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is string quarantineId)
            {
                if (_quarantineManager?.DeletePermanently(quarantineId) == true)
                {
                    SetStatus($"🗑️ Fichier supprimé définitivement de la quarantaine");
                    RefreshQuarantineList();
                    ((Views.AntivirusView)panelAntivirus)?.RefreshAllData();
                }
                else
                {
                    SetStatus($"❌ Erreur lors de la suppression", isError: true);
                }
            }
        }

        // ═══════════════════════════════════════════════════════════════════
        // MÉTHODES DE MISE À JOUR DES SIGNATURES
        // ═══════════════════════════════════════════════════════════════════

        // Handlers nommés — souscrits une seule fois à l'init pour éviter
        // l'accumulation de lambdas anonymes à chaque clic.
        private void OnFreshclamOutput(object? sender, string line)
            => (panelAntivirus as Views.AntivirusView)?.AppendSignatureLog($"[ClamAV] {line}");

        private void OnRulesUpdaterOutput(object? sender, string line)
            => (panelAntivirus as Views.AntivirusView)?.AppendSignatureLog($"[Règles] {line}");

        public async void BtnManualUpdateSignatures_Click(object sender, RoutedEventArgs e)
        {
            // Deux déclenchements rapprochés (carte Vue d'ensemble + bouton, ou double-clic)
            // lançaient un second flux qui voyait « déjà en cours » et dont le finally
            // remettait l'UI à l'état « terminé » pendant que le premier flux continuait.
            if (!await _manualSignatureUpdateLock.WaitAsync(0))
            {
                SetStatus("⚠️ Une mise à jour des signatures est déjà en cours.", isWarning: true);
                return;
            }

            SetStatus("🔄 Mise à jour complète des signatures et règles...");
            var antivirusView = panelAntivirus as Views.AntivirusView;
            var completedOk = true;

            try
            {
                await Task.Yield();

                if (antivirusView != null)
                {
                    antivirusView.SetSignatureUpdating(true);
                    antivirusView.AppendSignatureLog("=== MISE À JOUR COMPLÈTE ===");
                }

                // ── 1. ClamAV : UpdateAsync utilise ConfigureAwait(false) en interne ;
                //    ConfigureAwait(true) ici ramène sur le dispatcher pour le journal et le finally.
                if (antivirusView != null)
                    antivirusView.AppendSignatureLog("1. Mise à jour des signatures ClamAV...");

                if (_freshclamUpdater != null)
                {
                    var clamResult = await _freshclamUpdater.UpdateAsync().ConfigureAwait(true);

                    if (antivirusView != null)
                    {
                        if (clamResult.Success)
                            antivirusView.AppendSignatureLog($"✅ ClamAV : {clamResult.Message}");
                        else
                        {
                            completedOk = false;
                            antivirusView.AppendSignatureLog($"❌ ClamAV : {clamResult.Message}");
                        }
                    }
                }

                RefreshSignaturesDisplay();

                // ── 2. Règles YARA ───────────────────────────────────────────────
                if (antivirusView != null)
                {
                    antivirusView.AppendSignatureLog("");
                    antivirusView.AppendSignatureLog("2. Mise à jour des règles de détection...");
                }

                if (_rulesUpdater != null)
                {
                    var progress = new Progress<string>(msg =>
                        Dispatcher.BeginInvoke(
                            new Action(() => antivirusView?.AppendSignatureLog(msg)),
                            System.Windows.Threading.DispatcherPriority.Background));

                    var rulesResult = await _rulesUpdater.UpdateAsync(progress).ConfigureAwait(true);

                    if (antivirusView != null)
                    {
                        if (rulesResult.Success)
                            antivirusView.AppendSignatureLog($"✅ Règles : {rulesResult.Message}");
                        else
                        {
                            completedOk = false;
                            antivirusView.AppendSignatureLog($"❌ Règles : {rulesResult.Message}");
                        }
                    }
                }

                if (antivirusView != null)
                {
                    antivirusView.AppendSignatureLog("");
                    antivirusView.AppendSignatureLog("=== MISE À JOUR TERMINÉE ===");
                }
            }
            catch (Exception ex)
            {
                completedOk = false;
                AppLogger.Error("MainWindow", "BtnManualUpdateSignatures_Click", ex);
                antivirusView?.AppendSignatureLog($"❌ Erreur : {ex.Message}");
                SetStatus($"❌ Mise à jour : {ex.Message}", isError: true);
            }
            finally
            {
                antivirusView?.SetSignatureUpdating(false);
                RefreshSignaturesDisplay();
                RefreshYaraStatus();
                if (completedOk)
                    SetStatus("✅ Mise à jour complète terminée");
                else
                    SetStatus("⚠️ Mise à jour terminée avec erreurs — voir le journal.", isWarning: true);

                _manualSignatureUpdateLock.Release();
            }
        }

        public void BtnStopUpdateSignatures_Click(object sender, RoutedEventArgs e)
        {
            SetStatus("⏹️ Arrêt de la mise à jour...");
            var antivirusView = panelAntivirus as Views.AntivirusView;

            // Annulation effective des process en cours (freshclam.exe + règles YARA).
            // Sans cet appel, le bouton ne faisait que masquer le spinner pendant
            // que freshclam continuait à tourner en arrière-plan.
            try { _freshclamUpdater?.CancelUpdate(); }
            catch (Exception ex) { Debug.WriteLine($"Cancel ClamAV: {ex.Message}"); }

            try { _rulesUpdater?.CancelUpdate(); }
            catch (Exception ex) { Debug.WriteLine($"Cancel Règles: {ex.Message}"); }

            antivirusView?.AppendSignatureLog("Mise à jour interrompue par l'utilisateur");
            antivirusView?.SetSignatureUpdating(false);
        }

        // ═══════════════════════════════════════════════════════════════════
        // MÉTHODES D'ACCÈS AUX SERVICES
        // ═══════════════════════════════════════════════════════════════════
        public QuarantineManager? GetQuarantineManager() => _quarantineManager;
        public ScanLogManager? GetLogManager() => _logManager;
        public ScanOrchestrator? GetOrchestrator() => _antivirusOrchestrator;
        public FreshclamUpdater? GetFreshclamUpdater() => _freshclamUpdater;
        public YaraForgeUpdater? GetRulesUpdater() => _rulesUpdater;
    }
}