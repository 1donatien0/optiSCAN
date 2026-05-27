using optiSCAN.Localization;
using optiSCAN.Models;
using optiSCAN.Services;
using optiSCAN.Strings;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Input;
using WpfApp = System.Windows.Application;
// RelayCommand et AsyncRelayCommand définis dans optiSCAN (ViewModels/RelayCommand.cs)

namespace optiSCAN.ViewModels
{
    /// <summary>
    /// ViewModel principal de la fenêtre de scan optiSCAN.
    /// Utilise ScanOrchestrator pour le moteur ClamAV + YARA en parallèle.
    /// </summary>
    public class ScanViewModel : INotifyPropertyChanged, IDisposable
    {
        private bool _disposed;

        // ── Services ─────────────────────────────────────────────────────────────
        private readonly ScanOrchestrator _orchestrator;
        private readonly ClamAvEngine _clamAv;
        private readonly IScanEngine _scanEngine;
        private readonly FreshclamUpdater _updater;
        private readonly YaraForgeUpdater _rulesUpdater;
        private readonly QuarantineManager _quarantine;
        private readonly ScanLogManager _logger;
        private readonly YaraEngine _yara;

        private CancellationTokenSource? _cts;
        private long _scanEpoch;

        // ── Propriétés bindées ───────────────────────────────────────────────────

        private bool _isScanning;
        public bool IsScanning
        {
            get => _isScanning;
            set
            {
                _isScanning = value; OnPropertyChanged();
                OnPropertyChanged(nameof(CanScan)); OnPropertyChanged(nameof(CanStop));
            }
        }

        private bool _isUpdating;
        public bool IsUpdating
        {
            get => _isUpdating;
            set { _isUpdating = value; OnPropertyChanged(); }
        }

        private string _statusMessage = LocalizationService.GetString("Scan_Ready");
        public string StatusMessage
        {
            get => _statusMessage;
            set { _statusMessage = value; OnPropertyChanged(); }
        }

        private int _filesScanned;
        public int FilesScanned
        {
            get => _filesScanned;
            set { _filesScanned = value; OnPropertyChanged(); }
        }

        private int _threatsFound;
        public int ThreatsFound
        {
            get => _threatsFound;
            set { _threatsFound = value; OnPropertyChanged(); }
        }

        private double _progressValue;
        public double ProgressValue
        {
            get => _progressValue;
            set { _progressValue = value; OnPropertyChanged(); }
        }

        private bool _isIndeterminate;
        public bool IsIndeterminate
        {
            get => _isIndeterminate;
            set { _isIndeterminate = value; OnPropertyChanged(); }
        }

        private string _currentScanItem = "";
        /// <summary>Fichier ou dossier en cours d’analyse (affichage type suite antivirus).</summary>
        public string CurrentScanItem
        {
            get => _currentScanItem;
            set { _currentScanItem = value; OnPropertyChanged(); }
        }

        private string _scanProgressDetail = "";
        /// <summary>Résumé chiffré : pourcentage ou « N / total » fichiers.</summary>
        public string ScanProgressDetail
        {
            get => _scanProgressDetail;
            set { _scanProgressDetail = value; OnPropertyChanged(); }
        }

        private string _clamAvVersion = "Vérification…";
        public string ClamAvVersion
        {
            get => _clamAvVersion;
            set { _clamAvVersion = value; OnPropertyChanged(); }
        }

        private string _dbVersion = "Inconnue";
        public string DbVersion
        {
            get => _dbVersion;
            set { _dbVersion = value; OnPropertyChanged(); }
        }

        private string _lastUpdateDisplay = "Jamais";
        public string LastUpdateDisplay
        {
            get => _lastUpdateDisplay;
            set { _lastUpdateDisplay = value; OnPropertyChanged(); }
        }

        private string _rulesPackVersion = "—";
        public string RulesPackVersion
        {
            get => _rulesPackVersion;
            set { _rulesPackVersion = value; OnPropertyChanged(); }
        }

        private string _rulesLastUpdateDisplay = "—";
        public string RulesLastUpdateDisplay
        {
            get => _rulesLastUpdateDisplay;
            set { _rulesLastUpdateDisplay = value; OnPropertyChanged(); }
        }

        private string _yaraStatus = "YARA : vérification…";
        public string YaraStatus
        {
            get => _yaraStatus;
            set { _yaraStatus = value; OnPropertyChanged(); }
        }

        // Indique qu'une initialisation asynchrone est en cours.
        // Permet à l'UI d'afficher un overlay "Chargement..." plutôt que de
        // laisser des champs en "Vérification…" indéfiniment si l'init échoue.
        private bool _isInitializing = true;
        public bool IsInitializing
        {
            get => _isInitializing;
            set { _isInitializing = value; OnPropertyChanged(); }
        }

        // Erreur d'initialisation (vide si tout s'est bien passé).
        // Bindée par l'UI pour afficher un message clair à l'utilisateur.
        private string _initializationError = string.Empty;
        public string InitializationError
        {
            get => _initializationError;
            set { _initializationError = value; OnPropertyChanged(); }
        }

        private ScanResult? _lastResult;
        public ScanResult? LastResult
        {
            get => _lastResult;
            set { _lastResult = value; OnPropertyChanged(); OnPropertyChanged(nameof(SummaryDisplay)); }
        }

        public string SummaryDisplay => _lastResult?.SummaryDisplay ?? string.Empty;

        // UpdateLog : exposé sous deux formes pour rester compatible avec
        // l'ancien binding texte. La source de vérité est UpdateLogLines
        // (ObservableCollection cappée à 500 lignes), et UpdateLog est
        // recalculé au besoin sans concaténation O(N²) à chaque ajout.
        private const int MaxLogLines = 500;
        public ObservableCollection<string> UpdateLogLines { get; } = new();

        /// <summary>Vue texte plate du journal (pour les TextBox legacy).</summary>
        public string UpdateLog => string.Join("\n", UpdateLogLines);

        private void AppendUpdateLog(string line)
        {
            if (string.IsNullOrEmpty(line)) return;
            WpfApp.Current?.Dispatcher.BeginInvoke(new Action(() =>
            {
                UpdateLogLines.Add(line);
                // Capping : éviter l'explosion mémoire si freshclam émet 50k lignes.
                while (UpdateLogLines.Count > MaxLogLines)
                    UpdateLogLines.RemoveAt(0);
                OnPropertyChanged(nameof(UpdateLog));
            }));
        }

        // ── Propriétés supplémentaires pour l'interface ──────────────────────────

        private int _yaraRulesCount;
        public int YaraRulesCount
        {
            get => _yaraRulesCount;
            set
            {
                if (_yaraRulesCount == value) return;
                _yaraRulesCount = value;
                OnPropertyChanged();
                RefreshProtectionStatus();
            }
        }

        private bool _isClamAvAvailable;
        public bool IsClamAvAvailable
        {
            get => _isClamAvAvailable;
            set
            {
                if (_isClamAvAvailable == value) return;
                _isClamAvAvailable = value;
                OnPropertyChanged();
                RefreshProtectionStatus();
            }
        }

        private ProtectionBadgeLevel _protectionBadgeLevel = ProtectionBadgeLevel.Inactive;
        /// <summary>Niveau global : ClamAV + YARA + protection temps réel.</summary>
        public ProtectionBadgeLevel ProtectionBadgeLevel
        {
            get => _protectionBadgeLevel;
            private set
            {
                if (_protectionBadgeLevel == value) return;
                _protectionBadgeLevel = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(ProtectionBadgeText));
            }
        }

        public string ProtectionBadgeText =>
            ProtectionStatusEvaluator.GetBadgeText(ProtectionBadgeLevel);

        // ── Collections ──────────────────────────────────────────────────────────

        public ObservableCollection<ThreatInfo> Threats { get; } = new();
        public ObservableCollection<ScanSession> History { get; } = new();
        public ObservableCollection<RecentScanTarget> RecentTargets { get; } = new();
        public ObservableCollection<QuarantineEntry> QuarantineEntries { get; } = new();

        /// <summary>Taille d'une page chargée depuis <see cref="QuarantineManager.GetEntriesPaged"/>.</summary>
        private const int QuarantinePageSize = 200;

        private int _quarantineTotalCount;
        /// <summary>Nombre total d'entrées en quarantaine (manifest).</summary>
        public int QuarantineTotalCount
        {
            get => _quarantineTotalCount;
            private set { _quarantineTotalCount = value; OnPropertyChanged(); }
        }

        /// <summary>Indique s'il reste des entrées à charger dans <see cref="QuarantineEntries"/>.</summary>
        public bool QuarantineHasMore => QuarantineTotalCount > 0 && QuarantineEntries.Count < QuarantineTotalCount;

        /// <summary>Texte d'état pour l'onglet quarantaine (pagination).</summary>
        public string QuarantinePagingStatus
        {
            get
            {
                if (QuarantineTotalCount == 0)
                    return "Aucun fichier en quarantaine.";
                if (!QuarantineHasMore)
                    return $"Toutes les entrées sont affichées ({QuarantineTotalCount:N0}).";
                return $"{QuarantineEntries.Count:N0} sur {QuarantineTotalCount:N0} affiché(s) — « Charger plus » pour la suite.";
            }
        }

        // ── Commandes ────────────────────────────────────────────────────────────

        public bool CanScan => !IsScanning;
        public bool CanStop => IsScanning;

        public ICommand QuickScanCommand { get; }
        public ICommand FullScanCommand { get; }
        public ICommand ScanFolderCommand { get; }
        public ICommand ScanFileCommand { get; }
        public ICommand ScanRecentCommand { get; }
        public ICommand StopScanCommand { get; }
        public ICommand UpdateDbCommand { get; }
        public ICommand QuarantineAllCommand { get; }
        public ICommand RestoreFileCommand { get; }
        public ICommand DeleteFileCommand { get; }
        public ICommand PurgeQuarantineCommand { get; }
        public ICommand LoadMoreQuarantineCommand { get; }

        /// <summary>
        /// Déclenché au début d’un scan rapide ou complet pour basculer l’UI vers
        /// l’onglet « Scan en cours » (écouteur : <see cref="optiSCAN.Views.AntivirusView"/>).
        /// </summary>
        public event EventHandler? DisplayScanProgressRequested;

        // ── Constructeur ─────────────────────────────────────────────────────────

        // Sans paramètre : utilise ServiceContainer.Default (mêmes services que MainWindow).
        // Le constructeur avec injection de container reste pour les tests ou scénarios avancés.
        public ScanViewModel() : this(ServiceContainer.Default) { }

        public ScanViewModel(ServiceContainer container)
        {
            _clamAv = container.ClamAv;
            _scanEngine = container.ScanEngine;
            _yara = container.Yara;
            _orchestrator = container.Orchestrator;
            _updater = container.FreshclamUpdater;
            _rulesUpdater = container.RulesUpdater;
            _quarantine = container.Quarantine;
            _logger = container.Logger;

            _updater.UpdateOutput += SurAjoutSortieMiseAJour;
            _updater.UpdateCompleted += SurTermineeMiseAJourSignatures;
            _rulesUpdater.UpdateOutput += SurAjoutSortieMiseAJour;
            _rulesUpdater.UpdateCompleted += SurTermineeMiseAJourRegles;
            container.ProtectionStateRefreshRequested += SurDemandeRafraichissementProtection;

            QuickScanCommand = new AsyncRelayCommand(async _ => await StartScanAsync(ScanType.QuickScan));
            FullScanCommand = new AsyncRelayCommand(async _ => await StartScanAsync(ScanType.FullScan));
            ScanFolderCommand = new AsyncRelayCommand(async p => await StartScanAsync(ScanType.Folder, p as string));
            ScanFileCommand = new AsyncRelayCommand(async p => await StartScanAsync(ScanType.File, p as string));
            ScanRecentCommand = new AsyncRelayCommand(async p =>
            {
                if (p is RecentScanTarget t)
                {
                    if (t.ScanType is ScanType.File or ScanType.Folder)
                        await StartScanAsync(t.ScanType, t.Path);
                    else
                        await StartScanAsync(t.ScanType);
                }
            });
            StopScanCommand = new RelayCommand(_ => _cts?.Cancel(), _ => IsScanning);
            // Délègue au flux MainWindow → SignatureUpdateCoordinator (source unique de vérité).
            UpdateDbCommand = new RelayCommand(_ => ServiceContainer.Default.TriggerSignatureUpdate(), _ => !IsUpdating);
            QuarantineAllCommand = new RelayCommand(_ => QuarantineAllThreats(), _ => Threats.Count > 0);
            RestoreFileCommand = new RelayCommand(p => RestoreFromQuarantine(p as string));
            DeleteFileCommand = new RelayCommand(p => DeleteFromQuarantine(p as string));
            PurgeQuarantineCommand = new RelayCommand(_ => PurgeAll(), _ => _quarantine.Count > 0);
            LoadMoreQuarantineCommand = new RelayCommand(_ => LoadMoreQuarantinePage(), _ => QuarantineHasMore);

            _ = InitializeAsync();
        }

        // ── Initialisation ────────────────────────────────────────────────────────
        /// <summary>
        /// Initialise les services et prépare l'état initial de la vue de scan.
        /// Récupère les versions ClamAV/YARA, charge l'historique, la quarantaine
        /// et met l'UI en état cohérent (incluant les dégradations).
        /// </summary>
        /// <remarks>
        /// L'initialisation est tolérante aux pannes : chaque étape peut échouer
        /// sans empêcher les suivantes, et toute erreur est journalisée.
        /// L'objectif est d'éviter l'UI bloquée sur des libellés d'état génériques.
        /// </remarks>

        private async Task InitializeAsync()
        {
            // Initialisation découpée en étapes isolées : un échec dans une étape
            // ne bloque pas les suivantes, et chaque erreur est journalisée.
            // Évite l'UI bloquée en "Vérification…" si un seul service échoue.
            IsInitializing = true;
            try
            {
                AppLogger.Info("ScanViewModel", "Initialisation démarrée");

                await TryStepAsync("Version ClamAV", async () =>
                {
                    ClamAvVersion = await _scanEngine.GetVersionAsync();
                });

                TryStep("Base de signatures", () =>
                {
                    DbVersion = _updater.GetLocalDatabaseVersion();
                    LastUpdateDisplay = _updater.LastUpdateTime?.ToString("dd/MM/yyyy HH:mm") ?? "Jamais";
                    RulesPackVersion = _rulesUpdater.GetRulesPackVersionDisplay();
                    RulesLastUpdateDisplay = _rulesUpdater.GetRulesLastUpdateDisplay();
                });

                TryStep("Statut YARA", () =>
                {
                    bool yaraOk = _yara.IsAvailable;
                    YaraRulesCount = _yara.RulesCount;
                    YaraStatus = yaraOk
                        ? LocalizationService.Format("Vm_YaraOperational", _yara.RulesCount)
                        : LocalizationService.GetString("Vm_YaraUnavailable");
                    RefreshProtectionStatus();
                });

                TryStep("Statut ClamAV", () =>
                {
                    IsClamAvAvailable = _clamAv.IsClamAvInstalled();
                    RefreshProtectionStatus();
                });

                TryStep("Chargement historique", () => { LoadHistory(); RefreshRecentTargets(); });
                TryStep("Compteur analyses (migration)", MigrateScanCountFromHistoryIfNeeded);
                TryStep("Chargement quarantaine", () => LoadQuarantine());

                if (!IsClamAvAvailable)
                    StatusMessage = ScanUserDisplay.ReadyDegraded;
                else
                    StatusMessage = ScanUserDisplay.Ready;

                AppLogger.Info("ScanViewModel", "Initialisation terminée");
                ServiceContainer.Default.RequestScanHistoryViewsRefresh();
            }
            catch (Exception ex)
            {
                // Un crash global de InitializeAsync ne devrait plus jamais arriver
                // grâce aux TryStep ci-dessus, mais on ceinture-bretelles.
                AppLogger.Fatal("ScanViewModel", "Init globale", ex);
                InitializationError = ex.Message;
                StatusMessage = $"Erreur d'initialisation : {ex.Message}";
            }
            finally
            {
                IsInitializing = false;
                RefreshProtectionStatus();
            }
        }

        /// <summary>Recalcule le badge de protection (en-tête Antivirus).</summary>
        public void RefreshProtectionStatus()
        {
            var c = ServiceContainer.Default;
            ProtectionBadgeLevel = ProtectionStatusEvaluator.Evaluate(
                IsClamAvAvailable,
                _yara.IsAvailable,
                YaraRulesCount,
                ExclusionSettings.Current.RealTimeEnabled,
                c.RealTimeProtection.IsEnabled);
        }

        private void SurDemandeRafraichissementProtection(object? sender, EventArgs e)
        {
            var d = WpfApp.Current?.Dispatcher;
            if (d == null) return;
            _ = d.InvokeAsync(RefreshProtectionStatus);
        }

        /// <summary>Exécute une étape d'init synchrone avec capture d'exception isolée.</summary>
        private void TryStep(string name, Action step)
        {
            try { step(); }
            catch (Exception ex)
            {
                AppLogger.Warn("ScanViewModel", $"Init step '{name}' échouée", ex);
                if (string.IsNullOrEmpty(InitializationError))
                    InitializationError = $"{name}: {ex.Message}";
            }
        }

        /// <summary>Exécute une étape d'init asynchrone avec capture d'exception isolée.</summary>
        private async Task TryStepAsync(string name, Func<Task> step)
        {
            try { await step(); }
            catch (Exception ex)
            {
                AppLogger.Warn("ScanViewModel", $"Init step '{name}' échouée", ex);
                if (string.IsNullOrEmpty(InitializationError))
                    InitializationError = $"{name}: {ex.Message}";
            }
        }

        // ── Scans ─────────────────────────────────────────────────────────────────

        /// <summary>
        /// Démarre un scan (rapide, complet, dossier, fichier) et met à jour l'état exposé à l'UI.
        /// </summary>
        /// <remarks>
        /// La progression est injectée via <c>IProgress&lt;ScanProgress&gt;</c> afin d’éviter
        /// les blocages inter-thread, et les erreurs sont converties en message utilisateur
        /// dans <see cref="StatusMessage"/>.
        /// </remarks>
        private async Task StartScanAsync(ScanType type, string? path = null)
        {
            if (IsScanning) return;

            IsScanning = true;
            IsIndeterminate = true;
            ProgressValue = 0;
            FilesScanned = 0;
            ThreatsFound = 0;
            CurrentScanItem = ScanUserDisplay.Preparation;
            ScanProgressDetail = ScanUserDisplay.Preparation;

            WpfApp.Current?.Dispatcher.Invoke(() => Threats.Clear());

            if (type is ScanType.QuickScan or ScanType.FullScan)
            {
                ServiceContainer.Default.Navigation?.NavigateTo(OptiscanStrings.PanelIds.Antivirus);
                DisplayScanProgressRequested?.Invoke(this, EventArgs.Empty);
            }

            StatusMessage = ScanUserDisplay.ScanStarting(type, path);

            _cts = new CancellationTokenSource();
            var epoch = Interlocked.Increment(ref _scanEpoch);
            var progress = new Progress<ScanProgress>(p => SurChangementProgressionScan(p, epoch));

            try
            {
                ScanResult result = type switch
                {
                    ScanType.QuickScan => await _orchestrator.QuickScanAsync(progress, _cts.Token),
                    ScanType.FullScan => await _orchestrator.FullScanAsync(progress, _cts.Token),
                    ScanType.Folder => await _orchestrator.ScanFolderAsync(path!, progress, _cts.Token),
                    ScanType.File => await _orchestrator.ScanFileAsync(path!, progress, _cts.Token),
                    _ => throw new InvalidOperationException()
                };

                LastResult = result;
                _logger.SaveScanResult(result);
                var prefs = UserPreferences.Current;
                prefs.FavoriteScanType = type;
                if (type is ScanType.File or ScanType.Folder && !string.IsNullOrWhiteSpace(path))
                    prefs.AddRecentTarget(path, type);
                else if (type is ScanType.QuickScan or ScanType.FullScan)
                    prefs.AddRecentTarget(string.Empty, type);
                prefs.IncrementScanCount(type);
                RefreshRecentTargets();
                LoadHistory();
                ServiceContainer.Default.RequestScanHistoryViewsRefresh();

                WpfApp.Current?.Dispatcher.Invoke(() =>
                {
                    foreach (var t in result.Threats)
                        Threats.Add(t);
                });

                int autoQuarantined = 0;
                if (ExclusionSettings.Current.AutoQuarantineEnabled && result.Threats.Count > 0)
                {
                    autoQuarantined = _quarantine.QuarantineAll(result.Threats);
                    WpfApp.Current?.Dispatcher.Invoke(LoadQuarantine);
                }

                StatusMessage = autoQuarantined > 0
                    ? $"{result.SummaryDisplay} — {autoQuarantined} fichier(s) mis en quarantaine automatiquement."
                    : result.SummaryDisplay;
                FilesScanned = result.FilesScanned;
                ThreatsFound = result.Threats.Count;

                if (UserPreferences.Current.ActionNotificationsEnabled)
                {
                    ServiceContainer.Default.Notifications.ShowScanCompleted(
                        result.Threats.Count,
                        result.FilesScanned);
                }
            }
            catch (OperationCanceledException)
            {
                StatusMessage = OptiscanStrings.UiMessages.AnalyseInterrompueSurDemande;
            }
            catch (Exception ex)
            {
                StatusMessage = $"Erreur : {ex.Message}";
            }
            finally
            {
                Interlocked.Increment(ref _scanEpoch);
                IsScanning = false;
                IsIndeterminate = false;
                ProgressValue = 0;
                CurrentScanItem = string.Empty;
                ScanProgressDetail = string.Empty;
                _cts?.Dispose();
                _cts = null;
            }
        }

        // ── Progression ───────────────────────────────────────────────────────────

        /// <summary>
        /// Reçoit les mises à jour de progression d’un scan et met à jour l’état bindé.
        /// </summary>
        /// <remarks>
        /// Cette méthode s’exécute via <c>IProgress&lt;ScanProgress&gt;</c> : on effectue
        /// un marshalling vers le thread UI via <c>Dispatcher.BeginInvoke</c> pour éviter
        /// les blocages sur les scans courts (fréquence élevée des événements de progression).
        /// Les compteurs (fichiers/menaces) ne reculent jamais pour refléter la stratégie
        /// multi-moteurs (ClamAV/YARA) et multi-cibles.
        /// </remarks>
        private void SurChangementProgressionScan(ScanProgress p, long epoch)
        {
            // BeginInvoke (asynchrone) plutôt que Invoke : le thread de scan
            // ne bloque pas en attente du Dispatcher UI. Sur un scan rapide
            // émettant 50+ progressions/sec, l'ancienne version sérialisait
            // le scan derrière le rendu WPF.
            WpfApp.Current?.Dispatcher.BeginInvoke(new Action(() =>
            {
                if (epoch != _scanEpoch)
                    return;

                if (p.FilesScanned > 0)
                    FilesScanned = Math.Max(FilesScanned, p.FilesScanned);
                if (p.ThreatsFound > 0)
                    ThreatsFound = Math.Max(ThreatsFound, p.ThreatsFound);

                if (!string.IsNullOrWhiteSpace(p.CurrentFilePath))
                    CurrentScanItem = p.CurrentFilePath;
                else if (p.Phase == ScanPhase.ThreatFound && p.ThreatInfo != null
                    && !string.IsNullOrWhiteSpace(p.ThreatInfo.FilePath))
                    CurrentScanItem = p.ThreatInfo.FilePath;

                int displayedFiles = FilesScanned;

                if (p.Phase != ScanPhase.ThreatFound)
                {
                    StatusMessage = ScanUserDisplay.SyncFileCountInMessage(
                        ScanUserDisplay.ForProgressMessage(p.Message),
                        displayedFiles);
                }

                if (p.TotalFiles > 0 && displayedFiles > 0 && displayedFiles <= p.TotalFiles)
                {
                    var pctVal = Math.Min(100.0, displayedFiles * 100.0 / p.TotalFiles);
                    ScanProgressDetail = $"{displayedFiles:N0} / {p.TotalFiles:N0} fichiers — {(int)pctVal} %";
                }
                else if (displayedFiles > 0)
                {
                    ScanProgressDetail = $"{displayedFiles:N0} fichier(s) parcourus — analyse en cours…";
                }
                else if (p.TotalFiles > 0)
                {
                    ScanProgressDetail = $"Environ {p.TotalFiles:N0} fichier(s) à parcourir — analyse en cours…";
                }
                else
                {
                    ScanProgressDetail = "Analyse en cours…";
                }

                double pctForBar = p.TotalFiles > 0 && displayedFiles > 0 && displayedFiles <= p.TotalFiles
                    ? Math.Min(100.0, displayedFiles * 100.0 / p.TotalFiles)
                    : p.PercentComplete;
                if (pctForBar >= 0)
                {
                    IsIndeterminate = false;
                    ProgressValue = Math.Max(ProgressValue, pctForBar);
                }

                if (p.Phase == ScanPhase.ThreatFound && p.ThreatInfo != null)
                {
                    CurrentScanItem = p.ThreatInfo.FilePath;
                    StatusMessage = p.ThreatInfo.VirusName;
                    if (!Threats.Any(t => string.Equals(t.FilePath, p.ThreatInfo.FilePath, StringComparison.OrdinalIgnoreCase)))
                        Threats.Add(p.ThreatInfo);
                }
            }));
        }

        // ── Mise à jour base de signatures ────────────────────────────────────────
        // Le flux de mise à jour est piloté par MainWindow → SignatureUpdateCoordinator.
        // ScanViewModel réagit aux événements UpdateCompleted des updaters pour
        // synchroniser ses propriétés bindées (DbVersion, YaraStatus, etc.).

        private void SurAjoutSortieMiseAJour(object? sender, string line)
            => AppendUpdateLog(line);

        /// <summary>Appelé par <see cref="FreshclamUpdater.UpdateCompleted"/> après une MAJ ClamAV.</summary>
        private void SurTermineeMiseAJourSignatures(object? sender, UpdateResult result)
        {
            var d = WpfApp.Current?.Dispatcher;
            if (d == null) return;
            _ = d.InvokeAsync(() =>
            {
                StatusMessage = result.Message;
                DbVersion = _updater.GetLocalDatabaseVersion();
                LastUpdateDisplay = _updater.LastUpdateTime?.ToString("dd/MM/yyyy HH:mm") ?? "Jamais";
                RulesPackVersion = _rulesUpdater.GetRulesPackVersionDisplay();
                RulesLastUpdateDisplay = _rulesUpdater.GetRulesLastUpdateDisplay();
            });
        }

        /// <summary>
        /// Appelé par <see cref="YaraForgeUpdater.UpdateCompleted"/> après une MAJ des règles.
        /// Rafraîchit toujours YaraRulesCount et YaraStatus, même si déjà à jour,
        /// pour garantir la cohérence du VM quel que soit l’état de départ.
        /// </summary>
        private void SurTermineeMiseAJourRegles(object? sender, RulesUpdateResult result)
        {
            var d = WpfApp.Current?.Dispatcher;
            if (d == null) return;
            _ = d.InvokeAsync(() =>
            {
                RulesPackVersion = _rulesUpdater.GetRulesPackVersionDisplay();
                RulesLastUpdateDisplay = _rulesUpdater.GetRulesLastUpdateDisplay();
                // Toujours rafraîchir : un rechargement peut avoir eu lieu même sans nouvelle version.
                YaraRulesCount = _yara.RulesCount;
                YaraStatus = _yara.IsAvailable
                    ? $"Moteur de détection actif — {_yara.RulesCount} règle(s)"
                    : result.Success
                        ? LocalizationService.GetString("Vm_SigEngineReloaded")
                        : LocalizationService.GetString("Vm_SigEngineUnavailable");
                RefreshProtectionStatus();
            });
        }

        // ── Quarantaine ───────────────────────────────────────────────────────────

        private void QuarantineAllThreats()
        {
            if (Threats.Count == 0) return;
            if (System.Windows.MessageBox.Show(
                    OptiscanStrings.Confirmations.QuarantineAll(Threats.Count),
                    OptiscanStrings.Confirmations.Title,
                    System.Windows.MessageBoxButton.YesNo,
                    System.Windows.MessageBoxImage.Warning) != System.Windows.MessageBoxResult.Yes)
                return;

            int count = _quarantine.QuarantineAll(Threats);
            LoadQuarantine();
            // Mettre à jour le statut des menaces
            foreach (var threat in Threats)
                threat.Status = ThreatStatus.Quarantined;
            StatusMessage = LocalizationService.Format("Vm_QuarantineBatch", count);
        }

        private void RestoreFromQuarantine(string? id)
        {
            if (string.IsNullOrEmpty(id)) return;
            bool ok = _quarantine.Restore(id);
            LoadQuarantine();
            StatusMessage = ok ? LocalizationService.GetString("Vm_RestoreOk") : LocalizationService.GetString("Vm_RestoreFail");
        }

        private void DeleteFromQuarantine(string? id)
        {
            if (string.IsNullOrEmpty(id)) return;
            bool ok = _quarantine.DeletePermanently(id);
            LoadQuarantine();
            StatusMessage = ok ? LocalizationService.GetString("Vm_DeleteOk") : LocalizationService.GetString("Vm_DeleteFail");
        }

        private void PurgeAll()
        {
            int total = _quarantine.Count;
            if (total == 0) return;
            if (System.Windows.MessageBox.Show(
                    OptiscanStrings.Confirmations.PurgeQuarantine(total),
                    OptiscanStrings.Confirmations.Title,
                    System.Windows.MessageBoxButton.YesNo,
                    System.Windows.MessageBoxImage.Warning) != System.Windows.MessageBoxResult.Yes)
                return;

            int count = _quarantine.PurgeAll();
            LoadQuarantine();
            StatusMessage = LocalizationService.Format("Vm_PurgeCount", count);
        }

        /// <summary>Recharge la première page de quarantaine (réinitialise la liste affichée).</summary>
        public void LoadQuarantine(bool reset = true)
        {
            WpfApp.Current?.Dispatcher.Invoke(() =>
            {
                QuarantineTotalCount = _quarantine.Count;
                if (reset)
                    QuarantineEntries.Clear();
                var offset = QuarantineEntries.Count;
                foreach (var e in _quarantine.GetEntriesPaged(offset, QuarantinePageSize))
                    QuarantineEntries.Add(e);
                NotifyQuarantinePaging();
            });
        }

        private void LoadMoreQuarantinePage() => LoadQuarantine(reset: false);

        private void NotifyQuarantinePaging()
        {
            OnPropertyChanged(nameof(QuarantineHasMore));
            OnPropertyChanged(nameof(QuarantinePagingStatus));
            CommandManager.InvalidateRequerySuggested();
        }

        /// <summary>
        /// Anciennes builds n'appelaient pas <see cref="UserPreferences.IncrementScanCount"/> :
        /// si le compteur est encore à zéro alors qu'un historique existe, on l'aligne une fois.
        /// </summary>
        private void MigrateScanCountFromHistoryIfNeeded()
        {
            var prefs = UserPreferences.Current;
            if (prefs.TotalScansCount > 0) return;
            int n = _logger.GetHistory().Count;
            if (n <= 0) return;
            prefs.TotalScansCount = n;
            prefs.Save();
        }

        private void LoadHistory()
        {
            WpfApp.Current?.Dispatcher.Invoke(() =>
            {
                History.Clear();
                foreach (var s in _logger.GetHistory())
                    History.Add(s);
            });
        }

        /// <summary>Ajoute une menace détectée par la protection temps réel (hors scan manuel).</summary>
        public void AppendLiveThreat(ThreatInfo threat)
        {
            if (string.IsNullOrWhiteSpace(threat.FilePath)) return;
            WpfApp.Current?.Dispatcher.Invoke(() =>
            {
                if (Threats.Any(t => string.Equals(t.FilePath, threat.FilePath, StringComparison.OrdinalIgnoreCase)))
                    return;
                Threats.Add(threat);
                ThreatsFound = Threats.Count;
                OnPropertyChanged(nameof(SummaryDisplay));
            });
        }

        // ── Méthodes publiques pour l'interface ───────────────────────────────────

        public void RefreshQuarantineList() => LoadQuarantine(reset: true);

        public void RefreshHistory()
        {
            LoadHistory();
            RefreshRecentTargets();
        }

        /// <summary>Recharge les 5 dernières cibles depuis <see cref="UserPreferences"/>.</summary>
        public void RefreshRecentTargets()
        {
            WpfApp.Current?.Dispatcher.Invoke(() =>
            {
                RecentTargets.Clear();
                foreach (var t in UserPreferences.Current.RecentTargets)
                    RecentTargets.Add(t);
            });
        }

        // ── INotifyPropertyChanged ────────────────────────────────────────────────

        public event PropertyChangedEventHandler? PropertyChanged;
        protected void OnPropertyChanged([CallerMemberName] string? name = null)
            => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

        // ── IDisposable ───────────────────────────────────────────────────────────
        // Nettoie proprement les ressources : annule un scan en cours, désabonne
        // les événements des updaters, libère le CTS. Sans cela, abonnements
        // persistants à _updater/_rulesUpdater (statiques de fait) → fuite mémoire.
        public void Dispose()
        {
            if (_disposed) return;
            try { _cts?.Cancel(); } catch { }
            try { _cts?.Dispose(); } catch { }
            _cts = null;

            try
            {
                _updater.UpdateOutput -= SurAjoutSortieMiseAJour;
                _updater.UpdateCompleted -= SurTermineeMiseAJourSignatures;
                _rulesUpdater.UpdateOutput -= SurAjoutSortieMiseAJour;
                _rulesUpdater.UpdateCompleted -= SurTermineeMiseAJourRegles;
                _updater.DisableAutoUpdate();
                _rulesUpdater.DisableAutoUpdate();
            }
            catch (Exception ex)
            {
                AppLogger.Warn("ScanViewModel", "Dispose détachement", ex);
            }

            _disposed = true;
            GC.SuppressFinalize(this);
        }
    }

    // RelayCommand et AsyncRelayCommand → ViewModels/RelayCommand.cs (source unique)
}
