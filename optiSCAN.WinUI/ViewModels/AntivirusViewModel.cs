using optiSCAN.Localization;
using optiSCAN.Models;
using optiSCAN.Services;
using optiSCAN.Strings;
using optiSCAN.ViewModels;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace optiSCAN.WinUI.ViewModels
{
    /// <summary>
    /// ViewModel principal de la fenêtre de scan optiSCAN.
    /// Utilise ScanOrchestrator pour le moteur ClamAV + YARA en parallèle.
    /// </summary>
    public partial class AntivirusViewModel : INotifyPropertyChanged, IDisposable, IAntivirusSignatureState, ILiveThreatSink
    {
        private bool _disposed;

        // ── Services ─────────────────────────────────────────────────────────────
        private readonly ScanOrchestrator _orchestrator;
        private readonly IScanEngine _scanEngine;
        private readonly FreshclamUpdater _updater;
        private readonly YaraForgeUpdater _rulesUpdater;
        private readonly QuarantineManager _quarantine;
        private readonly ScanLogManager _logger;
        private readonly IUserConfirmService _confirm;
        private readonly YaraEngine _yara;
        private readonly IUiEventBus _uiEvents;
        private readonly INavigationService? _navigation;
        private readonly RealTimeProtection _realTimeProtection;
        private readonly NotificationService _notifications;
        private readonly IUserPreferencesAccessor _prefs;
        private readonly IExclusionSettingsAccessor _exclusions;
        private readonly IUiThreadScheduler _ui;

        private CancellationTokenSource? _cts;
        private long _scanEpoch;

        /// <summary>Chemins déjà affichés dans <see cref="Threats"/> pour le scan en cours (O(1)).</summary>
        private readonly HashSet<string> _scanThreatPaths = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>Session en cours (stable dès le début du scan — liée à la quarantaine).</summary>
        private Guid _activeScanSessionId;

        /// <summary>Fichiers mis en quarantaine pendant le scan en cours (exclus du résultat final).</summary>
        private readonly HashSet<string> _quarantinedDuringScanPaths = new(StringComparer.OrdinalIgnoreCase);

        // Coalescence des mises à jour UI pendant un scan (dernier ScanProgress gagnant).
        private readonly object _progressCoalesceLock = new();
        private ScanProgress? _pendingProgress;
        private long _pendingProgressEpoch;
        private int _progressCoalesceArmPosted;
        private System.Threading.Timer? _progressCoalesceTimer;
        private static readonly TimeSpan ProgressCoalesceInterval = TimeSpan.FromMilliseconds(100);

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

        private string _clamAvVersion = LocalizationService.GetString("Vm_Checking");
        public string ClamAvVersion
        {
            get => _clamAvVersion;
            set { _clamAvVersion = value; OnPropertyChanged(); }
        }

        private string _dbVersion;
        public string DbVersion
        {
            get => _dbVersion;
            set { _dbVersion = value; OnPropertyChanged(); }
        }

        private string _lastUpdateDisplay = LocalizationService.GetString("Vm_Never");
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

        private string _yaraStatus = LocalizationService.GetString("Vm_Checking");
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

        // UpdateLogLines est la source de vérité ; UpdateLog est recalculé à la demande.
        private const int MaxLogLines = 500;
        public ObservableCollection<string> UpdateLogLines { get; } = new();

        /// <summary>Journal des mises à jour signatures, concaténé pour affichage texte.</summary>
        public string UpdateLog => string.Join("\n", UpdateLogLines);

        private void AppendUpdateLog(string line)
        {
            if (string.IsNullOrEmpty(line)) return;
            _ui.BeginInvoke(() =>
            {
                UpdateLogLines.Add(line);
                while (UpdateLogLines.Count > MaxLogLines)
                    UpdateLogLines.RemoveAt(0);
                OnPropertyChanged(nameof(UpdateLog));
            });
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
                    return LocalizationService.GetString("Vm_QuarantineEmpty");
                if (!QuarantineHasMore)
                    return LocalizationService.Format("Vm_QuarantineAllShown", QuarantineTotalCount);
                return LocalizationService.Format("Vm_QuarantinePartial", QuarantineEntries.Count, QuarantineTotalCount);
            }
        }

        // ── Commandes ────────────────────────────────────────────────────────────

        public bool CanScan => !IsScanning;
        public bool CanStop => IsScanning;

        /// <summary>Identifiant de la session scan en cours (Guid.Empty si aucun scan actif).</summary>
        public Guid ActiveScanSessionId => IsScanning ? _activeScanSessionId : Guid.Empty;

        public IRelayCommand QuickScanCommand { get; }
        public IRelayCommand FullScanCommand { get; }
        public IRelayCommand ScanFolderCommand { get; }
        public IRelayCommand ScanFileCommand { get; }
        public IRelayCommand ScanRecentCommand { get; }
        public IRelayCommand StopScanCommand { get; }
        public IRelayCommand UpdateDbCommand { get; }
        public IRelayCommand QuarantineAllCommand { get; }
        public IRelayCommand RestoreFileCommand { get; }
        public IRelayCommand DeleteFileCommand { get; }
        public IRelayCommand PurgeQuarantineCommand { get; }
        public IRelayCommand LoadMoreQuarantineCommand { get; }

        /// <summary>
        /// Déclenché au début d’un scan rapide ou complet pour basculer l’UI vers
        /// l’onglet Analyse (<see cref="optiSCAN.WinUI.Views.AntivirusPage"/>).
        /// </summary>
        public event EventHandler? DisplayScanProgressRequested;

        // ── Constructeur ─────────────────────────────────────────────────────────

        public AntivirusViewModel(ServiceContainer container, IUserConfirmService? confirm = null, IUiThreadScheduler? ui = null)
        {
            _scanEngine = container.ScanEngine;
            _yara = container.Yara;
            _orchestrator = container.Orchestrator;
            _updater = container.FreshclamUpdater;
            _rulesUpdater = container.RulesUpdater;
            _quarantine = container.Quarantine;
            _logger = container.Logger;
            _confirm = confirm ?? DeclineUserConfirmService.Instance;
            _ui = ui ?? SyncUiThreadScheduler.Instance;
            _uiEvents = container;
            _navigation = container.Navigation;
            _realTimeProtection = container.RealTimeProtection;
            _notifications = container.Notifications;
            _prefs = container.UserPreferencesAccessor;
            _exclusions = container.ExclusionSettingsAccessor;
            _dbVersion = VersionDisplayHelper.UnknownLabel;

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
            // Mise à jour signatures via ServiceContainer (coordonnateur unique).
            UpdateDbCommand = new RelayCommand(_ => _uiEvents.TriggerSignatureUpdate(), _ => !IsUpdating);
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
                AppLogger.Info("AntivirusViewModel", "Initialisation démarrée");

                await TryStepAsync("Version ClamAV", async () =>
                {
                    ClamAvVersion = await _scanEngine.GetVersionAsync();
                });

                await TryStepAsync("Base de signatures", async () =>
                {
                    // Pas de ConfigureAwait(false) : la suite de l'initialisation remplit des
                    // ObservableCollection liées à des ListView, qui doivent rester sur le thread UI.
                    DbVersion = await _updater.GetLocalDatabaseVersionAsync();
                    LastUpdateDisplay = _updater.LastUpdateTime?.ToString("dd/MM/yyyy HH:mm") ?? LocalizationService.GetString("Vm_Never");
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
                    IsClamAvAvailable = _scanEngine.IsAvailable;
                    RefreshProtectionStatus();
                });

                TryStep(LocalizationService.GetString("Vm_LoadingHistory"), () => { LoadHistory(); RefreshRecentTargets(); });
                TryStep("Compteur analyses (migration)", MigrateScanCountFromHistoryIfNeeded);
                TryStep(LocalizationService.GetString("Vm_LoadingQuarantine"), () => LoadQuarantine());

                if (!IsClamAvAvailable)
                    StatusMessage = ScanUserDisplay.ReadyDegraded;
                else
                    StatusMessage = ScanUserDisplay.Ready;

                AppLogger.Info("AntivirusViewModel", "Initialisation terminée");
                _uiEvents.RequestScanHistoryViewsRefresh();
            }
            catch (Exception ex)
            {
                // Un crash global de InitializeAsync ne devrait plus jamais arriver
                // grâce aux TryStep ci-dessus, mais on ceinture-bretelles.
                AppLogger.Fatal("AntivirusViewModel", "Init globale", ex);
                InitializationError = ex.Message;
                StatusMessage = LocalizationService.Format("Vm_InitError", ex.Message);
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
            ProtectionBadgeLevel = ProtectionStatusEvaluator.Evaluate(
                IsClamAvAvailable,
                _yara.IsAvailable,
                YaraRulesCount,
                _exclusions.Current.RealTimeEnabled,
                _realTimeProtection.IsEnabled,
                DefenderCoexistenceService.IsRealTimeDelegated(_prefs.Current));
        }

        private void SurDemandeRafraichissementProtection(object? sender, EventArgs e) =>
            _ui.BeginInvoke(RefreshProtectionStatus);

        /// <summary>Exécute une étape d'init synchrone avec capture d'exception isolée.</summary>
        private void TryStep(string name, Action step)
        {
            try { step(); }
            catch (Exception ex)
            {
                AppLogger.Warn("AntivirusViewModel", $"Init step '{name}' échouée", ex);
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
                AppLogger.Warn("AntivirusViewModel", $"Init step '{name}' échouée", ex);
                if (string.IsNullOrEmpty(InitializationError))
                    InitializationError = $"{name}: {ex.Message}";
            }
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
                _progressCoalesceTimer?.Dispose();
                _progressCoalesceTimer = null;
            }
            catch { /* ignore */ }

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
                AppLogger.Warn("AntivirusViewModel", "Dispose détachement", ex);
            }

            _disposed = true;
            GC.SuppressFinalize(this);
        }
    }

    // RelayCommand et AsyncRelayCommand → ViewModels/RelayCommand.cs (source unique)
}
