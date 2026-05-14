using optiSCAN.Models;
using optiSCAN.Services;
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
    /// Utilise ScanOrchestrator pour le pipeline ClamAV + YARA en parallèle.
    /// </summary>
    public class ScanViewModel : INotifyPropertyChanged, IDisposable
    {
        private bool _disposed;

        // ── Services ─────────────────────────────────────────────────────────────
        private readonly ScanOrchestrator _orchestrator;
        private readonly ClamAvEngine _clamAv;
        private readonly FreshclamUpdater _updater;
        private readonly YaraForgeUpdater _rulesUpdater;
        private readonly QuarantineManager _quarantine;
        private readonly ScanLogManager _logger;
        private readonly YaraEngine _yara;

        private CancellationTokenSource? _cts;

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

        private string _statusMessage = "Prêt à scanner.";
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
            set { _yaraRulesCount = value; OnPropertyChanged(); }
        }

        private bool _isClamAvAvailable;
        public bool IsClamAvAvailable
        {
            get => _isClamAvAvailable;
            set { _isClamAvAvailable = value; OnPropertyChanged(); }
        }

        // ── Collections ──────────────────────────────────────────────────────────

        public ObservableCollection<ThreatInfo> Threats { get; } = new();
        public ObservableCollection<ScanSession> History { get; } = new();
        public ObservableCollection<QuarantineEntry> QuarantineEntries { get; } = new();

        // ── Commandes ────────────────────────────────────────────────────────────

        public bool CanScan => !IsScanning;
        public bool CanStop => IsScanning;

        public ICommand QuickScanCommand { get; }
        public ICommand FullScanCommand { get; }
        public ICommand ScanFolderCommand { get; }
        public ICommand ScanFileCommand { get; }
        public ICommand StopScanCommand { get; }
        public ICommand UpdateDbCommand { get; }
        public ICommand QuarantineAllCommand { get; }
        public ICommand RestoreFileCommand { get; }
        public ICommand DeleteFileCommand { get; }
        public ICommand PurgeQuarantineCommand { get; }

        /// <summary>
        /// Déclenché au début d’un scan rapide ou complet pour basculer l’UI vers
        /// l’onglet « Scan en cours » (écouteur : <see cref="optiSCAN.Views.AntivirusView"/>).
        /// </summary>
        public event EventHandler? DisplayScanProgressRequested;

        // ── Constructeur ─────────────────────────────────────────────────────────

        // Constructeur sans paramètre : résout depuis le container global pour
        // partager les services avec MainWindow (cf. audit A1 — fini la double
        // instanciation). Le constructeur paramétré ci-dessous reste disponible
        // pour les tests unitaires ou la substitution.
        public ScanViewModel() : this(ServiceContainer.Default) { }

        public ScanViewModel(ServiceContainer container)
        {
            _clamAv = container.ClamAv;
            _yara = container.Yara;
            _orchestrator = container.Orchestrator;
            _updater = container.FreshclamUpdater;
            _rulesUpdater = container.RulesUpdater;
            _quarantine = container.Quarantine;
            _logger = container.Logger;

            _updater.UpdateOutput += OnUpdateOutput;
            _updater.UpdateCompleted += OnUpdateCompleted;
            _rulesUpdater.UpdateOutput += (_, msg) => OnUpdateOutput(_, msg);
            _rulesUpdater.UpdateCompleted += OnRulesUpdateCompleted;

            QuickScanCommand = new AsyncRelayCommand(async _ => await StartScanAsync(ScanType.QuickScan));
            FullScanCommand = new AsyncRelayCommand(async _ => await StartScanAsync(ScanType.FullScan));
            ScanFolderCommand = new AsyncRelayCommand(async p => await StartScanAsync(ScanType.Folder, p as string));
            ScanFileCommand = new AsyncRelayCommand(async p => await StartScanAsync(ScanType.File, p as string));
            StopScanCommand = new RelayCommand(_ => _cts?.Cancel(), _ => IsScanning);
            UpdateDbCommand = new AsyncRelayCommand(async _ => await UpdateDatabaseAsync());
            QuarantineAllCommand = new RelayCommand(_ => QuarantineAllThreats(), _ => Threats.Count > 0);
            RestoreFileCommand = new RelayCommand(p => RestoreFromQuarantine(p as string));
            DeleteFileCommand = new RelayCommand(p => DeleteFromQuarantine(p as string));
            PurgeQuarantineCommand = new RelayCommand(_ => PurgeAll(), _ => QuarantineEntries.Count > 0);

            _ = InitializeAsync();
        }

        // ── Initialisation ────────────────────────────────────────────────────────

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
                    ClamAvVersion = await _clamAv.GetVersionAsync();
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
                        ? $"YARA opérationnel — {_yara.RulesCount} règle(s)"
                        : "YARA non disponible (yara64.exe manquant ou aucune règle)";
                });

                TryStep("Statut ClamAV", () =>
                {
                    IsClamAvAvailable = _clamAv.IsClamAvInstalled();
                });

                TryStep("Chargement historique", LoadHistory);
                TryStep("Chargement quarantaine", LoadQuarantine);

                if (!IsClamAvAvailable)
                    StatusMessage = "⚠ ClamAV non détecté. Vérifiez 'clamav/x64/' dans le dossier de l'application.";
                else
                    StatusMessage = "Prêt — pipeline ClamAV + YARA actif.";

                AppLogger.Info("ScanViewModel", "Initialisation terminée");
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
            }
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

        private async Task StartScanAsync(ScanType type, string? path = null)
        {
            if (IsScanning) return;

            IsScanning = true;
            IsIndeterminate = true;
            ProgressValue = 0;
            FilesScanned = 0;
            ThreatsFound = 0;

            WpfApp.Current?.Dispatcher.Invoke(() => Threats.Clear());

            if (type is ScanType.QuickScan or ScanType.FullScan)
            {
                ServiceContainer.Default.Navigation?.NavigateTo("Antivirus");
                DisplayScanProgressRequested?.Invoke(this, EventArgs.Empty);
            }

            StatusMessage = type switch
            {
                ScanType.QuickScan => "Scan rapide en cours (ClamAV + YARA)…",
                ScanType.FullScan => "Scan complet en cours (ClamAV + YARA)…",
                ScanType.Folder => $"Scan du dossier : {path}",
                ScanType.File => $"Scan du fichier : {System.IO.Path.GetFileName(path ?? "")}",
                _ => "Scan en cours…"
            };

            _cts = new CancellationTokenSource();
            var progress = new Progress<ScanProgress>(OnScanProgress);

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
                LoadHistory();

                WpfApp.Current?.Dispatcher.Invoke(() =>
                {
                    foreach (var t in result.Threats)
                        Threats.Add(t);
                });

                StatusMessage = result.SummaryDisplay;
                FilesScanned = result.FilesScanned;
                ThreatsFound = result.Threats.Count;
            }
            catch (OperationCanceledException)
            {
                StatusMessage = "Scan annulé par l'utilisateur.";
            }
            catch (Exception ex)
            {
                StatusMessage = $"Erreur : {ex.Message}";
            }
            finally
            {
                IsScanning = false;
                IsIndeterminate = false;
                ProgressValue = 0;
                _cts?.Dispose();
                _cts = null;
            }
        }

        // ── Progression ───────────────────────────────────────────────────────────

        private void OnScanProgress(ScanProgress p)
        {
            // BeginInvoke (asynchrone) plutôt que Invoke : le thread de scan
            // ne bloque pas en attente du Dispatcher UI. Sur un scan rapide
            // émettant 50+ progressions/sec, l'ancienne version sérialisait
            // le scan derrière le rendu WPF.
            WpfApp.Current?.Dispatcher.BeginInvoke(new Action(() =>
            {
                StatusMessage = p.Message;
                FilesScanned = p.FilesScanned;
                ThreatsFound = p.ThreatsFound;

                // ProgressBar : déterminée si on connaît le total, indéterminée
                // sinon (cas ClamAV en début de scan, avant le premier --summary).
                var pct = p.PercentComplete;
                if (pct >= 0)
                {
                    IsIndeterminate = false;
                    ProgressValue = pct;
                }

                if (p.Phase == ScanPhase.ThreatFound && p.ThreatInfo != null)
                {
                    // Éviter les doublons
                    if (!Threats.Any(t => t.FilePath == p.ThreatInfo.FilePath))
                        Threats.Add(p.ThreatInfo);
                }
            }));
        }

        // ── Mise à jour base de signatures ────────────────────────────────────────

        private async Task UpdateDatabaseAsync()
        {
            if (IsUpdating) return;
            IsUpdating = true;
            // Reset du journal : on vide la collection sur le thread UI pour
            // ne pas violer le contrat WPF (collection-changed cross-thread).
            WpfApp.Current?.Dispatcher.Invoke(() => UpdateLogLines.Clear());
            OnPropertyChanged(nameof(UpdateLog));
            StatusMessage = "Mise à jour des signatures en cours…";

            // ── 1. Mise à jour des signatures ClamAV (hors thread UI) ───────────
            var clamResult = await Task.Run(() => _updater.UpdateAsync()).ConfigureAwait(true);

            DbVersion = _updater.GetLocalDatabaseVersion();
            var clamWhenStr = _updater.GetLastSignatureChangeDisplay();
            LastUpdateDisplay = _updater.LastUpdateTime?.ToString("dd/MM/yyyy HH:mm")
                ?? (clamWhenStr != "—" ? clamWhenStr : "Jamais");

            // ── 2. Mise à jour des règles de détection comportementale ─────────
            StatusMessage = "Mise à jour des règles de détection en cours…";

            var rulesProgress = new Progress<string>(msg =>
            {
                AppendUpdateLog(msg);
                WpfApp.Current?.Dispatcher.BeginInvoke(new Action(() => StatusMessage = msg));
            });

            var rulesResult = await Task.Run(() => _rulesUpdater.UpdateAsync(rulesProgress)).ConfigureAwait(true);

            RulesPackVersion = _rulesUpdater.GetRulesPackVersionDisplay();
            RulesLastUpdateDisplay = _rulesUpdater.GetRulesLastUpdateDisplay();

            // Rafraîchir le statut du moteur de détection
            YaraRulesCount = _yara.RulesCount;
            YaraStatus = _yara.IsAvailable
                ? $"Moteur de détection actif — {_yara.RulesCount} règle(s)"
                : "Moteur de détection non disponible";

            // ── 3. Résumé final ───────────────────────────────────────────────
            var summary = clamResult.Success
                ? $"Signatures : {clamResult.Message}"
                : $"Signatures : ⚠ {clamResult.Message}";
            summary += "\n" + (rulesResult.Success
                ? $"Règles : {rulesResult.Message}"
                : $"Règles : ⚠ {rulesResult.Message}");

            StatusMessage = clamResult.Success && rulesResult.Success
                ? "✅ Mise à jour complète."
                : "⚠ Mise à jour partielle — consultez le journal.";

            AppendUpdateLog("");
            AppendUpdateLog(summary);
            IsUpdating = false;
        }

        private void OnUpdateOutput(object? sender, string line)
            => AppendUpdateLog(line);

        private void OnUpdateCompleted(object? sender, UpdateResult result)
        {
            var d = WpfApp.Current?.Dispatcher;
            if (d == null) return;
            _ = d.InvokeAsync(() =>
            {
                StatusMessage = result.Message;
                DbVersion = _updater.GetLocalDatabaseVersion();
                RulesPackVersion = _rulesUpdater.GetRulesPackVersionDisplay();
                RulesLastUpdateDisplay = _rulesUpdater.GetRulesLastUpdateDisplay();
            });
        }

        private void OnRulesUpdateCompleted(object? sender, RulesUpdateResult result)
        {
            var d = WpfApp.Current?.Dispatcher;
            if (d == null) return;
            _ = d.InvokeAsync(() =>
            {
                RulesPackVersion = _rulesUpdater.GetRulesPackVersionDisplay();
                RulesLastUpdateDisplay = _rulesUpdater.GetRulesLastUpdateDisplay();
                if (!result.AlreadyUpToDate && result.Success)
                {
                    YaraRulesCount = _yara.RulesCount;
                    YaraStatus = _yara.IsAvailable
                        ? $"Moteur de détection actif — {_yara.RulesCount} règle(s)"
                        : "Moteur de détection : règles mises à jour (rechargement au prochain scan)";
                }
            });
        }

        // ── Quarantaine ───────────────────────────────────────────────────────────

        private void QuarantineAllThreats()
        {
            int count = _quarantine.QuarantineAll(Threats);
            LoadQuarantine();
            // Mettre à jour le statut des menaces
            foreach (var threat in Threats)
                threat.Status = ThreatStatus.Quarantined;
            StatusMessage = $"{count} fichier(s) placé(s) en quarantaine.";
        }

        private void RestoreFromQuarantine(string? id)
        {
            if (string.IsNullOrEmpty(id)) return;
            bool ok = _quarantine.Restore(id);
            LoadQuarantine();
            StatusMessage = ok ? "Fichier restauré." : "Impossible de restaurer le fichier.";
        }

        private void DeleteFromQuarantine(string? id)
        {
            if (string.IsNullOrEmpty(id)) return;
            bool ok = _quarantine.DeletePermanently(id);
            LoadQuarantine();
            StatusMessage = ok ? "Fichier supprimé définitivement." : "Erreur lors de la suppression.";
        }

        private void PurgeAll()
        {
            int count = _quarantine.PurgeAll();
            LoadQuarantine();
            StatusMessage = $"{count} fichier(s) supprimé(s) de la quarantaine.";
        }

        private void LoadQuarantine()
        {
            WpfApp.Current?.Dispatcher.Invoke(() =>
            {
                QuarantineEntries.Clear();
                foreach (var e in _quarantine.GetEntries())
                    QuarantineEntries.Add(e);
            });
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

        // ── Méthodes publiques pour l'interface ───────────────────────────────────

        public void RefreshQuarantineList()
        {
            LoadQuarantine();
        }

        public void RefreshHistory()
        {
            LoadHistory();
        }

        public QuarantineManager GetQuarantineManager() => _quarantine;
        public ScanLogManager GetLogManager() => _logger;
        public ScanOrchestrator GetOrchestrator() => _orchestrator;
        public FreshclamUpdater GetFreshclamUpdater() => _updater;
        public YaraEngine GetYaraEngine() => _yara;
        public ClamAvEngine GetClamAvEngine() => _clamAv;

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
                _updater.UpdateOutput -= OnUpdateOutput;
                _updater.UpdateCompleted -= OnUpdateCompleted;
                _rulesUpdater.UpdateCompleted -= OnRulesUpdateCompleted;
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