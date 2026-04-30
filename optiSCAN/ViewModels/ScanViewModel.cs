using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using optiSCAN.Models;
using optiSCAN.Services;
using WpfApp = System.Windows.Application;

namespace optiSCAN.ViewModels
{
    /// <summary>
    /// ViewModel principal de la fenêtre de scan optiSCAN.
    /// Utilise ScanOrchestrator pour le pipeline ClamAV + YARA en parallèle.
    /// </summary>
    public class ScanViewModel : INotifyPropertyChanged
    {
        // ── Services ─────────────────────────────────────────────────────────────
        private readonly ScanOrchestrator  _orchestrator;
        private readonly ClamAvEngine      _clamAv;      // accès direct pour version/freshclam
        private readonly FreshclamUpdater  _updater;
        private readonly YaraForgeUpdater  _rulesUpdater;
        private readonly QuarantineManager _quarantine;
        private readonly ScanLogManager    _logger;
        private readonly YaraEngine        _yara;

        private CancellationTokenSource? _cts;

        // ── Propriétés bindées ───────────────────────────────────────────────────

        private bool _isScanning;
        public bool IsScanning
        {
            get => _isScanning;
            set { _isScanning = value; OnPropertyChanged();
                  OnPropertyChanged(nameof(CanScan)); OnPropertyChanged(nameof(CanStop)); }
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

        private string _yaraStatus = "YARA : vérification…";
        public string YaraStatus
        {
            get => _yaraStatus;
            set { _yaraStatus = value; OnPropertyChanged(); }
        }

        private ScanResult? _lastResult;
        public ScanResult? LastResult
        {
            get => _lastResult;
            set { _lastResult = value; OnPropertyChanged(); OnPropertyChanged(nameof(SummaryDisplay)); }
        }

        public string SummaryDisplay => _lastResult?.SummaryDisplay ?? string.Empty;

        private string _updateLog = string.Empty;
        public string UpdateLog
        {
            get => _updateLog;
            set { _updateLog = value; OnPropertyChanged(); }
        }

        // ── Collections ──────────────────────────────────────────────────────────

        public ObservableCollection<ThreatInfo>    Threats          { get; } = new();
        public ObservableCollection<ScanSession>   History          { get; } = new();
        public ObservableCollection<QuarantineEntry> QuarantineEntries { get; } = new();

        // ── Commandes ────────────────────────────────────────────────────────────

        public bool CanScan => !IsScanning;
        public bool CanStop => IsScanning;

        public ICommand QuickScanCommand      { get; }
        public ICommand FullScanCommand       { get; }
        public ICommand ScanFolderCommand     { get; }
        public ICommand ScanFileCommand       { get; }
        public ICommand StopScanCommand       { get; }
        public ICommand UpdateDbCommand       { get; }
        public ICommand QuarantineAllCommand  { get; }
        public ICommand RestoreFileCommand    { get; }
        public ICommand DeleteFileCommand     { get; }
        public ICommand PurgeQuarantineCommand{ get; }
        public ICommand EicarTestCommand      { get; }

        // ── Constructeur ─────────────────────────────────────────────────────────

        public ScanViewModel()
        {
            _clamAv       = new ClamAvEngine();
            _yara         = new YaraEngine();
            _orchestrator  = new ScanOrchestrator(_clamAv, _yara);
            _updater      = new FreshclamUpdater();
            _rulesUpdater = new YaraForgeUpdater();
            _quarantine   = new QuarantineManager();
            _logger       = new ScanLogManager();

            _updater.UpdateOutput    += OnUpdateOutput;
            _updater.UpdateCompleted += OnUpdateCompleted;
            _rulesUpdater.UpdateOutput    += (_, msg) => OnUpdateOutput(_, msg);
            _rulesUpdater.UpdateCompleted += OnRulesUpdateCompleted;

            QuickScanCommand       = new AsyncRelayCommand(async _ => await StartScanAsync(ScanType.QuickScan));
            FullScanCommand        = new AsyncRelayCommand(async _ => await StartScanAsync(ScanType.FullScan));
            ScanFolderCommand      = new AsyncRelayCommand(async p => await StartScanAsync(ScanType.Folder, p as string));
            ScanFileCommand        = new AsyncRelayCommand(async p => await StartScanAsync(ScanType.File, p as string));
            StopScanCommand        = new RelayCommand(_ => _cts?.Cancel(), _ => IsScanning);
            UpdateDbCommand        = new AsyncRelayCommand(async _ => await UpdateDatabaseAsync());
            QuarantineAllCommand   = new RelayCommand(_ => QuarantineAllThreats(), _ => Threats.Count > 0);
            RestoreFileCommand     = new RelayCommand(p => RestoreFromQuarantine(p as string));
            DeleteFileCommand      = new RelayCommand(p => DeleteFromQuarantine(p as string));
            PurgeQuarantineCommand = new RelayCommand(_ => PurgeAll(), _ => QuarantineEntries.Count > 0);
            EicarTestCommand       = new AsyncRelayCommand(async _ => await RunEicarTestAsync(), _ => CanScan);

            _ = InitializeAsync();
        }

        // ── Initialisation ────────────────────────────────────────────────────────

        private async Task InitializeAsync()
        {
            // Version ClamAV
            ClamAvVersion = await _clamAv.GetVersionAsync();

            // Statut base de signatures
            DbVersion          = _updater.GetLocalDatabaseVersion();
            LastUpdateDisplay  = _updater.LastUpdateTime?.ToString("dd/MM/yyyy HH:mm") ?? "Jamais";

            // Statut YARA
            YaraStatus = _yara.IsAvailable
                ? $"YARA opérationnel — {_yara.RulesCount} règle(s)"
                : "YARA non disponible (yara64.exe manquant ou aucune règle)";

            LoadHistory();
            LoadQuarantine();

            if (!_clamAv.IsClamAvInstalled())
                StatusMessage = "⚠ ClamAV non détecté. Vérifiez 'clamav/x64/' dans le dossier de l'application.";
            else
                StatusMessage = "Prêt — pipeline ClamAV + YARA actif.";
        }

        // ── Scans ─────────────────────────────────────────────────────────────────

        private async Task StartScanAsync(ScanType type, string? path = null)
        {
            if (IsScanning) return;

            IsScanning      = true;
            IsIndeterminate = true;
            FilesScanned    = 0;
            ThreatsFound    = 0;

            WpfApp.Current?.Dispatcher.Invoke(() => Threats.Clear());

            StatusMessage = type switch
            {
                ScanType.QuickScan => "Scan rapide en cours (ClamAV + YARA)…",
                ScanType.FullScan  => "Scan complet en cours (ClamAV + YARA)…",
                ScanType.Folder    => $"Scan du dossier : {path}",
                ScanType.File      => $"Scan du fichier : {System.IO.Path.GetFileName(path ?? "")}",
                _                  => "Scan en cours…"
            };

            _cts = new CancellationTokenSource();
            var progress = new Progress<ScanProgress>(OnScanProgress);

            try
            {
                ScanResult result = type switch
                {
                    ScanType.QuickScan => await _orchestrator.QuickScanAsync(progress, _cts.Token),
                    ScanType.FullScan  => await _orchestrator.FullScanAsync(progress, _cts.Token),
                    ScanType.Folder    => await _orchestrator.ScanFolderAsync(path!, progress, _cts.Token),
                    ScanType.File      => await _orchestrator.ScanFileAsync(path!, progress, _cts.Token),
                    _                  => throw new InvalidOperationException()
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
            }
            catch (Exception ex)
            {
                StatusMessage = $"Erreur : {ex.Message}";
            }
            finally
            {
                IsScanning      = false;
                IsIndeterminate = false;
                ProgressValue   = 0;
                _cts?.Dispose();
                _cts = null;
            }
        }

        // ── Test EICAR ────────────────────────────────────────────────────────────

        private async Task RunEicarTestAsync()
        {
            if (IsScanning) return;

            IsScanning      = true;
            IsIndeterminate = true;
            FilesScanned    = 0;
            ThreatsFound    = 0;
            WpfApp.Current?.Dispatcher.Invoke(() => Threats.Clear());
            StatusMessage = "Test EICAR en cours…";

            _cts = new CancellationTokenSource();
            var progress = new Progress<ScanProgress>(OnScanProgress);

            try
            {
                var result = await _orchestrator.RunEicarTestAsync(progress, _cts.Token);
                LastResult = result;

                WpfApp.Current?.Dispatcher.Invoke(() =>
                {
                    foreach (var t in result.Threats)
                        Threats.Add(t);
                });

                if (result.ThreatsFound > 0)
                {
                    var detectedBy = result.Threats[0].DetectedBy;
                    StatusMessage = $"✅ Test EICAR réussi — détecté par {detectedBy} " +
                                    $"({result.ThreatsFound} alerte(s))";
                }
                else
                {
                    StatusMessage = "⚠ Test EICAR : aucune détection. " +
                                    "Vérifiez que la base ClamAV est téléchargée et que les règles YARA sont présentes.";
                }
            }
            catch (Exception ex)
            {
                StatusMessage = $"Erreur test EICAR : {ex.Message}";
            }
            finally
            {
                IsScanning      = false;
                IsIndeterminate = false;
                ProgressValue   = 0;
                _cts?.Dispose();
                _cts = null;
            }
        }

        // ── Progression ───────────────────────────────────────────────────────────

        private void OnScanProgress(ScanProgress p)
        {
            WpfApp.Current?.Dispatcher.Invoke(() =>
            {
                StatusMessage = p.Message;
                FilesScanned  = p.FilesScanned;
                ThreatsFound  = p.ThreatsFound;

                if (p.Phase == ScanPhase.ThreatFound && p.ThreatInfo != null)
                    Threats.Add(p.ThreatInfo);
            });
        }

        // ── Mise à jour base de signatures ────────────────────────────────────────

        private async Task UpdateDatabaseAsync()
        {
            if (IsUpdating) return;
            IsUpdating    = true;
            UpdateLog     = string.Empty;
            StatusMessage = "Mise à jour des signatures en cours…";

            // ── 1. Mise à jour des signatures ClamAV ──────────────────────────
            var clamResult = await _updater.UpdateAsync();

            DbVersion         = _updater.GetLocalDatabaseVersion();
            LastUpdateDisplay = DateTime.Now.ToString("dd/MM/yyyy HH:mm");

            // ── 2. Mise à jour des règles de détection comportementale ─────────
            StatusMessage = "Mise à jour des règles de détection en cours…";

            var rulesProgress = new Progress<string>(msg =>
                WpfApp.Current?.Dispatcher.Invoke(() =>
                {
                    UpdateLog    += msg + "\n";
                    StatusMessage = msg;
                }));

            var rulesResult = await _rulesUpdater.UpdateAsync(rulesProgress);

            // Rafraîchir le statut du moteur de détection
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

            UpdateLog += "\n" + summary;
            IsUpdating = false;
        }

        private void OnUpdateOutput(object? sender, string line)
            => WpfApp.Current?.Dispatcher.Invoke(() => UpdateLog += line + "\n");

        private void OnUpdateCompleted(object? sender, UpdateResult result)
            => WpfApp.Current?.Dispatcher.Invoke(() =>
            {
                StatusMessage = result.Message;
                DbVersion     = _updater.GetLocalDatabaseVersion();
            });

        private void OnRulesUpdateCompleted(object? sender, RulesUpdateResult result)
            => WpfApp.Current?.Dispatcher.Invoke(() =>
            {
                if (!result.AlreadyUpToDate && result.Success)
                {
                    YaraStatus = _yara.IsAvailable
                        ? $"Moteur de détection actif — {_yara.RulesCount} règle(s)"
                        : "Moteur de détection : règles mises à jour (rechargement au prochain scan)";
                }
            });

        // ── Quarantaine ───────────────────────────────────────────────────────────

        private void QuarantineAllThreats()
        {
            int count = _quarantine.QuarantineAll(Threats);
            LoadQuarantine();
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

        // ── INotifyPropertyChanged ────────────────────────────────────────────────

        public event PropertyChangedEventHandler? PropertyChanged;
        protected void OnPropertyChanged([CallerMemberName] string? name = null)
            => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }

    // ── Helpers de commande ──────────────────────────────────────────────────────

    public class RelayCommand : ICommand
    {
        private readonly Action<object?> _execute;
        private readonly Func<object?, bool>? _canExecute;

        public RelayCommand(Action<object?> execute, Func<object?, bool>? canExecute = null)
        {
            _execute    = execute;
            _canExecute = canExecute;
        }

        public bool CanExecute(object? parameter) => _canExecute?.Invoke(parameter) ?? true;
        public void Execute(object? parameter) => _execute(parameter);

        public event EventHandler? CanExecuteChanged
        {
            add    => CommandManager.RequerySuggested += value;
            remove => CommandManager.RequerySuggested -= value;
        }
    }

    public class AsyncRelayCommand : ICommand
    {
        private readonly Func<object?, Task> _execute;
        private readonly Func<object?, bool>? _canExecute;
        private bool _isRunning;

        public AsyncRelayCommand(Func<object?, Task> execute, Func<object?, bool>? canExecute = null)
        {
            _execute    = execute;
            _canExecute = canExecute;
        }

        public bool CanExecute(object? parameter)
            => !_isRunning && (_canExecute?.Invoke(parameter) ?? true);

        public async void Execute(object? parameter)
        {
            _isRunning = true;
            CommandManager.InvalidateRequerySuggested();
            try { await _execute(parameter); }
            finally
            {
                _isRunning = false;
                CommandManager.InvalidateRequerySuggested();
            }
        }

        public event EventHandler? CanExecuteChanged
        {
            add    => CommandManager.RequerySuggested += value;
            remove => CommandManager.RequerySuggested -= value;
        }
    }
}
