using optiSCAN.Models;

namespace optiSCAN.Services
{
    // Interfaces principales pour permettre les tests unitaires (mocks) et
    // découpler MainWindow / ScanViewModel des implémentations concrètes.
    //
    // Rationale audit (A1, A3) : ScanViewModel construisait ses propres
    // ClamAvEngine/YaraEngine/FreshclamUpdater via `new`, ET MainWindow
    // construisait les siens en parallèle. Double instanciation, états
    // divergents, tests impossibles. Avec ces interfaces et le ServiceContainer
    // ci-dessous, les services sont singleton et substituables.

    /// <summary>
    /// Moteur de scan antivirus (ClamAV, ou alternatif).
    /// </summary>
    public interface IScanEngine
    {
        bool IsAvailable { get; }
        Task<ScanResult> ScanFileAsync(string filePath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default);
        Task<ScanResult> ScanFolderAsync(string folderPath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default);
        Task<ScanResult> QuickScanAsync(IProgress<ScanProgress>? progress = null, CancellationToken ct = default);
        Task<ScanResult> FullScanAsync(IProgress<ScanProgress>? progress = null, CancellationToken ct = default);
        Task<string> GetVersionAsync();
    }

    /// <summary>
    /// Mise à jour d'un asset versionné (signatures ClamAV, règles YARA...).
    /// </summary>
    public interface IUpdater<TResult>
    {
        bool IsUpdating { get; }
        DateTime? LastUpdateTime { get; }
        event EventHandler<string>? UpdateOutput;
        event EventHandler<TResult>? UpdateCompleted;
        Task<TResult> UpdateAsync(CancellationToken ct = default);
        void EnableAutoUpdate(TimeSpan? interval = null);
        void DisableAutoUpdate();
        void CancelUpdate();
    }

    /// <summary>
    /// Stockage des fichiers en quarantaine.
    /// </summary>
    public interface IThreatStore
    {
        bool Quarantine(ThreatInfo threat);
        int QuarantineAll(IEnumerable<ThreatInfo> threats);
        bool Restore(string quarantineId);
        bool RestoreTo(string quarantineId, string destinationFolder);
        bool DeletePermanently(string quarantineId);
        int PurgeAll();
        IReadOnlyList<QuarantineEntry> GetEntries();
        int Count { get; }
        long TotalSize { get; }
    }

    /// <summary>
    /// Adaptation de la classe concrète ClamAvEngine en IScanEngine.
    /// L'interface IScanEngine ne contient pas de propriété IsClamAvInstalled
    /// (spécifique ClamAV) — on expose IsAvailable comme proxy.
    /// </summary>
    public sealed class ClamAvScanEngineAdapter : IScanEngine
    {
        private readonly ClamAvEngine _engine;
        public ClamAvScanEngineAdapter(ClamAvEngine engine) => _engine = engine;

        public bool IsAvailable => _engine.IsClamAvInstalled();

        public Task<ScanResult> ScanFileAsync(string filePath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default)
            => _engine.ScanFileAsync(filePath, progress, ct);

        public Task<ScanResult> ScanFolderAsync(string folderPath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default)
            => _engine.ScanFolderAsync(folderPath, progress, ct);

        public Task<ScanResult> QuickScanAsync(IProgress<ScanProgress>? progress = null, CancellationToken ct = default)
            => _engine.QuickScanAsync(progress, ct);

        public Task<ScanResult> FullScanAsync(IProgress<ScanProgress>? progress = null, CancellationToken ct = default)
            => _engine.FullScanAsync(progress, ct);

        public Task<string> GetVersionAsync() => _engine.GetVersionAsync();
    }
}
