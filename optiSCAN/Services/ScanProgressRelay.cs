using optiSCAN.Models;

namespace optiSCAN.Services
{
    /// <summary>
    /// Normalise les événements <see cref="ScanProgress"/> pour un cumul monotone :
    /// baseline multi-cibles, max ClamAV/YARA, masquage des totaux locaux trompeurs.
    /// </summary>
    internal sealed class ScanProgressRelay
    {
        private readonly int _baseline;
        private int _filesHigh;
        private int _threatsHigh;

        public ScanProgressRelay(int filesBaseline = 0)
        {
            _baseline = Math.Max(0, filesBaseline);
            _filesHigh = _baseline;
        }

        public int FilesScannedHigh => _filesHigh;

        public IProgress<ScanProgress>? ToParent(IProgress<ScanProgress>? parent)
        {
            if (parent == null)
                return null;

            return new RelayProgress(parent, this);
        }

        internal ScanProgress Normalize(ScanProgress p)
        {
            int files = ResolveFilesScanned(p.FilesScanned);
            _filesHigh = Math.Max(_filesHigh, files);

            if (p.ThreatsFound > 0)
                _threatsHigh = Math.Max(_threatsHigh, p.ThreatsFound);

            var r = p.Clone();
            r.FilesScanned = _filesHigh;
            if (_threatsHigh > 0)
                r.ThreatsFound = Math.Max(r.ThreatsFound, _threatsHigh);

            if (r.TotalFiles > 0 && r.FilesScanned > r.TotalFiles)
                r.TotalFiles = 0;

            r.Message = ScanUserDisplay.SyncFileCountInMessage(p.Message, _filesHigh);
            return r;
        }

        private int ResolveFilesScanned(int localFilesScanned)
        {
            if (localFilesScanned > 0)
                return _baseline + localFilesScanned;

            return _filesHigh > _baseline ? _filesHigh : _baseline;
        }

        private sealed class RelayProgress(IProgress<ScanProgress> parent, ScanProgressRelay relay) : IProgress<ScanProgress>
        {
            public void Report(ScanProgress value) => parent.Report(relay.Normalize(value));
        }
    }
}
