namespace optiSCAN.Services;

/// <summary>
/// Limite le débit des opérations <c>scan_path</c> / <c>scan_buffer</c> sur le pipe IPC
/// (anti-DoS local — le pipe reste accessible aux utilisateurs authentifiés pour l'AMSI).
/// </summary>
public sealed class IpcScanRateLimiter
{
    public const int DefaultMaxScansPerMinute = 120;
    public const int DefaultMaxConcurrentScans = 4;

    private readonly int _maxPerMinute;
    private readonly SemaphoreSlim _concurrency;
    private readonly Queue<DateTime> _recent = new();
    private readonly object _lock = new();

    public IpcScanRateLimiter(
        int maxPerMinute = DefaultMaxScansPerMinute,
        int maxConcurrent = DefaultMaxConcurrentScans)
    {
        _maxPerMinute = maxPerMinute;
        _concurrency = new SemaphoreSlim(maxConcurrent, maxConcurrent);
    }

    /// <summary>Tente d'acquérir un slot ; libérer le lease après le scan.</summary>
    public bool TryEnter(out IDisposable? lease)
    {
        lease = null;
        if (!_concurrency.Wait(0))
            return false;

        lock (_lock)
        {
            var now = DateTime.UtcNow;
            TrimOlderThanOneMinute(now);
            if (_recent.Count >= _maxPerMinute)
            {
                _concurrency.Release();
                return false;
            }

            _recent.Enqueue(now);
        }

        lease = new Lease(_concurrency);
        return true;
    }

    private void TrimOlderThanOneMinute(DateTime now)
    {
        while (_recent.Count > 0 && now - _recent.Peek() > TimeSpan.FromMinutes(1))
            _recent.Dequeue();
    }

    private sealed class Lease(SemaphoreSlim concurrency) : IDisposable
    {
        private int _released;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _released, 1) != 0)
                return;
            concurrency.Release();
        }
    }
}
