namespace optiSCAN.Services;

/// <summary>Limite le débit des opérations de scan IPC (anti-DoS local sur le pipe).</summary>
public sealed class IpcScanRateLimiter
{
    private readonly int _maxPerMinute;
    private readonly int _maxConcurrent;
    private int _concurrent;
    private readonly Queue<DateTime> _window = new();
    private readonly object _gate = new();

    public IpcScanRateLimiter(int maxPerMinute = 60, int maxConcurrent = 4)
    {
        _maxPerMinute = Math.Max(1, maxPerMinute);
        _maxConcurrent = Math.Max(1, maxConcurrent);
    }

    public bool TryEnter(out IDisposable? lease)
    {
        lock (_gate)
        {
            PruneExpired();
            if (_concurrent >= _maxConcurrent || _window.Count >= _maxPerMinute)
            {
                lease = null;
                return false;
            }

            _concurrent++;
            _window.Enqueue(DateTime.UtcNow);
            lease = new Lease(this);
            return true;
        }
    }

    private void Release()
    {
        lock (_gate)
            _concurrent = Math.Max(0, _concurrent - 1);
    }

    private void PruneExpired()
    {
        var cutoff = DateTime.UtcNow.AddMinutes(-1);
        while (_window.Count > 0 && _window.Peek() < cutoff)
            _window.Dequeue();
    }

    private sealed class Lease(IpcScanRateLimiter owner) : IDisposable
    {
        private int _disposed;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
                return;
            owner.Release();
        }
    }
}
