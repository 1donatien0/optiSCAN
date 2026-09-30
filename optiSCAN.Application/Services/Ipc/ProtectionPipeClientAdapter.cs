using optiSCAN.IPC;

namespace optiSCAN.Services.Ipc;

/// <summary>Adaptateur DI vers <see cref="ProtectionPipeClient"/>.</summary>
public sealed class ProtectionPipeClientAdapter : IProtectionPipeClient
{
    private readonly ProtectionPipeClient _inner;

    public ProtectionPipeClientAdapter(string? pipeName = null, TimeSpan? timeout = null)
        => _inner = new ProtectionPipeClient(pipeName, timeout);

    public bool IsServiceReachable() => _inner.IsServiceReachable();

    public Task<ProtectionPipeResponse> ScanPathAsync(string path, CancellationToken ct = default) =>
        _inner.ScanPathAsync(path, ct);

    public Task<ProtectionPipeResponse> ScanBufferAsync(ReadOnlyMemory<byte> buffer, string contentName, CancellationToken ct = default) =>
        _inner.ScanBufferAsync(buffer, contentName, ct);

    public Task<ProtectionPipeResponse> GetStatusAsync(CancellationToken ct = default) =>
        _inner.GetStatusAsync(ct);

    public Task RequestShutdownAsync(CancellationToken ct = default) =>
        _inner.RequestShutdownAsync(ct);

    public Task<ProtectionPipeResponse> SendAsync(ProtectionPipeRequest request, CancellationToken ct = default) =>
        _inner.SendAsync(request, ct);

    public void Dispose() => _inner.Dispose();
}
