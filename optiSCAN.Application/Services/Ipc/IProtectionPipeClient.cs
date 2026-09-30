using optiSCAN.IPC;

namespace optiSCAN.Services.Ipc;

/// <summary>Abstraction du client pipe IPC (implémentation dans <see cref="optiSCAN.IPC.ProtectionPipeClient"/>).</summary>
public interface IProtectionPipeClient : IDisposable
{
    bool IsServiceReachable();

    Task<ProtectionPipeResponse> ScanPathAsync(string path, CancellationToken ct = default);

    Task<ProtectionPipeResponse> ScanBufferAsync(ReadOnlyMemory<byte> buffer, string contentName, CancellationToken ct = default);

    Task<ProtectionPipeResponse> GetStatusAsync(CancellationToken ct = default);

    Task RequestShutdownAsync(CancellationToken ct = default);

    Task<ProtectionPipeResponse> SendAsync(ProtectionPipeRequest request, CancellationToken ct = default);
}
