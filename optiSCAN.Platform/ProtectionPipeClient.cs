using System.IO.Pipes;
using System.Text;
using System.Text.Json;

namespace optiSCAN.Platform;

/// <summary>Client IPC vers le moteur de protection (service / --service-host).</summary>
public sealed class ProtectionPipeClient : IDisposable
{
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };
    private readonly string _pipeName;
    private readonly TimeSpan _timeout;

    public ProtectionPipeClient(string? pipeName = null, TimeSpan? timeout = null)
    {
        _pipeName = pipeName ?? ProtectionPipeNames.Protection;
        _timeout = timeout ?? TimeSpan.FromSeconds(30);
    }

    public bool IsServiceReachable()
    {
        try
        {
            var response = SendAsync(new ProtectionPipeRequest { Operation = ProtectionPipeOperations.Ping })
                .GetAwaiter().GetResult();
            return response.Ok;
        }
        catch
        {
            return false;
        }
    }

    public Task<ProtectionPipeResponse> ScanPathAsync(string path, CancellationToken ct = default) =>
        SendAsync(new ProtectionPipeRequest { Operation = ProtectionPipeOperations.ScanPath, Path = path }, ct);

    public Task<ProtectionPipeResponse> ScanBufferAsync(ReadOnlyMemory<byte> buffer, string contentName, CancellationToken ct = default)
    {
        var request = new ProtectionPipeRequest
        {
            Operation = ProtectionPipeOperations.ScanBuffer,
            BufferBase64 = Convert.ToBase64String(buffer.Span),
            ContentName = contentName,
        };
        return SendAsync(request, ct);
    }

    public Task<ProtectionPipeResponse> GetStatusAsync(CancellationToken ct = default) =>
        SendAsync(new ProtectionPipeRequest { Operation = ProtectionPipeOperations.GetStatus }, ct);

    public Task<ProtectionPipeResponse> GetServiceQuarantineSummaryAsync(CancellationToken ct = default) =>
        SendAsync(new ProtectionPipeRequest { Operation = ProtectionPipeOperations.QuarantineSummary }, ct);

    public Task<ProtectionPipeResponse> ListServiceQuarantineAsync(CancellationToken ct = default) =>
        SendAsync(new ProtectionPipeRequest { Operation = ProtectionPipeOperations.QuarantineList }, ct);

    public Task<ProtectionPipeResponse> RestoreServiceQuarantineAsync(string id, string? destinationFolder = null, CancellationToken ct = default) =>
        SendAsync(new ProtectionPipeRequest
        {
            Operation = ProtectionPipeOperations.QuarantineRestore,
            QuarantineId = id,
            DestinationFolder = destinationFolder,
        }, ct);

    public Task<ProtectionPipeResponse> DeleteServiceQuarantineAsync(string id, CancellationToken ct = default) =>
        SendAsync(new ProtectionPipeRequest { Operation = ProtectionPipeOperations.QuarantineDelete, QuarantineId = id }, ct);

    public Task<ProtectionPipeResponse> GetRecentDetectionsAsync(long sinceSequence, CancellationToken ct = default) =>
        SendAsync(new ProtectionPipeRequest { Operation = ProtectionPipeOperations.RecentDetections, SinceSequence = sinceSequence }, ct);

    public Task<ProtectionPipeResponse> PurgeServiceQuarantineAsync(CancellationToken ct = default) =>
        SendAsync(new ProtectionPipeRequest { Operation = ProtectionPipeOperations.QuarantinePurge }, ct);

    public async Task RequestShutdownAsync(CancellationToken ct = default)
    {
        if (!ProtectionPipeShutdownToken.TryRead(out var token))
            return;

        try
        {
            await SendAsync(new ProtectionPipeRequest
            {
                Operation = ProtectionPipeOperations.Shutdown,
                AuthToken = token,
            }, ct).ConfigureAwait(false);
        }
        catch { /* service en cours d'arrêt */ }
    }

    public async Task<ProtectionPipeResponse> SendAsync(ProtectionPipeRequest request, CancellationToken ct = default)
    {
        await using var pipe = new NamedPipeClientStream(
            ".",
            _pipeName,
            PipeDirection.InOut,
            PipeOptions.Asynchronous,
            System.Security.Principal.TokenImpersonationLevel.Impersonation);

        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
        linked.CancelAfter(_timeout);
        await pipe.ConnectAsync(linked.Token).ConfigureAwait(false);
        if (!PipeServerTrust.IsTrusted(pipe.SafePipeHandle))
            return ProtectionPipeResponse.Error("Serveur IPC non reconnu");

        request.ProtocolVersion ??= ProtectionIdentifiers.ProtocolVersion;
        var payload = JsonSerializer.Serialize(request, JsonOptions);
        var bytes = Encoding.UTF8.GetBytes(payload);
        await pipe.WriteAsync(bytes, linked.Token).ConfigureAwait(false);
        await pipe.FlushAsync(linked.Token).ConfigureAwait(false);

        var text = await ProtectionPipeJsonFraming.ReadJsonPayloadAsync(pipe, linked.Token).ConfigureAwait(false);
        return JsonSerializer.Deserialize<ProtectionPipeResponse>(text, JsonOptions)
            ?? ProtectionPipeResponse.Error("Réponse IPC invalide");
    }

    /// <summary>
    /// Rien à libérer : chaque requête ouvre son propre pipe et le ferme
    /// (<c>await using</c> dans <see cref="SendAsync"/>).
    /// </summary>
    public void Dispose()
    {
    }
}
