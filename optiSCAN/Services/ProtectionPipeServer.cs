using optiSCAN.Platform;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;

namespace optiSCAN.Services;

/// <summary>Serveur IPC du moteur de protection (mode --service-host / AMSI / UI distante).</summary>
public sealed class ProtectionPipeServer : IDisposable
{
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };

    private readonly ScanOrchestrator _orchestrator;
    private readonly string _pipeName;
    private CancellationTokenSource? _cts;
    private Task? _listenTask;

    public ProtectionPipeServer(ScanOrchestrator orchestrator, string? pipeName = null)
    {
        _orchestrator = orchestrator;
        _pipeName = pipeName ?? ProtectionPipeNames.Protection;
    }

    public void Start()
    {
        if (_listenTask != null)
            return;

        _cts = new CancellationTokenSource();
        _listenTask = Task.Run(() => ListenLoopAsync(_cts.Token));
        AppLogger.Info("ProtectionPipeServer", $"IPC démarré ({_pipeName})");
    }

    public async Task StopAsync()
    {
        if (_cts == null)
            return;

        _cts.Cancel();
        try
        {
            if (_listenTask != null)
                await _listenTask.ConfigureAwait(false);
        }
        catch (OperationCanceledException) { }

        _cts.Dispose();
        _cts = null;
        _listenTask = null;
    }

    private async Task ListenLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            await using var pipe = new NamedPipeServerStream(
                _pipeName,
                PipeDirection.InOut,
                NamedPipeServerStream.MaxAllowedServerInstances,
                PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous);

            try
            {
                await pipe.WaitForConnectionAsync(ct).ConfigureAwait(false);
                await HandleClientAsync(pipe, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("ProtectionPipeServer", "ListenLoop", ex);
                await Task.Delay(250, ct).ConfigureAwait(false);
            }
        }
    }

    private async Task HandleClientAsync(NamedPipeServerStream pipe, CancellationToken ct)
    {
        using var ms = new MemoryStream();
        var buf = new byte[8192];
        while (true)
        {
            var read = await pipe.ReadAsync(buf, ct).ConfigureAwait(false);
            if (read <= 0)
                break;
            ms.Write(buf, 0, read);
        }

        ProtectionPipeResponse response;
        try
        {
            var text = Encoding.UTF8.GetString(ms.ToArray());
            var request = JsonSerializer.Deserialize<ProtectionPipeRequest>(text, JsonOptions)
                ?? throw new InvalidOperationException("Requête IPC vide");
            response = await DispatchAsync(request, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            response = ProtectionPipeResponse.Error(ex.Message);
        }

        var outBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(response, JsonOptions));
        await pipe.WriteAsync(outBytes, ct).ConfigureAwait(false);
        await pipe.FlushAsync(ct).ConfigureAwait(false);
        pipe.WaitForPipeDrain();
    }

    private async Task<ProtectionPipeResponse> DispatchAsync(ProtectionPipeRequest request, CancellationToken ct)
    {
        switch (request.Operation)
        {
            case ProtectionPipeOperations.Ping:
                return ProtectionPipeResponse.SuccessClean();

            case ProtectionPipeOperations.GetStatus:
                return new ProtectionPipeResponse
                {
                    Ok = true,
                    Clean = true,
                    Message = $"clam={_orchestrator.IsClamAvAvailable};yara={_orchestrator.IsYaraAvailable}",
                };

            case ProtectionPipeOperations.Shutdown:
                _ = Task.Run(() => Environment.Exit(0));
                return ProtectionPipeResponse.SuccessClean();

            case ProtectionPipeOperations.ScanPath:
                if (string.IsNullOrWhiteSpace(request.Path) || !File.Exists(request.Path))
                    return ProtectionPipeResponse.Error("Chemin invalide");
                return await ScanPathAsync(request.Path, ct).ConfigureAwait(false);

            case ProtectionPipeOperations.ScanBuffer:
                if (string.IsNullOrWhiteSpace(request.BufferBase64))
                    return ProtectionPipeResponse.Error("Buffer vide");
                return await ScanBufferAsync(request.BufferBase64, request.ContentName ?? "amsi_buffer", ct).ConfigureAwait(false);

            default:
                return ProtectionPipeResponse.Error($"Opération inconnue : {request.Operation}");
        }
    }

    private async Task<ProtectionPipeResponse> ScanPathAsync(string path, CancellationToken ct)
    {
        var result = await _orchestrator.ScanFileAsync(path, ct: ct).ConfigureAwait(false);
        if (result.Threats.Count == 0)
            return ProtectionPipeResponse.SuccessClean();

        var threat = result.Threats[0];
        return ProtectionPipeResponse.Threat(threat.VirusName, threat.DetectedBy);
    }

    private async Task<ProtectionPipeResponse> ScanBufferAsync(string bufferBase64, string contentName, CancellationToken ct)
    {
        var bytes = Convert.FromBase64String(bufferBase64);
        var tempDir = Path.Combine(Path.GetTempPath(), "optiscan_ipc_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        var tempFile = Path.Combine(tempDir, Path.GetFileName(contentName));
        if (string.IsNullOrWhiteSpace(Path.GetFileName(tempFile)))
            tempFile = Path.Combine(tempDir, "amsi_buffer.bin");

        try
        {
            await File.WriteAllBytesAsync(tempFile, bytes, ct).ConfigureAwait(false);
            return await ScanPathAsync(tempFile, ct).ConfigureAwait(false);
        }
        finally
        {
            try { Directory.Delete(tempDir, recursive: true); } catch { }
        }
    }

    public void Dispose() => _ = StopAsync();
}
