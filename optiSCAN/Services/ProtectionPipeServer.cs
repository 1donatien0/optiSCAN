using optiSCAN.Platform;
using System.IO;
using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;

namespace optiSCAN.Services;

/// <summary>Serveur IPC du moteur de protection (mode --service-host / AMSI / UI distante).</summary>
[SupportedOSPlatform("windows")]
public sealed class ProtectionPipeServer : IDisposable
{
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };

    // Borne anti-DoS : le pipe est accessible aux utilisateurs authentifiés (cf. ProtectionPipeAcl).
    // La requête entière est déjà plafonnée par le cadrage JSON (ProtectionPipeJsonFraming, 1 Mo) :
    // un buffer base64 ne peut donc pas dépasser cette taille. La borne est alignée dessus.
    internal const int MaxScanBufferBase64Length = ProtectionPipeJsonFraming.DefaultMaxBytes;

    /// <summary>Temps maximal pour recevoir une requête complète.</summary>
    private static readonly TimeSpan RequestReadTimeout = TimeSpan.FromSeconds(10);

    /// <summary>Temps maximal pour écrire la réponse.</summary>
    private static readonly TimeSpan ResponseWriteTimeout = TimeSpan.FromSeconds(10);

    private readonly ScanOrchestrator _orchestrator;
    private readonly IpcScanRateLimiter _scanRateLimiter;
    private readonly string _pipeName;
    private readonly string? _shutdownTokenOverride;
    private readonly Action? _onShutdown;
    private readonly ServiceQuarantineAdmin? _quarantineAdmin;
    private string? _shutdownToken;
    private CancellationTokenSource? _cts;
    private Task? _listenTask;

    public ProtectionPipeServer(
        ScanOrchestrator orchestrator,
        string? pipeName = null,
        string? shutdownToken = null,
        Action? onShutdown = null,
        IpcScanRateLimiter? scanRateLimiter = null,
        QuarantineManager? serviceQuarantine = null)
    {
        _quarantineAdmin = serviceQuarantine == null ? null : new ServiceQuarantineAdmin(serviceQuarantine);
        _orchestrator = orchestrator;
        _scanRateLimiter = scanRateLimiter ?? new IpcScanRateLimiter();
        _pipeName = pipeName ?? ProtectionPipeNames.Protection;
        _shutdownTokenOverride = shutdownToken;
        _onShutdown = onShutdown;
    }

    public void Start()
    {
        if (_listenTask != null)
            return;

        _shutdownToken = _shutdownTokenOverride ?? ProtectionPipeShutdownToken.Generate();
        try { ProtectionPipeShutdownToken.Persist(_shutdownToken); }
        catch (Exception ex) { AppLogger.Warn("ProtectionPipeServer", "Persist shutdown token", ex); }

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
        var first = true;
        var createFailures = 0;
        var inflight = new List<Task>();
        while (!ct.IsCancellationRequested)
        {
            NamedPipeServerStream pipe;
            try
            {
                pipe = ProtectionPipeAcl.CreateListeningStream(_pipeName, first);
                first = false;
            }
            catch (Exception ex)
            {
                // Nom pris par un autre processus, ou ressource momentanément refusée :
                // réessayer plutôt que d'abandonner l'IPC jusqu'à la prochaine relance.
                createFailures++;
                AppLogger.Warn("ProtectionPipeServer", $"Création du pipe refusée (essai {createFailures})", ex);
                var wait = TimeSpan.FromSeconds(Math.Min(30, 1 << Math.Min(createFailures, 5)));
                try { await Task.Delay(wait, ct).ConfigureAwait(false); }
                catch (OperationCanceledException) { break; }
                continue;
            }

            createFailures = 0;

            try
            {
                await pipe.WaitForConnectionAsync(ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                await DisposePipeAsync(pipe).ConfigureAwait(false);
                break;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("ProtectionPipeServer", "ListenLoop", ex);
                await DisposePipeAsync(pipe).ConfigureAwait(false);
                try { await Task.Delay(250, ct).ConfigureAwait(false); }
                catch (OperationCanceledException) { break; }
                continue;
            }

            var accepted = pipe;
            var account = NamedPipeClientAccess.GetClientAccount(accepted);
            if (!TryReserveClientSlot(account))
            {
                // Ce compte occupe déjà ses places : refus immédiat, sans lire sa requête.
                // Les autres comptes (et le service lui-même) gardent les leurs.
                inflight.Add(RejectBusyAsync(accepted, ct));
            }
            else
            {
                inflight.Add(HandleAndDisposeAsync(accepted, account, ct));
            }

            inflight.RemoveAll(t => t.IsCompleted);
            if (inflight.Count >= MaxConcurrentClients)
                await Task.WhenAny(inflight).ConfigureAwait(false);
        }

        try { await Task.WhenAll(inflight).ConfigureAwait(false); }
        catch (Exception ex) { AppLogger.Debug("ProtectionPipeServer", $"Fin d'écoute : {ex.Message}"); }
    }

    private async Task HandleAndDisposeAsync(NamedPipeServerStream pipe, string account, CancellationToken ct)
    {
        try
        {
            await HandleClientAsync(pipe, account, ct).ConfigureAwait(false);
        }
        finally
        {
            ReleaseClientSlot(account);
            await DisposePipeAsync(pipe).ConfigureAwait(false);
        }
    }

    private static async Task RejectBusyAsync(NamedPipeServerStream pipe, CancellationToken ct)
    {
        try
        {
            var busy = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(
                ProtectionPipeResponse.Error("Trop de requêtes simultanées pour ce compte"), JsonOptions));
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
            deadline.CancelAfter(TimeSpan.FromSeconds(1));
            await pipe.WriteAsync(busy, deadline.Token).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            AppLogger.Debug("ProtectionPipeServer", "Refus client occupé : " + ex.Message);
        }
        finally
        {
            await DisposePipeAsync(pipe).ConfigureAwait(false);
        }
    }

    /// <summary>Places d'écoute au total ; chaque compte n'en prend que <see cref="MaxConcurrentPerAccount"/>.</summary>
    internal const int MaxConcurrentClients = 16;

    /// <summary>Un compte (hors SYSTEM) ne peut occuper que ces places à la fois.</summary>
    internal const int MaxConcurrentPerAccount = 2;

    private readonly Dictionary<string, int> _slotsByAccount = new(StringComparer.Ordinal);
    private readonly Dictionary<string, IpcScanRateLimiter> _limitersByAccount = new(StringComparer.Ordinal);

    internal bool TryReserveClientSlot(string account)
    {
        lock (_slotsByAccount)
        {
            _slotsByAccount.TryGetValue(account, out var used);
            var exempt = account is NamedPipeClientAccess.SystemAccount or NamedPipeClientAccess.SelfAccount;
            if (!exempt && used >= MaxConcurrentPerAccount)
                return false;
            _slotsByAccount[account] = used + 1;
            return true;
        }
    }

    internal void ReleaseClientSlot(string account)
    {
        lock (_slotsByAccount)
        {
            if (!_slotsByAccount.TryGetValue(account, out var used))
                return;
            if (used <= 1)
                _slotsByAccount.Remove(account);
            else
                _slotsByAccount[account] = used - 1;
        }
    }

    /// <summary>Débit de scan par compte : la moitié du plafond global, pour qu'un compte ne l'épuise pas seul.</summary>
    private IpcScanRateLimiter LimiterFor(string account)
    {
        lock (_limitersByAccount)
        {
            if (!_limitersByAccount.TryGetValue(account, out var limiter))
            {
                limiter = new IpcScanRateLimiter(maxPerMinute: 30, maxConcurrent: 2);
                _limitersByAccount[account] = limiter;
            }

            return limiter;
        }
    }

    private static async Task DisposePipeAsync(NamedPipeServerStream pipe)
    {
        try
        {
            if (pipe.IsConnected)
                pipe.Disconnect();
        }
        catch (Exception ex) { AppLogger.Debug("ProtectionPipeServer", $"Pipe disconnect: {ex.Message}"); }
        await pipe.DisposeAsync().ConfigureAwait(false);
    }

    private async Task HandleClientAsync(NamedPipeServerStream pipe, string account, CancellationToken ct)
    {
        ProtectionPipeResponse response;
        try
        {
            // Délai global : un client qui envoie un octet toutes les quelques secondes
            // ne garde pas une des places d'écoute indéfiniment.
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
            deadline.CancelAfter(RequestReadTimeout);
            var text = await ProtectionPipeJsonFraming.ReadJsonPayloadAsync(pipe, deadline.Token).ConfigureAwait(false);
            var request = JsonSerializer.Deserialize<ProtectionPipeRequest>(text, JsonOptions)
                ?? throw new InvalidOperationException("Requête IPC vide");
            response = Dispatch(request, pipe, account);
        }
        catch (Exception ex)
        {
            AppLogger.Warn("ProtectionPipeServer", "Requête IPC", ex);
            response = ProtectionPipeResponse.Error("Requête refusée");
        }

        var outBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(response, JsonOptions));
        // Un client qui ne lit pas sa réponse ne garde pas une place d'écoute indéfiniment.
        using var writeDeadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        writeDeadline.CancelAfter(ResponseWriteTimeout);
        try
        {
            await pipe.WriteAsync(outBytes, writeDeadline.Token).ConfigureAwait(false);
            await pipe.FlushAsync(writeDeadline.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            AppLogger.Debug("ProtectionPipeServer", "Réponse abandonnée : le client ne lit pas");
        }
    }

    private ProtectionPipeResponse Dispatch(ProtectionPipeRequest request, NamedPipeServerStream pipe, string account)
    {
        // Client absent du champ "proto" = client historique (v1). Un client plus récent que le
        // serveur est refusé explicitement plutôt que mal interprété.
        var clientProto = request.ProtocolVersion ?? 1;
        if (clientProto < 1 || clientProto > ProtectionIdentifiers.ProtocolVersion)
            return ProtectionPipeResponse.Error($"Protocole IPC non supporté : {clientProto} (serveur : {ProtectionIdentifiers.ProtocolVersion})");

        switch (request.Operation)
        {
            case ProtectionPipeOperations.Ping:
                return ProtectionPipeResponse.SuccessClean();

            case ProtectionPipeOperations.SetPolicy:
                // Un compte standard peut renforcer la protection (activer) ; la réduire, ou
                // toucher à la quarantaine automatique, exige SYSTEM ou un administrateur élevé.
                // L'interface relance alors une instance élevée (--push-host-policy).
                if (!HostPolicyStore.IsStrengtheningOnly(request)
                    && !NamedPipeClientAccess.IsElevatedAdministrator(pipe))
                    return ProtectionPipeResponse.Error("Non autorisé");
                return HostPolicyStore.TryApply(request);

            case ProtectionPipeOperations.GetStatus:
                return new ProtectionPipeResponse
                {
                    Ok = true,
                    Clean = true,
                    Message = $"clam={_orchestrator.IsClamAvAvailable};yara={_orchestrator.IsYaraAvailable}",
                };

            case ProtectionPipeOperations.Shutdown:
                if (!ProtectionPipeShutdownToken.Validate(_shutdownToken, request.AuthToken))
                    return ProtectionPipeResponse.Error("Non autorisé");
                if (_onShutdown != null)
                    _onShutdown();
                else
                    _ = Task.Run(() => Environment.Exit(0));
                return ProtectionPipeResponse.SuccessClean();

            case ProtectionPipeOperations.ScanPath:
                if (string.IsNullOrWhiteSpace(request.Path))
                    return ProtectionPipeResponse.Error("Chemin invalide");
                string fullPath;
                try { fullPath = Path.GetFullPath(request.Path); }
                catch { return ProtectionPipeResponse.Error("Chemin invalide"); }
                if (QuarantineManager.IsSensitivePath(fullPath))
                    return ProtectionPipeResponse.Error("Chemin refusé");
                // Aucun accès au chemin avec les droits du service (pas même File.Exists) :
                // le fichier est ouvert par le client, et c'est cette poignée qui est scannée.
                return ExecuteScanWithRateLimit(account, () => ScanClientFile(pipe, fullPath));

            case ProtectionPipeOperations.ScanBuffer:
                if (string.IsNullOrWhiteSpace(request.BufferBase64))
                    return ProtectionPipeResponse.Error("Buffer vide");
                if (request.BufferBase64.Length > MaxScanBufferBase64Length)
                    return ProtectionPipeResponse.Error("Buffer trop volumineux");
                return ExecuteScanWithRateLimit(account, () =>
                    ScanBuffer(request.BufferBase64, request.ContentName ?? "amsi_buffer"));

            case ProtectionPipeOperations.QuarantineSummary:
                // Nombre et taille seulement : aucun chemin ni nom de fichier d'un autre compte.
                return _quarantineAdmin?.Summary() ?? QuarantineUnavailable();

            case ProtectionPipeOperations.QuarantineList:
            case ProtectionPipeOperations.QuarantineRestore:
            case ProtectionPipeOperations.QuarantineDelete:
            case ProtectionPipeOperations.QuarantinePurge:
                if (_quarantineAdmin == null)
                    return QuarantineUnavailable();
                // Les chemins d'origine concernent tous les comptes de la machine, et restaurer
                // remet un fichier détecté en place : réservé à un administrateur élevé.
                if (!NamedPipeClientAccess.IsElevatedAdministrator(pipe))
                    return ProtectionPipeResponse.Error("Non autorisé");
                return request.Operation switch
                {
                    ProtectionPipeOperations.QuarantineList => _quarantineAdmin.List(),
                    ProtectionPipeOperations.QuarantineDelete => _quarantineAdmin.Delete(request.QuarantineId),
                    ProtectionPipeOperations.QuarantinePurge => _quarantineAdmin.Purge(),
                    _ => _quarantineAdmin.Restore(
                        request.QuarantineId,
                        request.DestinationFolder,
                        path => NamedPipeClientAccess.CreateNewForClient(pipe, path)),
                };

            default:
                return ProtectionPipeResponse.Error($"Opération inconnue : {request.Operation}");
        }
    }

    private static ProtectionPipeResponse QuarantineUnavailable() =>
        ProtectionPipeResponse.Error("Quarantaine du service indisponible");

    private ProtectionPipeResponse ExecuteScanWithRateLimit(string account, Func<ProtectionPipeResponse> scan)
    {
        var exempt = account is NamedPipeClientAccess.SystemAccount or NamedPipeClientAccess.SelfAccount;
        IDisposable? accountLease = null;
        if (!exempt && !LimiterFor(account).TryEnter(out accountLease))
            return ProtectionPipeResponse.Error("Limite de débit atteinte");

        using (accountLease)
        {
            if (!_scanRateLimiter.TryEnter(out var lease))
                return ProtectionPipeResponse.Error("Limite de débit atteinte");

            using (lease)
                return scan();
        }
    }

    private ProtectionPipeResponse ScanClientFile(NamedPipeServerStream pipe, string fullPath)
    {
        using var source = NamedPipeClientAccess.OpenForClient(pipe, fullPath);
        if (source == null)
            return ProtectionPipeResponse.Error("Chemin refusé");
        if (source.Length > ScanStaging.MaxIpcStagedBytes)
            return ProtectionPipeResponse.Error("Fichier trop volumineux pour un scan IPC");

        try
        {
            using var staged = ScanStaging.Stage(source, Path.GetFileName(fullPath));
            return ScanStaged(staged.Path);
        }
        catch (IOException ex)
        {
            AppLogger.Warn("ProtectionPipeServer", "Copie pour scan IPC", ex);
            return ProtectionPipeResponse.Error("Scan impossible");
        }
    }

    private ProtectionPipeResponse ScanStaged(string path)
    {
        var result = _orchestrator.ScanFileAsync(path).GetAwaiter().GetResult();
        if (result.Threats.Count > 0)
        {
            var threat = result.Threats[0];
            return ProtectionPipeResponse.Threat(
                threat.VirusName,
                threat.DetectedBy,
                incomplete: result.Status != Models.ScanStatus.Completed || result.HasCoverageGaps);
        }

        // Seul un scan terminé sans menace peut répondre « propre ».
        if (result.Status != Models.ScanStatus.Completed || result.HasCoverageGaps)
            return ProtectionPipeResponse.Error("Scan incomplet");

        return ProtectionPipeResponse.SuccessClean();
    }

    private ProtectionPipeResponse ScanBuffer(string bufferBase64, string contentName)
    {
        var bytes = Convert.FromBase64String(bufferBase64);
        try
        {
            using var source = new MemoryStream(bytes, writable: false);
            using var staged = ScanStaging.Stage(source, contentName);
            return ScanStaged(staged.Path);
        }
        catch (IOException ex)
        {
            AppLogger.Warn("ProtectionPipeServer", "Copie pour scan IPC", ex);
            return ProtectionPipeResponse.Error("Scan impossible");
        }
    }

    public void Dispose() => _ = StopAsync();
}
