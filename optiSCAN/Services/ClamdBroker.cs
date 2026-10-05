using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Net.Sockets;
using System.Security.AccessControl;
using System.Security.Principal;

namespace optiSCAN.Services;

/// <summary>
/// Relie le tube nommé (ACL du compte parent) au TCP de clamd, qui reste dans le conteneur.
/// </summary>
internal static class ClamdBroker
{
    internal static async Task RunAsync(string pipeName, int port, int parentPid, string allowedSid, CancellationToken ct)
    {
        var first = true;
        var inflight = new List<Task>();
        while (!ct.IsCancellationRequested && ParentAlive(parentPid))
        {
            NamedPipeServerStream pipe;
            try
            {
                pipe = ClamdPipeAcl.Create(pipeName, first, allowedSid);
                first = false;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("ClamdBroker", "Création du tube clamd refusée", ex);
                break;
            }

            try
            {
                await pipe.WaitForConnectionAsync(ct).ConfigureAwait(false);
            }
            catch
            {
                await pipe.DisposeAsync().ConfigureAwait(false);
                break;
            }

            var accepted = pipe;
            inflight.Add(RelayAsync(accepted, port));
            inflight.RemoveAll(t => t.IsCompleted);
        }

        try { await Task.WhenAll(inflight).ConfigureAwait(false); }
        catch { /* arrêt */ }
    }

    /// <summary>
    /// Côté hôte, hors conteneur : un client optiSCAN parle au tube utilisateur,
    /// le relais dans le conteneur se branche sur le tube pont.
    /// </summary>
    internal static async Task ServeAsync(
        string userPipe,
        string allowedSid,
        Func<Stream?> openBridge,
        CancellationToken ct)
    {
        var firstUser = true;
        var inflight = new List<Task>();
        while (!ct.IsCancellationRequested)
        {
            NamedPipeServerStream user;
            try
            {
                user = ClamdPipeAcl.Create(userPipe, firstUser, allowedSid);
                firstUser = false;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("ClamdBroker", "Création du tube clamd refusée", ex);
                break;
            }

            try
            {
                await user.WaitForConnectionAsync(ct).ConfigureAwait(false);
            }
            catch
            {
                await user.DisposeAsync().ConfigureAwait(false);
                break;
            }

            var accepted = user;
            inflight.Add(BridgeAsync(accepted, openBridge, ct));
            inflight.RemoveAll(t => t.IsCompleted);
        }

        try { await Task.WhenAll(inflight).ConfigureAwait(false); }
        catch { /* arrêt */ }
    }

    private static async Task BridgeAsync(NamedPipeServerStream user, Func<Stream?> openBridge, CancellationToken ct)
    {
        Stream? bridge = null;
        try
        {
            bridge = openBridge();
            if (bridge == null)
                return;
            // Une lecture et une écriture en même temps sur le tube se terminent
            // par 0 octet et cassent le retour. On alterne : une commande, puis sa réponse.
            await ExchangeAsync(user, bridge, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is OperationCanceledException or IOException)
        {
            /* fin de session */
        }
        catch (Exception ex)
        {
            AppLogger.Warn("ClamdBroker", "Pont : " + ex.Message);
        }
        finally
        {
            if (bridge != null)
            {
                try { await bridge.DisposeAsync().ConfigureAwait(false); } catch { /* ignore */ }
            }
            try { await user.DisposeAsync().ConfigureAwait(false); } catch { /* ignore */ }
        }
    }

    private static async Task ExchangeAsync(Stream inbound, Stream outbound, CancellationToken ct)
    {
        var command = new byte[8192];
        var response = new byte[8192];
        while (!ct.IsCancellationRequested)
        {
            var read = await inbound.ReadAsync(command, ct).ConfigureAwait(false);
            if (read == 0)
                return;

            read = await ClamdInstreamFramer.CompleteHeaderAsync(inbound, command, read, ct).ConfigureAwait(false);
            // Calculé avant l'envoi : ForwardRequestAsync réutilise le tampon.
            var streaming = IsMultiResponse(command.AsSpan(0, read));
            if (ClamdInstreamFramer.IsInstreamHeader(command.AsSpan(0, read)))
            {
                // INSTREAM : plusieurs écritures avant la réponse. Les transmettre toutes.
                if (!await ClamdInstreamFramer.ForwardRequestAsync(inbound, outbound, command, read, ct).ConfigureAwait(false))
                    return;
            }
            else
            {
                await outbound.WriteAsync(command.AsMemory(0, read), ct).ConfigureAwait(false);
                await outbound.FlushAsync(ct).ConfigureAwait(false);
            }

            while (!ct.IsCancellationRequested)
            {
                var got = await outbound.ReadAsync(response, ct).ConfigureAwait(false);
                if (got == 0)
                    return;
                await inbound.WriteAsync(response.AsMemory(0, got), ct).ConfigureAwait(false);
                await inbound.FlushAsync(ct).ConfigureAwait(false);
                if (!streaming && response.AsSpan(0, got).IndexOf((byte)'\n') >= 0)
                    break;
            }
        }
    }

    internal static bool IsMultiResponse(ReadOnlySpan<byte> command)
    {
        // nCONTSCAN / zCONTSCAN : plusieurs lignes, puis clamd ferme.
        if (command.Length == 0)
            return false;
        var marker = command[0];
        return marker is (byte)'n' or (byte)'N' or (byte)'z' or (byte)'Z';
    }

    private static bool ParentAlive(int parentPid)
    {
        if (parentPid <= 0)
            return true;
        try
        {
            using var process = Process.GetProcessById(parentPid);
            return !process.HasExited;
        }
        catch
        {
            return false;
        }
    }

    private static async Task RelayAsync(NamedPipeServerStream pipe, int port)
    {
        TcpClient? tcp = null;
        try
        {
            tcp = new TcpClient();
            var connected = false;
            for (var i = 0; i < 80 && !connected; i++)
            {
                try
                {
                    await tcp.ConnectAsync("127.0.0.1", port).ConfigureAwait(false);
                    connected = true;
                }
                catch
                {
                    await Task.Delay(250).ConfigureAwait(false);
                }
            }
            if (!connected)
                return;

            await using var remote = tcp.GetStream();
            using var stop = new CancellationTokenSource();
            var outbound = CopyAsync(pipe, remote, stop.Token);
            var inbound = CopyAsync(remote, pipe, stop.Token);
            await Task.WhenAny(outbound, inbound).ConfigureAwait(false);
            stop.Cancel();
            try { await Task.WhenAll(outbound, inbound).ConfigureAwait(false); }
            catch { /* fin de flux */ }
        }
        catch (Exception ex)
        {
            AppLogger.Debug("ClamdBroker", "Relais : " + ex.Message);
        }
        finally
        {
            try { tcp?.Dispose(); } catch { /* ignore */ }
            try { await pipe.DisposeAsync(); } catch { /* ignore */ }
        }
    }

    internal static async Task CopyAsync(Stream from, Stream to, CancellationToken ct)
    {
        var buffer = new byte[8192];
        while (!ct.IsCancellationRequested)
        {
            var read = await from.ReadAsync(buffer, ct).ConfigureAwait(false);
            if (read == 0)
                break;
            await to.WriteAsync(buffer.AsMemory(0, read), ct).ConfigureAwait(false);
            await to.FlushAsync(ct).ConfigureAwait(false);
        }
    }
}

/// <summary>
/// Le conteneur reçoit des handles déjà ouverts. Il n'ouvre pas le tube par son nom.
/// </summary>
internal static class ClamdRelay
{
    internal static void Run(int port, int parentPid, string controlFile)
    {
        _ = parentPid;
        var seen = 0;
        while (HostHolding(controlFile))
        {
            string text;
            try { text = File.ReadAllText(controlFile); }
            catch
            {
                Thread.Sleep(50);
                continue;
            }

            var lines = text.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            while (seen < lines.Length)
            {
                if (long.TryParse(lines[seen], out var value) && value > 0)
                {
                    try
                    {
                        var dataHandle = new Microsoft.Win32.SafeHandles.SafePipeHandle(new IntPtr(value), ownsHandle: true);
                        var data = new NamedPipeClientStream(PipeDirection.InOut, false, true, dataHandle);
                        var file = controlFile;
                        _ = Task.Run(() => Pump(data, port, file));
                    }
                    catch
                    {
                        /* handle inutilisable */
                    }
                }
                seen++;
            }

            Thread.Sleep(50);
        }
    }

    private static void Pump(NamedPipeClientStream pipe, int port, string controlFile)
    {
        TcpClient? tcp = null;
        try
        {
            var connected = false;
            for (var i = 0; i < 80 && !connected && HostHolding(controlFile); i++)
            {
                tcp?.Dispose();
                tcp = new TcpClient();
                try
                {
                    var attempt = tcp.ConnectAsync("127.0.0.1", port);
                    if (!attempt.Wait(TimeSpan.FromSeconds(2)))
                        throw new TimeoutException("connexion locale expirée");
                    connected = true;
                }
                catch
                {
                    Thread.Sleep(250);
                }
            }

            if (!connected || tcp == null)
            {
                tcp?.Dispose();
                return;
            }

            using (tcp)
            using (pipe)
            using (var remote = tcp.GetStream())
            {
                var command = new byte[8192];
                var response = new byte[8192];
                while (HostHolding(controlFile))
                {
                    int read;
                    try { read = pipe.Read(command, 0, command.Length); }
                    catch (IOException) { return; }
                    if (read <= 0)
                        return;

                    read = ClamdInstreamFramer.CompleteHeader(pipe, command, read);
                    var streaming = ClamdBroker.IsMultiResponse(command.AsSpan(0, read));
                    if (ClamdInstreamFramer.IsInstreamHeader(command.AsSpan(0, read)))
                    {
                        bool forwarded;
                        try { forwarded = ClamdInstreamFramer.ForwardRequest(pipe, remote, command, read); }
                        catch (IOException) { return; }
                        if (!forwarded)
                            return;
                    }
                    else
                    {
                        remote.Write(command, 0, read);
                        remote.Flush();
                    }
                    while (HostHolding(controlFile))
                    {
                        int got;
                        try { got = remote.Read(response, 0, response.Length); }
                        catch (IOException) { got = 0; }
                        if (got <= 0)
                            return;
                        pipe.Write(response, 0, got);
                        pipe.Flush();
                        if (!streaming && response.AsSpan(0, got).IndexOf((byte)'\n') >= 0)
                            break;
                    }
                }
            }
        }
        catch
        {
            try { tcp?.Dispose(); } catch { /* ignore */ }
            try { pipe.Dispose(); } catch { /* ignore */ }
        }
    }

    private static bool HostHolding(string controlFile)
    {
        // Le conteneur ne voit pas le processus parent. Le verrou exclusif
        // du fichier .lock est le signal de vie : violation de partage = hôte vivant.
        try
        {
            using var probe = new FileStream(controlFile + ".lock", FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            return false;
        }
        catch (FileNotFoundException)
        {
            return false;
        }
        catch (DirectoryNotFoundException)
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return true;
        }
        catch (IOException)
        {
            return true;
        }
    }
}

/// <summary>Transmet au relais des handles de tube déjà connectés.</summary>
internal sealed class ClamdRelayChannel : IDisposable
{
    private readonly string _controlFile;
    private readonly string _allowedSid;
    private readonly object _gate = new();
    private FileStream? _lock;

    internal string ControlFile => _controlFile;

    private ClamdRelayChannel(string controlFile, string allowedSid)
    {
        _controlFile = controlFile;
        _allowedSid = allowedSid;
    }

    internal static ClamdRelayChannel? Create(string allowedSid, string controlFile)
    {
        try
        {
            var directory = Path.GetDirectoryName(controlFile);
            if (!string.IsNullOrEmpty(directory))
                Directory.CreateDirectory(directory);
            File.WriteAllText(controlFile, string.Empty);
            var lockFile = controlFile + ".lock";
            File.WriteAllText(lockFile, "1");
            if (!ClamdIsolation.TryGrantFile(controlFile) || !ClamdIsolation.TryGrantFile(lockFile))
            {
                TryDelete(controlFile);
                TryDelete(lockFile);
                return null;
            }

            var channel = new ClamdRelayChannel(controlFile, allowedSid);
            channel._lock = new FileStream(lockFile, FileMode.Open, FileAccess.Read, FileShare.None);
            return channel;
        }
        catch
        {
            return null;
        }
    }

    internal Stream? OpenData(Process relay)
    {
        lock (_gate)
        {
            var name = "optiSCAN_data_" + Guid.NewGuid().ToString("N");
            var serverHandle = ClamdPipeAcl.CreateHandle(name, true, _allowedSid);
            var client = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.None);
            client.Connect(2000);
            var server = new NamedPipeServerStream(PipeDirection.InOut, true, true, serverHandle);
            var raw = client.SafePipeHandle;
            var added = false;
            raw.DangerousAddRef(ref added);
            try
            {
                if (!ClamdIsolation.TryDuplicateInto(relay, raw.DangerousGetHandle(), out var remote))
                {
                    server.Dispose();
                    client.Dispose();
                    return null;
                }

                File.AppendAllText(_controlFile, remote.ToInt64().ToString() + "\n");
                // Fermer le handle d'origine coupe le tube même si le doublon vit
                // dans le relais : on le garde ouvert le temps du pont.
                return new BridgeStream(server, client);
            }
            finally
            {
                if (added)
                    raw.DangerousRelease();
            }
        }
    }

    public void Dispose()
    {
        try { _lock?.Dispose(); } catch { /* déjà fermé */ }
        _lock = null;
        TryDelete(_controlFile);
        TryDelete(_controlFile + ".lock");
    }

    private static void TryDelete(string path)
    {
        try { File.Delete(path); } catch { /* déjà retiré */ }
    }

    /// <summary>
    /// Le serveur du tube de données, plus le client d'origine. Fermer ce client
    /// casse le tube alors que le relais en détient un doublon.
    /// </summary>
    private sealed class BridgeStream : Stream
    {
        private readonly Stream _server;
        private readonly NamedPipeClientStream _client;

        internal BridgeStream(Stream server, NamedPipeClientStream client)
        {
            _server = server;
            _client = client;
        }

        public override bool CanRead => _server.CanRead;
        public override bool CanSeek => false;
        public override bool CanWrite => _server.CanWrite;
        public override long Length => _server.Length;
        public override long Position
        {
            get => _server.Position;
            set => _server.Position = value;
        }

        public override void Flush() => _server.Flush();
        public override int Read(byte[] buffer, int offset, int count) => _server.Read(buffer, offset, count);
        public override void Write(byte[] buffer, int offset, int count) => _server.Write(buffer, offset, count);
        public override long Seek(long offset, SeekOrigin origin) => _server.Seek(offset, origin);
        public override void SetLength(long value) => _server.SetLength(value);
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            _server.ReadAsync(buffer, offset, count, cancellationToken);
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            _server.ReadAsync(buffer, cancellationToken);
        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            _server.WriteAsync(buffer, offset, count, cancellationToken);
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) =>
            _server.WriteAsync(buffer, cancellationToken);
        public override Task FlushAsync(CancellationToken cancellationToken) => _server.FlushAsync(cancellationToken);

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                try { _server.Dispose(); } catch { /* déjà fermé */ }
                try { _client.Dispose(); } catch { /* déjà fermé */ }
            }
            base.Dispose(disposing);
        }
    }
}

#if OPTISCAN_TEST_HOOKS
/// <summary>Répond PONG sur la boucle locale. Sert à prouver l'isolation, pas à scanner.</summary>
internal static class ClamdLoopbackStub
{
    internal static void Run(int port)
    {
        var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, port);
        listener.Start();
        try
        {
            while (true)
            {
                using var client = listener.AcceptTcpClient();
                using var stream = client.GetStream();
                var buffer = new byte[64];
                var read = stream.Read(buffer, 0, buffer.Length);
                var line = System.Text.Encoding.UTF8.GetString(buffer, 0, Math.Max(read, 0)).Trim();
                if (line.Equals("PING", StringComparison.OrdinalIgnoreCase))
                {
                    var pong = System.Text.Encoding.UTF8.GetBytes("PONG\n");
                    stream.Write(pong, 0, pong.Length);
                }
            }
        }
        finally
        {
            listener.Stop();
        }
    }
}
#endif

internal static class ClamdPipeAcl
{
    internal static NamedPipeServerStream Create(string pipeName, bool firstInstance, string allowedSid)
    {
        var security = new PipeSecurity();
        Add(security, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null));
        Add(security, new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));
        Add(security, new SecurityIdentifier(allowedSid));
        var current = WindowsIdentity.GetCurrent().User;
        if (current != null)
            Add(security, current);

        return Open(pipeName, firstInstance, security);
    }

    internal static Microsoft.Win32.SafeHandles.SafePipeHandle CreateHandle(string pipeName, bool firstInstance, string allowedSid)
    {
        var security = new PipeSecurity();
        Add(security, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null));
        Add(security, new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));
        Add(security, new SecurityIdentifier(allowedSid));
        var current = WindowsIdentity.GetCurrent().User;
        if (current != null)
            Add(security, current);
        return OpenHandle(pipeName, firstInstance, security);
    }

    private static NamedPipeServerStream Open(string pipeName, bool firstInstance, PipeSecurity security)
    {
        var handle = OpenHandle(pipeName, firstInstance, security);
        return new NamedPipeServerStream(PipeDirection.InOut, true, false, handle);
    }

    private static Microsoft.Win32.SafeHandles.SafePipeHandle OpenHandle(string pipeName, bool firstInstance, PipeSecurity security)
    {
        var bytes = security.GetSecurityDescriptorBinaryForm();
        var ptr = System.Runtime.InteropServices.Marshal.AllocHGlobal(bytes.Length);
        try
        {
            System.Runtime.InteropServices.Marshal.Copy(bytes, 0, ptr, bytes.Length);
            var attributes = new Attributes
            {
                Length = System.Runtime.InteropServices.Marshal.SizeOf<Attributes>(),
                SecurityDescriptor = ptr,
            };
            var open = 0x00000003u | 0x40000000u;
            if (firstInstance)
                open |= 0x00080000u;
            // Message + rejet des clients distants. En mode octet, une lecture
            // pendant que le pair lit aussi se termine par 0 et ferme le pont.
            var mode = 0x00000004u | 0x00000002u | 0x00000008u;
            var handle = CreateNamedPipe(
                @"\\.\pipe\" + pipeName,
                open,
                mode,
                255,
                65536,
                65536,
                0,
                ref attributes);
            if (handle.IsInvalid)
                throw new System.ComponentModel.Win32Exception(System.Runtime.InteropServices.Marshal.GetLastWin32Error());
            return handle;
        }
        finally
        {
            System.Runtime.InteropServices.Marshal.FreeHGlobal(ptr);
        }
    }

    private static void Add(PipeSecurity security, SecurityIdentifier sid) =>
        security.AddAccessRule(new PipeAccessRule(sid, PipeAccessRights.FullControl, AccessControlType.Allow));

    [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
    private struct Attributes
    {
        public int Length;
        public IntPtr SecurityDescriptor;
        [System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
        public bool InheritHandle;
    }

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    private static extern Microsoft.Win32.SafeHandles.SafePipeHandle CreateNamedPipe(
        string name, uint openMode, uint pipeMode, uint maxInstances, uint outBuffer, uint inBuffer, uint timeout, ref Attributes security);
}
