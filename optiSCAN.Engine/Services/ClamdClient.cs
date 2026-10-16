// SPDX-License-Identifier: GPL-3.0-or-later
using System.Buffers.Binary;
using System.IO;
using System.IO.Pipes;
using System.Net.Sockets;
using System.Text;

namespace optiSCAN.Services
{
    /// <summary>Client TCP minimal pour le protocole clamd (PING, SCAN, CONTSCAN).</summary>
    internal sealed class ClamdClient : IDisposable
    {
        private readonly string _host;
        private readonly int _port;
        private readonly string? _pipeName;
        private readonly int _pipeConnectTimeoutMs;
        private TcpClient? _client;
        private Stream? _stream;
        private StreamReader? _reader;
        private readonly SemaphoreSlim _session = new(1, 1);

        public ClamdClient(string host = "127.0.0.1", int port = ClamdConfSupport.DefaultTcpPort)
        {
            _host = host;
            _port = port;
        }

        private ClamdClient(string pipeName, int pipeConnectTimeoutMs, bool pipe)
        {
            _pipeName = pipeName;
            _pipeConnectTimeoutMs = pipeConnectTimeoutMs;
            _host = "127.0.0.1";
        }

        public static ClamdClient ForPipe(string pipeName, int connectTimeoutMs = 2000) =>
            new(pipeName, connectTimeoutMs, pipe: true);

        public async Task<bool> PingAsync(CancellationToken ct = default)
        {
            var response = await SendCommandAsync("PING", ct).ConfigureAwait(false);
            return response.Completed
                && response.Text.Trim().Equals("PONG", StringComparison.OrdinalIgnoreCase);
        }

        public async Task<string> ScanFileAsync(string filePath, CancellationToken ct = default)
        {
            var path = Path.GetFullPath(filePath);
            var response = await SendCommandAsync("SCAN " + path, ct).ConfigureAwait(false);
            return response.Text;
        }

        public async Task<ClamdCommandResult> ScanRecursiveAsync(string directoryPath, CancellationToken ct = default)
        {
            var path = Path.GetFullPath(directoryPath);
            // nCONTSCAN : réponse terminée par un saut de ligne, connexion fermée à la fin.
            return await SendCommandAsync("nCONTSCAN " + path, ct).ConfigureAwait(false);
        }

        /// <summary>Taille d'un bloc INSTREAM.</summary>
        internal const int InstreamChunkSize = 64 * 1024;

        /// <summary>
        /// Envoie le contenu à clamd (<c>zINSTREAM</c>). clamd ne lit rien sur le disque :
        /// le fichier est ouvert par l'appelant, avec ses propres droits.
        /// Réponse attendue : <c>stream: OK</c>, <c>stream: Nom FOUND</c> ou une ligne <c>ERROR</c>.
        /// </summary>
        public async Task<ClamdCommandResult> InstreamAsync(Stream content, long maxBytes, CancellationToken ct = default)
        {
            ArgumentNullException.ThrowIfNull(content);
            await _session.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                await EnsureConnectedAsync(ct).ConfigureAwait(false);
                if (_stream == null || _reader == null)
                    throw new InvalidOperationException("Connexion clamd indisponible.");

                await _stream.WriteAsync("zINSTREAM\0"u8.ToArray(), ct).ConfigureAwait(false);

                var block = new byte[4 + InstreamChunkSize];
                long total = 0;
                while (true)
                {
                    var filled = 0;
                    while (filled < InstreamChunkSize)
                    {
                        var n = await content.ReadAsync(block.AsMemory(4 + filled, InstreamChunkSize - filled), ct).ConfigureAwait(false);
                        if (n <= 0)
                            break;
                        filled += n;
                    }

                    if (filled == 0)
                        break;

                    total += filled;
                    if (total > maxBytes)
                        throw new ClamdStreamTooLargeException(maxBytes);

                    BinaryPrimitives.WriteUInt32BigEndian(block, (uint)filled);
                    await _stream.WriteAsync(block.AsMemory(0, 4 + filled), ct).ConfigureAwait(false);
                }

                await _stream.WriteAsync(new byte[4], ct).ConfigureAwait(false);
                await _stream.FlushAsync(ct).ConfigureAwait(false);

                // Préfixe « z » : réponse terminée par NUL, puis clamd ferme la connexion.
                var text = await _reader.ReadToEndAsync(ct).ConfigureAwait(false);
                var completed = text.Contains('\0', StringComparison.Ordinal);
                return new ClamdCommandResult(text.Replace("\0", string.Empty, StringComparison.Ordinal).Trim(), completed);
            }
            finally
            {
                DisposeSocket();
                _session.Release();
            }
        }

        public async Task<ClamdCommandResult> SendCommandAsync(string command, CancellationToken ct = default)
        {
            await _session.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                await EnsureConnectedAsync(ct).ConfigureAwait(false);

                if (_stream == null || _reader == null)
                    throw new InvalidOperationException("Connexion clamd indisponible.");

                var payload = Encoding.UTF8.GetBytes(command + "\n");
                await _stream.WriteAsync(payload, ct).ConfigureAwait(false);
                await _stream.FlushAsync(ct).ConfigureAwait(false);

                return await ReadResponseAsync(command, ct).ConfigureAwait(false);
            }
            finally
            {
                _session.Release();
            }
        }

        private async Task EnsureConnectedAsync(CancellationToken ct)
        {
            if (_stream != null && (_client == null || _client.Connected))
                return;

            DisposeSocket();

            if (!string.IsNullOrEmpty(_pipeName))
            {
                // Identification seulement : un faux serveur ne peut pas usurper ce processus
                // (SYSTEM pour l'hôte du service). Puis serveur du même compte exigé, avant
                // d'envoyer le moindre octet (voir PipeServerAccount).
                var pipe = new NamedPipeClientStream(
                    ".", _pipeName, PipeDirection.InOut, PipeOptions.Asynchronous,
                    PipeServerAccount.ClientImpersonation);
                using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
                linked.CancelAfter(_pipeConnectTimeoutMs);
                await pipe.ConnectAsync(linked.Token).ConfigureAwait(false);
                if (!PipeServerAccount.IsSameAccount(pipe))
                {
                    await pipe.DisposeAsync().ConfigureAwait(false);
                    AppLogger.Warn("ClamdClient", "Tube clamd servi par un autre compte : connexion refusée.");
                    throw new IOException("Serveur du tube clamd non reconnu.");
                }
                _stream = pipe;
            }
            else
            {
                _client = new TcpClient();
                await _client.ConnectAsync(_host, _port, ct).ConfigureAwait(false);
                _stream = _client.GetStream();
            }

            _reader = new StreamReader(_stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: false, leaveOpen: true);
        }

        /// <summary>Plafond d'une réponse multi-lignes (nCONTSCAN) gardée en mémoire.</summary>
        internal const int MaxResponseChars = 16 * 1024 * 1024;

        private async Task<ClamdCommandResult> ReadResponseAsync(string command, CancellationToken ct)
        {
            var reader = _reader;
            if (reader == null)
                return new ClamdCommandResult(string.Empty, false);

            var singleLine = command.Equals("PING", StringComparison.OrdinalIgnoreCase)
                || command.StartsWith("SCAN ", StringComparison.OrdinalIgnoreCase);

            var sb = new StringBuilder();
            var completed = false;
            try
            {
                if (singleLine)
                {
                    var line = await reader.ReadLineAsync(ct).ConfigureAwait(false);
                    if (line != null)
                    {
                        sb.Append(line);
                        completed = true;
                    }

                    return new ClamdCommandResult(sb.ToString(), completed);
                }

                // Jusqu'à la fermeture de la connexion. Un délai entre deux lignes
                // couperait un dossier lent et ferait croire à un scan vide.
                while (!ct.IsCancellationRequested)
                {
                    var line = await reader.ReadLineAsync(ct).ConfigureAwait(false);
                    if (line == null)
                    {
                        completed = true;
                        break;
                    }

                    if (sb.Length + line.Length > MaxResponseChars)
                    {
                        // Réponse anormalement longue : lecture arrêtée, réponse incomplète
                        // (le scan passe en erreur et le repli clamscan prend le relais).
                        AppLogger.Warn("ClamdClient", $"Réponse clamd tronquée au-delà de {MaxResponseChars} caractères");
                        return new ClamdCommandResult(sb.ToString(), false);
                    }

                    if (sb.Length > 0)
                        sb.AppendLine();
                    sb.Append(line);
                }
            }
            finally
            {
                DisposeSocket();
            }

            return new ClamdCommandResult(sb.ToString(), completed);
        }

        private void DisposeSocket()
        {
            try { _reader?.Dispose(); } catch (Exception ex) when (!ex.IsFatal()) { AppLogger.Warn("ClamdClient", "Dispose reader failed", ex); }
            try { _stream?.Dispose(); } catch (Exception ex) when (!ex.IsFatal()) { AppLogger.Warn("ClamdClient", "Dispose stream failed", ex); }
            try { _client?.Dispose(); } catch (Exception ex) when (!ex.IsFatal()) { AppLogger.Warn("ClamdClient", "Dispose client failed", ex); }
            _reader = null;
            _stream = null;
            _client = null;
        }

        public void Dispose()
        {
            DisposeSocket();
            _session.Dispose();
        }
    }

    internal readonly record struct ClamdCommandResult(string Text, bool Completed);

    /// <summary>Contenu plus gros que le StreamMaxLength de clamd : à scanner autrement.</summary>
    internal sealed class ClamdStreamTooLargeException : IOException
    {
        public ClamdStreamTooLargeException(long maxBytes)
            : base("Contenu supérieur à la limite INSTREAM de clamd (" + maxBytes + " octets).")
        {
        }
    }
}

