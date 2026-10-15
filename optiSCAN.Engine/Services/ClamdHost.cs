using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.Versioning;

namespace optiSCAN.Services
{
    /// <summary>Démarre et arrête clamd.exe avec une configuration gérée par optiSCAN.</summary>
    [SupportedOSPlatform("windows")]
    internal sealed class ClamdHost : IDisposable
    {
        /// <summary>
        /// Ligne de commande de clamd. <see cref="ProcessStartInfo.ArgumentList"/> (et non
        /// <c>Arguments</c>) : .NET met les guillemets lui-même, sinon un profil
        /// « C:\Users\Jean Dupont » coupe le chemin en deux et clamd refuse de démarrer.
        /// </summary>
        internal static ProcessStartInfo BuildStartInfo(string clamdExe, string confPath)
        {
            var psi = new ProcessStartInfo
            {
                FileName = clamdExe,
                UseShellExecute = false,
                CreateNoWindow = true,
                WorkingDirectory = Path.GetDirectoryName(clamdExe) ?? Environment.CurrentDirectory,
            };
            psi.ArgumentList.Add("--config-file=" + confPath);
            return psi;
        }

        private static readonly object Gate = new();
        private static readonly SemaphoreSlim StartGate = new(1, 1);
        private static ClamdHost? _shared;

        private readonly string _clamdExe;
        private readonly string _databaseDir;
        private Process? _process;
        private Process? _relay;
        private ClamdRelayChannel? _channel;
        private CancellationTokenSource? _brokerStop;
        private Task? _brokerTask;
        private int _port;
        private string? _pipeName;
        private bool _disposed;

        /// <summary>Tube nommé du relais, avec ACL du compte; le TCP clamd reste local et non authentifié.</summary>
        public string? PipeName => _pipeName;

        public static ClamdHost Shared
        {
            get
            {
                lock (Gate)
                {
                    var binDir = ClamAvDatabasePaths.ResolveClamAvBinDir("clamd.exe");
                    var dbDir = ClamAvDatabasePaths.ResolveWritableDatabaseDir(binDir);
                    return _shared ??= new ClamdHost(binDir, dbDir);
                }
            }
        }

        private ClamdHost(string clamavBinDir, string databaseDir)
        {
            _clamdExe = Path.Combine(clamavBinDir, "clamd.exe");
            _databaseDir = databaseDir;
        }

        public bool IsBinaryPresent => File.Exists(_clamdExe);

        public async Task<bool> EnsureRunningAsync(CancellationToken ct = default)
        {
            if (!IsBinaryPresent)
                return false;

            if (await PingOwnedAsync(ct).ConfigureAwait(false))
                return true;

            await StartGate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                if (await PingOwnedAsync(ct).ConfigureAwait(false))
                    return true;

                lock (Gate)
                {
                    try
                    {
                        StopProcessLocked();
                        StopOrphanLocked();
                        _port = AllocateLoopbackPort();
                        _pipeName = "optiSCAN_clamd_" + Guid.NewGuid().ToString("N");
                        var excludePatterns = AppInstallPaths.GetClamScanExcludePatterns().ToList();
                        ClamdConfSupport.EnsureConf(_databaseDir, _port, excludePatterns);
                        File.WriteAllText(ClamdConfSupport.GetPipePath(), _pipeName);

                        var conf = ClamdConfSupport.GetConfPath();
                        var work = Path.GetDirectoryName(_clamdExe) ?? Environment.CurrentDirectory;
                        _process = ClamdIsolation.Start(
                            _clamdExe,
                            "--config-file=\"" + conf + "\"",
                            work,
                            network: true,
                            writableDirectories: new[]
                            {
                                Path.GetDirectoryName(conf)!,
                                _databaseDir,
                            });
                        var brokerExe = Environment.ProcessPath;
                        var allowed = System.Security.Principal.WindowsIdentity.GetCurrent().User?.Value;
                        if (_process == null || string.IsNullOrEmpty(brokerExe) || string.IsNullOrEmpty(allowed) || _pipeName == null)
                        {
                            StopProcessLocked();
                            return false;
                        }

                        var controlFile = Path.Combine(Path.GetDirectoryName(conf)!, "relay-handles.txt");
                        _channel = ClamdRelayChannel.Create(allowed, controlFile);
                        if (_channel == null)
                        {
                            StopProcessLocked();
                            return false;
                        }

                        _brokerStop = new CancellationTokenSource();
                        var userPipe = _pipeName;
                        var token = _brokerStop.Token;
                        var channel = _channel;
                        var sid = allowed;
                        _relay = ClamdIsolation.Start(
                            brokerExe,
                            "--clamd-relay " + _port.ToString(CultureInfo.InvariantCulture)
                                + " " + Environment.ProcessId.ToString(CultureInfo.InvariantCulture)
                                + " \"" + controlFile + "\"",
                            Path.GetDirectoryName(brokerExe) ?? work,
                            network: true,
                            writableDirectories: new[] { Path.GetDirectoryName(conf)! });
                        if (_relay == null)
                        {
                            StopProcessLocked();
                            return false;
                        }

                        var relay = _relay;
                        _brokerTask = Task.Run(() => ClamdBroker.ServeAsync(userPipe, sid, () => channel.OpenData(relay), token));
                    }
                    catch (Exception ex)
                    {
                        AppLogger.Warn("ClamdHost", "Démarrage clamd", ex);
                        StopProcessLocked();
                        return false;
                    }
                }
            }
            finally
            {
                StartGate.Release();
            }

            var deadline = DateTime.UtcNow.AddSeconds(20);
            while (DateTime.UtcNow < deadline && !ct.IsCancellationRequested)
            {
                await Task.Delay(400, ct).ConfigureAwait(false);
                if (await PingOwnedAsync(ct).ConfigureAwait(false))
                {
                    AppLogger.Info("ClamdHost", "clamd opérationnel (tube isolé)");
                    return true;
                }
            }

            AppLogger.Warn("ClamdHost", "clamd n'a pas répondu à PING à temps");
            Stop();
            return false;
        }

        /// <summary>
        /// N'accepte un PONG que du processus clamd.exe que nous avons lancé,
        /// ou d'un processus dont l'image est exactement ce binaire.
        /// </summary>
        private async Task<bool> PingOwnedAsync(CancellationToken ct)
        {
            if (!string.IsNullOrEmpty(_pipeName))
                return await PingPipeAsync(_pipeName, ct).ConfigureAwait(false);

            if (!TryReadOwnedEndpoint(out var port, out var pipe))
                return false;

            if (!await PingPipeAsync(pipe, ct).ConfigureAwait(false))
                return false;

            _port = port;
            _pipeName = pipe;
            return true;
        }

        private bool TryReadOwnedEndpoint(out int port, out string pipe)
        {
            port = 0;
            pipe = string.Empty;
            try
            {
                if (!File.Exists(ClamdConfSupport.GetPidPath())
                    || !File.Exists(ClamdConfSupport.GetPortPath())
                    || !File.Exists(ClamdConfSupport.GetPipePath()))
                    return false;
                if (!int.TryParse(File.ReadAllText(ClamdConfSupport.GetPidPath()).Trim(), out var pid))
                    return false;
                if (!int.TryParse(File.ReadAllText(ClamdConfSupport.GetPortPath()).Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out port))
                    return false;
                pipe = File.ReadAllText(ClamdConfSupport.GetPipePath()).Trim();
                if (string.IsNullOrEmpty(pipe))
                    return false;

                using var proc = Process.GetProcessById(pid);
                var image = proc.MainModule?.FileName;
                return image != null
                    && string.Equals(Path.GetFullPath(image), Path.GetFullPath(_clamdExe), StringComparison.OrdinalIgnoreCase);
            }
            catch
            {
                port = 0;
                pipe = string.Empty;
                return false;
            }
        }

        private static int AllocateLoopbackPort()
        {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            try
            {
                return ((IPEndPoint)listener.LocalEndpoint).Port;
            }
            finally
            {
                listener.Stop();
            }
        }

        private static async Task<bool> PingPipeAsync(string pipeName, CancellationToken ct)
        {
            try
            {
                using var client = ClamdClient.ForPipe(pipeName, connectTimeoutMs: 300);
                return await client.PingAsync(ct).ConfigureAwait(false);
            }
            catch
            {
                return false;
            }
        }

        public void Stop()
        {
            lock (Gate)
                StopProcessLocked();
        }

        private void StopOrphanLocked()
        {
            try
            {
                var pidPath = ClamdConfSupport.GetPidPath();
                if (!File.Exists(pidPath))
                    return;
                if (!int.TryParse(File.ReadAllText(pidPath).Trim(), out var pid))
                    return;
                using var proc = Process.GetProcessById(pid);
                var image = proc.MainModule?.FileName;
                if (image == null
                    || !string.Equals(Path.GetFullPath(image), Path.GetFullPath(_clamdExe), StringComparison.OrdinalIgnoreCase)
                    || proc.HasExited)
                    return;
                proc.Kill(entireProcessTree: true);
                proc.WaitForExit(3000);
            }
            catch (Exception ex)
            {
                AppLogger.Debug("ClamdHost", "Ancien clamd non arrêté : " + ex.Message);
            }
        }

        private void StopProcessLocked()
        {
            try
            {
                try { _brokerStop?.Cancel(); } catch { /* déjà libéré */ }
                if (_relay is { HasExited: false })
                {
                    _relay.Kill(entireProcessTree: true);
                    _relay.WaitForExit(3000);
                }
                if (_process is { HasExited: false })
                {
                    _process.Kill(entireProcessTree: true);
                    _process.WaitForExit(3000);
                }
            }
            catch (Exception ex)
            {
                AppLogger.Warn("ClamdHost", "Arrêt clamd", ex);
            }
            finally
            {
                try { _brokerTask?.Wait(1000); } catch { /* arrêt du courtier */ }
                try { _brokerStop?.Dispose(); } catch { /* ignore */ }
                _brokerStop = null;
                _brokerTask = null;
                if (_relay != null)
                    ClamdIsolation.Release(_relay);
                _relay?.Dispose();
                _relay = null;
                if (_process != null)
                    ClamdIsolation.Release(_process);
                _channel?.Dispose();
                _channel = null;
                _process?.Dispose();
                _process = null;
                _pipeName = null;
            }
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            Stop();
        }

        internal static void ResetSharedForTests()
        {
            lock (Gate)
            {
                _shared?.Dispose();
                _shared = null;
            }
        }
    }
}
