using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;

namespace optiSCAN.Services
{
    /// <summary>
    /// Interface avec clamd (mode démon) via socket TCP.
    /// clamd reste en mémoire et ne recharge pas les signatures à chaque scan.
    /// </summary>
    public class ClamDaemon : IDisposable, IAsyncDisposable
    {
        private readonly string _clamdExe;
        private readonly string _clamdConfPath;
        private Process? _clamdProcess;
        private TcpClient? _tcpClient;
        private NetworkStream? _stream;
        // SemaphoreSlim sérialise les commandes TCP concurrentes (la protection
        // temps réel et l'UI peuvent appeler ScanFileAsync simultanément).
        private readonly SemaphoreSlim _commandLock = new(1, 1);
        private bool _isConnected;
        private bool _disposed;

        // Configuration clamd par défaut
        private const int ClamdPort = 3310;
        private const string ClamdHost = "127.0.0.1";

        public bool IsRunning => _isConnected && _clamdProcess != null && !_clamdProcess.HasExited;

        public ClamDaemon()
        {
            var baseDir = AppDomain.CurrentDomain.BaseDirectory;
            var arch = Environment.Is64BitProcess ? "x64" : "x86";
            var clamavDir = Path.Combine(baseDir, "clamav", arch);

            if (!Directory.Exists(clamavDir))
                clamavDir = Path.Combine(baseDir, "clamav");

            _clamdExe = Path.Combine(clamavDir, "clamd.exe");
            _clamdConfPath = Path.Combine(clamavDir, "clamd.conf");
        }

        /// <summary>
        /// Démarre le démon clamd
        /// </summary>
        public async Task<bool> StartAsync(CancellationToken ct = default)
        {
            if (IsRunning) return true;

            if (!File.Exists(_clamdExe))
            {
                AppLogger.Warn("ClamDaemon", "clamd.exe introuvable");
                return false;
            }

            EnsureConfFile();

            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = _clamdExe,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardError = true
                };
                // ArgumentList : échappement sûr du chemin de conf, même s'il
                // contient des espaces ou caractères spéciaux (ex. compte
                // utilisateur avec accent).
                psi.ArgumentList.Add($"--config-file={_clamdConfPath}");

                _clamdProcess = new Process { StartInfo = psi };

                _clamdProcess.Start();

                // Attendre que clamd soit prêt (connexion TCP)
                await WaitForConnectionAsync(ct);

                return _isConnected;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("ClamDaemon", "Erreur démarrage clamd", ex);
                return false;
            }
        }

        /// <summary>
        /// Arrête le démon clamd
        /// </summary>
        public async Task StopAsync()
        {
            if (_tcpClient != null)
            {
                try { await SendCommandAsync("SHUTDOWN"); } catch { }
                Disconnect();
            }

            if (_clamdProcess != null && !_clamdProcess.HasExited)
            {
                try
                {
                    _clamdProcess.Kill();
                    await _clamdProcess.WaitForExitAsync();
                }
                catch { }
                _clamdProcess.Dispose();
                _clamdProcess = null;
            }
        }

        /// <summary>
        /// Scanne un fichier via clamd
        /// </summary>
        public async Task<(bool IsInfected, string VirusName)> ScanFileAsync(string filePath, CancellationToken ct = default)
        {
            if (!_isConnected)
                throw new InvalidOperationException("clamd n'est pas connecté");

            // Le protocole clamd reconnaît SCAN <chemin>\n.
            // Si filePath contient un \n ou \0, c'est suspect → on rejette.
            // (filename Windows n'autorise pas ces caractères, mais défense
            // en profondeur contre une corruption de manifest ou malware.)
            if (filePath.Contains('\n') || filePath.Contains('\0'))
                throw new ArgumentException("Caractère interdit dans le chemin", nameof(filePath));

            var command = $"SCAN {filePath}\n";
            var response = await SendCommandAsync(command, ct);

            // Format réponse : "filename: OK" ou "filename: VirusName FOUND"
            if (response.Contains(": OK"))
                return (false, string.Empty);

            var foundIndex = response.IndexOf(": ", StringComparison.Ordinal);
            if (foundIndex >= 0)
            {
                var rest = response.Substring(foundIndex + 2);
                if (rest.Contains("FOUND"))
                {
                    var virusName = rest.Replace(" FOUND", "").Trim();
                    return (true, virusName);
                }
            }

            return (false, string.Empty);
        }

        /// <summary>
        /// Scanne un dossier via clamd
        /// </summary>
        public async Task<(int FilesScanned, List<(string Path, string VirusName)> Threats)> ScanFolderAsync(
            string folderPath,
            IProgress<(string File, int Index, int Total)>? progress = null,
            CancellationToken ct = default)
        {
            var threats = new List<(string, string)>();
            var files = Directory.GetFiles(folderPath, "*.*", SearchOption.AllDirectories);
            var scanned = 0;

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) break;

                var (infected, virusName) = await ScanFileAsync(file, ct);
                scanned++;
                progress?.Report((file, scanned, files.Length));

                if (infected)
                    threats.Add((file, virusName));
            }

            return (scanned, threats);
        }

        /// <summary>
        /// Récupère la version de clamd
        /// </summary>
        public async Task<string> GetVersionAsync()
        {
            if (!_isConnected) return "Non connecté";
            try
            {
                var response = await SendCommandAsync("VERSION\r\n");
                return response.Trim();
            }
            catch { return "Erreur"; }
        }

        /// <summary>
        /// Statistiques de clamd
        /// </summary>
        public async Task<string> GetStatsAsync()
        {
            if (!_isConnected) return "Non connecté";
            try { return await SendCommandAsync("STATS\r\n"); }
            catch { return "Erreur"; }
        }

        private async Task<bool> WaitForConnectionAsync(CancellationToken ct, int maxAttempts = 20)
        {
            for (int i = 0; i < maxAttempts; i++)
            {
                if (ct.IsCancellationRequested) return false;
                try
                {
                    await Task.Delay(500, ct);
                    await ConnectAsync();
                    return true;
                }
                catch { /* réessayer */ }
            }
            return false;
        }

        private async Task ConnectAsync()
        {
            // Avant connexion TCP : vérifier que le processus en écoute sur le port 3310
            // est bien NOTRE _clamdProcess. Sinon, un autre processus local pourrait
            // s'être inséré (crash + réutilisation du port). On refuse la connexion dans ce cas.
            if (_clamdProcess != null && !VerifyListenerIsOwn(ClamdPort, _clamdProcess.Id))
            {
                AppLogger.Fatal("ClamDaemon",
                    $"Le port {ClamdPort} est utilisé par un autre process — refus de connexion (possible TCP hijack)");
                throw new InvalidOperationException("clamd port hijack détecté");
            }

            _tcpClient = new TcpClient();
            // Forçage explicite IPv4 loopback pour éviter une bind sur ::1
            // (différent de 127.0.0.1 dans la table TCP).
            await _tcpClient.ConnectAsync(IPAddress.Loopback, ClamdPort);
            _stream = _tcpClient.GetStream();
            _isConnected = true;
        }

        // ── Vérification que le listener TCP est bien notre clamd ───────────────────

        /// <summary>
        /// Vérifie qu'au moins une socket en LISTEN sur le port donné appartient
        /// au PID attendu. Utilise GetExtendedTcpTable (iphlpapi.dll) pour
        /// obtenir la table TCP avec les owning PIDs.
        ///
        /// Si l'API échoue (rare), on retourne true par défaut pour ne pas
        /// bloquer un usage normal — le risque résiduel est journalisé.
        /// </summary>
        private static bool VerifyListenerIsOwn(int port, int expectedPid)
        {
            try
            {
                int bufferSize = 0;
                // Appel 1 : récupérer la taille du buffer nécessaire.
                NativeMethods.GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true,
                    NativeMethods.AF_INET, NativeMethods.TCP_TABLE_OWNER_PID_ALL, 0);

                IntPtr buffer = Marshal.AllocHGlobal(bufferSize);
                try
                {
                    int err = NativeMethods.GetExtendedTcpTable(buffer, ref bufferSize, true,
                        NativeMethods.AF_INET, NativeMethods.TCP_TABLE_OWNER_PID_ALL, 0);
                    if (err != 0)
                    {
                        AppLogger.Warn("ClamDaemon", $"GetExtendedTcpTable err={err}");
                        return true; // best-effort
                    }

                    int rowCount = Marshal.ReadInt32(buffer);
                    IntPtr rowPtr = IntPtr.Add(buffer, 4);
                    int rowSize = Marshal.SizeOf<NativeMethods.MIB_TCPROW_OWNER_PID>();

                    for (int i = 0; i < rowCount; i++)
                    {
                        var row = Marshal.PtrToStructure<NativeMethods.MIB_TCPROW_OWNER_PID>(rowPtr);
                        rowPtr = IntPtr.Add(rowPtr, rowSize);

                        // Port en network byte order — on swap les 2 octets de poids fort.
                        // row.localPort est uint (P/Invoke), on cast en int après le swap.
                        int localPort = (int)(((row.localPort & 0xFF) << 8) | ((row.localPort >> 8) & 0xFF));

                        if (localPort == port && row.state == NativeMethods.MIB_TCP_STATE_LISTEN)
                        {
                            if (row.owningPid == expectedPid) return true;
                        }
                    }
                }
                finally { Marshal.FreeHGlobal(buffer); }

                // Aucune entrée LISTEN avec le bon PID. clamd n'écoute pas (ou plus).
                return false;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("ClamDaemon", "VerifyListenerIsOwn", ex);
                return true; // fail-open en cas d'erreur API
            }
        }

        // ── P/Invoke iphlpapi.dll ────────────────────────────────────────────────

        private static class NativeMethods
        {
            public const int AF_INET = 2;
            public const int TCP_TABLE_OWNER_PID_ALL = 5;
            public const int MIB_TCP_STATE_LISTEN = 2;

            [StructLayout(LayoutKind.Sequential)]
            public struct MIB_TCPROW_OWNER_PID
            {
                public uint state;
                public uint localAddr;
                public uint localPort;
                public uint remoteAddr;
                public uint remotePort;
                public int owningPid;
            }

            [DllImport("iphlpapi.dll", SetLastError = true)]
            public static extern int GetExtendedTcpTable(
                IntPtr pTcpTable,
                ref int dwOutBufLen,
                bool sort,
                int ipVersion,
                int tblClass,
                int reserved);
        }

        private void Disconnect()
        {
            _stream?.Dispose();
            _tcpClient?.Dispose();
            _stream = null;
            _tcpClient = null;
            _isConnected = false;
        }

        private async Task<string> SendCommandAsync(string command, CancellationToken ct = default)
        {
            // Sérialise les commandes concurrentes : un seul send/read à la fois
            // sur la même socket TCP (protocole clamd ne supporte pas le pipelining).
            await _commandLock.WaitAsync(ct);
            try
            {
                if (!_isConnected)
                    await ConnectAsync();

                var bytes = Encoding.ASCII.GetBytes(command);
                await _stream!.WriteAsync(bytes, 0, bytes.Length, ct);
                await _stream.FlushAsync(ct);

                var buffer = new byte[8192];
                var ms = new MemoryStream();

                while (true)
                {
                    var read = await _stream.ReadAsync(buffer, 0, buffer.Length, ct);
                    if (read == 0) break;
                    ms.Write(buffer, 0, read);

                    // Lecture incrémentale en O(N) : on ne reconvertit pas tout
                    // le buffer à chaque itération (ancienne version O(N²)).
                    if (buffer.AsSpan(0, read).IndexOf((byte)'\n') >= 0)
                        return Encoding.ASCII.GetString(ms.ToArray());
                }

                return Encoding.ASCII.GetString(ms.ToArray());
            }
            finally
            {
                _commandLock.Release();
            }
        }

        private void EnsureConfFile()
        {
            var clamavDir = Path.GetDirectoryName(_clamdExe) ?? "";
            var databaseDir = ClamAvDatabasePaths.ResolveWritableDatabaseDir(clamavDir)
                .Replace('\\', '/');

            // Régénérer si absent, BOM, ou si le chemin des bases a changé (ex. migration PF → LocalAppData).
            if (File.Exists(_clamdConfPath) && !HasUtf8Bom(_clamdConfPath))
            {
                try
                {
                    var existing = File.ReadAllText(_clamdConfPath);
                    var needle = $"DatabaseDirectory \"{databaseDir}\"";
                    if (existing.Contains(needle, StringComparison.OrdinalIgnoreCase))
                        return;
                }
                catch { /* régénérer */ }
            }
            var logFile = Path.Combine(Path.GetTempPath(), "clamd.log").Replace('\\', '/');

            var lines = new[]
            {
                "# clamd.conf généré par optiSCAN",
                $"LogFile \"{logFile}\"",
                "LogTime yes",
                $"DatabaseDirectory \"{databaseDir}\"",
                $"TCPSocket {ClamdPort}",
                $"TCPAddr {ClamdHost}",
                "MaxThreads 10",
                "MaxQueue 20",
                "ScanPE yes",
                "ScanOLE2 yes",
                "ScanHTML yes",
                "ScanPDF yes",
                "ScanArchive yes",
            };

            Directory.CreateDirectory(Path.GetDirectoryName(_clamdConfPath)!);

            // Écriture binaire pour garantir 0 BOM (clamd, comme freshclam,
            // refuse les fichiers de configuration avec BOM UTF-8).
            var content = string.Join("\n", lines) + "\n";
            var bytes = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false).GetBytes(content);
            try { if (File.Exists(_clamdConfPath)) File.Delete(_clamdConfPath); } catch { }
            AtomicFile.WriteAllBytes(_clamdConfPath, bytes);
        }

        /// <summary>Détecte la présence du BOM UTF-8 (0xEF 0xBB 0xBF).</summary>
        private static bool HasUtf8Bom(string path)
        {
            try
            {
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
                if (fs.Length < 3) return false;
                Span<byte> bom = stackalloc byte[3];
                _ = fs.Read(bom);
                return bom[0] == 0xEF && bom[1] == 0xBB && bom[2] == 0xBF;
            }
            catch { return false; }
        }

        public void Dispose()
        {
            if (_disposed) return;
            // Best effort synchrone : on attend max 2 s que clamd se termine
            // proprement (SHUTDOWN + drain), puis on force le kill.
            // Évite le process zombie de l'ancienne version qui faisait fire-and-forget.
            try { StopAsync().Wait(TimeSpan.FromSeconds(2)); }
            catch (Exception ex) { AppLogger.Warn("ClamDaemon", "Dispose sync wait", ex); }

            try { _commandLock.Dispose(); } catch { }
            _disposed = true;
        }

        /// <summary>
        /// Variante async pour les contextes await using : laisse le SHUTDOWN
        /// clamd remonter proprement avant de fermer la socket et le process.
        /// </summary>
        public async ValueTask DisposeAsync()
        {
            if (_disposed) return;
            try { await StopAsync().ConfigureAwait(false); }
            catch (Exception ex) { AppLogger.Warn("ClamDaemon", "DisposeAsync", ex); }

            try { _commandLock.Dispose(); } catch { }
            _disposed = true;
            GC.SuppressFinalize(this);
        }
    }
}
