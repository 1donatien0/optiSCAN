using System.Diagnostics;
using System.IO;
using System.Security.Principal;
using System.Text;
using optiSCAN.Platform;

namespace optiSCAN.Services;

/// <summary>Paramètres de lancement d'un analyseur en ligne de commande.</summary>
internal sealed class ScannerLaunch
{
    public ScannerLaunch(string executable, IEnumerable<string> arguments)
    {
        Executable = executable;
        Arguments = arguments.ToList();
    }

    public string Executable { get; }
    public IReadOnlyList<string> Arguments { get; }

    /// <summary>Appelé pour chaque ligne de sortie standard, puis avec <c>null</c> en fin de flux.</summary>
    public Action<string?>? OnOutput { get; init; }

    /// <summary>Appelé pour chaque ligne d'erreur, puis avec <c>null</c> en fin de flux.</summary>
    public Action<string?>? OnError { get; init; }

    public Encoding OutputEncoding { get; init; } = new UTF8Encoding(false);

    /// <summary>Dossiers que l'analyseur doit lire (règles, signatures, copies d'analyse).</summary>
    public IReadOnlyList<string> ReadableDirectories { get; init; } = Array.Empty<string>();
}

/// <summary>
/// Processus d'analyseur (<c>yara</c>, <c>yarac</c>, <c>clamscan</c>). Sous SYSTEM, il est
/// lancé dans l'AppContainer de clamd (<see cref="ScannerSandbox"/>) ; ailleurs, c'est un
/// processus ordinaire du compte de l'utilisateur, qui n'a pas plus de droits que lui.
/// </summary>
internal abstract class ScannerProcess : IDisposable
{
    /// <summary>Lance l'analyseur. Sous SYSTEM, un échec du confinement lève une exception.</summary>
    public static ScannerProcess Start(ScannerLaunch launch)
    {
        ArgumentNullException.ThrowIfNull(launch);
        return ScannerSandbox.IsRequired
            ? ContainedScannerProcess.Launch(launch)
            : PlainScannerProcess.Launch(launch);
    }

    /// <summary>Vrai si le processus s'exécute dans l'AppContainer.</summary>
    public abstract bool IsContained { get; }

    public abstract bool HasExited { get; }

    /// <summary>Code de sortie ; -1 si le processus n'est pas terminé ou a été arrêté sans code lisible.</summary>
    public abstract int ExitCode { get; }

    /// <summary>
    /// Attend la fin du processus et la lecture complète de ses sorties. Lève
    /// <see cref="OperationCanceledException"/> si <paramref name="ct"/> est annulé (le processus
    /// n'est pas arrêté pour autant : voir <see cref="Kill"/>).
    /// </summary>
    public abstract Task WaitForExitAsync(CancellationToken ct);

    /// <summary>Attente synchrone bornée de la fin du processus et de ses sorties.</summary>
    public abstract void WaitForExit(TimeSpan timeout);

    /// <summary>Arrête le processus (et ses enfants), sans lever d'exception.</summary>
    public abstract void Kill();

    public abstract void Dispose();

    /// <summary>
    /// Ligne de commande Windows dont <c>CommandLineToArgvW</c> rend exactement
    /// <paramref name="arguments"/> (règles de la CRT Microsoft).
    /// </summary>
    internal static string BuildCommandLine(string executable, IEnumerable<string> arguments)
    {
        var sb = new StringBuilder();
        AppendQuoted(sb, executable, forceQuotes: true);
        foreach (var argument in arguments)
        {
            sb.Append(' ');
            AppendQuoted(sb, argument, forceQuotes: false);
        }
        return sb.ToString();
    }

    private static readonly System.Buffers.SearchValues<char> QuoteTriggers =
        System.Buffers.SearchValues.Create(" \t\n\v\"");

    private static void AppendQuoted(StringBuilder sb, string argument, bool forceQuotes)
    {
        ArgumentNullException.ThrowIfNull(argument);
        if (argument.Contains('\0'))
            throw new ArgumentException("Argument contenant un caractère NUL.", nameof(argument));

        if (!forceQuotes && argument.Length > 0 && argument.AsSpan().IndexOfAny(QuoteTriggers) < 0)
        {
            sb.Append(argument);
            return;
        }

        sb.Append('"');
        var backslashes = 0;
        foreach (var c in argument)
        {
            if (c == '\\')
            {
                backslashes++;
                continue;
            }

            if (c == '"')
            {
                sb.Append('\\', backslashes * 2 + 1);
                sb.Append('"');
            }
            else
            {
                sb.Append('\\', backslashes);
                sb.Append(c);
            }
            backslashes = 0;
        }
        sb.Append('\\', backslashes * 2);
        sb.Append('"');
    }

    private sealed class PlainScannerProcess : ScannerProcess
    {
        private readonly Process _process;
        private readonly TaskCompletionSource _outputDone = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _errorDone = new(TaskCreationOptions.RunContinuationsAsynchronously);

        private PlainScannerProcess(Process process) => _process = process;

        public static PlainScannerProcess Launch(ScannerLaunch launch)
        {
            var psi = new ProcessStartInfo
            {
                FileName = launch.Executable,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                StandardOutputEncoding = launch.OutputEncoding,
            };
            foreach (var argument in launch.Arguments)
                psi.ArgumentList.Add(argument);

            var process = new Process { StartInfo = psi };
            var wrapper = new PlainScannerProcess(process);
            process.OutputDataReceived += (_, e) =>
            {
                launch.OnOutput?.Invoke(e.Data);
                if (e.Data == null)
                    wrapper._outputDone.TrySetResult();
            };
            process.ErrorDataReceived += (_, e) =>
            {
                launch.OnError?.Invoke(e.Data);
                if (e.Data == null)
                    wrapper._errorDone.TrySetResult();
            };

            try
            {
                process.Start();
                process.BeginOutputReadLine();
                process.BeginErrorReadLine();
            }
            catch
            {
                process.Dispose();
                throw;
            }
            return wrapper;
        }

        public override bool IsContained => false;

        public override bool HasExited
        {
            get
            {
                try { return _process.HasExited; }
                catch (InvalidOperationException) { return true; }
            }
        }

        public override int ExitCode
        {
            get
            {
                try { return _process.HasExited ? _process.ExitCode : -1; }
                catch (InvalidOperationException) { return -1; }
            }
        }

        public override async Task WaitForExitAsync(CancellationToken ct)
        {
            await _process.WaitForExitAsync(ct).ConfigureAwait(false);
            await Task.WhenAll(_outputDone.Task, _errorDone.Task).WaitAsync(ct).ConfigureAwait(false);
        }

        public override void WaitForExit(TimeSpan timeout)
        {
            try
            {
                if (_process.WaitForExit(timeout))
                    Task.WhenAll(_outputDone.Task, _errorDone.Task).Wait(timeout);
            }
            catch (InvalidOperationException)
            {
                /* processus jamais démarré */
            }
        }

        public override void Kill()
        {
            try
            {
                if (!_process.HasExited)
                    _process.Kill(entireProcessTree: true);
            }
            catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or NotSupportedException)
            {
                AppLogger.Debug("ScannerProcess", "Arrêt : " + ex.Message);
            }
        }

        public override void Dispose() => _process.Dispose();
    }

    private sealed class ContainedScannerProcess : ScannerProcess
    {
        private readonly ClamdIsolation.ContainedScanner _scanner;
        private readonly Task _exited;
        private readonly Task _drained;
        private readonly RegisteredWaitHandle _registration;
        private readonly ManualResetEvent _exitEvent;

        private ContainedScannerProcess(ClamdIsolation.ContainedScanner scanner, ScannerLaunch launch)
        {
            _scanner = scanner;
            var exited = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            _exitEvent = new ManualResetEvent(false) { SafeWaitHandle = new Microsoft.Win32.SafeHandles.SafeWaitHandle(scanner.Process.DangerousGetHandle(), ownsHandle: false) };
            _registration = ThreadPool.RegisterWaitForSingleObject(
                _exitEvent, (_, _) => exited.TrySetResult(), null, Timeout.Infinite, executeOnlyOnce: true);
            _exited = exited.Task;
            _drained = Task.WhenAll(
                PumpAsync(scanner.Output, launch.OutputEncoding, launch.OnOutput),
                PumpAsync(scanner.Error, launch.OutputEncoding, launch.OnError));
        }

        public static ContainedScannerProcess Launch(ScannerLaunch launch)
        {
            var workingDirectory = Path.GetDirectoryName(launch.Executable) ?? ScannerSandbox.WorkDirectory;
            var readable = new List<string>(launch.ReadableDirectories) { ScannerSandbox.WorkDirectory };
            var scanner = ClamdIsolation.StartScanner(
                launch.Executable,
                BuildCommandLine(launch.Executable, launch.Arguments),
                workingDirectory,
                readable,
                new[] { ScannerSandbox.WorkDirectory });
            if (Interlocked.Exchange(ref _announced, 1) == 0)
                AppLogger.Info("ScannerProcess", "Analyseurs confinés dans l'AppContainer (PID " + scanner.ProcessId + ", " + Path.GetFileName(launch.Executable) + ").");
            return new ContainedScannerProcess(scanner, launch);
        }

        private static int _announced;

        private static Task PumpAsync(Microsoft.Win32.SafeHandles.SafeFileHandle handle, Encoding encoding, Action<string?>? onLine) =>
            Task.Run(() =>
            {
                try
                {
                    using var stream = new FileStream(handle, FileAccess.Read, 4096, isAsync: false);
                    using var reader = new StreamReader(stream, encoding, detectEncodingFromByteOrderMarks: false);
                    string? line;
                    while ((line = reader.ReadLine()) != null)
                        onLine?.Invoke(line);
                }
                catch (IOException ex)
                {
                    // Tube rompu à l'arrêt de l'analyseur : fin de flux.
                    AppLogger.Debug("ScannerProcess", "Lecture de la sortie : " + ex.Message);
                }
                catch (ObjectDisposedException)
                {
                    /* processus libéré pendant la lecture */
                }
                finally
                {
                    onLine?.Invoke(null);
                }
            });

        public override bool IsContained => true;

        public override bool HasExited => _exited.IsCompleted;

        public override int ExitCode => _scanner.TryGetExitCode(out var code) ? code : -1;

        public override async Task WaitForExitAsync(CancellationToken ct)
        {
            await _exited.WaitAsync(ct).ConfigureAwait(false);
            await _drained.WaitAsync(ct).ConfigureAwait(false);
        }

        public override void WaitForExit(TimeSpan timeout)
        {
            try
            {
                if (_exited.Wait(timeout))
                    _drained.Wait(timeout);
            }
            catch (AggregateException ex)
            {
                AppLogger.Debug("ScannerProcess", "Attente : " + ex.InnerException?.Message);
            }
        }

        public override void Kill() => _scanner.Terminate();

        public override void Dispose()
        {
            _registration.Unregister(null);
            _exitEvent.Dispose();
            _scanner.Dispose();
        }
    }
}

/// <summary>Quand et où les analyseurs sont confinés.</summary>
internal static class ScannerSandbox
{
    private static readonly Lazy<bool> RunningAsSystem = new(() =>
    {
        if (!OperatingSystem.IsWindows())
            return false;
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return identity.IsSystem;
        }
        catch (System.Security.SecurityException)
        {
            return false;
        }
    });

    /// <summary>Remplace la détection du compte (tests).</summary>
    internal static bool? OverrideRequired { get; set; }

    /// <summary>
    /// Vrai sous SYSTEM : les contenus analysés viennent d'autres comptes, un analyseur
    /// compromis ne doit pas obtenir les droits du service.
    /// </summary>
    internal static bool IsRequired => OverrideRequired ?? RunningAsSystem.Value;

    private const string WorkFolderName = "scanner-work";

    /// <summary>
    /// Dossier où l'analyseur confiné peut écrire (listes de cibles, fichiers temporaires,
    /// règles compilées). Sous SYSTEM : %ProgramData%\optiSCAN\scanner-work.
    /// </summary>
    internal static string WorkDirectory
    {
        get
        {
            if (IsRequired && OverrideRequired == null)
            {
                if (!OptiScanProgramData.EnsureTrusted())
                    throw new InvalidOperationException("Le stockage sécurisé du service est indisponible.");
                return Path.Combine(OptiScanProgramData.DirectoryPath, WorkFolderName);
            }
            return Path.Combine(Path.GetTempPath(), "optiscan_" + WorkFolderName);
        }
    }

    /// <summary>Chemin d'un fichier temporaire que l'analyseur pourra lire.</summary>
    internal static string NewWorkFile(string prefix, string extension)
    {
        var directory = IsRequired ? WorkDirectory : Path.GetTempPath();
        Directory.CreateDirectory(directory);
        return Path.Combine(directory, prefix + Guid.NewGuid().ToString("N") + extension);
    }

    /// <summary>
    /// Dossier des copies d'analyse, à rendre lisible par l'analyseur confiné. Les autres
    /// cibles (dossiers d'utilisateurs) restent illisibles pour lui : sous SYSTEM, le service
    /// n'analyse que des copies (<see cref="ScanStaging"/>).
    /// </summary>
    internal static IReadOnlyList<string> StagingDirectories()
    {
        if (!IsRequired)
            return Array.Empty<string>();
        try
        {
            var root = ScanStaging.Root;
            Directory.CreateDirectory(root);
            return new[] { root };
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            AppLogger.Warn("ScannerSandbox", "Dossier des copies d'analyse", ex);
            return Array.Empty<string>();
        }
    }
}
