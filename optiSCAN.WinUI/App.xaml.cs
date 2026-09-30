using Microsoft.UI.Xaml;
using optiSCAN.Localization;
using optiSCAN.Models;
using optiSCAN.Services;

namespace optiSCAN.WinUI;

public partial class App : Application
{
    // Distinct du WPF (Global\optiSCAN_UniqueInstance) : les deux editions peuvent coexister.
    private const string MutexName = "Global\\optiSCAN_WinUI_UniqueInstance";

    /// <summary>
    /// Argument ajouté lors d'une relance volontaire (changement de langue, « Exécuter en administrateur ») :
    /// la nouvelle instance attend que l'ancienne libère le mutex au lieu de se fermer aussitôt.
    /// </summary>
    public const string RestartArgument = "--restart";

    private static readonly TimeSpan RestartMutexWait = TimeSpan.FromSeconds(20);
    private static Mutex? _instanceMutex;

    public static MainWindow? MainWindowInstance { get; private set; }

    public static bool GuardSession { get; internal set; }

    public static string? PendingShellScanPath { get; internal set; }

    public App()
    {
        InitializeComponent();
        // Changement de langue : fermeture propre (icône de notification, services, mutex) pour que
        // l'instance relancée puisse prendre le relais.
        LocalizationService.RequestApplicationShutdown = () =>
        {
            if (MainWindowInstance != null)
                MainWindowInstance.ExitApplication();
            else
            {
                ReleaseInstanceMutex();
                Current.Exit();
            }
        };
        UnhandledException += OnUnhandledException;
    }

    protected override async void OnLaunched(LaunchActivatedEventArgs args)
    {
        LocalizationService.Initialize();

        var launchArgs = Environment.GetCommandLineArgs().Skip(1).ToArray();

        if (ShellScanArguments.TryGetScanPath(launchArgs, out var shellPath)
            && ElevationHelper.NeedsElevation(shellPath)
            && !ElevationHelper.IsRunningElevated())
        {
            if (ElevationHelper.RelaunchElevated(ShellScanArguments.Scan, shellPath))
            {
                Exit();
                return;
            }
        }

        var headlessMode = HeadlessScanArguments.ParseMode(launchArgs);
        if (headlessMode == HeadlessScanArguments.Mode.Guard)
            GuardSession = true;

        if (headlessMode == HeadlessScanArguments.Mode.Watchdog)
        {
            TamperProtectionService.RunWatchdogCheck();
            Exit();
            return;
        }

        if (headlessMode == HeadlessScanArguments.Mode.DefenderExclusions)
        {
            WindowsDefenderExclusionService.EnsureOptiscanExclusions();
            Exit();
            return;
        }

        if (headlessMode == HeadlessScanArguments.Mode.ServiceHost)
        {
            bool createdService;
            _instanceMutex = new Mutex(true, "Global\\optiSCAN_ServiceHost", out createdService);
            if (!createdService)
            {
                Exit();
                return;
            }

            await RunServiceHostAsync().ConfigureAwait(true);
            Exit();
            return;
        }

        if (headlessMode is HeadlessScanArguments.Mode.FullScan or HeadlessScanArguments.Mode.QuickScan)
        {
            bool createdHeadless;
            _instanceMutex = new Mutex(true, MutexName, out createdHeadless);
            if (!createdHeadless)
            {
                try { new ScanLogManager().WriteToLog("[Headless] Instance déjà active — scan ignoré."); }
                catch { }
                _instanceMutex.Close();
                _instanceMutex = null;
                Exit();
                return;
            }

            await RunHeadlessAsync(headlessMode, HeadlessScanArguments.IsQuiet(launchArgs)).ConfigureAwait(true);
            Exit();
            return;
        }

        bool createdNew;
        _instanceMutex = new Mutex(true, MutexName, out createdNew);

        // Relance volontaire : l'ancienne instance est en train de se fermer. Sans cette attente,
        // la nouvelle voyait le mutex encore pris, se contentait de « réveiller » l'ancienne puis
        // quittait — résultat : plus aucune fenêtre après un changement de langue ou « Exécuter en admin ».
        if (!createdNew && launchArgs.Any(a => string.Equals(a, RestartArgument, StringComparison.OrdinalIgnoreCase)))
        {
            try { createdNew = _instanceMutex.WaitOne(RestartMutexWait); }
            catch (AbandonedMutexException) { createdNew = true; }
        }

        if (!createdNew)
        {
            if (ShellScanArguments.TryGetScanPath(launchArgs, out var existingScanPath)
                && ShellScanArguments.IsValidScanTarget(existingScanPath))
            {
                ShellScanRequest.Publish(existingScanPath);
                SingleInstanceMessaging.NotifyShellScanRequest();
            }

            SingleInstanceMessaging.NotifyShowExistingInstance();
            _instanceMutex.Close();
            _instanceMutex = null;
            Exit();
            return;
        }

        if (ShellScanArguments.TryGetScanPath(launchArgs, out var pendingShellPath)
            && ShellScanArguments.IsValidScanTarget(pendingShellPath))
        {
            PendingShellScanPath = pendingShellPath;
        }

        var window = new MainWindow();
        MainWindowInstance = window;
        window.Activate();
    }

    private static async Task RunHeadlessAsync(HeadlessScanArguments.Mode mode, bool quiet)
    {
        try
        {
            var container = ServiceContainer.Default;
            var orchestrator = container.Orchestrator;
            var quarantine = container.Quarantine;
            var logger = container.Logger;

            logger.WriteToLog($"[Headless] Démarrage — mode {mode}, quiet={quiet}");

            DistractionFreeMonitor.Start();
            if (container.UserPreferencesAccessor.Current.GameModeAutoEnabled
                && DistractionFreeMonitor.ShouldSuppressNotifications())
            {
                logger.WriteToLog("[Headless] Scan reporté — mode jeu / plein écran actif.");
                return;
            }

            if (mode == HeadlessScanArguments.Mode.FullScan && !ElevationHelper.IsRunningElevated())
                logger.WriteToLog("[Headless] Analyse complète sans élévation — dossiers système partiels.");

            ScanResult result = mode switch
            {
                HeadlessScanArguments.Mode.FullScan => await orchestrator.FullScanAsync().ConfigureAwait(false),
                HeadlessScanArguments.Mode.QuickScan => await orchestrator.QuickScanAsync().ConfigureAwait(false),
                _ => throw new InvalidOperationException("Mode headless non supporté")
            };

            logger.SaveScanResult(result);
            logger.WriteToLog(
                $"[Headless] Terminé — {result.FilesScanned} fichier(s), " +
                $"{result.ThreatsFound} menace(s), statut {result.Status}");

            if (container.ExclusionSettingsAccessor.Current.AutoQuarantineEnabled)
            {
                int q = quarantine.QuarantineAll(result.Threats, result.SessionId);
                logger.WriteToLog($"[Headless] Quarantaine automatique : {q} fichier(s)");
            }

            if (!quiet && result.ThreatsFound > 0)
            {
                try { container.Notifications.ShowScanCompleted(result.ThreatsFound, result.FilesScanned); }
                catch (Exception ex) { logger.WriteToLog($"[Headless] Notification: {ex.Message}"); }
            }
        }
        catch (Exception ex)
        {
            try { new ScanLogManager().WriteToLog($"[Headless] FATAL: {ex}"); }
            catch { }
        }
    }

    private static async Task RunServiceHostAsync()
    {
        try
        {
            using var host = new ProtectionServiceHost(ServiceContainer.Default);
            host.Start();
            new ScanLogManager().WriteToLog("[ServiceHost] Protection système active (IPC + RTP + processus)");

            var tcs = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            AppDomain.CurrentDomain.ProcessExit += (_, _) => tcs.TrySetResult();
            Console.CancelKeyPress += (_, e) =>
            {
                e.Cancel = true;
                tcs.TrySetResult();
            };
            await tcs.Task.ConfigureAwait(false);
            await host.StopAsync().ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            try { new ScanLogManager().WriteToLog($"[ServiceHost] FATAL: {ex}"); }
            catch { }
        }
    }

    internal static void ReleaseInstanceMutex()
    {
        if (_instanceMutex == null)
            return;

        try { _instanceMutex.ReleaseMutex(); }
        catch (ApplicationException) { }
        catch (ObjectDisposedException) { }

        try { _instanceMutex.Dispose(); }
        catch { }

        _instanceMutex = null;
    }

    private static void OnUnhandledException(object sender, Microsoft.UI.Xaml.UnhandledExceptionEventArgs e)
    {
        try
        {
            AppLogger.Fatal("WinUI", "UnhandledException", e.Exception);
        }
        catch { }

        try
        {
            var logDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "optiSCAN",
                "Logs");
            Directory.CreateDirectory(logDir);
            var crashLog = Path.Combine(logDir, "winui-crash.log");
            // Rotation simple : le fichier n'est pas concerné par la purge 30 j. d'AppLogger.
            if (File.Exists(crashLog) && new FileInfo(crashLog).Length > 1024 * 1024)
                File.Move(crashLog, crashLog + ".old", overwrite: true);
            File.AppendAllText(
                crashLog,
                $"[{DateTimeOffset.Now:O}] {e.Exception}\n");
        }
        catch { }

        // Une erreur dans un gestionnaire de clic ne doit pas fermer l'antivirus (protection temps réel,
        // icône de notification) : l'erreur est journalisée et l'application continue.
        e.Handled = true;
    }
}
