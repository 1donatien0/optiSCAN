using optiSCAN.Localization;
using optiSCAN.Models;
using optiSCAN.Services;
using System.Windows;
using WinApplication = System.Windows.Application;

namespace optiSCAN
{
    /// <summary>
    /// Point d'entrée de l'application WPF optiSCAN.
    /// Gère l'instance unique (mutex), le mode headless (scans planifiés sans UI)
    /// et l'initialisation du thème au démarrage.
    /// </summary>
    public partial class App : WinApplication
    {
        private static Mutex? _instanceMutex;
        private const string MutexName = "Global\\optiSCAN_UniqueInstance";

        /// <summary>Session garde : RTP active, fenêtre masquée (systray).</summary>
        public static bool GuardSession { get; private set; }

        /// <summary>
        /// Appelé au démarrage de l'application. Gère dans l'ordre :
        /// le mode headless (scan sans UI), puis le contrôle d'instance unique,
        /// et enfin l'initialisation du thème pour le mode normal.
        /// </summary>
        protected override async void OnStartup(StartupEventArgs e)
        {
            LocalizationService.Initialize();

            // ── Mode headless ────────────────────────────────────────────────
            // Détecté en premier pour éviter d'afficher la fenêtre principale.
            // ScheduledScanService crée la tâche schtasks avec --fullscan --quiet ;
            // sans ce parsing, l'app se lançait simplement avec son UI.
            var headlessMode = HeadlessScanArguments.ParseMode(e.Args);
            if (headlessMode == HeadlessScanArguments.Mode.Watchdog)
            {
                ShutdownMode = ShutdownMode.OnExplicitShutdown;
                base.OnStartup(e);
                TamperProtectionService.RunWatchdogCheck();
                Shutdown();
                return;
            }

            if (headlessMode == HeadlessScanArguments.Mode.ServiceHost)
            {
                bool createdService;
                _instanceMutex = new Mutex(true, "Global\\optiSCAN_ServiceHost", out createdService);
                if (!createdService)
                {
                    Shutdown();
                    return;
                }

                ShutdownMode = ShutdownMode.OnExplicitShutdown;
                await RunServiceHostAsync();
                Shutdown();
                return;
            }

            if (headlessMode is HeadlessScanArguments.Mode.FullScan or HeadlessScanArguments.Mode.QuickScan)
            {
                bool createdHeadless;
                _instanceMutex = new Mutex(true, MutexName, out createdHeadless);
                if (!createdHeadless)
                {
                    try { new ScanLogManager().WriteToLog("[Headless] Instance déjà active — scan ignoré."); }
                    catch { /* ignore */ }
                    _instanceMutex.Close();
                    _instanceMutex = null;
                    Shutdown();
                    return;
                }

                ShutdownMode = ShutdownMode.OnExplicitShutdown;
                base.OnStartup(e);
                await RunHeadlessAsync(headlessMode, HeadlessScanArguments.IsQuiet(e.Args));
                Shutdown();
                return;
            }

            // ── Single-instance ──────────────────────────────────────────────
            bool createdNew;
            _instanceMutex = new Mutex(true, MutexName, out createdNew);

            if (!createdNew)
            {
                // Une autre instance tourne : on lui demande de remonter sa fenêtre
                // via le message broadcast géré par IpcManager.
                Services.IpcManager.NotifyShowExistingInstance();
                _instanceMutex.Close();
                _instanceMutex = null;
                Shutdown();
                return;
            }

            GuardSession = headlessMode == HeadlessScanArguments.Mode.Guard
                || headlessMode == HeadlessScanArguments.Mode.ServiceHost;

            base.OnStartup(e);
            // Thème : ThemeManager.Initialize() dans MainWindow (avant InitializeComponent).
        }

        // ── Headless ────────────────────────────────────────────────────────────

        /// <summary>
        /// Exécute un scan en mode headless (sans fenêtre WPF), persiste le résultat
        /// dans l'historique et déclenche la quarantaine automatique si configurée.
        /// </summary>
        private async Task RunHeadlessAsync(HeadlessScanArguments.Mode mode, bool quiet)
        {
            try
            {
                var container = ServiceContainer.Default;
                var orchestrator = container.Orchestrator;
                var quarantine = container.Quarantine;
                var logger = container.Logger;

                logger.WriteToLog($"[Headless] Démarrage — mode {mode}, quiet={quiet}");

                DistractionFreeMonitor.Start();
                if (UserPreferences.Current.GameModeAutoEnabled
                    && DistractionFreeMonitor.ShouldSuppressNotifications())
                {
                    logger.WriteToLog("[Headless] Scan reporté — mode jeu / plein écran actif.");
                    return;
                }

                if (mode == HeadlessScanArguments.Mode.FullScan && !ElevationHelper.IsRunningElevated())
                    logger.WriteToLog("[Headless] Analyse complète sans élévation — dossiers système partiels.");

                ScanResult result = mode switch
                {
                    HeadlessScanArguments.Mode.FullScan => await orchestrator.FullScanAsync(),
                    HeadlessScanArguments.Mode.QuickScan => await orchestrator.QuickScanAsync(),
                    _ => throw new InvalidOperationException("Mode headless non supporté")
                };

                logger.SaveScanResult(result);
                logger.WriteToLog(
                    $"[Headless] Terminé — {result.FilesScanned} fichier(s), " +
                    $"{result.ThreatsFound} menace(s), statut {result.Status}");

                // Quarantaine automatique en mode headless si l'utilisateur l'a
                // configurée — sinon les menaces sont simplement journalisées.
                if (ExclusionSettings.Current.AutoQuarantineEnabled)
                {
                    int q = quarantine.QuarantineAll(result.Threats, result.SessionId);
                    logger.WriteToLog($"[Headless] Quarantaine automatique : {q} fichier(s)");
                }

                // Notification optionnelle de fin (sauf si --quiet)
                if (!quiet && result.ThreatsFound > 0)
                {
                    try
                    {
                        var notifs = new NotificationService();
                        notifs.ShowScanCompleted(result.ThreatsFound, result.FilesScanned);
                    }
                    catch (Exception ex)
                    {
                        logger.WriteToLog($"[Headless] Notification: {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                // En mode headless, pas d'UI pour afficher l'erreur — log only.
                try { new ScanLogManager().WriteToLog($"[Headless] FATAL: {ex}"); }
                catch { /* dernier recours */ }
            }
        }

        private static async Task RunServiceHostAsync()
        {
            try
            {
                using var host = new ProtectionServiceHost();
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
                catch { /* ignore */ }
            }
        }

        /// <summary>
        /// Appelé à la fermeture de l'application. Libère le mutex d'instance unique
        /// et délègue à <see cref="ServiceContainer.Shutdown"/> pour disposer les services.
        /// </summary>
        protected override void OnExit(ExitEventArgs e)
        {
            // ReleaseMutex doit être appelé sur le même thread que celui qui a
            // appelé WaitOne/Constructor. WPF garantit OnStartup et OnExit sur
            // le thread UI, donc c'est OK ici. On enrobe quand même en try
            // pour le cas où la mutex serait déjà libérée (ApplicationException).
            if (_instanceMutex != null)
            {
                try { _instanceMutex.ReleaseMutex(); }
                catch (ApplicationException ex)
                {
                    // Mutex non détenue par le thread courant — incohérence.
                    Services.AppLogger.Warn("App", "ReleaseMutex sur mauvais thread", ex);
                }
                catch (Exception ex)
                {
                    Services.AppLogger.Warn("App", "ReleaseMutex", ex);
                }
                try { _instanceMutex.Dispose(); } catch { }
                _instanceMutex = null;
            }
            base.OnExit(e);
            try { Services.ServiceContainer.Default.Shutdown(); }
            catch (Exception ex) { Services.AppLogger.Warn("App", "ServiceContainer.Shutdown", ex); }
        }
    }

    // NativeMethods retiré : la logique IPC est désormais dans
    // Logique IPC : Services.IpcManager.
}