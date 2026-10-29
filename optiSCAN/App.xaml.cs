// SPDX-License-Identifier: GPL-3.0-or-later
using optiSCAN.Localization;
using optiSCAN.Models;
using optiSCAN.Services;
using System.Security.Principal;
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
        private const string MutexName = AppInstanceGate.MutexName;

        /// <summary>
        /// Vrai dans les modes sans fenêtre (hôte SYSTEM, scans planifiés, actions élevées) :
        /// aucune boîte de dialogue d'erreur. Dans l'hôte, en session 0, personne ne peut la
        /// fermer : elle bloquait le thread (finaliseur compris) et empêchait un processus
        /// condamné de se terminer, donc d'être relancé par le service (audit V5).
        /// </summary>
        private static volatile bool _noInteractiveUi;

        /// <summary>Session garde : RTP active, fenêtre masquée (systray).</summary>
        public static bool GuardSession { get; private set; }

        /// <summary>Chemin en attente depuis le menu contextuel Explorateur (<c>--scan</c>).</summary>
        public static string? PendingShellScanPath { get; internal set; }

        /// <summary>
        /// Appelé au démarrage de l'application. Gère dans l'ordre :
        /// le mode headless (scan sans UI), puis le contrôle d'instance unique,
        /// et enfin l'initialisation du thème pour le mode normal.
        /// </summary>
        protected override async void OnStartup(StartupEventArgs e)
        {
            // WPF charge StartupUri (MainWindow.xaml) dès le retour de OnStartup, même après
            // Shutdown() : le constructeur de la fenêtre créait alors ServiceContainer, l'icône de
            // la zone de notification et le ViewModel dans chaque mode sans interface. Pire, le
            // scan planifié (--fullscan --quiet) rend la main à son premier await : la fenêtre
            // s'affichait pendant toute l'analyse. Elle n'est rendue qu'à l'interface normale.
            var mainWindowUri = StartupUri;
            StartupUri = null;

            var earlyMode = HeadlessScanArguments.ParseMode(e.Args);
            _noInteractiveUi = !Environment.UserInteractive
                || earlyMode is not (HeadlessScanArguments.Mode.None
                    or HeadlessScanArguments.Mode.Guard
                    or HeadlessScanArguments.Mode.ServiceQuarantine);
            if (earlyMode == HeadlessScanArguments.Mode.ClamdStub)
            {
                ShutdownMode = ShutdownMode.OnExplicitShutdown;
#if OPTISCAN_TEST_HOOKS
                // Faux clamd des tests d'isolation : absent du binaire publié (dotnet publish).
                if (string.Equals(Environment.GetEnvironmentVariable("OPTISCAN_CLAMD_STUB"), "1", StringComparison.Ordinal)
                    && HeadlessScanArguments.TryParseClamdStub(e.Args, out var stubPort))
                {
                    try { ClamdLoopbackStub.Run(stubPort); }
                    catch (Exception ignored) when (!ignored.IsFatal()) { /* processus arrêté */ }
                }
#endif
                // Environment.Exit et non Shutdown() : Shutdown passe par OnExit, qui crée
                // ServiceContainer.Default (réglages, quarantaine, journaux) dans ce processus
                // auxiliaire. Il n'a rien à libérer : sortie immédiate voulue.
                Environment.Exit(0);
            }

            if (earlyMode == HeadlessScanArguments.Mode.ClamdRelay)
            {
                ShutdownMode = ShutdownMode.OnExplicitShutdown;
                if (HeadlessScanArguments.TryParseClamdRelay(e.Args, out var relayPort, out var relayParent, out var relayFile))
                {
                    try { ClamdRelay.Run(relayPort, relayParent, relayFile); }
                    catch (Exception ignored) when (!ignored.IsFatal()) { /* processus arrêté */ }
                }
                // Relais lancé dans l'AppContainer de clamd : Shutdown() passerait par OnExit et
                // créerait ServiceContainer.Default dans le conteneur. Sortie immédiate voulue.
                Environment.Exit(0);
            }

            // Avant TOUT : capter les exceptions non gérées. Sans cela, une exception
            // au démarrage tue le process silencieusement (« l'app disparaît du
            // gestionnaire des tâches sans message »). Désormais elles sont
            // journalisées (%LOCALAPPDATA%\optiSCAN\Logs) et affichées à l'écran.
            InstallGlobalCrashHandlers();

            // Après les modes auxiliaires (relais et faux clamd dans l'AppContainer) : le
            // constructeur statique de LocalizationService lit le profil, inaccessible au conteneur.
            LocalizationService.ShutdownRequested = () => Current?.Shutdown();
            LocalizationService.Initialize();

            if (ShellScanArguments.TryGetScanPath(e.Args, out var shellPath)
                && ElevationHelper.NeedsElevation(shellPath)
                && !ElevationHelper.IsRunningElevated())
            {
                if (ElevationHelper.RelaunchElevated(ShellScanArguments.Scan, shellPath))
                {
                    Shutdown();
                    return;
                }
            }

            // ── Mode headless ────────────────────────────────────────────────
            // Détecté en premier pour éviter d'afficher la fenêtre principale.
            // ScheduledScanService crée la tâche schtasks avec --fullscan --quiet ;
            // sans ce parsing, l'app se lançait simplement avec son UI.
            var headlessMode = HeadlessScanArguments.ParseMode(e.Args);

            // Processus élevé (relance UAC, outil admin) : retirer une fois par version les
            // exclusions Defender de la 3.0.0, même si la mise à jour n'est pas passée par l'installeur.
            if (headlessMode is not (HeadlessScanArguments.Mode.CleanupLegacyDefenderExclusions
                    or HeadlessScanArguments.Mode.RemoveDefenderExclusions))
                DefenderLegacyCleanup.TryRunOnceInBackground();

            if (headlessMode == HeadlessScanArguments.Mode.Watchdog)
            {
                ShutdownMode = ShutdownMode.OnExplicitShutdown;
                base.OnStartup(e);
                ProtectionWatchdogService.RunWatchdogCheck();
                Shutdown();
                return;
            }

            if (headlessMode == HeadlessScanArguments.Mode.DefenderExclusions)
            {
                ShutdownMode = ShutdownMode.OnExplicitShutdown;
                base.OnStartup(e);
                WindowsDefenderExclusionService.EnsureOptiscanExclusions();
                Shutdown();
                return;
            }

            if (headlessMode == HeadlessScanArguments.Mode.RemoveDefenderExclusions)
            {
                ShutdownMode = ShutdownMode.OnExplicitShutdown;
                base.OnStartup(e);
                WindowsDefenderExclusionService.RemoveOptiscanExclusions();
                Shutdown();
                return;
            }

            if (headlessMode == HeadlessScanArguments.Mode.CleanupLegacyDefenderExclusions)
            {
                // Lancé par l'installeur (élevé) : retire les exclusions des versions 3.0.0.
                ShutdownMode = ShutdownMode.OnExplicitShutdown;
                base.OnStartup(e);
                DefenderLegacyCleanup.RunAndMark();
                Shutdown();
                return;
            }

            if (headlessMode == HeadlessScanArguments.Mode.PushHostPolicy)
            {
                // Instance élevée lancée par l'interface pour un réglage qui réduit la protection.
                ShutdownMode = ShutdownMode.OnExplicitShutdown;
                base.OnStartup(e);
                HostPolicyStore.PushFromElevatedProcess(HeadlessScanArguments.GetPushHostPolicyArgument(e.Args));
                Shutdown();
                return;
            }

            if (headlessMode == HeadlessScanArguments.Mode.ServiceQuarantine)
            {
                // Instance élevée lancée par l'onglet Quarantaine : n'ouvre que l'administration
                // de la quarantaine du service, hors instance unique (l'interface reste ouverte).
                base.OnStartup(e);
                if (!ElevationHelper.IsRunningElevated())
                {
                    AppLogger.Warn("App", "--service-quarantine refusé : processus non élevé");
                    Shutdown();
                    return;
                }

                // Pas de MainWindow.xaml (StartupUri) : seule cette fenêtre s'ouvre.
                StartupUri = null;
                ThemeManager.Initialize();
                ShutdownMode = ShutdownMode.OnMainWindowClose;
                var window = new Views.ServiceQuarantineWindow { WindowStartupLocation = WindowStartupLocation.CenterScreen };
                MainWindow = window;
                window.Show();
                return;
            }

            if (headlessMode == HeadlessScanArguments.Mode.ClearDefenderHistory)
            {
                ShutdownMode = ShutdownMode.OnExplicitShutdown;
                base.OnStartup(e);
                // Tâche laissée par une version antérieure : la fonction est retirée,
                // la tâche se supprime au lieu de vider l'historique Defender.
                SystemTweaksService.RemoveDefenderHistoryTask();
                Shutdown();
                return;
            }

            if (headlessMode == HeadlessScanArguments.Mode.ApplyTweaks)
            {
                ShutdownMode = ShutdownMode.OnExplicitShutdown;
                base.OnStartup(e);
                SystemTweaksService.ExecuteTweakIds(HeadlessScanArguments.ParseTweakIds(e.Args));
                Shutdown();
                return;
            }

            if (headlessMode == HeadlessScanArguments.Mode.ServiceHost)
            {
                // Depuis 3.1, l'hôte SYSTEM est optiSCAN.Host.exe (sans WPF). L'interface refuse ce mode.
                AppLogger.Warn("App", "--service-host refusé : l'hôte de protection est optiSCAN.Host.exe");
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
                    catch (Exception ignored) when (!ignored.IsFatal()) { /* ignore */ }
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
                if (ShellScanArguments.TryGetScanPath(e.Args, out var existingScanPath)
                    && ShellScanArguments.IsValidScanTarget(existingScanPath))
                {
                    ShellScanRequest.Publish(existingScanPath);
                    Services.IpcManager.NotifyShellScanRequest();
                }

                // Une autre instance tourne : on lui demande de remonter sa fenêtre
                // via le message broadcast géré par IpcManager.
                Services.IpcManager.NotifyShowExistingInstance();
                _instanceMutex.Close();
                _instanceMutex = null;
                Shutdown();
                return;
            }

            if (ShellScanArguments.TryGetScanPath(e.Args, out var pendingShellPath)
                && ShellScanArguments.IsValidScanTarget(pendingShellPath))
            {
                PendingShellScanPath = pendingShellPath;
            }

            GuardSession = headlessMode == HeadlessScanArguments.Mode.Guard
                || headlessMode == HeadlessScanArguments.Mode.ServiceHost;

            StartupUri = mainWindowUri;
            base.OnStartup(e);
            // Thème : ThemeManager.Initialize() dans MainWindow (avant InitializeComponent).
        }

        // ── Gestion globale des exceptions non gérées ────────────────────────────

        /// <summary>
        /// Branche les trois sources d'exceptions non gérées d'une app WPF :
        /// le thread UI (Dispatcher), les autres threads (AppDomain) et les
        /// tâches non observées (TaskScheduler). Garantit qu'aucun crash ne
        /// reste invisible : tout est journalisé et présenté à l'utilisateur.
        /// </summary>
        private void InstallGlobalCrashHandlers()
        {
            DispatcherUnhandledException += (_, args) =>
            {
                LogFatal("Dispatcher", args.Exception);
                var recoverable = IsRecoverableDispatcherException(args.Exception);
                ShowCrashDialog(args.Exception, CrashDialogKind.Dispatcher, terminating: !recoverable);
                args.Handled = recoverable;
            };

            AppDomain.CurrentDomain.UnhandledException += (_, args) =>
            {
                if (args.ExceptionObject is Exception ex)
                {
                    LogFatal("AppDomain", ex);
                    ShowCrashDialog(ex, CrashDialogKind.AppDomain, terminating: args.IsTerminating);
                }
            };

            System.Threading.Tasks.TaskScheduler.UnobservedTaskException += (_, args) =>
            {
                LogFatal("UnobservedTask", args.Exception);
                args.SetObserved();
                ShowCrashDialog(
                    args.Exception.GetBaseException(),
                    CrashDialogKind.BackgroundTask);
            };
        }

        private enum CrashDialogKind
        {
            Dispatcher,
            AppDomain,
            BackgroundTask,
        }

        /// <summary>
        /// Exceptions UI récupérables : l'utilisateur peut lire le message et continuer.
        /// Les autres provoquent un arrêt propre après fermeture du dialogue.
        /// </summary>
        private static bool IsRecoverableDispatcherException(Exception ex) =>
            ex is not (StackOverflowException or OutOfMemoryException or AccessViolationException);

        private static void LogFatal(string source, Exception ex)
        {
            try { Services.AppLogger.Fatal("UnhandledException", source, ex); }
            catch (Exception ignored) when (!ignored.IsFatal()) { /* le logging ne doit jamais aggraver un crash */ }
        }

        private static void ShowCrashDialog(
            Exception ex,
            CrashDialogKind kind,
            bool terminating = false)
        {
            if (_noInteractiveUi)
            {
                // Déjà journalisée par LogFatal. Un processus condamné se termine tout de suite :
                // le service relance l'hôte, la tâche planifiée se termine en erreur.
                if (terminating)
                    Environment.Exit(1);
                return;
            }

            try
            {
                var title = kind switch
                {
                    CrashDialogKind.BackgroundTask => "optiSCAN — Erreur en arrière-plan",
                    _ when Current?.MainWindow == null => "optiSCAN — Erreur au démarrage",
                    _ => "optiSCAN — Erreur inattendue",
                };

                var message =
                    "optiSCAN a rencontré une erreur non gérée :\n\n" +
                    ex.GetType().Name + " : " + ex.Message + "\n\n" +
                    "Détails complets (stack trace) enregistrés dans :\n" +
                    "%LOCALAPPDATA%\\optiSCAN\\Logs";

                if (terminating)
                    message += "\n\nL'application va se fermer.";

                void Show()
                {
                    System.Windows.MessageBox.Show(
                        message,
                        title,
                        System.Windows.MessageBoxButton.OK,
                        System.Windows.MessageBoxImage.Error);

                    if (terminating && Current != null)
                        Current.Shutdown(-1);
                }

                var dispatcher = Current?.Dispatcher;
                if (dispatcher != null && !dispatcher.CheckAccess())
                    dispatcher.Invoke(Show);
                else
                    Show();
            }
            catch (Exception ignored) when (!ignored.IsFatal()) { /* pas d'UI disponible (mode headless) → log seul */ }
        }

        // ── Headless ────────────────────────────────────────────────────────────

        /// <summary>
        /// Exécute un scan en mode headless (sans fenêtre WPF), persiste le résultat
        /// dans l'historique et déclenche la quarantaine automatique si configurée.
        /// </summary>
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
                if (container.ExclusionSettingsAccessor.Current.AutoQuarantineEnabled)
                {
                    int q = quarantine.QuarantineAll(result.Threats, result.SessionId);
                    logger.WriteToLog($"[Headless] Quarantaine automatique : {q} fichier(s)");
                }

                // Notification optionnelle de fin (sauf si --quiet)
                if (!quiet && result.ThreatsFound > 0)
                {
                    try
                    {
                        container.Notifications.ShowScanCompleted(result.ThreatsFound, result.FilesScanned);
                    }
                    catch (Exception ex) when (!ex.IsFatal())
                    {
                        logger.WriteToLog($"[Headless] Notification: {ex.Message}");
                    }
                }
            }
            catch (Exception ex) when (!ex.IsFatal())
            {
                // En mode headless, pas d'UI pour afficher l'erreur — log only.
                try { new ScanLogManager().WriteToLog($"[Headless] FATAL: {ex}"); }
                catch (Exception ignored) when (!ignored.IsFatal()) { /* dernier recours */ }
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
                catch (Exception ex) when (!ex.IsFatal())
                {
                    Services.AppLogger.Warn("App", "ReleaseMutex", ex);
                }
                try { _instanceMutex.Dispose(); }
                catch (Exception ex) when (!ex.IsFatal()) { Services.AppLogger.Debug("App", $"Dispose instance mutex: {ex.Message}"); }
                _instanceMutex = null;
            }
            base.OnExit(e);
            // Seconde instance, actions élevées, watchdog… : le conteneur n'a jamais servi.
            // Le créer ici pour le fermer aussitôt chargeait réglages, quarantaine et moteurs.
            if (!Services.ServiceContainer.IsCreated)
                return;
            try { Services.ServiceContainer.Default.Shutdown(); }
            catch (Exception ex) when (!ex.IsFatal()) { Services.AppLogger.Warn("App", "ServiceContainer.Shutdown", ex); }
        }
    }

    // NativeMethods retiré : la logique IPC est désormais dans
    // Logique IPC : Services.IpcManager.
}
