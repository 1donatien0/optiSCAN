using optiSCAN.Models;
using optiSCAN.Services;
using System.Windows;
using WinApplication = System.Windows.Application;

namespace optiSCAN
{
    public partial class App : WinApplication
    {
        private static Mutex? _instanceMutex;
        private const string MutexName = "Global\\optiSCAN_UniqueInstance";

        // Modes headless supportés en ligne de commande (utilisés par la tâche
        // planifiée Windows et l'automatisation). En mode headless, l'UI WPF
        // n'est jamais affichée — l'app exécute le scan demandé puis Shutdown.
        private const string ArgFullScan = "--fullscan";
        private const string ArgQuickScan = "--quickscan";
        private const string ArgQuiet = "--quiet";

        protected override async void OnStartup(StartupEventArgs e)
        {
            // ── Mode headless ────────────────────────────────────────────────
            // Détecté en premier pour éviter d'afficher la fenêtre principale.
            // ScheduledScanService crée la tâche schtasks avec --fullscan --quiet ;
            // sans ce parsing, l'app se lançait simplement avec son UI.
            var headlessMode = ParseHeadlessMode(e.Args);
            if (headlessMode != HeadlessMode.None)
            {
                ShutdownMode = ShutdownMode.OnExplicitShutdown;
                base.OnStartup(e);
                await RunHeadlessAsync(headlessMode, IsQuiet(e.Args));
                Shutdown();
                return;
            }

            // ── Single-instance ──────────────────────────────────────────────
            bool createdNew;
            _instanceMutex = new Mutex(true, MutexName, out createdNew);

            if (!createdNew)
            {
                // Une autre instance tourne : on lui demande de remonter sa fenêtre
                // via le message broadcast géré par IpcManager (audit A5).
                Services.IpcManager.NotifyShowExistingInstance();
                _instanceMutex.Close();
                _instanceMutex = null;
                Shutdown();
                return;
            }

            base.OnStartup(e);
            // Applique le thème Donaby + MaterialDesign selon UserPreferences (sinon
            // seul le dictionnaire fusionné dans App.xaml est actif — incohérence).
            ThemeManager.Initialize();
        }

        // ── Headless ────────────────────────────────────────────────────────────

        private enum HeadlessMode { None, FullScan, QuickScan }

        private static HeadlessMode ParseHeadlessMode(string[] args)
        {
            foreach (var a in args)
            {
                if (string.Equals(a, ArgFullScan, StringComparison.OrdinalIgnoreCase))
                    return HeadlessMode.FullScan;
                if (string.Equals(a, ArgQuickScan, StringComparison.OrdinalIgnoreCase))
                    return HeadlessMode.QuickScan;
            }
            return HeadlessMode.None;
        }

        private static bool IsQuiet(string[] args)
            => args.Any(a => string.Equals(a, ArgQuiet, StringComparison.OrdinalIgnoreCase));

        private async Task RunHeadlessAsync(HeadlessMode mode, bool quiet)
        {
            try
            {
                var clamAv = new ClamAvEngine();
                var yara = new YaraEngine();
                var orchestrator = new ScanOrchestrator(clamAv, yara);
                var quarantine = new QuarantineManager();
                var logger = new ScanLogManager();

                logger.WriteToLog($"[Headless] Démarrage — mode {mode}, quiet={quiet}");

                ScanResult result = mode switch
                {
                    HeadlessMode.FullScan => await orchestrator.FullScanAsync(),
                    HeadlessMode.QuickScan => await orchestrator.QuickScanAsync(),
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
                    int q = quarantine.QuarantineAll(result.Threats);
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
        }
    }

    // NativeMethods retiré : la logique IPC est désormais dans
    // Services.IpcManager (audit A5 — décomposition de MainWindow).
}