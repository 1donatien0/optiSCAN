using Microsoft.Win32;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;

namespace optiSCAN.Services
{
    /// <summary>
    /// Tweaks système du panneau Optimiser (port C# de l'ancien utilitaire
    /// PowerShell OptiWin) : performance, confidentialité, interface,
    /// maintenance. L'application tourne en asInvoker : les actions HKCU sont
    /// appliquées directement ; les actions qui exigent l'admin (HKLM, services,
    /// DISM, cache Windows Update) sont exécutées par une instance relancée avec
    /// une seule invite UAC (<c>--apply-tweaks</c>, identifiants en liste blanche),
    /// qui appelle les outils système directement (<see cref="ElevatedCommand"/>).
    /// </summary>
    [SupportedOSPlatform("windows")]
    public static class SystemTweaksService
    {
        // GUID du plan d'alimentation « Performances élevées » (constante Windows).
        private const string HighPerformancePlanGuid = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c";

        /// <summary>
        /// Nom de la tâche de démarrage (SYSTEM) que les versions antérieures créaient pour
        /// vider l'historique Defender. Fonction retirée : ce nom ne sert qu'au nettoyage
        /// (<see cref="RemoveDefenderHistoryTask"/>).
        /// </summary>
        public const string ClearDefenderHistoryTaskName = "optiSCAN-ClearDefenderHistory";

        // ── Helpers registre (HKCU uniquement — pas d'élévation requise) ─────
        private static void SetHkcuValue(string subKey, string name, int value)
        {
            using var key = Registry.CurrentUser.CreateSubKey(subKey, writable: true);
            key.SetValue(name, value, RegistryValueKind.DWord);
        }

        // ── Performance ──────────────────────────────────────────────────────

        /// <summary>Active le plan d'alimentation « Performances élevées ».</summary>
        public static bool EnableHighPerformancePowerPlan()
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = SystemExecutables.System32("powercfg.exe"),
                    UseShellExecute = false,
                    CreateNoWindow = true,
                };
                psi.ArgumentList.Add("/setactive");
                psi.ArgumentList.Add(HighPerformancePlanGuid);
                using var p = Process.Start(psi);
                p?.WaitForExit(15000);
                return p is { ExitCode: 0 };
            }
            catch (Exception ex)
            {
                AppLogger.Warn("SystemTweaksService", "powercfg /setactive", ex);
                return false;
            }
        }

        /// <summary>Effets visuels sur « Meilleures performances » (effet à la reconnexion).</summary>
        public static bool SetVisualEffectsBestPerformance()
        {
            try
            {
                SetHkcuValue(@"Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects",
                    "VisualFXSetting", 2);
                return true;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("SystemTweaksService", "VisualFXSetting", ex);
                return false;
            }
        }

        /// <summary>Ouvre le Gestionnaire des tâches sur l'onglet Démarrage.</summary>
        public static bool OpenStartupAppsManager()
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = SystemExecutables.System32("taskmgr.exe"),
                    Arguments = "/0 /startup",
                    UseShellExecute = true,
                });
                return true;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("SystemTweaksService", "taskmgr /startup", ex);
                return false;
            }
        }

        // ── Confidentialité (HKCU — sans élévation) ──────────────────────────

        /// <summary>Désactive l'identifiant publicitaire.</summary>
        public static bool DisableAdvertisingId()
        {
            try
            {
                SetHkcuValue(@"Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo",
                    "Enabled", 0);
                return true;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("SystemTweaksService", "AdvertisingInfo", ex);
                return false;
            }
        }

        /// <summary>Désactive suggestions et publicités (menu Démarrer, écran de verrouillage).</summary>
        public static bool DisableSuggestions()
        {
            const string cdm = @"Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager";
            string[] names =
            {
                "SubscribedContent-338387Enabled", "SubscribedContent-338388Enabled",
                "SubscribedContent-338389Enabled", "SubscribedContent-353694Enabled",
                "SubscribedContent-353696Enabled", "SystemPaneSuggestionsEnabled",
                "SilentInstalledAppsEnabled", "SoftLandingEnabled",
            };
            try
            {
                foreach (var n in names)
                    SetHkcuValue(cdm, n, 0);
                return true;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("SystemTweaksService", "ContentDeliveryManager", ex);
                return false;
            }
        }

        /// <summary>Désactive les expériences personnalisées.</summary>
        public static bool DisableTailoredExperiences()
        {
            try
            {
                SetHkcuValue(@"Software\Microsoft\Windows\CurrentVersion\Privacy",
                    "TailoredExperiencesWithDiagnosticDataEnabled", 0);
                return true;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("SystemTweaksService", "TailoredExperiences", ex);
                return false;
            }
        }

        // ── Interface (HKCU — sans élévation) ────────────────────────────────

        public static bool ShowFileExtensions() => TrySetAdvanced("HideFileExt", 0);
        public static bool ShowHiddenFiles() => TrySetAdvanced("Hidden", 1);
        public static bool AlignTaskbarLeft() => TrySetAdvanced("TaskbarAl", 0);
        public static bool HideTaskbarWidgets() => TrySetAdvanced("TaskbarDa", 0);
        public static bool ExplorerOpensThisPc() => TrySetAdvanced("LaunchTo", 1);

        /// <summary>Réduit la zone de recherche de la barre des tâches à une icône.</summary>
        public static bool SearchBoxAsIcon()
        {
            try
            {
                SetHkcuValue(@"Software\Microsoft\Windows\CurrentVersion\Search",
                    "SearchboxTaskbarMode", 1);
                return true;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("SystemTweaksService", "SearchboxTaskbarMode", ex);
                return false;
            }
        }

        private static bool TrySetAdvanced(string name, int value)
        {
            try
            {
                SetHkcuValue(@"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
                    name, value);
                return true;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("SystemTweaksService", $"Explorer\\Advanced {name}", ex);
                return false;
            }
        }

        /// <summary>
        /// Redémarre l'Explorateur pour appliquer les tweaks d'interface.
        /// Windows relance explorer.exe automatiquement ; on le relance
        /// nous-mêmes par sécurité si ce n'est pas le cas après 3 s.
        /// </summary>
        public static void RestartExplorer()
        {
            try
            {
                foreach (var p in Process.GetProcessesByName("explorer"))
                {
                    try { p.Kill(); }
                    catch (Exception ex) { AppLogger.Warn("SystemTweaksService", "Kill explorer", ex); }
                    finally { p.Dispose(); }
                }

                _ = Task.Run(async () =>
                {
                    await Task.Delay(3000).ConfigureAwait(false);
                    if (Process.GetProcessesByName("explorer").Length == 0)
                    {
                        Process.Start(new ProcessStartInfo
                        {
                            FileName = SystemExecutables.Explorer,
                            UseShellExecute = true,
                        });
                    }
                });
            }
            catch (Exception ex)
            {
                AppLogger.Warn("SystemTweaksService", "RestartExplorer", ex);
            }
        }

        // ── Réseau ───────────────────────────────────────────────────────────

        [DllImport("dnsapi.dll", EntryPoint = "DnsFlushResolverCache", SetLastError = false)]
        private static extern uint DnsFlushResolverCache();

        /// <summary>Vide le cache DNS (sans élévation, via dnsapi.dll).</summary>
        public static bool FlushDnsCache()
        {
            try
            {
                DnsFlushResolverCache();
                return true;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("SystemTweaksService", "DnsFlushResolverCache", ex);
                return false;
            }
        }

        // ── Actions nécessitant l'élévation (regroupées, une seule invite UAC) ─

        /// <summary>
        /// Outil système et arguments d'une étape élevée. Les outils sont appelés directement,
        /// par leur chemin dans System32 et avec <see cref="ProcessStartInfo.ArgumentList"/> :
        /// jamais par <c>cmd /c</c>, dont l'analyse des guillemets ne suit pas l'échappement
        /// <c>\"</c> que produit ArgumentList.
        /// </summary>
        public sealed record ElevatedCommand(string Tool, IReadOnlyList<string> Arguments, IReadOnlyCollection<int> AcceptedExitCodes)
        {
            public ElevatedCommand(string tool, params string[] arguments)
                : this(tool, arguments, new[] { 0 })
            {
            }

            public string FilePath => Path.Combine(Environment.SystemDirectory, Tool);

            public override string ToString() => Tool + " " + string.Join(' ', Arguments);
        }

        // Codes de sortie de sc.exe sans conséquence pour le but recherché.
        private const int ServiceDoesNotExist = 1060;
        private const int ServiceAlreadyRunning = 1056;
        private const int ServiceNotActive = 1062;

        // Dism.exe : opération réussie, redémarrage requis.
        private const int RebootRequired = 3010;

        /// <summary>Télémétrie au minimum et service DiagTrack désactivé.</summary>
        public static IEnumerable<ElevatedCommand> ElevatedTelemetryCommands()
        {
            yield return new ElevatedCommand(
                "reg.exe",
                "add", @"HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection",
                "/v", "AllowTelemetry", "/t", "REG_DWORD", "/d", "0", "/f");
            yield return new ElevatedCommand(
                "sc.exe", new[] { "stop", "DiagTrack" }, new[] { 0, ServiceNotActive, ServiceDoesNotExist });
            yield return new ElevatedCommand(
                "sc.exe", new[] { "config", "DiagTrack", "start=", "disabled" }, new[] { 0, ServiceDoesNotExist });
        }

        /// <summary>Nettoyage des composants Windows (DISM, lent).</summary>
        public static IEnumerable<ElevatedCommand> ElevatedDismCleanupCommands()
        {
            yield return new ElevatedCommand(
                "Dism.exe", new[] { "/Online", "/Cleanup-Image", "/StartComponentCleanup" }, new[] { 0, RebootRequired });
        }

        /// <summary>Arrêt de Windows Update avant le vidage de son cache.</summary>
        internal static ElevatedCommand StopWindowsUpdateCommand { get; } =
            new("sc.exe", new[] { "stop", "wuauserv" }, new[] { 0, ServiceNotActive });

        /// <summary>Redémarrage de Windows Update après le vidage de son cache.</summary>
        internal static ElevatedCommand StartWindowsUpdateCommand { get; } =
            new("sc.exe", new[] { "start", "wuauserv" }, new[] { 0, ServiceAlreadyRunning });

        /// <summary>
        /// Retire la tâche de démarrage SYSTEM « vider l'historique Defender » et le script
        /// qu'une version antérieure a pu laisser. Cette fonction a été supprimée : effacer
        /// l'historique d'un autre antivirus détruit une trace utile et n'a pas sa place ici.
        /// </summary>
        public static void RemoveDefenderHistoryTask()
        {
            var script = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "optiSCAN",
                "clear-wd-history.cmd");
            try
            {
                if (File.Exists(script) && (File.GetAttributes(script) & FileAttributes.ReparsePoint) == 0)
                    File.Delete(script);
            }
            catch (Exception ex)
            {
                AppLogger.Warn("SystemTweaks", "Suppression du script Defender refusée", ex);
            }

            try
            {
                // Sans effet si la tâche n'existe pas.
                RunCaptured("schtasks.exe", "/Delete /F /TN \"" + ClearDefenderHistoryTaskName + "\"");
            }
            catch (Exception ex)
            {
                AppLogger.Debug("SystemTweaks", "Tâche historique Defender : " + ex.Message);
            }

            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\optiSCAN", writable: true);
                key?.DeleteValue("DefenderHistoryAttempts", throwOnMissingValue: false);
            }
            catch (Exception ex)
            {
                AppLogger.Debug("SystemTweaks", "Compteur historique Defender : " + ex.Message);
            }
        }

        private static string RunCaptured(string tool, string arguments)
        {
            using var process = Process.Start(new ProcessStartInfo
            {
                FileName = Path.Combine(Environment.SystemDirectory, tool),
                Arguments = arguments,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            });
            if (process == null)
                return string.Empty;
            var stdout = process.StandardOutput.ReadToEndAsync();
            var stderr = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(4000))
            {
                try { process.Kill(entireProcessTree: true); } catch { /* déjà terminé */ }
            }

            return stdout.GetAwaiter().GetResult() + stderr.GetAwaiter().GetResult();
        }

        /// <summary>Identifiants acceptés après <c>--apply-tweaks</c> (liste blanche).</summary>
        internal static readonly IReadOnlySet<string> KnownElevatedTweakIds =
            new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "telemetry", "dism", "wu-cache" };

        public static bool ExecuteTweakIds(IReadOnlyCollection<string> ids)
        {
            var wanted = new HashSet<string>(ids, StringComparer.OrdinalIgnoreCase);
            foreach (var unknown in wanted.Where(id => !KnownElevatedTweakIds.Contains(id)))
                AppLogger.Warn("SystemTweaksService", "Action élevée inconnue ou retirée, ignorée : " + unknown);

            var ok = true;
            if (wanted.Contains("telemetry"))
                ok &= RunAll(ElevatedTelemetryCommands());
            if (wanted.Contains("dism"))
                ok &= RunAll(ElevatedDismCleanupCommands());
            if (wanted.Contains("wu-cache"))
                ok &= ClearWindowsUpdateCache();

            return ok;
        }

        private static bool RunAll(IEnumerable<ElevatedCommand> commands)
        {
            var ok = true;
            foreach (var command in commands)
            {
                if (!RunElevatedCommand(command))
                    ok = false;
            }

            return ok;
        }

        /// <summary>
        /// Arrête Windows Update, vide <c>%SystemRoot%\SoftwareDistribution\Download</c> en C#
        /// (un lien trouvé dans le dossier est supprimé lui-même, jamais suivi), puis redémarre
        /// le service, même si le vidage a échoué.
        /// </summary>
        private static bool ClearWindowsUpdateCache()
        {
            if (!RunElevatedCommand(StopWindowsUpdateCommand))
                return false;

            var cleared = ClearDirectoryContents(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                "SoftwareDistribution",
                "Download"));
            var restarted = RunElevatedCommand(StartWindowsUpdateCommand);
            return cleared && restarted;
        }

        /// <summary>Vide un dossier sans traverser les jonctions ni les liens qu'il contient.</summary>
        internal static bool ClearDirectoryContents(string directory)
        {
            try
            {
                var info = new DirectoryInfo(directory);
                if (!info.Exists)
                    return true;
                if ((info.Attributes & FileAttributes.ReparsePoint) != 0)
                {
                    AppLogger.Warn("SystemTweaksService", "Cache Windows Update : le dossier est un lien, non vidé");
                    return false;
                }

                var ok = true;
                foreach (var entry in info.EnumerateFileSystemInfos())
                {
                    try
                    {
                        if (entry is DirectoryInfo child)
                        {
                            // Directory.Delete supprime une jonction sans la suivre ; un vrai
                            // dossier est supprimé avec son contenu, liens internes compris.
                            if ((child.Attributes & FileAttributes.ReparsePoint) != 0)
                                child.Delete();
                            else
                                child.Delete(recursive: true);
                        }
                        else
                        {
                            entry.Attributes = FileAttributes.Normal;
                            entry.Delete();
                        }
                    }
                    catch (Exception ex)
                    {
                        ok = false;
                        AppLogger.Debug("SystemTweaksService", "Cache Windows Update, élément conservé : " + ex.Message);
                    }
                }

                return ok;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("SystemTweaksService", "Cache Windows Update", ex);
                return false;
            }
        }

        public static bool RunElevatedKnown(string id, bool waitForExit) =>
            RelaunchTweaks(new[] { id }, waitForExit);

        private static bool RelaunchTweaks(IReadOnlyList<string> ids, bool waitForExit)
        {
            if (ids.Count == 0)
                return true;
            if (ElevationHelper.IsRunningElevated())
                return ExecuteTweakIds(ids);

            try
            {
                var exe = Environment.ProcessPath;
                if (string.IsNullOrWhiteSpace(exe))
                    return false;

                var psi = new ProcessStartInfo
                {
                    FileName = exe,
                    UseShellExecute = true,
                    Verb = "runas",
                    Arguments = "--apply-tweaks " + string.Join(',', ids) + " --quiet",
                    WindowStyle = ProcessWindowStyle.Minimized,
                };
                var process = Process.Start(psi);
                if (process == null)
                    return false;
                if (waitForExit)
                    process.WaitForExit();
                return !waitForExit || process.ExitCode == 0;
            }
            catch (System.ComponentModel.Win32Exception wex) when (wex.NativeErrorCode == 1223)
            {
                AppLogger.Info("SystemTweaksService", "Élévation refusée par l'utilisateur");
                return false;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("SystemTweaksService", "RelaunchTweaks", ex);
                return false;
            }
        }

        public static bool RunElevatedTweaks(bool telemetry, bool dism, bool waitForExit)
        {
            var ids = new List<string>();
            if (telemetry) ids.Add("telemetry");
            if (dism) ids.Add("dism");
            return RelaunchTweaks(ids, waitForExit);
        }

        private static bool RunElevatedCommand(ElevatedCommand command)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = command.FilePath,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                };
                foreach (var argument in command.Arguments)
                    psi.ArgumentList.Add(argument);
                using var process = Process.Start(psi);
                if (process == null)
                    return false;
                if (!process.WaitForExit(TimeSpan.FromMinutes(30)))
                {
                    try { process.Kill(entireProcessTree: true); } catch { /* déjà terminé */ }
                    AppLogger.Warn("SystemTweaksService", "Délai dépassé : " + command);
                    return false;
                }

                if (command.AcceptedExitCodes.Contains(process.ExitCode))
                    return true;
                AppLogger.Warn("SystemTweaksService", $"Échec ({process.ExitCode}) : {command}");
                return false;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("SystemTweaksService", "Commande admin : " + command, ex);
                return false;
            }
        }

        /// <summary>Demande un redémarrage Windows (<c>shutdown /r</c>).</summary>
        public static bool RequestSystemRestart(int delaySeconds = 0)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = SystemExecutables.System32("shutdown.exe"),
                    UseShellExecute = false,
                    CreateNoWindow = true,
                };
                psi.ArgumentList.Add("/r");
                psi.ArgumentList.Add("/t");
                psi.ArgumentList.Add(Math.Max(0, delaySeconds).ToString(CultureInfo.InvariantCulture));
                using var p = Process.Start(psi);
                p?.WaitForExit(15000);
                return p is { ExitCode: 0 };
            }
            catch (Exception ex)
            {
                AppLogger.Warn("SystemTweaksService", "shutdown /r", ex);
                return false;
            }
        }

        /// <summary>Ouvre les paramètres Windows Update.</summary>
        public static bool OpenWindowsUpdateSettings()
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "ms-settings:windowsupdate",
                    UseShellExecute = true,
                });
                return true;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("SystemTweaksService", "ms-settings:windowsupdate", ex);
                return false;
            }
        }
    }
}
