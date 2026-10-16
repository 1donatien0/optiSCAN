// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.IO;
using System.Runtime.Versioning;
using System.Threading;

namespace optiSCAN.Services
{
    /// <summary>
    /// Relance d'optiSCAN par une tâche planifiée quand la protection temps réel est attendue
    /// mais que l'application est arrêtée. Ce n'est pas une protection contre la manipulation :
    /// un processus du même compte peut supprimer la tâche (ancien nom, trompeur :
    /// <c>TamperProtectionService</c>, audit A11).
    /// </summary>
    [SupportedOSPlatform("windows")]
    public sealed class ProtectionWatchdogService
    {
        private const string WatchdogTaskName = "optiSCAN_Watchdog";

        private readonly string _exePath;
        private readonly IUserPreferencesAccessor _prefs;
        private readonly IExclusionSettingsAccessor _exclusions;

        public ProtectionWatchdogService(
            IUserPreferencesAccessor? preferences = null,
            IExclusionSettingsAccessor? exclusions = null)
        {
            _prefs = preferences ?? new DefaultUserPreferencesAccessor();
            _exclusions = exclusions ?? new DefaultExclusionSettingsAccessor();
            _exePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "optiSCAN.exe");
        }

        public bool EnsureWatchdogTask()
        {
            if (!_prefs.Current.TamperProtectionEnabled)
                return DeleteWatchdogTask();

            try
            {
                DeleteWatchdogTask();
                var psi = new ProcessStartInfo
                {
                    FileName = SystemExecutables.System32("schtasks.exe"),
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                };
                psi.ArgumentList.Add("/Create");
                psi.ArgumentList.Add("/F");
                psi.ArgumentList.Add("/TN");
                psi.ArgumentList.Add(WatchdogTaskName);
                psi.ArgumentList.Add("/SC");
                psi.ArgumentList.Add("MINUTE");
                psi.ArgumentList.Add("/MO");
                psi.ArgumentList.Add("15");
                psi.ArgumentList.Add("/RL");
                psi.ArgumentList.Add("LIMITED");
                psi.ArgumentList.Add("/TR");
                psi.ArgumentList.Add($"\"{_exePath}\" --watchdog --quiet");

                using var proc = Process.Start(psi);
                proc?.WaitForExit(15_000);
                var ok = proc is { ExitCode: 0 };
                if (ok)
                    AppLogger.Info("TamperProtection", "Tâche watchdog enregistrée");
                return ok;
            }
            catch (Exception ex) when (!ex.IsFatal())
            {
                AppLogger.Warn("TamperProtection", "EnsureWatchdogTask", ex);
                return false;
            }
        }

        public bool DeleteWatchdogTask()
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = SystemExecutables.System32("schtasks.exe"),
                    UseShellExecute = false,
                    CreateNoWindow = true,
                };
                psi.ArgumentList.Add("/Delete");
                psi.ArgumentList.Add("/F");
                psi.ArgumentList.Add("/TN");
                psi.ArgumentList.Add(WatchdogTaskName);
                using var proc = Process.Start(psi);
                proc?.WaitForExit(10_000);
                return true;
            }
            catch (Exception ignored) when (!ignored.IsFatal())
            {
                return false;
            }
        }

        /// <summary>Exécuté par <c>--watchdog</c> : relance la protection si RTP attendue mais aucune instance.</summary>
        public static void RunWatchdogCheck()
        {
            var exclusions = new DefaultExclusionSettingsAccessor();
            var prefs = new DefaultUserPreferencesAccessor();
            if (!exclusions.Current.RealTimeEnabled || !prefs.Current.TamperProtectionEnabled)
                return;

            if (prefs.Current.UsePlatformProtectionService)
            {
                if (PlatformProtectionBootstrap.IsRemoteProtectionActive())
                    return;

                PlatformProtectionBootstrap.EnsurePlatformProtectionRunning();
                return;
            }

            const string mutexName = AppInstanceGate.MutexName;
            try
            {
                using var existing = Mutex.OpenExisting(mutexName);
                return;
            }
            catch (WaitHandleCannotBeOpenedException)
            {
                /* aucune instance — relancer */
            }

            try
            {
                var exe = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "optiSCAN.exe");
                var psi = new ProcessStartInfo
                {
                    FileName = exe,
                    UseShellExecute = true,
                    WindowStyle = ProcessWindowStyle.Minimized,
                };
                psi.ArgumentList.Add("--guard");
                Process.Start(psi);
                AppLogger.Info("TamperProtection", "Watchdog — relance session garde");
            }
            catch (Exception ex) when (!ex.IsFatal())
            {
                AppLogger.Warn("TamperProtection", "RunWatchdogCheck", ex);
            }
        }
    }
}
