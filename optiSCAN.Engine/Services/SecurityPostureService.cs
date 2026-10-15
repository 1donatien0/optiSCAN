using Microsoft.Win32;
using optiSCAN.Localization;
using optiSCAN.Models;
using System.Diagnostics;
using System.Runtime.Versioning;

namespace optiSCAN.Services
{
    /// <summary>Évalue la posture de sécurité Windows + optiSCAN (score /100).</summary>
    [SupportedOSPlatform("windows")]
    public sealed class SecurityPostureService : ISecurityPostureService
    {
        /// <summary>Active la protection temps réel (sans ouvrir Options).</summary>
        public const string FixEnableProtection = "optiscan://fix/protection";

        /// <summary>Active les mises à jour automatiques de signatures.</summary>
        public const string FixEnableSigAuto = "optiscan://fix/sigauto";

        /// <summary>Retire les partages utilisateur exposés (ceux qui font échouer le contrôle).</summary>
        public const string FixRemoveExposedShares = "optiscan://fix/shares";

        /// <summary>Lance une analyse rapide.</summary>
        public const string FixStartQuickScan = "optiscan://fix/scan";

        /// <summary>Ouvre les paramètres UAC (primaire) ; repli Panneau de configuration.</summary>
        public const string FixUac =
            "UserAccountControlSettings.exe|control.exe /name Microsoft.UserAccountControl";

        /// <summary>Pare-feu Windows : page dédiée Win11, accueil Sécurité Windows, puis MMC.</summary>
        public const string FixFirewall =
            "ms-settings:windowsdefender-firewall|ms-settings:windowsdefender|WF.msc";

        private readonly IWindowsUpdateProbe _windowsUpdate;

        public SecurityPostureService(IWindowsUpdateProbe? windowsUpdateProbe = null)
        {
            _windowsUpdate = windowsUpdateProbe ?? new WindowsUpdateProbe();
        }

        public SecurityPostureReport Evaluate(SecurityPostureContext context)
        {
            var checks = new List<SecurityPostureCheck>
            {
                CheckFirewall(),
                CheckUac(),
                CheckWindowsUpdateRecent(),
                CheckUserVisibleShares(),
                CheckOptiscanProtection(context),
                CheckRecentScan(context.LastScanAt),
                CheckSignatureAutoUpdate(context.SignatureAutoUpdateEnabled),
            };

            int earned = checks.Where(c => c.Passed).Sum(c => c.Weight);
            int total = checks.Sum(c => c.Weight);
            int score = total > 0 ? (int)Math.Round(100.0 * earned / total) : 0;

            return new SecurityPostureReport
            {
                Score = Math.Clamp(score, 0, 100),
                Checks = checks,
            };
        }

        private static SecurityPostureCheck CheckFirewall()
        {
            bool ok = FirewallPostureHelper.IsFirewallEnabledOnAllProfiles();

            return new SecurityPostureCheck
            {
                Id = "firewall",
                Title = LocalizationService.GetString("Posture_Firewall"),
                Passed = ok,
                Weight = 15,
                FixUri = FixFirewall,
            };
        }

        private SecurityPostureCheck CheckUac()
        {
            bool ok = true;
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System");
                ok = key?.GetValue("EnableLUA") is int i && i != 0;
            }
            catch (Exception ex) { AppLogger.Warn("SecurityPosture", "UAC", ex); }

            return new SecurityPostureCheck
            {
                Id = "uac",
                Title = LocalizationService.GetString("Posture_Uac"),
                Passed = ok,
                Weight = 10,
                FixUri = FixUac,
            };
        }

        private SecurityPostureCheck CheckWindowsUpdateRecent()
        {
            bool ok = _windowsUpdate.HasRecentSuccessfulInstall(WindowsUpdateProbe.DefaultMaxAge);

            return new SecurityPostureCheck
            {
                Id = "wupdate",
                Title = LocalizationService.GetString("Posture_WindowsUpdate"),
                Passed = ok,
                Weight = 15,
                FixUri = "ms-settings:windowsupdate",
            };
        }

        private static SecurityPostureCheck CheckUserVisibleShares()
        {
            bool risky = false;
            try
            {
                risky = ListExposedShareNames().Count > 0;
            }
            catch (Exception ex) { AppLogger.Warn("SecurityPosture", "Shares", ex); }

            return new SecurityPostureCheck
            {
                Id = "shares",
                Title = LocalizationService.GetString("Posture_Shares"),
                Passed = !risky,
                Weight = 10,
                // Suppression réelle des partages exposés (pas une page Paramètres).
                FixUri = FixRemoveExposedShares,
            };
        }

        private static SecurityPostureCheck CheckOptiscanProtection(SecurityPostureContext context)
        {
            var level = ProtectionStatusEvaluator.Evaluate(
                context.ClamInstalled,
                context.YaraAvailable,
                context.YaraRulesCount,
                context.RealTimeProtectionEnabled,
                context.RealTimeProtectionRunning);

            return new SecurityPostureCheck
            {
                Id = "optiscan",
                Title = LocalizationService.GetString("Posture_Optiscan"),
                Passed = level == ProtectionBadgeLevel.Active,
                Weight = 25,
                FixUri = FixEnableProtection,
            };
        }

        private static SecurityPostureCheck CheckRecentScan(DateTime? lastScanAt)
        {
            bool ok = lastScanAt.HasValue && (DateTime.Now - lastScanAt.Value).TotalDays <= 7;
            return new SecurityPostureCheck
            {
                Id = "scan",
                Title = LocalizationService.GetString("Posture_RecentScan"),
                Passed = ok,
                Weight = 15,
                FixUri = FixStartQuickScan,
            };
        }

        private static SecurityPostureCheck CheckSignatureAutoUpdate(bool enabled) =>
            new()
            {
                Id = "sigauto",
                Title = LocalizationService.GetString("Posture_SigAuto"),
                Passed = enabled,
                Weight = 10,
                FixUri = FixEnableSigAuto,
            };

        /// <summary>Noms des partages visibles (hors partages administratifs en $).</summary>
        internal static IReadOnlyList<string> ListExposedShareNames()
        {
            var names = new List<string>();
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\lanmanserver\Shares");
            if (key == null)
                return names;

            foreach (var name in key.GetValueNames())
            {
                if (name is ("IPC$" or "ADMIN$" or "print$") || name.EndsWith('$'))
                    continue;
                if (!IsSafeShareName(name))
                    continue;
                if (ShareRegistryValueIndicatesUserPath(key.GetValue(name)))
                    names.Add(name);
            }

            return names;
        }

        /// <summary>Nom de partage sans métacaractère de cmd.exe ni caractère de contrôle.</summary>
        internal static bool IsCmdSafeShareName(string name) =>
            !string.IsNullOrWhiteSpace(name)
            && !name.Any(c => char.IsControl(c) || "\"&|<>^%!()".Contains(c));

        /// <summary>
        /// Ligne de commande cmd.exe qui supprime chaque partage et rend 1 si l'une des suppressions
        /// échoue : toutes sont tentées, mais un échec au milieu de la série n'est plus masqué par
        /// le code de retour de la dernière. Les noms doivent avoir passé <see cref="IsCmdSafeShareName"/>.
        /// </summary>
        internal static string BuildRemoveSharesCommand(IEnumerable<string> names, string netExePath)
        {
            // /d : sans AutoRun ; /s : cmd retire seulement les guillemets extérieurs.
            // « if defined » est évalué à l'exécution, contrairement à %VAR%.
            var commands = names.Select(n => $"\"{netExePath}\" share \"{n}\" /delete || set OPTISCAN_SHARE_FAIL=1");
            return "/d /s /c \"set \"OPTISCAN_SHARE_FAIL=\" & "
                + string.Join(" & ", commands)
                + " & if defined OPTISCAN_SHARE_FAIL exit 1\"";
        }

        /// <summary>
        /// Supprime les partages exposés que l'utilisateur a confirmés (intersection avec l'état courant).
        /// Demande l'UAC si l'app n'est pas élevée. Bloquant : à appeler hors thread UI.
        /// </summary>
        /// <returns><c>true</c> si tout a été supprimé ; <c>false</c> si échec ou UAC refusée.</returns>
        internal static bool TryRemoveExposedShares(IReadOnlyCollection<string> confirmedNames)
        {
            ArgumentNullException.ThrowIfNull(confirmedNames);
            var current = ListExposedShareNames();
            // Les noms passent par cmd.exe (élevé) : un nom contenant un métacaractère de cmd
            // ajouterait une commande. Ces partages-là ne sont pas traités ici.
            var confirmed = current
                .Where(n => confirmedNames.Contains(n, StringComparer.OrdinalIgnoreCase))
                .ToList();
            var names = confirmed.Where(IsCmdSafeShareName).ToList();
            var refused = confirmed.Count - names.Count;
            if (refused > 0)
                AppLogger.Warn("SecurityPosture", $"{refused} partage(s) au nom non sûr pour cmd.exe : à supprimer manuellement");
            if (names.Count == 0)
                return refused == 0;

            var psi = new ProcessStartInfo
            {
                FileName = SystemExecutables.System32("cmd.exe"),
                Arguments = BuildRemoveSharesCommand(names, SystemExecutables.System32("net.exe")),
                WorkingDirectory = Environment.SystemDirectory,
                UseShellExecute = true,
                WindowStyle = ProcessWindowStyle.Hidden,
            };
            if (!ElevationHelper.IsRunningElevated())
                psi.Verb = "runas";

            try
            {
                using var proc = Process.Start(psi);
                if (proc == null)
                    return false;
                if (!proc.WaitForExit(20_000))
                {
                    AppLogger.Warn("SecurityPosture", "Suppression des partages : délai dépassé (20 s)");
                    return false;
                }
                if (proc.ExitCode != 0)
                    AppLogger.Warn("SecurityPosture", $"Suppression des partages : code retour {proc.ExitCode}");
                return proc.ExitCode == 0 && refused == 0;
            }
            catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 1223)
            {
                // ERROR_CANCELLED : l'utilisateur a refusé l'invite UAC.
                AppLogger.Info("SecurityPosture", "Suppression des partages annulée (UAC refusée)");
                return false;
            }
        }

        private static bool IsSafeShareName(string name) =>
            name.Length is > 0 and <= 80
            && name.All(c => char.IsLetterOrDigit(c) || c is ' ' or '-' or '_' or '.');

        /// <summary>Les entrées lanmanserver\Shares sont REG_MULTI_SZ (string[]).</summary>
        internal static bool ShareRegistryValueIndicatesUserPath(object? value)
        {
            if (value is string single)
                return single.Contains("Path=", StringComparison.OrdinalIgnoreCase);

            if (value is string[] parts)
            {
                foreach (var part in parts)
                {
                    if (part.Contains("Path=", StringComparison.OrdinalIgnoreCase))
                        return true;
                }
            }

            return false;
        }
    }
}
