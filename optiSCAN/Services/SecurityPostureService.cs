using Microsoft.Win32;
using optiSCAN.Localization;
using optiSCAN.Models;
using System.Runtime.Versioning;

namespace optiSCAN.Services
{
    /// <summary>Évalue la posture de sécurité Windows + optiSCAN (score /100).</summary>
    [SupportedOSPlatform("windows")]
    public sealed class SecurityPostureService : ISecurityPostureService
    {
        /// <summary>Navigation in-app (Overview → panneau Antivirus).</summary>
        public const string FixNavigateAntivirus = "optiscan://panel/antivirus";

        /// <summary>Navigation in-app (Overview → Options).</summary>
        public const string FixNavigateOptions = "optiscan://panel/options";

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
                FixUri = "ms-settings:windowsdefender",
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
                FixUri = "ms-settings:developers",
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
                using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\lanmanserver\Shares");
                if (key != null)
                {
                    foreach (var name in key.GetValueNames())
                    {
                        if (name is ("IPC$" or "ADMIN$" or "print$")
                            || name.EndsWith('$'))
                            continue;

                        if (ShareRegistryValueIndicatesUserPath(key.GetValue(name)))
                        {
                            risky = true;
                            break;
                        }
                    }
                }
            }
            catch (Exception ex) { AppLogger.Warn("SecurityPosture", "Shares", ex); }

            return new SecurityPostureCheck
            {
                Id = "shares",
                Title = LocalizationService.GetString("Posture_Shares"),
                Passed = !risky,
                Weight = 10,
                // ms-settings:network-sharing n'existe plus ; Win 11 : partage avancé.
                FixUri = "ms-settings:advancedsharing",
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
                FixUri = FixNavigateOptions,
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
                FixUri = FixNavigateAntivirus,
            };
        }

        private static SecurityPostureCheck CheckSignatureAutoUpdate(bool enabled) =>
            new()
            {
                Id = "sigauto",
                Title = LocalizationService.GetString("Posture_SigAuto"),
                Passed = enabled,
                Weight = 10,
                FixUri = FixNavigateOptions,
            };

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
