using Microsoft.Win32;
using optiSCAN.Localization;
using optiSCAN.Models;
using System.Runtime.Versioning;

namespace optiSCAN.Services
{
    public enum PostureFixStatus { Done, NeedsRestart, Cancelled, Failed, NotSupported }

    public sealed record PostureFixResult(PostureFixStatus Status, string Message);

    /// <summary>
    /// Corrections en un clic des contrôles de la note de sécurité (une seule invite UAC au plus,
    /// script exécuté en arrière-plan). Les identifiants correspondent à <see cref="SecurityPostureCheck.Id"/>.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public static class PostureFixService
    {
        /// <summary>Vrai si le contrôle sait être corrigé directement par l'application.</summary>
        public static bool CanAutoFix(string? checkId) => checkId is
            "firewall" or "uac" or "wupdate" or "shares" or "optiscan" or "scan" or "sigauto";

        public static async Task<PostureFixResult> FixAsync(
            string checkId,
            ServiceContainer container,
            Func<string, string, bool> confirm)
        {
            try
            {
                switch (checkId)
                {
                    case "firewall":
                        return await RunAdminAsync(confirm, "Posture_FixConfirmFirewall", null,
                            ["netsh advfirewall set allprofiles state on"], false).ConfigureAwait(false);

                    case "uac":
                        return await RunAdminAsync(confirm, "Posture_FixConfirmUac", null,
                            [@"reg add ""HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"" /v EnableLUA /t REG_DWORD /d 1 /f"],
                            true).ConfigureAwait(false);

                    case "shares":
                    {
                        var shares = ListUserShares();
                        if (shares.Count == 0)
                            return new(PostureFixStatus.Done, LocalizationService.GetString("Posture_FixDone"));
                        var cmds = shares.Select(n => $"net share \"{n.Replace("\"", "")}\" /delete /y").ToList();
                        return await RunAdminAsync(confirm, "Posture_FixConfirmShares",
                            string.Join(", ", shares), cmds, false).ConfigureAwait(false);
                    }

                    case "wupdate":
                    {
                        bool ok = await Task.Run(() => SystemTweaksService.RunElevatedBatch(
                            ["UsoClient.exe StartScan", "UsoClient.exe StartDownload", "UsoClient.exe StartInstall"],
                            waitForExit: true)).ConfigureAwait(false);
                        if (!ok)
                            return new(PostureFixStatus.Cancelled, LocalizationService.GetString("Posture_FixCancelled"));
                        SystemTweaksService.OpenWindowsUpdateSettings();
                        return new(PostureFixStatus.Done, LocalizationService.GetString("Posture_FixWUpdateStarted"));
                    }

                    case "optiscan":
                        container.ApplyRealtimeProtection(true);
                        return new(PostureFixStatus.Done, LocalizationService.GetString("Posture_FixDone"));

                    case "sigauto":
                        container.ApplySignatureAutoUpdate(true);
                        return new(PostureFixStatus.Done, LocalizationService.GetString("Posture_FixDone"));

                    case "scan":
                        ServiceContainer.UiEvents.RequestScan(ScanType.QuickScan);
                        return new(PostureFixStatus.Done, LocalizationService.GetString("Posture_FixScanStarted"));

                    default:
                        return new(PostureFixStatus.NotSupported, string.Empty);
                }
            }
            catch (Exception ex)
            {
                AppLogger.Warn("PostureFixService", $"Correction {checkId}", ex);
                return new(PostureFixStatus.Failed,
                    LocalizationService.Format("Posture_FixFailed", ex.Message));
            }
        }

        private static async Task<PostureFixResult> RunAdminAsync(
            Func<string, string, bool> confirm,
            string confirmKey,
            string? detail,
            IReadOnlyList<string> commands,
            bool needsRestart)
        {
            string message = detail == null
                ? LocalizationService.GetString(confirmKey)
                : LocalizationService.Format(confirmKey, detail);
            if (!confirm(message, LocalizationService.GetString("Posture_Title")))
                return new(PostureFixStatus.Cancelled, LocalizationService.GetString("Posture_FixCancelled"));

            bool ok = await Task.Run(() => SystemTweaksService.RunElevatedBatch(commands, waitForExit: true))
                .ConfigureAwait(false);
            if (!ok)
                return new(PostureFixStatus.Cancelled, LocalizationService.GetString("Posture_FixCancelled"));

            return needsRestart
                ? new(PostureFixStatus.NeedsRestart, LocalizationService.GetString("Posture_FixNeedsRestart"))
                : new(PostureFixStatus.Done, LocalizationService.GetString("Posture_FixDone"));
        }

        /// <summary>Partages réseau créés par l'utilisateur (hors partages administratifs $).</summary>
        internal static List<string> ListUserShares()
        {
            var result = new List<string>();
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\lanmanserver\Shares");
                if (key == null)
                    return result;
                foreach (var name in key.GetValueNames())
                {
                    if (name.EndsWith('$'))
                        continue;
                    if (SecurityPostureService.ShareRegistryValueIndicatesUserPath(key.GetValue(name)))
                        result.Add(name);
                }
            }
            catch (Exception ex) { AppLogger.Warn("PostureFixService", "ListUserShares", ex); }
            return result;
        }
    }
}
