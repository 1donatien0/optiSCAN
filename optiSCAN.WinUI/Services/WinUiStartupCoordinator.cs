using optiSCAN.Coordinators;
using optiSCAN.Localization;
using optiSCAN.Services;
using optiSCAN.Strings;
using optiSCAN.WinUI.ViewModels;

namespace optiSCAN.WinUI.Services;

public static class WinUiStartupCoordinator
{
    public sealed class Host
    {
        public required ServiceContainer Container { get; init; }
        public required AntivirusViewModel ViewModel { get; init; }
        public required Action RefreshOverview { get; init; }
        public required Action RefreshAntivirus { get; init; }
        public required Action RefreshHistory { get; init; }
        public required Func<Task> RefreshSignaturesAsync { get; init; }
        public required Action<string, bool, bool> SetStatus { get; init; }
        public required Func<Task> WarmUpYaraRulesAsync { get; init; }
        public string? PendingShellScanPath { get; set; }
        public required Func<string, Task> RunShellScanAsync { get; init; }
        public bool GuardSession { get; init; }
        public Action? ShowOnboarding { get; init; }
    }

    public static async Task RunAsync(Host host)
    {
        RuntimeDependencies.LogReportIfIncomplete();
        var runtimeReport = RuntimeDependencies.Evaluate();
        bool clamAvOk = host.Container.ClamAv.IsClamAvInstalled();

        if (!runtimeReport.IsClamAvReady)
            host.SetStatus(runtimeReport.BuildSummaryLine() + LocalizationService.GetString("Main_RuntimeHint"), true, false);
        else
            host.SetStatus(
                clamAvOk ? LocalizationService.GetString("Main_ClamOperational") : LocalizationService.GetString("Main_ClamNotFound"),
                false,
                !clamAvOk);

        host.RefreshOverview();
        host.RefreshAntivirus();
        host.RefreshHistory();
        await host.RefreshSignaturesAsync().ConfigureAwait(true);

        try
        {
            host.Container.ApplyPreferencesOnStartup();
        }
        catch (Exception ex)
        {
            AppLogger.Warn("WinUiStartup", "ApplyPreferencesOnStartup", ex);
        }

        host.ViewModel.RefreshProtectionStatus();
        host.SetStatus(OptiscanStrings.UiMessages.ProtectionActive, false, false);
        _ = host.WarmUpYaraRulesAsync();

        if (!host.GuardSession)
            host.ShowOnboarding?.Invoke();

        if (host.GuardSession)
        {
            host.SetStatus(LocalizationService.GetString("Main_GuardSession"), false, false);
            return;
        }

        if (!string.IsNullOrWhiteSpace(host.PendingShellScanPath))
        {
            var shellPath = host.PendingShellScanPath;
            host.PendingShellScanPath = null;
            await host.RunShellScanAsync(shellPath).ConfigureAwait(true);
        }
    }
}
