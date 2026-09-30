using optiSCAN.Services;
using optiSCAN.Strings;

namespace optiSCAN.Coordinators;

/// <summary>Rafraîchit les données à chaque changement de panneau (agnostique UI).</summary>
public sealed class NavigationRefreshCoordinator
{
    private readonly INavigationService _navigation;
    private readonly Action<Action> _runOnUi;
    private readonly Func<Task> _refreshHistory;
    private readonly Func<Task> _refreshAntivirusStatus;
    private readonly Func<Task> _refreshSignatures;
    private readonly Func<Task> _refreshAntivirusData;

    public NavigationRefreshCoordinator(
        INavigationService navigation,
        Action<Action> runOnUi,
        Func<Task> refreshHistory,
        Func<Task> refreshAntivirusStatus,
        Func<Task> refreshSignatures,
        Func<Task> refreshAntivirusData)
    {
        _navigation = navigation;
        _runOnUi = runOnUi;
        _refreshHistory = refreshHistory;
        _refreshAntivirusStatus = refreshAntivirusStatus;
        _refreshSignatures = refreshSignatures;
        _refreshAntivirusData = refreshAntivirusData;
        _navigation.Navigated += OnNavigated;
    }

    public void Detach() => _navigation.Navigated -= OnNavigated;

    internal Task ApplyRefreshesForPanelAsync(string panelName) => ApplyRefreshesAsync(panelName);

    private void OnNavigated(object? sender, string panelName) =>
        _runOnUi(() => _ = ApplyRefreshesAsync(panelName));

    private async Task ApplyRefreshesAsync(string panelName)
    {
        switch (panelName)
        {
            case OptiscanStrings.PanelIds.Overview:
                await InvokeRefreshAsync(_refreshHistory).ConfigureAwait(true);
                await InvokeRefreshAsync(_refreshAntivirusStatus).ConfigureAwait(true);
                await InvokeRefreshAsync(_refreshSignatures).ConfigureAwait(true);
                break;
            case OptiscanStrings.PanelIds.Antivirus:
                await InvokeRefreshAsync(_refreshAntivirusData).ConfigureAwait(true);
                break;
            case OptiscanStrings.PanelIds.History:
                await InvokeRefreshAsync(_refreshHistory).ConfigureAwait(true);
                break;
        }
    }

    private static async Task InvokeRefreshAsync(Func<Task> refresh)
    {
        try
        {
            await refresh().ConfigureAwait(true);
        }
        catch (Exception ex)
        {
            AppLogger.Warn("NavigationRefreshCoordinator", "refresh", ex);
        }
    }
}
