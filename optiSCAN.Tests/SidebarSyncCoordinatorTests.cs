using optiSCAN.Coordinators;
using optiSCAN.Services;
using optiSCAN.Strings;

namespace optiSCAN.Tests;

public sealed class SidebarSyncCoordinatorTests
{
    [Fact]
    public void ApplySync_invokes_matching_sidebar_action()
    {
        var navigation = new NavigationService();
        string? selected = null;
        var coordinator = new SidebarSyncCoordinator(
            navigation,
            action => action(),
            new Dictionary<string, Action>
            {
                [OptiscanStrings.PanelIds.History] = () => selected = OptiscanStrings.PanelIds.History,
            });

        coordinator.ApplySync(OptiscanStrings.PanelIds.History);

        Assert.Equal(OptiscanStrings.PanelIds.History, selected);
        Assert.False(coordinator.IsSyncing);
    }

    [Fact]
    public void ApplySync_ignores_unknown_panel()
    {
        var navigation = new NavigationService();
        int calls = 0;
        var coordinator = new SidebarSyncCoordinator(
            navigation,
            action => action(),
            new Dictionary<string, Action>
            {
                [OptiscanStrings.PanelIds.Overview] = () => calls++,
            });

        coordinator.ApplySync(OptiscanStrings.PanelIds.Clean);

        Assert.Equal(0, calls);
    }

    [Fact]
    public void Detach_stops_navigated_handler()
    {
        var navigation = new NavigationService();
        int calls = 0;
        var coordinator = new SidebarSyncCoordinator(
            navigation,
            action => action(),
            new Dictionary<string, Action>
            {
                [OptiscanStrings.PanelIds.Options] = () => calls++,
            });

        coordinator.Detach();
        navigation.NavigateTo(OptiscanStrings.PanelIds.Options);

        Assert.Equal(0, calls);
    }
}
