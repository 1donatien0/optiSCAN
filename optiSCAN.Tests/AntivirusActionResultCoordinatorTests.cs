using optiSCAN.Coordinators;
using optiSCAN.Services;

namespace optiSCAN.Tests;

public sealed class AntivirusActionResultCoordinatorTests
{
    [Fact]
    public void Handle_failure_only_sets_status()
    {
        var coordinator = new AntivirusActionResultCoordinator();
        string? message = null;
        int historyRefreshes = 0;

        coordinator.Handle(
            new ActionResult { Success = false, Message = "échec", IsError = true },
            new AntivirusActionResultCoordinator.Host
            {
                SetStatus = (msg, _, _) => message = msg,
                RefreshQuarantineList = () => { },
                RefreshHistory = () => historyRefreshes++,
            });

        Assert.Equal("échec", message);
        Assert.Equal(0, historyRefreshes);
    }

    [Fact]
    public void Handle_success_refreshes_lists()
    {
        var coordinator = new AntivirusActionResultCoordinator();
        int quarantineRefreshes = 0;
        int historyRefreshes = 0;

        coordinator.Handle(
            new ActionResult { Success = true, Message = "ok" },
            new AntivirusActionResultCoordinator.Host
            {
                SetStatus = (_, _, _) => { },
                RefreshQuarantineList = () => quarantineRefreshes++,
                RefreshHistory = () => historyRefreshes++,
            });

        Assert.Equal(1, quarantineRefreshes);
        Assert.Equal(1, historyRefreshes);
    }
}
