using System.ComponentModel;
using optiSCAN.Coordinators;
using optiSCAN.Strings;

namespace optiSCAN.Tests;

public sealed class WindowTrayBehaviorCoordinatorTests
{
    [Fact]
    public void TryCancelClose_when_not_explicit_exit_cancels_and_hides()
    {
        var coordinator = new WindowTrayBehaviorCoordinator();
        var e = new CancelEventArgs();
        bool hidden = false;
        string? status = null;

        var cancelled = coordinator.TryCancelClose(
            explicitExit: false,
            e,
            new WindowTrayBehaviorCoordinator.Host
            {
                HideWindow = () => hidden = true,
                SetTrayStatus = msg => status = msg,
            });

        Assert.True(cancelled);
        Assert.True(e.Cancel);
        Assert.True(hidden);
        Assert.Equal(OptiscanStrings.UiMessages.ProtectionReducedTray, status);
    }

    [Fact]
    public void TryCancelClose_when_explicit_exit_does_not_cancel()
    {
        var coordinator = new WindowTrayBehaviorCoordinator();
        var e = new CancelEventArgs();

        var cancelled = coordinator.TryCancelClose(
            explicitExit: true,
            e,
            new WindowTrayBehaviorCoordinator.Host
            {
                HideWindow = () => { },
                SetTrayStatus = _ => { },
            });

        Assert.False(cancelled);
        Assert.False(e.Cancel);
    }
}
