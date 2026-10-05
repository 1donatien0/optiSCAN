using System.ComponentModel;
using optiSCAN.Coordinators;
using optiSCAN.Strings;

namespace optiSCAN.Tests;

public sealed class WindowTrayBehaviorCoordinatorTests
{
    [Fact]
    public void TryCancelClose_when_not_explicit_exit_cancels_and_hides()
    {
        var e = new CancelEventArgs();
        bool hidden = false;
        string? status = null;

        var cancelled = WindowTrayBehaviorCoordinator.TryCancelClose(
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
        Assert.True(
            status is "optiSCAN minimized to the system tray" or "optiSCAN réduit dans la barre système",
            status);
    }

    [Fact]
    public void TryCancelClose_when_explicit_exit_does_not_cancel()
    {
        var e = new CancelEventArgs();

        var cancelled = WindowTrayBehaviorCoordinator.TryCancelClose(
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
