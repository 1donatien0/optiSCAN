using optiSCAN.Coordinators;
using optiSCAN.Services;
using optiSCAN.Strings;

namespace optiSCAN.Tests;

public sealed class ManualSignatureUpdateCoordinatorTests
{
    [Fact]
    public async Task RunAsync_second_call_while_locked_sets_already_running_status()
    {
        var runner = new SignatureUpdateUiRunner();
        Assert.True(runner.TryEnterUpdate());

        var coordinator = new ManualSignatureUpdateCoordinator();
        string? status = null;

        try
        {
            await coordinator.RunAsync(new ManualSignatureUpdateCoordinator.Host
            {
                Runner = runner,
                Freshclam = null!,
                Rules = null!,
                SignatureStatus = null!,
                SetStatus = (text, _, _, _) => status = text,
                RefreshLiveFooter = () => { },
                RefreshSignaturesDisplayAsync = _ => Task.CompletedTask,
            });
        }
        finally
        {
            runner.ReleaseUpdate();
        }

        Assert.Equal(OptiscanStrings.StatusUpdates.SignaturesUpdateAlreadyRunning, status);
    }
}
