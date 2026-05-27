using optiSCAN.Services;

namespace optiSCAN.Tests;

public sealed class NotificationServiceTests
{
    [Fact]
    public void ResetActivationHookForTests_allows_second_instance_hook_semantics()
    {
        NotificationService.ResetActivationHookForTests();
        var first = new NotificationService();
        NotificationService.ResetActivationHookForTests();
        var second = new NotificationService();
        Assert.NotNull(first);
        Assert.NotNull(second);
    }
}
