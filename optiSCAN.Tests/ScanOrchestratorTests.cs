using optiSCAN.Services;

namespace optiSCAN.Tests;

public sealed class ScanOrchestratorTests
{
    [Fact]
    public void Constructor_does_not_throw()
    {
        var ex = Record.Exception(() => _ = new ScanOrchestrator());
        Assert.Null(ex);
    }
}
