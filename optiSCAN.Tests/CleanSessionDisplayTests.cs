using optiSCAN.Models;

namespace optiSCAN.Tests;

public sealed class CleanSessionDisplayTests
{
    [Fact]
    public void BytesDisplay_uses_binary_units()
    {
        var session = new CleanSession { BytesFreed = 2 * 1024 * 1024 };
        Assert.Contains("Mo", session.BytesDisplay);
        session.BytesFreed = 512;
        Assert.Contains("512", session.BytesDisplay);
    }

    [Fact]
    public void DurationDisplay_formats_elapsed()
    {
        var session = new CleanSession
        {
            StartedAt = DateTime.Now.AddMinutes(-2),
            FinishedAt = DateTime.Now,
        };
        var text = session.DurationDisplay;
        Assert.False(string.IsNullOrWhiteSpace(text));
    }
}
