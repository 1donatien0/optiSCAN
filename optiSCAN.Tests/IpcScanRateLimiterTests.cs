using optiSCAN.Services;

namespace optiSCAN.Tests;

public sealed class IpcScanRateLimiterTests
{
    [Fact]
    public void TryEnter_respects_max_concurrent()
    {
        var limiter = new IpcScanRateLimiter(maxPerMinute: 1000, maxConcurrent: 2);
        Assert.True(limiter.TryEnter(out var a));
        Assert.True(limiter.TryEnter(out var b));
        Assert.False(limiter.TryEnter(out _));
        a!.Dispose();
        Assert.True(limiter.TryEnter(out var c));
        c!.Dispose();
        b!.Dispose();
    }

    [Fact]
    public void TryEnter_respects_max_per_minute()
    {
        var limiter = new IpcScanRateLimiter(maxPerMinute: 2, maxConcurrent: 10);
        Assert.True(limiter.TryEnter(out var a));
        Assert.True(limiter.TryEnter(out var b));
        Assert.False(limiter.TryEnter(out _));
        a!.Dispose();
        b!.Dispose();
    }
}
