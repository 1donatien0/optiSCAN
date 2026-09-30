using optiSCAN.Services;
using System.Security.Cryptography;
using System.Text;

namespace optiSCAN.Tests;

public sealed class IpcScanRateLimiterTests
{
    [Fact]
    public void TryEnter_allows_up_to_concurrent_limit()
    {
        var limiter = new IpcScanRateLimiter(maxPerMinute: 1000, maxConcurrent: 2);
        Assert.True(limiter.TryEnter(out var lease1));
        Assert.True(limiter.TryEnter(out var lease2));
        Assert.False(limiter.TryEnter(out _));
        lease1?.Dispose();
        Assert.True(limiter.TryEnter(out var lease3));
        lease2?.Dispose();
        lease3?.Dispose();
    }

    [Fact]
    public void TryEnter_blocks_when_per_minute_limit_exceeded()
    {
        var limiter = new IpcScanRateLimiter(maxPerMinute: 2, maxConcurrent: 10);
        Assert.True(limiter.TryEnter(out var lease1));
        Assert.True(limiter.TryEnter(out var lease2));
        lease1?.Dispose();
        lease2?.Dispose();
        Assert.False(limiter.TryEnter(out _));
    }
}

public sealed class YaraForgePackageIntegrityTests
{
    [Fact]
    public void TryParseGitHubDigest_parses_sha256_prefix()
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes("rules"));
        var digest = "sha256:" + Convert.ToHexString(bytes);

        Assert.True(YaraForgePackageIntegrity.TryParseGitHubDigest(digest, out var parsed));
        Assert.Equal(bytes, parsed);
    }

    [Fact]
    public void Verify_rejects_size_or_digest_mismatch()
    {
        var content = Encoding.UTF8.GetBytes("zip");
        var hash = SHA256.HashData(content);

        Assert.True(YaraForgePackageIntegrity.Verify(content, content.LongLength, hash));
        Assert.False(YaraForgePackageIntegrity.Verify(content, content.LongLength + 1, hash));
        Assert.False(YaraForgePackageIntegrity.Verify(content, null, hash.AsSpan(0, 16)));

        var wrong = (byte[])hash.Clone();
        wrong[0] ^= 0xFF;
        Assert.False(YaraForgePackageIntegrity.Verify(content, content.LongLength, wrong));
    }
}
