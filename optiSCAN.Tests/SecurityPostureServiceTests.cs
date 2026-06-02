using optiSCAN.Models;
using optiSCAN.Services;

namespace optiSCAN.Tests;

public sealed class SecurityPostureServiceTests
{
    [Fact]
    public void Evaluate_returns_score_between_0_and_100()
    {
        var svc = new SecurityPostureService(new FakeWindowsUpdateProbe(DateTime.UtcNow.AddDays(-3)));
        var report = svc.Evaluate(MakeContext(
            clamInstalled: true,
            yaraRulesCount: 10,
            lastScanAt: DateTime.Now.AddDays(-1)));

        Assert.InRange(report.Score, 0, 100);
        Assert.NotEmpty(report.Checks);
        Assert.Equal(100, report.Checks.Sum(c => c.Weight));
    }

    [Fact]
    public void Evaluate_low_when_clam_missing_and_no_recent_scan()
    {
        var svc = new SecurityPostureService(new FakeWindowsUpdateProbe(null));
        var report = svc.Evaluate(MakeContext(
            clamInstalled: false,
            yaraRulesCount: 0,
            lastScanAt: null,
            signatureAutoUpdate: false));

        Assert.True(report.Score < 50);
    }

    [Fact]
    public void Windows_update_check_uses_injected_probe()
    {
        var recent = new SecurityPostureService(new FakeWindowsUpdateProbe(DateTime.UtcNow.AddDays(-2)));
        var stale = new SecurityPostureService(new FakeWindowsUpdateProbe(DateTime.UtcNow.AddDays(-90)));

        var ok = recent.Evaluate(MakeContext()).Checks.First(c => c.Id == "wupdate");
        var bad = stale.Evaluate(MakeContext()).Checks.First(c => c.Id == "wupdate");

        Assert.True(ok.Passed);
        Assert.False(bad.Passed);
    }

    [Fact]
    public void ShareRegistryValueIndicatesUserPath_handles_multi_sz()
    {
        Assert.True(SecurityPostureService.ShareRegistryValueIndicatesUserPath(
            new[] { "0", "Path=C:\\Users\\Public\\Share", "Security=..." }));
        Assert.False(SecurityPostureService.ShareRegistryValueIndicatesUserPath(new[] { "0", "Security=..." }));
        Assert.False(SecurityPostureService.ShareRegistryValueIndicatesUserPath(null));
    }

    private static SecurityPostureContext MakeContext(
        bool clamInstalled = true,
        int yaraRulesCount = 5,
        DateTime? lastScanAt = null,
        bool signatureAutoUpdate = true) =>
        new()
        {
            ClamInstalled = clamInstalled,
            YaraAvailable = true,
            YaraRulesCount = yaraRulesCount,
            RealTimeProtectionEnabled = true,
            RealTimeProtectionRunning = true,
            LastScanAt = lastScanAt,
            SignatureAutoUpdateEnabled = signatureAutoUpdate,
        };

    private sealed class FakeWindowsUpdateProbe : IWindowsUpdateProbe
    {
        private readonly DateTime? _lastUtc;

        public FakeWindowsUpdateProbe(DateTime? lastUtc) => _lastUtc = lastUtc;

        public DateTime? TryGetLastSuccessfulInstallUtc() => _lastUtc;

        public bool HasRecentSuccessfulInstall(TimeSpan maxAge) =>
            _lastUtc.HasValue && DateTime.UtcNow - _lastUtc.Value <= maxAge;
    }
}
