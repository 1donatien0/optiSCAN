// SPDX-License-Identifier: GPL-3.0-or-later
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

    // ── Checks individuels ────────────────────────────────────────────────────

    [Fact]
    public void Check_scan_passes_when_scan_within_7_days()
    {
        var svc = new SecurityPostureService(new FakeWindowsUpdateProbe(DateTime.UtcNow));
        var report = svc.Evaluate(MakeContext(lastScanAt: DateTime.Now.AddDays(-3)));
        Assert.True(report.Checks.First(c => c.Id == "scan").Passed);
    }

    [Fact]
    public void Check_scan_fails_when_no_scan_or_older_than_7_days()
    {
        var svc = new SecurityPostureService(new FakeWindowsUpdateProbe(DateTime.UtcNow));

        var noScan = svc.Evaluate(MakeContext(lastScanAt: null)).Checks.First(c => c.Id == "scan");
        var oldScan = svc.Evaluate(MakeContext(lastScanAt: DateTime.Now.AddDays(-10))).Checks.First(c => c.Id == "scan");

        Assert.False(noScan.Passed);
        Assert.False(oldScan.Passed);
    }

    [Fact]
    public void Check_optiscan_passes_when_clam_yara_and_rtp_all_active()
    {
        var svc = new SecurityPostureService(new FakeWindowsUpdateProbe(DateTime.UtcNow));
        var ctx = new SecurityPostureContext
        {
            ClamInstalled = true,
            YaraAvailable = true,
            YaraRulesCount = 5,
            RealTimeProtectionEnabled = true,
            RealTimeProtectionRunning = true,
            LastScanAt = DateTime.Now,
            SignatureAutoUpdateEnabled = true,
        };
        var check = svc.Evaluate(ctx).Checks.First(c => c.Id == "optiscan");
        Assert.True(check.Passed);
    }

    [Fact]
    public void Check_optiscan_fails_when_clam_missing()
    {
        var svc = new SecurityPostureService(new FakeWindowsUpdateProbe(DateTime.UtcNow));
        var check = svc.Evaluate(MakeContext(clamInstalled: false)).Checks.First(c => c.Id == "optiscan");
        Assert.False(check.Passed);
    }

    [Fact]
    public void Check_sigauto_passes_when_enabled()
    {
        var svc = new SecurityPostureService(new FakeWindowsUpdateProbe(DateTime.UtcNow));
        var check = svc.Evaluate(MakeContext(signatureAutoUpdate: true)).Checks.First(c => c.Id == "sigauto");
        Assert.True(check.Passed);
    }

    [Fact]
    public void Check_sigauto_fails_when_disabled()
    {
        var svc = new SecurityPostureService(new FakeWindowsUpdateProbe(DateTime.UtcNow));
        var check = svc.Evaluate(MakeContext(signatureAutoUpdate: false)).Checks.First(c => c.Id == "sigauto");
        Assert.False(check.Passed);
    }

    // ── FixUri ────────────────────────────────────────────────────────────────

    [Fact]
    public void Uac_check_FixUri_uses_user_account_control_settings_not_developers()
    {
        var svc = new SecurityPostureService(new FakeWindowsUpdateProbe(DateTime.UtcNow));
        var check = svc.Evaluate(MakeContext()).Checks.First(c => c.Id == "uac");

        Assert.Contains("UserAccountControlSettings.exe", check.FixUri, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("|", check.FixUri);
        Assert.DoesNotContain("developers", check.FixUri, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Firewall_check_FixUri_prefers_firewall_settings_with_fallbacks()
    {
        var svc = new SecurityPostureService(new FakeWindowsUpdateProbe(DateTime.UtcNow));
        var check = svc.Evaluate(MakeContext()).Checks.First(c => c.Id == "firewall");

        Assert.Contains("windowsdefender-firewall", check.FixUri, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("WF.msc", check.FixUri, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("shares", SecurityPostureService.FixRemoveExposedShares)]
    [InlineData("optiscan", SecurityPostureService.FixEnableProtection)]
    [InlineData("scan", SecurityPostureService.FixStartQuickScan)]
    [InlineData("sigauto", SecurityPostureService.FixEnableSigAuto)]
    public void InApp_checks_use_optiscan_fix_actions(string checkId, string expectedFixUri)
    {
        var svc = new SecurityPostureService(new FakeWindowsUpdateProbe(DateTime.UtcNow));
        var check = svc.Evaluate(MakeContext()).Checks.First(c => c.Id == checkId);

        Assert.Equal(expectedFixUri, check.FixUri);
        Assert.StartsWith("optiscan://fix/", check.FixUri, StringComparison.Ordinal);
    }

    [Fact]
    public void TryRemoveExposedShares_with_empty_confirmation_removes_nothing()
    {
        // Aucun nom confirmé → aucun appel à net share, succès immédiat.
        Assert.True(SecurityPostureService.TryRemoveExposedShares(Array.Empty<string>()));
    }

    [Fact]
    public void All_checks_have_non_empty_FixUri()
    {
        var svc = new SecurityPostureService(new FakeWindowsUpdateProbe(DateTime.UtcNow));
        var checks = svc.Evaluate(MakeContext()).Checks;

        foreach (var c in checks)
            Assert.False(string.IsNullOrWhiteSpace(c.FixUri), $"Check '{c.Id}' has no FixUri");
    }

    // ── Score maximal ─────────────────────────────────────────────────────────

    [Fact]
    public void Score_weights_sum_to_100()
    {
        var svc = new SecurityPostureService(new FakeWindowsUpdateProbe(DateTime.UtcNow));
        var checks = svc.Evaluate(MakeContext()).Checks;
        Assert.Equal(100, checks.Sum(c => c.Weight));
    }

    [Fact]
    public void ShareRegistryValueIndicatesUserPath_handles_single_string()
    {
        Assert.True(SecurityPostureService.ShareRegistryValueIndicatesUserPath("Path=C:\\Users\\Public\\Share"));
        Assert.False(SecurityPostureService.ShareRegistryValueIndicatesUserPath("Security=0x1"));
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
