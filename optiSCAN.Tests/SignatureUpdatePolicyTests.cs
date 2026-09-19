using Moq;
using optiSCAN.Services;

namespace optiSCAN.Tests;

public sealed class SignatureUpdatePolicyTests
{
    [Fact]
    public void ApplyAutoUpdateTimers_when_disabled_calls_disable_on_both_targets()
    {
        var freshclam = new Mock<ISignatureAutoUpdateTarget>(MockBehavior.Strict);
        var rules = new Mock<ISignatureAutoUpdateTarget>(MockBehavior.Strict);
        freshclam.Setup(f => f.DisableAutoUpdate());
        rules.Setup(r => r.DisableAutoUpdate());

        SignatureUpdatePolicy.ApplyAutoUpdateTimers(freshclam.Object, rules.Object, enabled: false, new DefaultUserPreferencesAccessor());

        freshclam.Verify(f => f.DisableAutoUpdate(), Times.Once);
        rules.Verify(r => r.DisableAutoUpdate(), Times.Once);
        freshclam.VerifyNoOtherCalls();
        rules.VerifyNoOtherCalls();
    }

    [Fact]
    public void ApplyAutoUpdateTimers_when_enabled_schedules_both_updaters()
    {
        var freshclam = new Mock<ISignatureAutoUpdateTarget>(MockBehavior.Strict);
        var rules = new Mock<ISignatureAutoUpdateTarget>(MockBehavior.Strict);
        freshclam.Setup(f => f.EnableAutoUpdate(It.IsAny<TimeSpan?>()));
        rules.Setup(r => r.EnableAutoUpdate(It.IsAny<TimeSpan?>()));

        SignatureUpdatePolicy.ApplyAutoUpdateTimers(freshclam.Object, rules.Object, enabled: true, new DefaultUserPreferencesAccessor());

        freshclam.Verify(f => f.EnableAutoUpdate(It.IsAny<TimeSpan?>()), Times.Once);
        rules.Verify(r => r.EnableAutoUpdate(It.IsAny<TimeSpan?>()), Times.Once);
    }

    [Fact]
    public void EvaluateStartupNeed_when_fresh_is_not_needed()
    {
        var last = DateTime.UtcNow.AddHours(-1);
        var r = SignatureUpdatePolicy.EvaluateStartupNeed(last, hasLocalYaraRules: true, staleThresholdDays: 7, utcNow: DateTime.UtcNow);
        Assert.False(r.Needed);
        Assert.False(r.MissingClam);
        Assert.False(r.MissingYara);
        Assert.False(r.ClamStale);
    }

    [Fact]
    public void EvaluateStartupNeed_when_clam_missing_is_needed()
    {
        var r = SignatureUpdatePolicy.EvaluateStartupNeed(null, hasLocalYaraRules: true, staleThresholdDays: 7);
        Assert.True(r.Needed);
        Assert.True(r.MissingClam);
    }

    [Fact]
    public void EvaluateStartupNeed_when_yara_missing_is_needed()
    {
        var r = SignatureUpdatePolicy.EvaluateStartupNeed(DateTime.UtcNow, hasLocalYaraRules: false, staleThresholdDays: 7);
        Assert.True(r.Needed);
        Assert.True(r.MissingYara);
        Assert.False(r.MissingClam);
    }

    [Fact]
    public void EvaluateStartupNeed_when_clam_older_than_threshold_is_stale()
    {
        var now = new DateTime(2026, 9, 17, 12, 0, 0, DateTimeKind.Utc);
        var last = now.AddDays(-10);
        var r = SignatureUpdatePolicy.EvaluateStartupNeed(last, hasLocalYaraRules: true, staleThresholdDays: 7, utcNow: now);
        Assert.True(r.Needed);
        Assert.True(r.ClamStale);
    }
}
