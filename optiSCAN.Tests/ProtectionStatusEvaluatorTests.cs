using optiSCAN.Localization;
using optiSCAN.Services;

namespace optiSCAN.Tests;

[Collection("Localization")]
public sealed class ProtectionStatusEvaluatorTests
{
    public ProtectionStatusEvaluatorTests() => LocalizationService.ApplyCulture("fr-FR");
    [Theory]
    [InlineData(false, false, 0, true, true, ProtectionBadgeLevel.Inactive)]
    [InlineData(true, true, 0, true, true, ProtectionBadgeLevel.Degraded)]
    [InlineData(true, false, 10, false, false, ProtectionBadgeLevel.Degraded)]
    [InlineData(true, true, 5, true, true, ProtectionBadgeLevel.Active)]
    [InlineData(true, false, 10, true, true, ProtectionBadgeLevel.Active)]
    public void Evaluate_matches_expected_level(
        bool clam, bool yaraAvail, int rules, bool rtpSetting, bool rtpRunning, ProtectionBadgeLevel expected)
    {
        var level = ProtectionStatusEvaluator.Evaluate(clam, yaraAvail, rules, rtpSetting, rtpRunning);
        Assert.Equal(expected, level);
    }

    [Theory]
    [InlineData(true, true, 5, false, false, ProtectionBadgeLevel.Active)]    // RTP déléguée à Defender : pas « dégradé »
    [InlineData(true, true, 0, false, false, ProtectionBadgeLevel.Degraded)]  // règles YARA manquantes : reste dégradé
    [InlineData(false, true, 5, false, false, ProtectionBadgeLevel.Inactive)] // ClamAV absent : inactif
    public void Evaluate_complement_mode_does_not_penalize_disabled_rtp(
        bool clam, bool yaraAvail, int rules, bool rtpSetting, bool rtpRunning, ProtectionBadgeLevel expected)
    {
        var level = ProtectionStatusEvaluator.Evaluate(clam, yaraAvail, rules, rtpSetting, rtpRunning,
            realTimeDelegatedToDefender: true);
        Assert.Equal(expected, level);
    }

    [Fact]
    public void GetBadgeText_returns_french_labels()
    {
        LocalizationService.ApplyCulture("fr-FR");
        Assert.Equal("Actif", ProtectionStatusEvaluator.GetBadgeText(ProtectionBadgeLevel.Active));
        Assert.Equal("Dégradé", ProtectionStatusEvaluator.GetBadgeText(ProtectionBadgeLevel.Degraded));
        Assert.Equal("Inactif", ProtectionStatusEvaluator.GetBadgeText(ProtectionBadgeLevel.Inactive));
    }
}
