using optiSCAN.Models;
using optiSCAN.Services;

namespace optiSCAN.Tests;

public sealed class RiskScoringServiceTests
{
    [Fact]
    public void Assess_ransomware_keyword_is_critical()
    {
        var threat = new ThreatInfo
        {
            FilePath = @"C:\Users\test\file.exe",
            VirusName = "Trojan.Ransom.Generic",
            DetectedBy = "ClamAV",
        };

        var result = RiskScoringService.Assess(threat);

        Assert.Equal(RiskLevel.Critical, result.Level);
    }

    [Fact]
    public void Assess_system32_path_elevates_risk()
    {
        var threat = new ThreatInfo
        {
            FilePath = @"C:\Windows\System32\svc.exe",
            VirusName = "Suspicious",
            DetectedBy = "YARA",
        };

        var result = RiskScoringService.Assess(threat);

        Assert.True(result.Score >= 40);
    }

    [Fact]
    public void AssessAll_returns_worst_threat()
    {
        var threats = new[]
        {
            new ThreatInfo { FilePath = @"C:\a.txt", VirusName = "Adware", DetectedBy = "ClamAV" },
            new ThreatInfo { FilePath = @"C:\b.exe", VirusName = "Ransomware", DetectedBy = "ClamAV" },
        };

        var worst = RiskScoringService.AssessAll(threats);

        Assert.Equal(RiskLevel.Critical, worst.Level);
    }

    [Fact]
    public void GetSeverityBrushKey_maps_levels()
    {
        Assert.Equal("RiskCritical", RiskScoringService.GetSeverityBrushKey(RiskLevel.Critical));
        Assert.Equal("RiskInformational", RiskScoringService.GetSeverityBrushKey(RiskLevel.Informational));
    }
}

public sealed class TamperProtectionServiceTests
{
    [Fact]
    public void EnsureWatchdogTask_when_disabled_attempts_cleanup()
    {
        var prefs = new UserPreferences { TamperProtectionEnabled = false };
        var accessor = new FixedUserPreferencesAccessor(prefs);
        var service = new TamperProtectionService(accessor);

        var result = service.EnsureWatchdogTask();

        Assert.True(result);
    }

    private sealed class FixedUserPreferencesAccessor(UserPreferences prefs) : IUserPreferencesAccessor
    {
        public UserPreferences Current => prefs;
        public void Save() { }
    }
}
