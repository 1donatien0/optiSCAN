using optiSCAN.Coordinators;
using optiSCAN.Models;
using optiSCAN.Services;
using optiSCAN.ViewModels;

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

public sealed class RealTimeThreatCoordinatorTests
{
    [Fact]
    public void Handle_notifies_sink_and_refresh_callbacks()
    {
        var threat = new ThreatInfo { FilePath = @"C:\t.exe", VirusName = "Test" };
        var sink = new RecordingLiveThreatSink();
        int quarantineRefreshes = 0;
        int overviewRefreshes = 0;

        RealTimeThreatCoordinator.Handle(threat, new RealTimeThreatCoordinator.Host
        {
            LiveThreatSink = sink,
            RefreshQuarantineList = () => quarantineRefreshes++,
            RefreshOverviewProtection = () => overviewRefreshes++,
        });

        Assert.Single(sink.Threats);
        Assert.Equal(threat.FilePath, sink.Threats[0].FilePath);
        Assert.Equal(1, quarantineRefreshes);
        Assert.Equal(1, overviewRefreshes);
    }

    private sealed class RecordingLiveThreatSink : ILiveThreatSink
    {
        public List<ThreatInfo> Threats { get; } = new();

        public void AppendLiveThreat(ThreatInfo threat) => Threats.Add(threat);
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
