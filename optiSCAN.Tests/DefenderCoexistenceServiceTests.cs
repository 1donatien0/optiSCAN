using optiSCAN.Services;

namespace optiSCAN.Tests;

public sealed class DefenderCoexistenceServiceTests
{
    [Fact]
    public void BuildStatus_when_defender_inactive_uses_inactive_key()
    {
        if (!OperatingSystem.IsWindows())
            return;

        var status = DefenderCoexistenceService.BuildStatus(new DefaultUserPreferencesAccessor());
        if (DefenderCoexistenceService.IsDefenderActive())
            return;

        Assert.False(status.IsDefenderActive);
        Assert.Equal("Defender_Opt_StatusInactive", status.StatusMessageKey);
    }

    [Fact]
    public void ApplyNewInstallDefaults_sets_complement_flags_when_defender_active()
    {
        if (!OperatingSystem.IsWindows() || !DefenderCoexistenceService.IsDefenderActive())
            return;

        var prefs = new UserPreferences();
        DefenderCoexistenceService.ApplyNewInstallDefaults(prefs);

        Assert.True(prefs.FirstLaunchDefenderPending);
        Assert.False(prefs.DefenderCoexistenceConfigured);
        Assert.True(prefs.DefenderComplementModeEnabled);
        Assert.False(prefs.UsePlatformProtectionService);
        Assert.False(prefs.ProcessMonitorEnabled);
    }

    [Fact]
    public void ApplyComplementMode_disables_realtime_in_exclusions()
    {
        var prefs = new UserPreferences();
        var exclusions = new ExclusionSettings { RealTimeEnabled = true };
        var prefsAccessor = new InMemoryPreferencesAccessor(prefs);
        var exclAccessor = new InMemoryExclusionSettingsAccessor(exclusions);

        DefenderCoexistenceService.ApplyComplementMode(
            prefsAccessor,
            exclAccessor,
            _ => { },
            _ => { },
            _ => { });

        Assert.True(prefs.DefenderComplementModeEnabled);
        Assert.False(prefs.UsePlatformProtectionService);
        Assert.False(exclusions.RealTimeEnabled);
    }

    [Fact]
    public void ApplyFullOptiscanMode_enables_platform_when_gate_is_open()
    {
        var prefs = new UserPreferences
        {
            DefenderComplementModeEnabled = true,
            UsePlatformProtectionService = false,
            ProcessMonitorEnabled = false
        };
        var exclusions = new ExclusionSettings { RealTimeEnabled = false };
        var prefsAccessor = new InMemoryPreferencesAccessor(prefs);
        var exclAccessor = new InMemoryExclusionSettingsAccessor(exclusions);
        var platform = false;

        DefenderCoexistenceService.ApplyFullOptiscanMode(
            prefsAccessor,
            exclAccessor,
            _ => { },
            enabled => platform = enabled,
            _ => { });

        Assert.False(prefs.DefenderComplementModeEnabled);
        Assert.Equal(PlatformProtectionFeatureGate.IsUserActivatable, prefs.UsePlatformProtectionService);
        Assert.True(exclusions.RealTimeEnabled);
        Assert.Equal(PlatformProtectionFeatureGate.IsUserActivatable, platform);
    }

    private sealed class InMemoryPreferencesAccessor(UserPreferences current) : IUserPreferencesAccessor
    {
        public UserPreferences Current { get; } = current;
    }

    private sealed class InMemoryExclusionSettingsAccessor(ExclusionSettings current) : IExclusionSettingsAccessor
    {
        public ExclusionSettings Current { get; } = current;
    }
}
