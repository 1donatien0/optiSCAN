using optiSCAN.Services;

namespace optiSCAN.Tests;

public sealed class PlatformProtectionFeatureGateTests
{
    [Fact]
    public void IsUserActivatable_is_true_on_win()
    {
        Assert.True(PlatformProtectionFeatureGate.IsUserActivatable);
    }

    [Fact]
    public void NormalizePreferences_keeps_platform_flag_when_activatable()
    {
        var dir = Path.Combine(Path.GetTempPath(), "optiscan_gate_" + Guid.NewGuid().ToString("N"));
        var securePath = Path.Combine(dir, "preferences.dat");
        var legacyPath = Path.Combine(dir, "preferences.json");
        try
        {
            Directory.CreateDirectory(dir);
            var prefs = new UserPreferences { UsePlatformProtectionService = true };
            UserPreferences.SaveToStorage(securePath, prefs);

            var loaded = UserPreferences.LoadFromStorage(securePath, legacyPath);

            Assert.True(loaded.UsePlatformProtectionService);
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { }
        }
    }
}
