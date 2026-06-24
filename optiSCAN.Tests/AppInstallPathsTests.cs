using optiSCAN.Services;

namespace optiSCAN.Tests;

public sealed class InstallExclusionTests
{
    [Fact]
    public void Files_under_app_base_directory_are_excluded_from_scans()
    {
        var root = AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        Assert.False(string.IsNullOrWhiteSpace(root));

        var exe = Path.Combine(root, "optiSCAN.exe");
        var rule = Path.Combine(root, "rules", "test.yar");

        Assert.True(ExclusionSettings.Current.IsFileExcluded(exe));
        Assert.True(ExclusionSettings.Current.IsFileExcluded(rule));
    }

    [Fact]
    public void Files_under_local_app_data_optiSCAN_are_excluded_from_scans()
    {
        var root = OptiscanProtectedPaths.GetLocalAppDataRoot();
        var clamDb = Path.Combine(root, "clamav", "database", "main.cvd");
        var quarantine = Path.Combine(root, "Quarantine", "manifest.json");

        Assert.True(ExclusionSettings.Current.IsFileExcluded(clamDb));
        Assert.True(ExclusionSettings.Current.IsFileExcluded(quarantine));
    }
}
