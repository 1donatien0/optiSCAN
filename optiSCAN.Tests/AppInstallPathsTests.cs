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
}
