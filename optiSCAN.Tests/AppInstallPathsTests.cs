using optiSCAN.Platform;
using optiSCAN.Services;

namespace optiSCAN.Tests;

public sealed class InstallExclusionTests
{
    [Fact]
    public void Engines_and_rules_under_app_base_directory_are_excluded_from_scans()
    {
        var root = AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        Assert.False(string.IsNullOrWhiteSpace(root));

        var exe = Path.Combine(root, "optiSCAN.exe");
        var rule = Path.Combine(root, "rules", "test.yar");

        Assert.True(ExclusionSettings.Current.IsFileExcluded(rule));
        // Le binaire n'est exclu que si le dossier est réservé aux administrateurs.
        Assert.Equal(
            InstallLocationTrust.IsAdminOnlyInstall(root, out _),
            ExclusionSettings.Current.IsFileExcluded(exe));
    }

    [Fact]
    public void Signatures_and_quarantine_under_local_app_data_are_excluded_from_scans()
    {
        var root = OptiscanProtectedPaths.GetLocalAppDataRoot();
        var clamDb = Path.Combine(root, "clamav", "database", "main.cvd");
        var quarantine = Path.Combine(root, "Quarantine", "manifest.json");
        var dropped = Path.Combine(root, "dropped.exe");

        Assert.True(ExclusionSettings.Current.IsFileExcluded(clamDb));
        Assert.True(ExclusionSettings.Current.IsFileExcluded(quarantine));
        Assert.False(ExclusionSettings.Current.IsFileExcluded(dropped));
    }
}
