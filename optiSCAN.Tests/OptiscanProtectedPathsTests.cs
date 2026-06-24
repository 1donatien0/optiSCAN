using optiSCAN.Services;

namespace optiSCAN.Tests;

public sealed class OptiscanProtectedPathsTests
{
    [Fact]
    public void LocalAppData_optiSCAN_tree_is_protected()
    {
        var root = OptiscanProtectedPaths.GetLocalAppDataRoot();
        var dbFile = Path.Combine(root, "clamav", "database", "daily.cvd");
        var updateStaging = Path.Combine(root, "Updates", "optiSCAN.exe");

        Assert.True(OptiscanProtectedPaths.IsUnderProtectedPath(root));
        Assert.True(OptiscanProtectedPaths.IsUnderProtectedPath(dbFile));
        Assert.True(OptiscanProtectedPaths.IsUnderProtectedPath(updateStaging));
        Assert.True(OptiscanProtectedPaths.IsMandatoryExcludedFolder(root));
    }

    [Fact]
    public void Process_install_directory_is_protected()
    {
        var root = AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var exe = Path.Combine(root, "optiSCAN.exe");

        Assert.True(OptiscanProtectedPaths.IsUnderProtectedPath(exe));
        Assert.Contains(OptiscanProtectedPaths.GetProtectedRoots(),
            r => string.Equals(r, Path.GetFullPath(root), StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void ClamScan_exclude_patterns_are_nonempty()
    {
        var patterns = AppInstallPaths.GetClamScanExcludePatterns().ToList();
        Assert.NotEmpty(patterns);
        Assert.All(patterns, p => Assert.StartsWith("^", p));
    }

    [Fact]
    public void Mandatory_folder_cannot_be_removed_from_exclusions()
    {
        var settings = new ExclusionSettings();
        var protectedRoot = OptiscanProtectedPaths.GetLocalAppDataRoot();
        settings.ExcludedFolders.Add(protectedRoot);

        Assert.False(settings.RemoveFolder(protectedRoot));
        Assert.Contains(settings.ExcludedFolders,
            f => string.Equals(f.TrimEnd('\\'), protectedRoot.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase));
    }
}
