using optiSCAN.Platform;
using optiSCAN.Services;

namespace optiSCAN.Tests;

public sealed class OptiscanProtectedPathsTests
{
    [Fact]
    public void LocalAppData_optiSCAN_protects_only_signatures_rules_and_quarantine()
    {
        var root = OptiscanProtectedPaths.GetLocalAppDataRoot();
        var dbFile = Path.Combine(root, "clamav", "database", "daily.cvd");
        var quarantine = Path.Combine(root, "Quarantine", "manifest.json");
        var updateStaging = Path.Combine(root, "Updates", "optiSCAN.exe");

        Assert.True(OptiscanProtectedPaths.IsUnderProtectedPath(dbFile));
        Assert.True(OptiscanProtectedPaths.IsUnderProtectedPath(quarantine));
        Assert.True(OptiscanProtectedPaths.IsMandatoryExcludedFolder(Path.Combine(root, "clamav")));
        // Le reste du dossier, inscriptible par la session, est analysé.
        Assert.False(OptiscanProtectedPaths.IsUnderProtectedPath(root));
        Assert.False(OptiscanProtectedPaths.IsUnderProtectedPath(updateStaging));
        Assert.False(OptiscanProtectedPaths.IsMandatoryExcludedFolder(root));
    }

    [Fact]
    public void Process_install_directory_is_protected_when_admin_only_otherwise_only_its_engines()
    {
        var root = Path.GetFullPath(AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
        var exe = Path.Combine(root, "optiSCAN.exe");
        var rule = Path.Combine(root, "rules", "test.yar");

        Assert.True(OptiscanProtectedPaths.IsUnderProtectedPath(rule));
        if (InstallLocationTrust.IsAdminOnlyInstall(root, out _))
        {
            Assert.True(OptiscanProtectedPaths.IsUnderProtectedPath(exe));
            Assert.Contains(OptiscanProtectedPaths.GetProtectedRoots(),
                r => string.Equals(r, root, StringComparison.OrdinalIgnoreCase));
        }
        else
        {
            Assert.False(OptiscanProtectedPaths.IsUnderProtectedPath(exe));
        }
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
        var protectedRoot = Path.Combine(OptiscanProtectedPaths.GetLocalAppDataRoot(), "clamav");
        settings.ExcludedFolders.Add(protectedRoot);

        Assert.False(settings.RemoveFolder(protectedRoot));
        Assert.Contains(settings.ExcludedFolders,
            f => string.Equals(f.TrimEnd('\\'), protectedRoot.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase));
    }
}
