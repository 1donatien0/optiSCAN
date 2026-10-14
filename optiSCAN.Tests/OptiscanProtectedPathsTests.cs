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
    public void Executables_dropped_in_user_writable_data_folders_are_scanned()
    {
        var root = OptiscanProtectedPaths.GetLocalAppDataRoot();
        foreach (var sub in OptiscanProtectedPaths.LocalAppDataProtectedSubfolders)
        {
            var folder = Path.Combine(root, sub);
            // Le dossier est parcouru ; seuls les fichiers de données d'optiSCAN sont exclus.
            Assert.False(OptiscanProtectedPaths.IsUnderProtectedPath(folder));
            Assert.False(OptiscanProtectedPaths.IsUnderProtectedPath(Path.Combine(folder, "payload.exe")));
            Assert.False(OptiscanProtectedPaths.IsUnderProtectedPath(Path.Combine(folder, "x", "loader.ps1")));
            Assert.False(new ExclusionSettings { ExcludedFolders = { folder } }
                .IsFolderExcluded(Path.Combine(folder, "payload.dll")));
        }

        Assert.True(OptiscanProtectedPaths.IsUnderProtectedPath(Path.Combine(root, "clamav", "database", "main.cld")));
        Assert.True(OptiscanProtectedPaths.IsUnderProtectedPath(Path.Combine(root, "rules", "_compiled.yarc")));
        Assert.True(OptiscanProtectedPaths.IsUnderProtectedPath(Path.Combine(root, "SafetyBackups", "a.optibak")));
    }

    [Fact]
    public void ClamScan_exclude_patterns_keep_data_folders_browsable()
    {
        var clamav = Path.Combine(OptiscanProtectedPaths.GetLocalAppDataRoot(), "clamav");
        var patterns = AppInstallPaths.GetClamScanExcludePatterns()
            .Select(p => new System.Text.RegularExpressions.Regex(p, System.Text.RegularExpressions.RegexOptions.IgnoreCase))
            .ToList();

        Assert.Contains(patterns, r => r.IsMatch(Path.Combine(clamav, "database", "daily.cvd")));
        Assert.DoesNotContain(patterns, r => r.IsMatch(Path.Combine(clamav, "payload.exe")));
        Assert.DoesNotContain(patterns, r => r.IsMatch(clamav));
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
