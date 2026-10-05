using optiSCAN.Platform;
using optiSCAN.Services;

namespace optiSCAN.Tests;

public sealed class WindowsDefenderExclusionServiceTests
{
    [Fact]
    public void CollectExclusionPaths_skips_user_writable_folders()
    {
        var paths = WindowsDefenderExclusionService.CollectExclusionPaths();
        var local = OptiscanProtectedPaths.GetLocalAppDataRoot();

        Assert.DoesNotContain(paths, p =>
            p.StartsWith(local, StringComparison.OrdinalIgnoreCase));
        Assert.All(paths, p => Assert.True(InstallLocationTrust.IsAdminOnlyInstall(p, out _), p));

        var install = Path.GetFullPath(AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
        if (InstallLocationTrust.IsAdminOnlyInstall(install, out _))
            Assert.Contains(paths, p => p.Equals(install, StringComparison.OrdinalIgnoreCase));
        else
            Assert.Empty(WindowsDefenderExclusionService.CollectProcessExclusionPaths());

        Assert.All(WindowsDefenderExclusionService.CollectProcessExclusionPaths(), path =>
            Assert.Contains(Path.DirectorySeparatorChar, path));
    }

    [Fact]
    public void IsWindowsDefenderPresent_matches_mpcmdrun_on_windows()
    {
        var mpcmd = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            "Windows Defender",
            "MpCmdRun.exe");

        Assert.Equal(File.Exists(mpcmd), WindowsDefenderExclusionService.IsWindowsDefenderPresent());
    }
}
