// SPDX-License-Identifier: GPL-3.0-or-later
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
    public void OptiSCAN_binaries_are_never_process_exclusions()
    {
        var processes = WindowsDefenderExclusionService.CollectProcessExclusionPaths(requireTrustedInstall: false);

        Assert.DoesNotContain(processes, p =>
            Path.GetFileName(p).Equals("optiSCAN.exe", StringComparison.OrdinalIgnoreCase)
            || Path.GetFileName(p).Equals("optiSCAN.Service.exe", StringComparison.OrdinalIgnoreCase));
        Assert.All(WindowsDefenderExclusionService.EngineProcessRelativePaths, rel =>
            Assert.DoesNotContain("optiSCAN", Path.GetFileName(rel), StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Retired_app_process_exclusions_are_full_paths_for_removal()
    {
        var retired = WindowsDefenderExclusionService.CollectRetiredProcessExclusionPaths();

        Assert.Contains(retired, p => Path.GetFileName(p).Equals("optiSCAN.exe", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(retired, p => Path.GetFileName(p).Equals("optiSCAN.Service.exe", StringComparison.OrdinalIgnoreCase));
        Assert.All(retired, p => Assert.True(Path.IsPathFullyQualified(p), p));
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
