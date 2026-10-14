using optiSCAN.Services;

namespace optiSCAN.Tests;

/// <summary>Défauts relevés à la relecture des corrections (audit du 13 octobre, section « relecture »).</summary>
public sealed class AuditReviewFixesTests
{
    [Theory]
    [InlineData("bad.exe", false)]
    [InlineData(@"Downloads\bad.exe", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void Actions_refuse_paths_that_are_not_fully_qualified(string? path, bool expected)
    {
        Assert.Equal(expected, AntivirusActions.IsActionablePath(path));
    }

    [Fact]
    public void Actions_accept_a_fully_qualified_path()
    {
        Assert.True(AntivirusActions.IsActionablePath(Path.Combine(Path.GetTempPath(), "x.exe")));
    }

    [Fact]
    public void Executable_disguised_as_data_file_in_a_data_folder_is_scanned()
    {
        var folder = Path.Combine(OptiscanProtectedPaths.GetLocalAppDataRoot(), "SafetyBackups");
        Directory.CreateDirectory(folder);
        var disguised = Path.Combine(folder, "payload_" + Guid.NewGuid().ToString("N") + ".dat");
        var data = Path.Combine(folder, "data_" + Guid.NewGuid().ToString("N") + ".dat");
        try
        {
            // En-tête PE minimal : MZ, e_lfanew = 0x40, signature PE\0\0.
            var pe = new byte[0x200];
            pe[0] = (byte)'M'; pe[1] = (byte)'Z';
            BitConverter.GetBytes(0x40).CopyTo(pe, 0x3C);
            pe[0x40] = (byte)'P'; pe[0x41] = (byte)'E';
            File.WriteAllBytes(disguised, pe);
            File.WriteAllText(data, "donnees");

            Assert.False(OptiscanProtectedPaths.IsUnderProtectedPath(disguised));
            Assert.True(OptiscanProtectedPaths.IsUnderProtectedPath(data));
        }
        finally
        {
            try { File.Delete(disguised); } catch { }
            try { File.Delete(data); } catch { }
        }
    }

    [Fact]
    public void Clamscan_excludes_only_large_binary_data_in_data_folders()
    {
        var clamav = Path.Combine(OptiscanProtectedPaths.GetLocalAppDataRoot(), "clamav");
        var patterns = AppInstallPaths.GetClamScanExcludePatterns()
            .Select(p => new System.Text.RegularExpressions.Regex(p, System.Text.RegularExpressions.RegexOptions.IgnoreCase))
            .ToList();

        Assert.Contains(patterns, r => r.IsMatch(Path.Combine(clamav, "database", "main.cld")));
        Assert.DoesNotContain(patterns, r => r.IsMatch(Path.Combine(clamav, "freshclam.conf")));
        Assert.DoesNotContain(patterns, r => r.IsMatch(Path.Combine(clamav, "payload.dat")));
    }
}
