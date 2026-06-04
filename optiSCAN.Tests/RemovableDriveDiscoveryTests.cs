using optiSCAN.Services;

namespace optiSCAN.Tests;

public class RemovableDriveDiscoveryTests
{
    [Theory]
    [InlineData(0, 100_000_000_000L, true)]
    [InlineData(64, 32L * 1024 * 1024 * 1024, true)]
    [InlineData(64, 65L * 1024 * 1024 * 1024, false)]
    [InlineData(32, 40L * 1024 * 1024 * 1024, false)]
    public void IsWithinSizeLimit_respects_max_gb(int maxGb, long totalBytes, bool expected) =>
        Assert.Equal(expected, RemovableDriveDiscovery.IsWithinSizeLimit(totalBytes, maxGb));

    [Theory]
    [InlineData("E:", "E:\\")]
    [InlineData("F:\\", "F:\\")]
    [InlineData("", null)]
    public void NormalizeRootFromDriveName_maps_letters(string input, string? expected) =>
        Assert.Equal(expected, RemovableDriveDiscovery.NormalizeRootFromDriveName(input));

    [Fact]
    public void FindNewRemovableRoots_skips_known()
    {
        var known = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { @"E:\" };
        var found = RemovableDriveDiscovery.FindNewRemovableRoots(known);
        Assert.DoesNotContain(@"E:\", found, StringComparer.OrdinalIgnoreCase);
    }

    [Fact]
    public void EnumerateAllFiles_includes_non_executable_extensions()
    {
        var dir = Path.Combine(Path.GetTempPath(), "optiscan_usb_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var doc = Path.Combine(dir, "readme.txt");
            File.WriteAllText(doc, "test");
            var files = RemovableDriveDiscovery.EnumerateAllFiles(dir, 10).ToList();
            Assert.Contains(doc, files);
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { /* ignore */ }
        }
    }
}
