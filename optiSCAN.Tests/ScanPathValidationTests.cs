using optiSCAN.Services;

namespace optiSCAN.Tests;

public sealed class ScanPathValidationTests
{
    [Fact]
    public void TryNormalizeScanTarget_rejects_device_paths()
    {
        Assert.False(ScanPathValidation.TryNormalizeScanTarget(@"\\.\C:\", out _));
        Assert.False(ScanPathValidation.TryNormalizeScanTarget(@"\\?\C:\", out _));
    }

    [Fact]
    public void TryNormalizeScanTarget_accepts_existing_file()
    {
        var file = Path.Combine(Path.GetTempPath(), "scanval_" + Guid.NewGuid().ToString("N") + ".txt");
        File.WriteAllText(file, "x");
        try
        {
            Assert.True(ScanPathValidation.TryNormalizeScanTarget(file, out var full));
            Assert.True(File.Exists(full));
        }
        finally
        {
            File.Delete(file);
        }
    }

    [Fact]
    public void TryNormalizeScanTarget_rejects_missing_path()
    {
        var missing = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        Assert.False(ScanPathValidation.TryNormalizeScanTarget(missing, out _));
    }
}
