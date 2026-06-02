using optiSCAN.Models;
using optiSCAN.Services;

namespace optiSCAN.Tests;

public sealed class ClamScanLineParserTests
{
    [Fact]
    public void ProcessLine_FOUND_adds_threat()
    {
        var result = new ScanResult();
        ClamScanLineParser.ProcessLine(@"C:\temp\eicar.com: Eicar-Test-Signature FOUND", result, null);

        Assert.Single(result.Threats);
        Assert.Equal("Eicar-Test-Signature", result.Threats[0].VirusName);
        Assert.Equal("ClamAV", result.Threats[0].DetectedBy);
    }

    [Fact]
    public void ProcessLine_OK_increments_files_scanned()
    {
        var result = new ScanResult();
        ClamScanLineParser.ProcessLine(@"C:\temp\clean.txt: OK", result, null);

        Assert.Equal(1, result.FilesScanned);
        Assert.Empty(result.Threats);
    }

    [Fact]
    public void ProcessLine_stats_updates_scanned_files()
    {
        var result = new ScanResult();
        ClamScanLineParser.ProcessLine("Scanned files: 42", result, null);

        Assert.Equal(42, result.FilesScanned);
    }
}
