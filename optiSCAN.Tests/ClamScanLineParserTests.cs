// SPDX-License-Identifier: GPL-3.0-or-later
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

    [Fact]
    public void ProcessLine_data_scanned_parses_megabytes_with_decimals()
    {
        var result = new ScanResult();
        ClamScanLineParser.ProcessLine("Data scanned: 10.5 MB", result, null);

        Assert.Equal((long)(10.5 * 1024 * 1024), result.TotalBytesScanned);
    }

    [Fact]
    public void ProcessLine_OK_throttles_progress_after_500_files()
    {
        var progress = new SyncProgress();
        var reports = progress.Reports;

        var result = new ScanResult();
        for (var i = 1; i <= 1000; i++)
            ClamScanLineParser.ProcessLine($@"C:\f\file{i}.txt: OK", result, progress);

        Assert.Equal(1000, result.FilesScanned);
        Assert.True(reports.Count < 200, $"trop de rapports UI: {reports.Count}");
        Assert.Contains(500, reports);
        Assert.Contains(600, reports);
        Assert.Contains(1000, reports);
    }

    [Theory]
    [InlineData(@"C:\a.txt: Access denied. ERROR", true)]
    [InlineData("ERROR: Can't open file", true)]
    [InlineData(@"C:\a.txt: OK", false)]
    public void IsErrorLine_detects_clam_errors(string line, bool expected) =>
        Assert.Equal(expected, ClamScanLineParser.IsErrorLine(line));

    [Theory]
    [InlineData(0, 0, false, ScanStatus.Completed)]
    [InlineData(1, 1, false, ScanStatus.Completed)]
    [InlineData(1, 0, false, ScanStatus.Error)]
    [InlineData(2, 1, false, ScanStatus.Error)]
    [InlineData(2, 0, false, ScanStatus.Error)]
    [InlineData(2, 0, true, ScanStatus.Cancelled)]
    public void ClassifyExit_honors_clamscan_status(int exitCode, int threats, bool cancelled, ScanStatus expected)
    {
        var status = ClamAvEngine.ClassifyExit(exitCode, threats, cancelled, out _);
        Assert.Equal(expected, status);
    }

    /// <summary>IProgress synchrone : Progress&lt;T&gt; poste le rappel sur un autre thread.</summary>
    private sealed class SyncProgress : IProgress<ScanProgress>
    {
        public List<int> Reports { get; } = new();

        public void Report(ScanProgress value)
        {
            if (value.Phase == ScanPhase.Scanning && value.FilesScanned > 0)
                Reports.Add(value.FilesScanned);
        }
    }
}
