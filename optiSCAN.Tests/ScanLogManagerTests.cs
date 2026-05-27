using optiSCAN.Models;
using optiSCAN.Services;

namespace optiSCAN.Tests;

public sealed class ScanLogManagerTests : IDisposable
{
    private readonly string _logDir;
    private readonly ScanLogManager _manager;

    public ScanLogManagerTests()
    {
        _logDir = Path.Combine(Path.GetTempPath(), "optiscan_logs_" + Guid.NewGuid().ToString("N"));
        _manager = new ScanLogManager(_logDir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_logDir, recursive: true); } catch { }
    }

    [Fact]
    public void SaveScanResult_caps_history_at_100_entries()
    {
        for (int i = 0; i < 105; i++)
        {
            _manager.SaveScanResult(new ScanResult
            {
                Type = ScanType.QuickScan,
                TargetPath = $"target-{i}",
                Status = ScanStatus.Completed,
                FilesScanned = i,
            });
        }

        Assert.Equal(100, _manager.GetHistory().Count);
        Assert.Equal(104, _manager.GetHistory()[0].FilesScanned);
    }

    [Fact]
    public void WriteToLog_and_ReadLastLogLines_roundtrip()
    {
        _manager.WriteToLog("ligne de test optiSCAN");
        var lines = _manager.ReadLastLogLines(10);
        Assert.Contains(lines, l => l.Contains("ligne de test optiSCAN", StringComparison.Ordinal));
    }
}
