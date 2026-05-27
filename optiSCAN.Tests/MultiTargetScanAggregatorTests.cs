using optiSCAN.Models;
using optiSCAN.Services;

namespace optiSCAN.Tests;

public sealed class MultiTargetScanAggregatorTests
{
    [Fact]
    public async Task Aggregate_progress_keeps_cumulative_files_scanned_across_targets()
    {
        var reported = new List<int>();
        var progress = new Progress<ScanProgress>(p => reported.Add(p.FilesScanned));

        await MultiTargetScanAggregator.AggregateAsync(
            ScanType.QuickScan,
            new[] { @"C:\targetA", @"C:\targetB" },
            (target, prog, _) =>
            {
                if (target.Contains("targetA", StringComparison.Ordinal))
                    prog?.Report(new ScanProgress { FilesScanned = 12_000, Phase = ScanPhase.Scanning });
                else
                    prog?.Report(new ScanProgress { FilesScanned = 12, Phase = ScanPhase.Scanning });

                return Task.FromResult(new ScanResult
                {
                    FilesScanned = target.Contains("targetA", StringComparison.Ordinal) ? 12_000 : 12,
                    Status = ScanStatus.Completed,
                });
            },
            CancellationToken.None,
            progress,
            reportTargetProgress: false);

        Assert.Contains(12_000, reported);
        Assert.Contains(12_012, reported);
    }
}
