// SPDX-License-Identifier: GPL-3.0-or-later
using optiSCAN.Models;
using optiSCAN.Services;

namespace optiSCAN.Tests;

public sealed class MultiTargetScanAggregatorTests
{
    [Fact]
    public async Task Aggregate_progress_keeps_cumulative_files_scanned_across_targets()
    {
        var reported = new List<int>();
        // Progress<T> publie de façon asynchrone sur le pool : la liste pouvait être encore vide
        // à l'assertion sous charge. Rapport synchrone pour un test déterministe.
        var progress = new SyncProgress<ScanProgress>(p => { lock (reported) reported.Add(p.FilesScanned); });

        await MultiTargetScanAggregator.AggregateAsync(
            ScanType.QuickScan,
            new[] { @"C:\targetA", @"C:\targetB" },
            (target, prog, _) =>
            {
                if (target.Contains("targetA", StringComparison.Ordinal))
                    prog?.Report(new ScanProgress { FilesScanned = 12_000, ClamFilesScanned = 12_000, Phase = ScanPhase.Scanning });
                else
                    prog?.Report(new ScanProgress { FilesScanned = 12, ClamFilesScanned = 12, Phase = ScanPhase.Scanning });

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

    [Fact]
    public async Task Aggregate_merges_same_file_detected_in_two_zones()
    {
        var path = @"C:\zone\evil.exe";
        var result = await MultiTargetScanAggregator.AggregateAsync(
            ScanType.QuickScan,
            new[] { @"C:\zoneA", @"C:\zoneB" },
            (_, _, _) => Task.FromResult(new ScanResult
            {
                Status = ScanStatus.Completed,
                Threats =
                {
                    new ThreatInfo { FilePath = path, VirusName = "Trojan.X", DetectedBy = "ClamAV" },
                }
            }),
            CancellationToken.None);

        Assert.Single(result.Threats);
        Assert.Equal(path, result.Threats[0].FilePath);
    }
}

internal sealed class SyncProgress<T> : IProgress<T>
{
    private readonly Action<T> _handler;

    public SyncProgress(Action<T> handler) => _handler = handler;

    public void Report(T value) => _handler(value);
}
