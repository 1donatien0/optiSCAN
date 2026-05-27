using optiSCAN.Models;
using optiSCAN.Services;

namespace optiSCAN.Tests;

public sealed class ScanProgressRelayTests
{
    [Fact]
    public void Relay_keeps_monotonic_files_across_local_resets()
    {
        var reported = new List<int>();
        var relay = new ScanProgressRelay(12_000);
        var progress = relay.ToParent(new CollectProgress(reported));
        Assert.NotNull(progress);

        progress.Report(new ScanProgress { FilesScanned = 120, Phase = ScanPhase.Scanning });
        progress.Report(new ScanProgress { FilesScanned = 50, Phase = ScanPhase.Scanning });
        progress.Report(new ScanProgress { FilesScanned = 0, Phase = ScanPhase.Scanning });

        Assert.Equal(3, reported.Count);
        Assert.All(reported, n => Assert.Equal(12_120, n));
    }

    [Fact]
    public void Relay_merges_parallel_engines_to_max_local_count()
    {
        var reported = new List<int>();
        var relay = new ScanProgressRelay();
        var progress = relay.ToParent(new CollectProgress(reported));
        Assert.NotNull(progress);

        progress.Report(new ScanProgress { FilesScanned = 120, Phase = ScanPhase.Scanning });
        progress.Report(new ScanProgress { FilesScanned = 12, Phase = ScanPhase.Scanning });

        Assert.Equal(2, reported.Count);
        Assert.All(reported, n => Assert.Equal(120, n));
    }

    private sealed class CollectProgress(List<int> sink) : IProgress<ScanProgress>
    {
        public void Report(ScanProgress value) => sink.Add(value.FilesScanned);
    }
}
