using optiSCAN.Models;
using optiSCAN.Services;

namespace optiSCAN.Tests;

/// <summary>
/// Une erreur de moteur ne doit jamais ressortir comme un scan propre, et un fichier
/// que clamd n'a pas lu doit être repris par clamscan.
/// </summary>
public sealed class EngineFailureTests
{
    [Fact]
    public void Merge_reports_error_when_an_engine_analysed_nothing()
    {
        var clam = new ScanResult { Status = ScanStatus.Error, ErrorMessage = "clamscan code 2" };
        var yara = new ScanResult { Status = ScanStatus.Completed, FilesScanned = 3 };

        var merged = ScanThreatMerger.Merge(ScanType.Folder, @"C:\d", clam, yara, new FixedExclusions());

        Assert.Equal(ScanStatus.Error, merged.Status);
        Assert.Equal("clamscan code 2", merged.ErrorMessage);
    }

    [Fact]
    public void Merge_keeps_completed_but_records_a_partial_engine_error()
    {
        var clam = new ScanResult { Status = ScanStatus.Error, FilesScanned = 40, ErrorMessage = "2 fichiers illisibles" };
        var yara = new ScanResult { Status = ScanStatus.Completed, FilesScanned = 40 };

        var merged = ScanThreatMerger.Merge(ScanType.Folder, @"C:\d", clam, yara, new FixedExclusions());

        Assert.Equal(ScanStatus.Completed, merged.Status);
        Assert.Contains("partiel", merged.ErrorMessage);
    }

    [Fact]
    public void Merge_keeps_threats_found_by_an_incomplete_engine()
    {
        var path = Path.Combine(Path.GetTempPath(), "optiscan_ut_partial.exe");
        var clam = new ScanResult { Status = ScanStatus.Completed, FilesScanned = 1 };
        var yara = new ScanResult
        {
            Status = ScanStatus.Error,
            ErrorMessage = "YARA code 1",
            Threats = { new ThreatInfo { FilePath = path, VirusName = "Rule", DetectedBy = "YARA" } },
        };

        var merged = ScanThreatMerger.Merge(ScanType.File, path, clam, yara, new FixedExclusions());

        Assert.Single(merged.Threats);
        Assert.Equal(ScanStatus.Completed, merged.Status);
    }

    [Fact]
    public async Task MultiTarget_is_error_only_when_no_zone_could_be_scanned()
    {
        var allFail = await MultiTargetScanAggregator.AggregateAsync(
            ScanType.QuickScan,
            new[] { "A", "B" },
            (t, _, _) => Task.FromResult(new ScanResult { Status = ScanStatus.Error, ErrorMessage = "refus" }),
            CancellationToken.None);
        Assert.Equal(ScanStatus.Error, allFail.Status);

        var oneFails = await MultiTargetScanAggregator.AggregateAsync(
            ScanType.QuickScan,
            new[] { "A", "B" },
            (t, _, _) => Task.FromResult(t == "A"
                ? new ScanResult { Status = ScanStatus.Error, ErrorMessage = "refus" }
                : new ScanResult { Status = ScanStatus.Completed, FilesScanned = 10 }),
            CancellationToken.None);
        Assert.Equal(ScanStatus.Completed, oneFails.Status);
        Assert.Contains("A", oneFails.ErrorMessage);
    }

    [Fact]
    public async Task Files_clamd_could_not_read_are_rescanned_by_clamscan()
    {
        var clamd = new UnscannedBackend(@"C:\d\locked.sys");
        var clamscan = new ListBackend();
        var composite = new CompositeClamAvBackend(_ => Task.FromResult(true), clamd, clamscan);

        var result = await composite.ScanFolderAsync(@"C:\d");

        Assert.Equal(new[] { @"C:\d\locked.sys" }, clamscan.LastList);
        Assert.Equal(ScanStatus.Completed, result.Status);
        Assert.Equal(6, result.FilesScanned);
        Assert.Single(result.Threats);
        Assert.Empty(result.UnscannedFiles);
    }

    [Fact]
    public async Task Rescan_failure_makes_the_folder_scan_an_error()
    {
        var clamd = new UnscannedBackend(@"C:\d\locked.sys");
        var clamscan = new ListBackend { Fail = true };
        var composite = new CompositeClamAvBackend(_ => Task.FromResult(true), clamd, clamscan);

        var result = await composite.ScanFolderAsync(@"C:\d");

        Assert.Equal(ScanStatus.Error, result.Status);
    }

    [Fact]
    public async Task Orchestrator_keeps_yara_matches_when_yara_stops_with_an_error()
    {
        var dir = Path.Combine(Path.GetTempPath(), "optiscan_ut_yara_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var file = Path.Combine(dir, "x.bin");
        await File.WriteAllTextAsync(file, "x");
        try
        {
            var yara = new IncompleteYara(file);
            var orch = new ScanOrchestrator(new ListBackend(), yara, exclusions: new FixedExclusions());

            var result = await orch.ScanFileAsync(file);

            Assert.Contains(result.Threats, t => t.VirusName.Contains("Partial_Rule"));
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { /* best effort */ }
        }
    }

    [Fact]
    public void Folder_enumeration_includes_hidden_files_and_skips_excluded_or_linked_folders()
    {
        var root = Path.Combine(Path.GetTempPath(), "optiscan_ut_enum_" + Guid.NewGuid().ToString("N"));
        var excluded = Path.Combine(root, "excluded");
        var nested = Path.Combine(root, "a", "b");
        Directory.CreateDirectory(excluded);
        Directory.CreateDirectory(nested);
        File.WriteAllText(Path.Combine(root, "top.txt"), "1");
        File.WriteAllText(Path.Combine(nested, "deep.txt"), "2");
        File.WriteAllText(Path.Combine(excluded, "skip.txt"), "3");
        var hidden = Path.Combine(root, "hidden.txt");
        File.WriteAllText(hidden, "4");
        File.SetAttributes(hidden, File.GetAttributes(hidden) | FileAttributes.Hidden);
        var linked = false;
        try
        {
            Directory.CreateSymbolicLink(Path.Combine(root, "link"), nested);
            linked = true;
        }
        catch
        {
            /* création de lien refusée sans privilège : partie ignorée */
        }

        try
        {
            var files = ClamdEngine.EnumerateScannableFiles(
                    root,
                    dir => string.Equals(dir, excluded, StringComparison.OrdinalIgnoreCase))
                .Select(Path.GetFileName)
                .OrderBy(n => n)
                .ToList();

            Assert.Equal(new[] { "deep.txt", "hidden.txt", "top.txt" }, files);
            if (linked)
                Assert.DoesNotContain(files, f => f == "link");
        }
        finally
        {
            try { Directory.Delete(root, recursive: true); } catch { /* best effort */ }
        }
    }

    [Theory]
    [InlineData(0xA0000003u, true)]   // jonction
    [InlineData(0xA000000Cu, true)]   // lien symbolique
    [InlineData(0x9000001Au, false)]  // OneDrive (cloud files)
    [InlineData(0x8000001Bu, false)]  // AppExecLink
    public void Only_name_surrogate_reparse_points_block_a_quarantine_delete(uint tag, bool blocks) =>
        Assert.Equal(blocks, SafePathDelete.IsNameSurrogate(tag));

    [Fact]
    public void Installer_cleanup_mode_is_parsed() =>
        Assert.Equal(
            HeadlessScanArguments.Mode.CleanupLegacyDefenderExclusions,
            HeadlessScanArguments.ParseMode(new[] { "--cleanup-legacy-defender-exclusions", "--quiet" }));

    private sealed class FixedExclusions : IExclusionSettingsAccessor
    {
        public ExclusionSettings Current { get; } = new();
    }

    private sealed class UnscannedBackend : IClamAvOrchestratorBackend
    {
        private readonly string _unscanned;

        public UnscannedBackend(string unscanned) => _unscanned = unscanned;

        public bool IsClamAvInstalled() => true;

        public Task<ScanResult> ScanFileAsync(string filePath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default) =>
            Task.FromResult(new ScanResult { Status = ScanStatus.Completed, FilesScanned = 1 });

        public Task<ScanResult> ScanFolderAsync(string folderPath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default)
        {
            var result = new ScanResult { Type = ScanType.Folder, TargetPath = folderPath, Status = ScanStatus.Completed, FilesScanned = 5 };
            result.UnscannedFiles.Add(_unscanned);
            return Task.FromResult(result);
        }

        public Task<ScanResult> ScanFileListAsync(IReadOnlyList<string> files, string targetPath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default) =>
            throw new NotSupportedException();
    }

    private sealed class ListBackend : IClamAvOrchestratorBackend
    {
        public bool Fail { get; init; }
        public IReadOnlyList<string>? LastList { get; private set; }

        public bool IsClamAvInstalled() => true;

        public Task<ScanResult> ScanFileAsync(string filePath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default) =>
            Task.FromResult(new ScanResult { Type = ScanType.File, TargetPath = filePath, Status = ScanStatus.Completed, FilesScanned = 1 });

        public Task<ScanResult> ScanFolderAsync(string folderPath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default) =>
            Task.FromResult(new ScanResult { Status = ScanStatus.Completed });

        public Task<ScanResult> ScanFileListAsync(IReadOnlyList<string> files, string targetPath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default)
        {
            LastList = files.ToList();
            if (Fail)
                return Task.FromResult(new ScanResult { Status = ScanStatus.Error, ErrorMessage = "clamscan code 2" });

            var result = new ScanResult { Status = ScanStatus.Completed, FilesScanned = files.Count };
            result.Threats.Add(new ThreatInfo { FilePath = files[0], VirusName = "Win.Test", DetectedBy = "ClamAV" });
            return Task.FromResult(result);
        }
    }

    private sealed class IncompleteYara : IYaraOrchestratorBackend
    {
        private readonly string _file;

        public IncompleteYara(string file) => _file = file;

        public bool IsAvailable => true;
        public int RulesCount => 1;

        public Task<List<YaraMatch>> ScanFileAsync(string filePath, CancellationToken ct = default) =>
            throw new YaraScanIncompleteException(
                "YARA s'est terminé avec le code 1.",
                new List<YaraMatch> { new() { FilePath = _file, RuleName = "Partial_Rule" } });

        public Task<List<YaraMatch>> ScanFolderAsync(string folderPath, IProgress<string>? progress = null, CancellationToken ct = default) =>
            Task.FromResult(new List<YaraMatch>());

        public Task<List<YaraMatch>> ScanFilesAsync(IReadOnlyList<string> files, IProgress<string>? progress = null, CancellationToken ct = default) =>
            Task.FromResult(new List<YaraMatch>());
    }
}
