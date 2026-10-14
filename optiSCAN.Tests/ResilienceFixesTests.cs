using optiSCAN.Models;
using optiSCAN.Services;

namespace optiSCAN.Tests;

/// <summary>
/// Copies d'analyse orphelines, clés et manifeste de quarantaine illisibles, journal du service,
/// comptage multi-zones, temps réel de l'hôte SYSTEM.
/// </summary>
public sealed class ResilienceFixesTests
{
    // ── Copies d'analyse laissées par un arrêt brutal ─────────────────────────────

    [Fact]
    public void Stale_staging_copies_are_purged_and_recent_ones_kept()
    {
        var root = Path.Combine(Path.GetTempPath(), "optiscan_staging_purge_" + Guid.NewGuid().ToString("N"));
        var old = Path.Combine(root, "old");
        var recent = Path.Combine(root, "recent");
        Directory.CreateDirectory(old);
        Directory.CreateDirectory(recent);
        File.WriteAllText(Path.Combine(old, "payload.exe"), "x");
        File.WriteAllText(Path.Combine(recent, "payload.exe"), "x");
        var past = DateTime.UtcNow.AddDays(-1);
        Directory.SetCreationTimeUtc(old, past);
        Directory.SetLastWriteTimeUtc(old, past);
        try
        {
            var removed = ScanStaging.PurgeStale(TimeSpan.FromHours(2), root);

            Assert.Equal(1, removed);
            Assert.False(Directory.Exists(old));
            Assert.True(Directory.Exists(recent));
        }
        finally
        {
            try { Directory.Delete(root, recursive: true); } catch { /* nettoyage */ }
        }
    }

    // ── Quarantaine : une clé ou un manifeste illisible n'est jamais détruit ─────

    [Fact]
    public void Unreadable_master_key_is_kept_aside_before_a_new_one_is_created()
    {
        if (!OperatingSystem.IsWindows())
            return;

        var dir = Path.Combine(Path.GetTempPath(), "optiscan_qkey_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        File.WriteAllBytes(Path.Combine(dir, ".key"), new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 });
        try
        {
            using var manager = new QuarantineManager(dir);

            Assert.Contains(Directory.GetFiles(dir), f => Path.GetFileName(f).StartsWith(".key.unreadable-", StringComparison.Ordinal));
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { /* nettoyage */ }
        }
    }

    [Fact]
    public void Rejected_manifest_is_kept_aside_instead_of_being_overwritten()
    {
        if (!OperatingSystem.IsWindows())
            return;

        var dir = Path.Combine(Path.GetTempPath(), "optiscan_qmanifest_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, "manifest.json"),
            "{\"Version\":2,\"Hmac\":\"\",\"Entries\":[{\"Id\":\"0123456789abcdef0123456789abcdef\",\"OriginalPath\":\"C:\\\\x.exe\"}]}");
        try
        {
            using var manager = new QuarantineManager(dir);

            Assert.Equal(0, manager.Count);
            Assert.Contains(Directory.GetFiles(dir), f => Path.GetFileName(f).StartsWith("manifest.json.rejected-", StringComparison.Ordinal));
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { /* nettoyage */ }
        }
    }

    // ── Comptage d'une analyse multi-zones sans progression (scan planifié, service) ─

    [Fact]
    public async Task Files_of_each_zone_add_up_without_progress_reporting()
    {
        var result = await MultiTargetScanAggregator.AggregateAsync(
            ScanType.FullScan,
            new[] { @"C:\", @"D:\" },
            (target, _, _) => Task.FromResult(new ScanResult
            {
                Status = ScanStatus.Completed,
                FilesScanned = target.StartsWith('C') ? 1000 : 250,
            }),
            CancellationToken.None);

        Assert.Equal(1250, result.FilesScanned);
    }

    // ── Hôte SYSTEM : pas de seconde quarantaine sans empreinte ──────────────────

    [Fact]
    public void Service_host_logs_the_source_quarantine_without_quarantining_again()
    {
        var root = Path.Combine(Path.GetTempPath(), "optiscan_host_" + Guid.NewGuid().ToString("N"));
        var logger = new ScanLogManager(Path.Combine(root, "logs"));
        var quarantine = new QuarantineManager(Path.Combine(root, "q"));
        var context = new Context(quarantine, logger);
        var handler = new ServiceHostThreatHandler(context, new DefaultExclusionSettingsAccessor(), new DefaultUserPreferencesAccessor());
        try
        {
            handler.OnThreatDetected(this, new ThreatInfo
            {
                FilePath = @"C:\temp\evil.exe",
                VirusName = "Test.Done",
                Status = ThreatStatus.Quarantined,
            });

            Assert.Contains(logger.ReadLastLogLines(), l => l.Contains("Test.Done") && l.Contains("mise en quarantaine"));
            Assert.Equal(0, quarantine.Count);
        }
        finally
        {
            quarantine.Dispose();
            try { Directory.Delete(root, recursive: true); } catch { /* nettoyage */ }
        }
    }

    [Fact]
    public void Service_host_preferences_never_apply_the_first_launch_defender_rule()
    {
        var root = FindRepoRoot();
        var code = File.ReadAllText(Path.Combine(root, "optiSCAN", "Services", "ServiceContainer.cs"));
        var start = code.IndexOf("public void ApplyHostPreferences()", StringComparison.Ordinal);
        var end = code.IndexOf("private void OnHostPolicyChanged", start, StringComparison.Ordinal);
        Assert.True(start > 0 && end > start);
        Assert.DoesNotContain("EnsureFirstLaunchExclusionSettings", code[start..end], StringComparison.Ordinal);
    }

    // ── Journal texte borné ───────────────────────────────────────────────────

    [Fact]
    public void Text_log_is_rotated_beyond_its_size_limit()
    {
        var dir = Path.Combine(Path.GetTempPath(), "optiscan_logrot_" + Guid.NewGuid().ToString("N"));
        var logger = new ScanLogManager(dir);
        try
        {
            Directory.CreateDirectory(dir);
            using (var fs = new FileStream(logger.TextLogPath, FileMode.Create))
                fs.SetLength(ScanLogManager.MaxTextLogBytes + 1);

            logger.WriteToLog("après rotation");

            Assert.True(File.Exists(logger.TextLogPath + ".1"));
            Assert.True(new FileInfo(logger.TextLogPath).Length < 1024);
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { /* nettoyage */ }
        }
    }

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !File.Exists(Path.Combine(dir.FullName, "optiSCAN.sln")))
            dir = dir.Parent;
        Assert.NotNull(dir);
        return dir!.FullName;
    }

    private sealed class Context(QuarantineManager quarantine, ScanLogManager logger) : IServiceHostThreatContext
    {
        public QuarantineManager Quarantine { get; } = quarantine;
        public ScanLogManager Logger { get; } = logger;
        public CloudThreatIntelService CloudThreatIntel { get; } = new(new NoReputation());
    }

    private sealed class NoReputation : IThreatReputationService
    {
        public Task<ThreatReputationService.ReputationResult> LookupFileAsync(string filePath, CancellationToken ct = default) =>
            Task.FromResult(new ThreatReputationService.ReputationResult());
    }
}
