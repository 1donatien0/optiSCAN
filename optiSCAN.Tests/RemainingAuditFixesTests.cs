// SPDX-License-Identifier: GPL-3.0-or-later
using System.Security.Cryptography;
using optiSCAN.Services;

namespace optiSCAN.Tests;

public sealed class WingetLocaleAndFooterTests
{
    private const string GermanUpgrade =
        "Name               ID                    Version   Verfügbar  Quelle\n" +
        "-------------------------------------------------------------------\n" +
        "7-Zip 23.01 (x64)  7zip.7zip             23.01     24.08      winget\n" +
        "Mozilla Firefox    Mozilla.Firefox       128.0     131.0      winget\n" +
        "2 Aktualisierungen verfügbar.\n";

    [Fact]
    public void Upgrade_table_is_read_in_any_language_and_names_may_start_with_a_digit()
    {
        var parsed = WingetUpdateService.ParseUpgradeOutput(GermanUpgrade);
        Assert.Equal(2, parsed.Count);
        Assert.Equal("7zip.7zip", parsed[0].Id);
        Assert.Equal("23.01", parsed[0].InstalledVersion);
        Assert.Equal("24.08", parsed[0].AvailableVersion);
        Assert.Equal("Mozilla.Firefox", parsed[1].Id);
    }

    [Fact]
    public void Progress_spinner_rewritten_with_carriage_returns_is_ignored()
    {
        var output = "   - \r   \\ \r" + GermanUpgrade.Replace("\n", "\r\n", StringComparison.Ordinal);
        Assert.Equal(2, WingetUpdateService.ParseUpgradeOutput(output).Count);
    }

    [Fact]
    public void Spanish_list_output_is_read()
    {
        const string output =
            "Nombre        Id              Versión   Origen\n" +
            "----------------------------------------------\n" +
            "Foo App       Foo.App         4.0.0     winget\n" +
            "Foo App       Foo.App         7.0.0     winget\n" +
            "\n";
        var parsed = WingetUpdateService.ParseListOutput(output);
        Assert.Equal(["4.0.0", "7.0.0"], parsed.Select(p => p.Version).ToList());
    }

    [Fact]
    public void No_table_means_no_updates()
    {
        Assert.Empty(WingetUpdateService.ParseUpgradeOutput("Aucune mise à niveau disponible."));
    }

    [Fact]
    public void Winget_runs_are_bounded()
    {
        Assert.True(WingetUpdateService.QueryTimeout > TimeSpan.Zero);
        Assert.True(WingetUpdateService.UpgradeTimeout >= TimeSpan.FromMinutes(10));
        Assert.True(WingetUpdateService.UpgradeAllTimeout > WingetUpdateService.UpgradeTimeout);
    }
}

public sealed class SafetyCopyRetentionTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "optiscan_safety_" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch { }
    }

    [Fact]
    public void Safety_copy_can_be_read_back_by_content_hash()
    {
        var content = "contenu de test"u8.ToArray();
        Assert.True(ThreatRemediationService.TryCreateSafetyCopy(content, _root));

        var hash = Convert.ToHexString(SHA256.HashData(content));
        Assert.Equal(content, ThreatRemediationService.TryReadSafetyCopy(hash, _root));
        Assert.Null(ThreatRemediationService.TryReadSafetyCopy(new string('0', 64), _root));

        Assert.Equal(1, ThreatRemediationService.DeleteSafetyCopies(hash, _root));
        Assert.Null(ThreatRemediationService.TryReadSafetyCopy(hash, _root));
    }

    [Fact]
    public void Expired_copies_are_purged_and_recent_ones_kept()
    {
        Directory.CreateDirectory(_root);
        var old = Path.Combine(_root, "20200101_000000_ABC_1.optibak");
        var recent = Path.Combine(_root, "20991231_000000_DEF_2.optibak");
        File.WriteAllBytes(old, new byte[10]);
        File.WriteAllBytes(recent, new byte[10]);
        File.SetLastWriteTimeUtc(old, DateTime.UtcNow - ThreatRemediationService.SafetyCopyRetention - TimeSpan.FromDays(1));

        Assert.Equal(1, ThreatRemediationService.PurgeSafetyCopies(_root));
        Assert.False(File.Exists(old));
        Assert.True(File.Exists(recent));
    }
}

public sealed class QuickScanTargetTests
{
    [Fact]
    public void Quick_scan_covers_roaming_app_data()
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        if (!Directory.Exists(appData))
            return;
        Assert.Contains(ScanTargets.QuickScanTargets(), t => string.Equals(
            Path.TrimEndingDirectorySeparator(t), Path.TrimEndingDirectorySeparator(appData), StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Nested_targets_are_scanned_once()
    {
        var root = Path.Combine(Path.GetTempPath(), "optiscan_nest");
        var result = ScanTargets.RemoveNested(new[]
        {
            Path.Combine(root, "Roaming", "Microsoft", "Startup"),
            Path.Combine(root, "Roaming"),
            Path.Combine(root, "Roaming2"),
            Path.Combine(root, "Roaming") + Path.DirectorySeparatorChar,
        });
        Assert.Equal(new[] { Path.Combine(root, "Roaming"), Path.Combine(root, "Roaming2") }, result);
    }
}
