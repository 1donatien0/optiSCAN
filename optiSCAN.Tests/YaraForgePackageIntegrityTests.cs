// SPDX-License-Identifier: GPL-3.0-or-later
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using optiSCAN.Services;

namespace optiSCAN.Tests;

public sealed class YaraForgePackageIntegrityTests
{
    [Fact]
    public void Validate_rejects_non_zip()
    {
        Assert.False(YaraForgePackageIntegrity.Validate([0x00, 0x01], null, null));
    }

    [Fact]
    public void Validate_requires_size_and_sha256()
    {
        var zip = BuildZip(("a.yar", "rule a { condition: true }"));
        Assert.False(YaraForgePackageIntegrity.Validate(zip, null, null));
        Assert.False(YaraForgePackageIntegrity.Validate(zip, zip.Length, null));
        Assert.False(YaraForgePackageIntegrity.Validate(zip, null, SHA256.HashData(zip)));
        Assert.True(YaraForgePackageIntegrity.Validate(zip, zip.Length, SHA256.HashData(zip)));
    }

    [Theory]
    [InlineData("""{"size":12345}""")]
    [InlineData("""{"size":12345,"digest":"md5:abcd"}""")]
    [InlineData("""{"digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}""")]
    [InlineData("""{"size":999999999999,"digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}""")]
    public void TryGetExpectedDigest_refuses_missing_or_unusable_digest(string json) =>
        Assert.False(YaraForgePackageIntegrity.TryGetExpectedDigest(JsonNode.Parse(json), out _, out _));

    [Theory]
    [InlineData("https://github.com/YARAHQ/yara-forge/releases/download/20261026/yara-forge-rules-core.zip", "20261026", "yara-forge-rules-core.zip", true)]
    [InlineData("http://github.com/YARAHQ/yara-forge/releases/download/20261026/yara-forge-rules-core.zip", "20261026", "yara-forge-rules-core.zip", false)]
    [InlineData("https://github.com.evil.example/YARAHQ/yara-forge/releases/download/20261026/yara-forge-rules-core.zip", "20261026", "yara-forge-rules-core.zip", false)]
    [InlineData("https://github.com/YARAHQ/yara-forge/releases/download/20261005/yara-forge-rules-core.zip", "20261005", "yara-forge-rules-core.zip", false)]
    [InlineData("https://github.com/YARAHQ/yara-forge/releases/download/20261026/other.zip", "20261026", "other.zip", false)]
    [InlineData(null, "20261026", "yara-forge-rules-core.zip", false)]
    public void IsAllowedDownloadUrl_only_accepts_the_pinned_yara_forge_asset(
        string? url, string tagName, string assetName, bool expected) =>
        Assert.Equal(expected, YaraForgePackageIntegrity.IsAllowedDownloadUrl(url, tagName, assetName));

    [Fact]
    public void ExtractRules_writes_yar_files_flat_and_ignores_other_entries()
    {
        var dir = Path.Combine(Path.GetTempPath(), "optiscan_yf_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var zip = BuildZip(("packages/core/a.yar", "rule a { condition: true }"), ("README.md", "x"), ("../../evil.yar", "rule e { condition: true }"));
            using var archive = new System.IO.Compression.ZipArchive(new MemoryStream(zip));
            var count = YaraForgePackageIntegrity.ExtractRules(archive, dir, CancellationToken.None);

            Assert.Equal(2, count);
            Assert.True(File.Exists(Path.Combine(dir, "a.yar")));
            Assert.True(File.Exists(Path.Combine(dir, "evil.yar")));
            Assert.False(File.Exists(Path.Combine(Path.GetDirectoryName(dir)!, "evil.yar")));
            Assert.False(File.Exists(Path.Combine(dir, "README.md")));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void ExtractRules_refuses_an_entry_beyond_the_size_cap()
    {
        var dir = Path.Combine(Path.GetTempPath(), "optiscan_yf_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var big = new string('a', (int)YaraForgePackageIntegrity.MaxEntryBytes + 1);
            var zip = BuildZip(("big.yar", big));
            using var archive = new System.IO.Compression.ZipArchive(new MemoryStream(zip));
            Assert.Throws<InvalidDataException>(() => YaraForgePackageIntegrity.ExtractRules(archive, dir, CancellationToken.None));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task ReadBoundedAsync_refuses_more_than_the_limit()
    {
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            YaraForgePackageIntegrity.ReadBoundedAsync(new MemoryStream(new byte[11]), 10, CancellationToken.None));
        var ok = await YaraForgePackageIntegrity.ReadBoundedAsync(new MemoryStream(new byte[10]), 10, CancellationToken.None);
        Assert.Equal(10, ok.Length);
    }

    private static byte[] BuildZip(params (string Name, string Content)[] entries)
    {
        using var ms = new MemoryStream();
        using (var archive = new System.IO.Compression.ZipArchive(ms, System.IO.Compression.ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var (name, content) in entries)
            {
                var entry = archive.CreateEntry(name);
                using var writer = new StreamWriter(entry.Open(), Encoding.UTF8);
                writer.Write(content);
            }
        }
        return ms.ToArray();
    }

    [Fact]
    public void Validate_checks_size_and_sha256()
    {
        var zip = BuildZip(("b.yar", "rule b { condition: false }"));
        var hash = SHA256.HashData(zip);
        Assert.True(YaraForgePackageIntegrity.Validate(zip, zip.Length, hash));
        Assert.False(YaraForgePackageIntegrity.Validate(zip, zip.Length + 1, hash));
        Assert.False(YaraForgePackageIntegrity.Validate(zip, zip.Length, SHA256.HashData([1, 2, 3])));
    }

    [Fact]
    public void TryGetExpectedDigest_parses_github_asset()
    {
        var json = """
            {"size":12345,"digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
            """;
        var node = JsonNode.Parse(json);
        Assert.True(YaraForgePackageIntegrity.TryGetExpectedDigest(node, out var size, out var hash));
        Assert.Equal(12345, size);
        Assert.NotNull(hash);
        Assert.Equal(32, hash!.Length);
    }
}
