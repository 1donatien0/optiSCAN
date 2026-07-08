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
    public void Validate_accepts_zip_without_expected_digest()
    {
        var zip = new byte[] { 0x50, 0x4B, 0x03, 0x04 };
        Assert.True(YaraForgePackageIntegrity.Validate(zip, null, null));
    }

    [Fact]
    public void Validate_checks_size_and_sha256()
    {
        var zip = new byte[] { 0x50, 0x4B, 0x03, 0x04, 0x2A };
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
