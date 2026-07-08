using System.Security.Cryptography;
using System.Text.Json.Nodes;

namespace optiSCAN.Services;

/// <summary>Vérification d'intégrité des paquets YARA-Forge téléchargés (taille + digest GitHub).</summary>
internal static class YaraForgePackageIntegrity
{
    public static bool TryGetExpectedDigest(JsonNode? asset, out long? size, out byte[]? sha256)
    {
        size = null;
        sha256 = null;
        if (asset is null)
            return false;

        try
        {
            size = asset["size"]?.GetValue<long>();
        }
        catch
        {
            /* taille absente */
        }

        var digest = asset["digest"]?.GetValue<string>();
        if (string.IsNullOrWhiteSpace(digest))
            return size.HasValue;

        const string prefix = "sha256:";
        if (!digest.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            return size.HasValue;

        var hex = digest[prefix.Length..].Trim();
        if (hex.Length != 64)
            return size.HasValue;

        try
        {
            sha256 = Convert.FromHexString(hex);
            return true;
        }
        catch
        {
            return size.HasValue;
        }
    }

    public static bool Validate(byte[] zipBytes, long? expectedSize, byte[]? expectedSha256)
    {
        if (zipBytes.Length < 4 || zipBytes[0] != 0x50 || zipBytes[1] != 0x4B)
            return false;

        if (expectedSize.HasValue && zipBytes.Length != expectedSize.Value)
            return false;

        if (expectedSha256 is { Length: 32 })
        {
            var actual = SHA256.HashData(zipBytes);
            if (!CryptographicOperations.FixedTimeEquals(actual, expectedSha256))
                return false;
        }

        return true;
    }
}
