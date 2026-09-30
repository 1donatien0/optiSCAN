using System.Security.Cryptography;
using System.Text;

namespace optiSCAN.Services;

/// <summary>Vérification d'intégrité des paquets YARA-Forge téléchargés (digest GitHub + taille).</summary>
internal static class YaraForgePackageIntegrity
{
    private const string Sha256Prefix = "sha256:";

    /// <summary>
    /// Parse le champ <c>digest</c> de l'API GitHub Releases (ex. <c>sha256:ABCD…</c>).
    /// </summary>
    internal static bool TryParseGitHubDigest(string? digest, out byte[] sha256)
    {
        sha256 = Array.Empty<byte>();
        if (string.IsNullOrWhiteSpace(digest))
            return false;

        var trimmed = digest.Trim();
        if (!trimmed.StartsWith(Sha256Prefix, StringComparison.OrdinalIgnoreCase))
            return false;

        var hex = trimmed[Sha256Prefix.Length..];
        if (hex.Length != 64)
            return false;

        try
        {
            sha256 = Convert.FromHexString(hex);
            return sha256.Length == 32;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    /// <summary>
    /// Vérifie taille attendue (si fournie par l'API) et digest SHA-256 du contenu téléchargé.
    /// </summary>
    internal static bool Verify(byte[] content, long? expectedSize, ReadOnlySpan<byte> expectedSha256)
    {
        if (content.Length == 0)
            return false;

        if (expectedSize is > 0 && content.LongLength != expectedSize.Value)
            return false;

        if (expectedSha256.Length > 0)
        {
            if (expectedSha256.Length != 32)
                return false;

            Span<byte> actual = stackalloc byte[32];
            SHA256.HashData(content, actual);
            return actual.SequenceEqual(expectedSha256);
        }

        return true;
    }

    internal static string FormatDigestForLog(ReadOnlySpan<byte> sha256) =>
        sha256.Length == 32
            ? Convert.ToHexString(sha256)
            : Encoding.UTF8.GetString(sha256);
}
