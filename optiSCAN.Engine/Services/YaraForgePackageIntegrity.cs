// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json.Nodes;

namespace optiSCAN.Services;

/// <summary>
/// Vérification et extraction des paquets YARA-Forge.
/// <para>
/// L'asset core est accepté uniquement pour une release et une empreinte approuvées dans le code.
/// Le digest GitHub doit aussi correspondre à cette liste locale ; plafonds de téléchargement et
/// de décompression, extraction confinée au dossier de règles via un dossier temporaire.
/// Une nouvelle release nécessite une mise à jour optiSCAN qui approuve explicitement son empreinte.
/// </para>
/// </summary>
internal static class YaraForgePackageIntegrity
{
    /// <summary>Le paquet « core » pèse quelques Mo ; au-delà, le téléchargement est refusé.</summary>
    internal const long MaxPackageBytes = 64L * 1024 * 1024;

    /// <summary>Plafonds de décompression (anti zip bomb).</summary>
    internal const long MaxEntryBytes = 32L * 1024 * 1024;
    internal const long MaxTotalExtractedBytes = 256L * 1024 * 1024;
    internal const int MaxRuleFiles = 5_000;

    private const string AllowedHost = "github.com";
    private const string AllowedPathPrefix = "/YARAHQ/yara-forge/releases/download/";
    internal const string TrustedTag = "20261026";
    private const string TrustedAssetName = "yara-forge-rules-core.zip";
    private const long TrustedAssetSize = 1_744_047;
    private const string TrustedSha256Hex = "95ff046c4250e8965928f467dda61621a2c776dd02f40a375a829d60a4e92e13";

    /// <summary>
    /// Release interrogée : celle qui est épinglée, jamais « latest ». Avec « latest », chaque
    /// nouvelle publication hebdomadaire de YARA-Forge faisait échouer toute mise à jour des
    /// règles (« vérification d'intégrité »), alors que la release approuvée restait disponible.
    /// </summary>
    internal const string TrustedReleaseApiUrl = "https://api.github.com/repos/YARAHQ/yara-forge/releases/tags/" + TrustedTag;

    /// <summary>
    /// Vérifie la release et l'asset contre l'allowlist embarquée, puis vérifie que les
    /// métadonnées retournées par GitHub sont conformes à l'empreinte approuvée localement.
    /// </summary>
    public static bool TryGetTrustedExpectedDigest(
        string? tagName, string? assetName, JsonNode? asset, out long? size, out byte[]? sha256)
    {
        size = null;
        sha256 = null;
        if (!string.Equals(tagName, TrustedTag, StringComparison.Ordinal)
            || !string.Equals(assetName, TrustedAssetName, StringComparison.Ordinal)
            || asset is null)
            return false;

        string? reportedName;
        try { reportedName = asset["name"]?.GetValue<string>(); }
        catch (Exception ignored) when (!ignored.IsFatal()) { reportedName = null; }
        if (!string.Equals(reportedName, TrustedAssetName, StringComparison.Ordinal))
            return false;

        if (!TryGetExpectedDigest(asset, out var reportedSize, out var reportedSha256)
            || reportedSize != TrustedAssetSize
            || reportedSha256 is not { Length: 32 })
            return false;

        var trustedSha256 = Convert.FromHexString(TrustedSha256Hex);
        if (!CryptographicOperations.FixedTimeEquals(reportedSha256, trustedSha256))
            return false;

        size = TrustedAssetSize;
        sha256 = trustedSha256;
        return true;
    }

    /// <summary>Taille et SHA-256 de l'asset GitHub ; faux si l'un des deux manque ou est invalide.</summary>
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
        catch (Exception ignored) when (!ignored.IsFatal())
        {
            size = null;
        }

        string? digest;
        try { digest = asset["digest"]?.GetValue<string>(); }
        catch (Exception ignored) when (!ignored.IsFatal()) { digest = null; }

        const string prefix = "sha256:";
        if (string.IsNullOrWhiteSpace(digest) || !digest.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            return false;

        var hex = digest[prefix.Length..].Trim();
        if (hex.Length != 64)
            return false;

        try
        {
            sha256 = Convert.FromHexString(hex);
        }
        catch (FormatException)
        {
            return false;
        }

        return size is > 0 and <= MaxPackageBytes;
    }

    /// <summary>URL de téléchargement attendue pour un asset YARA-Forge.</summary>
    public static bool IsAllowedDownloadUrl(string? url, string? tagName, string? assetName) =>
        string.Equals(tagName, TrustedTag, StringComparison.Ordinal)
        && string.Equals(assetName, TrustedAssetName, StringComparison.Ordinal)
        && Uri.TryCreate(url, UriKind.Absolute, out var uri)
        && uri.Scheme == Uri.UriSchemeHttps
        && uri.IsDefaultPort
        && string.IsNullOrEmpty(uri.UserInfo)
        && string.IsNullOrEmpty(uri.Query)
        && string.IsNullOrEmpty(uri.Fragment)
        && string.Equals(uri.Host, AllowedHost, StringComparison.OrdinalIgnoreCase)
        && string.Equals(uri.AbsolutePath, AllowedPathPrefix + TrustedTag + "/" + TrustedAssetName, StringComparison.Ordinal);

    /// <summary>Taille et SHA-256 exigés (plus de validation « magic PK seul »).</summary>
    public static bool Validate(byte[] zipBytes, long? expectedSize, byte[]? expectedSha256)
    {
        if (expectedSize is null || expectedSha256 is not { Length: 32 })
            return false;

        if (zipBytes.Length < 4 || zipBytes[0] != 0x50 || zipBytes[1] != 0x4B)
            return false;

        if (zipBytes.Length != expectedSize.Value)
            return false;

        var actual = SHA256.HashData(zipBytes);
        return CryptographicOperations.FixedTimeEquals(actual, expectedSha256);
    }

    /// <summary>Lit au plus <paramref name="maxBytes"/> octets ; au-delà, refus.</summary>
    public static async Task<byte[]> ReadBoundedAsync(Stream source, long maxBytes, CancellationToken ct)
    {
        using var buffer = new MemoryStream();
        var chunk = new byte[81920];
        int read;
        while ((read = await source.ReadAsync(chunk, ct).ConfigureAwait(false)) > 0)
        {
            if (buffer.Length + read > maxBytes)
                throw new InvalidDataException("Paquet YARA-Forge trop volumineux");
            buffer.Write(chunk, 0, read);
        }

        return buffer.ToArray();
    }

    /// <summary>
    /// Extrait les fichiers <c>.yar</c> à plat dans <paramref name="targetDirectory"/>, en
    /// refusant tout nom qui sortirait de ce dossier, et dans les plafonds de taille.
    /// Rend le nombre de fichiers écrits ; lève <see cref="InvalidDataException"/> si un plafond
    /// est dépassé (rien ne doit alors être installé).
    /// </summary>
    public static int ExtractRules(ZipArchive archive, string targetDirectory, CancellationToken ct)
    {
        var root = Path.GetFullPath(targetDirectory).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        long total = 0;
        var written = 0;
        var seen = 0;

        foreach (var entry in archive.Entries)
        {
            if ((seen++ & 0x3F) == 0)
                ct.ThrowIfCancellationRequested();

            var name = entry.Name;
            if (name.Length == 0 || !name.EndsWith(".yar", StringComparison.OrdinalIgnoreCase))
                continue;

            if (++written > MaxRuleFiles)
                throw new InvalidDataException("Trop de fichiers dans le paquet YARA-Forge");
            if (entry.Length > MaxEntryBytes)
                throw new InvalidDataException($"Règle trop volumineuse : {name}");

            var dest = Path.GetFullPath(Path.Combine(root, name));
            if (!dest.StartsWith(root, StringComparison.OrdinalIgnoreCase)
                || !string.Equals(Path.GetDirectoryName(dest) + Path.DirectorySeparatorChar, root, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException($"Nom de règle refusé : {name}");

            // La taille déclarée peut mentir : on compte ce qui est réellement décompressé.
            using var input = entry.Open();
            using var output = new FileStream(dest, FileMode.Create, FileAccess.Write, FileShare.None);
            var chunk = new byte[81920];
            long entryBytes = 0;
            int read;
            while ((read = input.Read(chunk, 0, chunk.Length)) > 0)
            {
                entryBytes += read;
                total += read;
                if (entryBytes > MaxEntryBytes || total > MaxTotalExtractedBytes)
                    throw new InvalidDataException("Décompression YARA-Forge au-delà du plafond");
                output.Write(chunk, 0, read);
            }
        }

        return written;
    }
}
