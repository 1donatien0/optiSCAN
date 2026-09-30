using System.IO;

namespace optiSCAN.Services;

/// <summary>Validation des chemins proposés pour analyse (menu contextuel, pipe IPC, CLI).</summary>
public static class ScanPathValidation
{
    /// <summary>Normalise et valide un chemin utilisateur scannable.</summary>
    public static bool TryNormalizeScanTarget(string? path, out string fullPath)
    {
        fullPath = string.Empty;
        if (string.IsNullOrWhiteSpace(path))
            return false;

        var trimmed = path.Trim().Trim('"');
        if (trimmed.IndexOfAny(['\0', '\r', '\n']) >= 0)
            return false;

        if (trimmed.StartsWith(@"\\.\", StringComparison.Ordinal)
            || trimmed.StartsWith(@"\\?\", StringComparison.Ordinal))
            return false;

        try
        {
            fullPath = Path.GetFullPath(trimmed);
        }
        catch
        {
            return false;
        }

        if (QuarantineManager.IsSensitivePath(fullPath))
            return false;

        return File.Exists(fullPath) || Directory.Exists(fullPath);
    }
}
