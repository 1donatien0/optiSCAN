// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;

namespace optiSCAN.Services;

/// <summary>Dossier de règles YARA inscriptible par la session, pas par Program Files.</summary>
internal static class YaraRulesLocation
{
    internal static string WritableDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "optiSCAN",
        "rules");

    internal static string InstallDirectory =>
        Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "rules");

    internal static string ResolveWritable(string? explicitDirectory = null)
    {
        if (!string.IsNullOrWhiteSpace(explicitDirectory))
            return explicitDirectory;

        var writable = WritableDirectory;
        Directory.CreateDirectory(writable);
        TrySeedFromInstall(writable);
        return writable;
    }

    private static void TrySeedFromInstall(string writable)
    {
        try
        {
            if (Directory.EnumerateFiles(writable, "*.yar").Any())
                return;

            var installed = InstallDirectory;
            if (!Directory.Exists(installed))
                return;

            foreach (var file in Directory.EnumerateFiles(installed, "*.yar"))
            {
                var dest = Path.Combine(writable, Path.GetFileName(file));
                if (!File.Exists(dest))
                    File.Copy(file, dest, overwrite: false);
            }
        }
        catch (Exception ex) when (!ex.IsFatal())
        {
            AppLogger.Warn("YaraRules", "Copie initiale des règles", ex);
        }
    }
}
