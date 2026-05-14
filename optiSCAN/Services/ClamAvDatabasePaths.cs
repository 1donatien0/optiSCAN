using System.IO;

namespace optiSCAN.Services
{
    /// <summary>
    /// Répertoire des signatures ClamAV : doit être inscriptible (freshclam crée
    /// des sous-dossiers <c>tmp.*</c>). Les installs sous Program Files échouent
    /// souvent au 2e lancement même si la 1re MAJ a réussi.
    /// </summary>
    internal static class ClamAvDatabasePaths
    {
        private const string SeedMarker = ".optiscan-db-seeded";

        /// <summary>Résout le dossier <c>database</c> à côté des binaires (ou parent).</summary>
        public static string ResolvePreferredDatabaseDir(string clamavBinDir)
        {
            clamavBinDir = Path.GetFullPath(clamavBinDir);
            var local = Path.Combine(clamavBinDir, "database");
            if (Directory.Exists(local))
                return Path.GetFullPath(local);

            var parent = Path.GetDirectoryName(clamavBinDir);
            if (parent != null)
            {
                var parentDb = Path.Combine(parent, "database");
                if (Directory.Exists(parentDb))
                    return Path.GetFullPath(parentDb);
            }

            return Path.GetFullPath(local);
        }

        /// <summary>
        /// Répertoire effectif pour freshclam / clamscan / clamd : préféré si sain,
        /// sinon <c>%LocalAppData%\optiSCAN\clamav\database</c> avec copie initiale
        /// des bases depuis le chemin en lecture seule.
        /// </summary>
        public static string ResolveWritableDatabaseDir(string clamavBinDir)
        {
            var preferred = ResolvePreferredDatabaseDir(clamavBinDir);

            if (!IsUnderProgramFilesOrProgramFilesX86(preferred)
                && IsUsableWritableDatabaseRoot(preferred))
                return preferred;

            var fallback = Path.GetFullPath(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "optiSCAN", "clamav", "database"));

            Directory.CreateDirectory(fallback);
            TrySeedSignatureFiles(preferred, fallback);
            return fallback;
        }

        private static bool IsUnderProgramFilesOrProgramFilesX86(string fullPath)
        {
            fullPath = Path.GetFullPath(fullPath);
            var pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            var pfx86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);

            if (!string.IsNullOrEmpty(pf))
            {
                var sep = Path.DirectorySeparatorChar;
                var p = Path.GetFullPath(pf.TrimEnd(sep));
                if (fullPath.StartsWith(p + sep, StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            if (!string.IsNullOrEmpty(pfx86))
            {
                var sep = Path.DirectorySeparatorChar;
                var p = Path.GetFullPath(pfx86.TrimEnd(sep));
                if (fullPath.StartsWith(p + sep, StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            return false;
        }

        private static bool IsUsableWritableDatabaseRoot(string dir)
        {
            try
            {
                Directory.CreateDirectory(dir);
                var probeDir = Path.Combine(dir, ".optiscan-write-probe-" + Guid.NewGuid().ToString("N"));
                Directory.CreateDirectory(probeDir);
                var probeFile = Path.Combine(probeDir, "t.tmp");
                File.WriteAllText(probeFile, "x");
                File.Delete(probeFile);
                Directory.Delete(probeDir, recursive: false);
                return true;
            }
            catch
            {
                return false;
            }
        }

        private static void TrySeedSignatureFiles(string readOnlySourceDir, string writableDestDir)
        {
            try
            {
                if (File.Exists(Path.Combine(writableDestDir, SeedMarker)))
                    return;

                var destHasDb = Directory.Exists(writableDestDir)
                    && (Directory.GetFiles(writableDestDir, "*.cvd").Length > 0
                        || Directory.GetFiles(writableDestDir, "*.cld").Length > 0);

                if (destHasDb)
                {
                    File.WriteAllText(Path.Combine(writableDestDir, SeedMarker), "1");
                    return;
                }

                if (!Directory.Exists(readOnlySourceDir))
                {
                    File.WriteAllText(Path.Combine(writableDestDir, SeedMarker), "1");
                    return;
                }

                foreach (var path in Directory.EnumerateFiles(readOnlySourceDir))
                {
                    var ext = Path.GetExtension(path).ToUpperInvariant();
                    if (ext is not (".CVD" or ".CLD"))
                        continue;
                    var destFile = Path.Combine(writableDestDir, Path.GetFileName(path));
                    if (!File.Exists(destFile))
                        File.Copy(path, destFile, overwrite: false);
                }

                File.WriteAllText(Path.Combine(writableDestDir, SeedMarker), "1");
            }
            catch (Exception ex)
            {
                AppLogger.Warn("ClamAvDatabasePaths", "TrySeedSignatureFiles", ex);
            }
        }
    }
}
