using System.IO;
using System.Text.RegularExpressions;

namespace optiSCAN.Services
{
    /// <summary>
    /// Répertoire racine du processus optiSCAN en cours (publish / install / debug).
    /// Sert à exclure implicitement ce périmètre des scans et de la RTP pour éviter
    /// les auto-détections (règles YARA, binaires YARA, bases ClamAV embarquées).
    /// </summary>
    internal static class AppInstallPaths
    {
        private static readonly Lazy<string> CachedRoot = new(ResolveRoot, LazyThreadSafetyMode.ExecutionAndPublication);

        /// <summary>Racine normalisée sans slash final (Path.GetFullPath).</summary>
        public static string GetInstallRoot() => CachedRoot.Value;

        private static string ResolveRoot()
        {
            var baseDir = AppContext.BaseDirectory;
            if (string.IsNullOrWhiteSpace(baseDir))
                baseDir = AppDomain.CurrentDomain.BaseDirectory;

            try
            {
                return Path.GetFullPath(baseDir.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
            }
            catch
            {
                return baseDir.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            }
        }

        /// <summary>Vrai si <paramref name="path"/> désigne un fichier ou dossier sous la racine d’installation.</summary>
        public static bool IsUnderInstallRoot(string? path)
        {
            if (string.IsNullOrWhiteSpace(path))
                return false;

            string root;
            string fullPath;
            try
            {
                root = GetInstallRoot();
                fullPath = Path.GetFullPath(path.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
            }
            catch
            {
                return false;
            }

            if (fullPath.Equals(root, StringComparison.OrdinalIgnoreCase))
                return true;

            return fullPath.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)
                || fullPath.StartsWith(root + Path.AltDirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Motif PCRE pour <c>clamscan --exclude</c> : tout chemin sous la racine d'installation.
        /// </summary>
        public static string GetClamScanExcludePattern()
        {
            var root = GetInstallRoot().TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            return "^" + Regex.Escape(root) + @"([\\/]|$)";
        }
    }
}
