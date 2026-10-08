using System.IO;

namespace optiSCAN.Services
{
    /// <summary>
    /// Mesure et vidage des dossiers du panneau Nettoyer (Temp Windows, Temp utilisateur, journaux,
    /// caches de navigateurs) <b>sans suivre de jonction ni de lien</b>.
    /// </summary>
    /// <remarks>
    /// <c>Directory.EnumerateFiles(…, AllDirectories)</c> descend dans les jonctions. Un compte
    /// standard peut créer un dossier dans <c>C:\Windows\Temp</c> : une jonction posée là vers
    /// <c>C:\Windows\System32</c> ou le profil d'un autre compte faisait supprimer ces fichiers par
    /// un administrateur qui lançait le nettoyage. Ici :
    /// <list type="bullet">
    /// <item>le dossier racine ne doit pas être lui-même un lien ;</item>
    /// <item>l'énumération ignore tout point de réanalyse (jonction, lien, fichier lié) ;</item>
    /// <item>sous Windows, chaque fichier est supprimé par <see cref="SafePathDelete"/>, qui
    /// redescend le chemin nom par nom sans traverser de jonction : un dossier remplacé par une
    /// jonction entre l'énumération et la suppression est refusé.</item>
    /// </list>
    /// </remarks>
    internal static class SafeDirectoryCleaner
    {
        internal static EnumerationOptions WithoutLinks => new()
        {
            RecurseSubdirectories = true,
            AttributesToSkip = FileAttributes.ReparsePoint,
            IgnoreInaccessible = true,
            MatchType = MatchType.Win32,
            ReturnSpecialDirectories = false,
        };

        /// <summary>Taille des fichiers sous <paramref name="path"/>, liens exclus. 0 si refusé.</summary>
        internal static long Measure(string? path)
        {
            if (!IsCleanableRoot(path))
                return 0;

            long total = 0;
            try
            {
                foreach (var file in new DirectoryInfo(path!).EnumerateFiles("*", WithoutLinks))
                {
                    try { total += file.Length; }
                    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                    {
                        /* fichier disparu ou illisible : ignoré */
                    }
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                AppLogger.Warn("SafeDirectoryCleaner", $"Mesure impossible « {path} » : {ex.Message}");
            }

            return total;
        }

        /// <summary>
        /// Supprime les fichiers sous <paramref name="path"/> (les dossiers restent), liens exclus.
        /// Rend les octets libérés ; <paramref name="onFailure"/> reçoit chaque fichier conservé.
        /// </summary>
        internal static long Clean(string? path, Action<string, Exception>? onFailure = null)
        {
            if (!IsCleanableRoot(path))
                return 0;

            long freed = 0;
            List<FileInfo> files;
            try
            {
                files = new DirectoryInfo(path!).EnumerateFiles("*", WithoutLinks).ToList();
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                AppLogger.Warn("SafeDirectoryCleaner", $"Nettoyage impossible « {path} » : {ex.Message}");
                return 0;
            }

            foreach (var file in files)
            {
                try
                {
                    var size = file.Length;
                    DeleteFile(file.FullName);
                    freed += size;
                }
                catch (Exception ex)
                {
                    onFailure?.Invoke(file.FullName, ex);
                }
            }

            return freed;
        }

        /// <summary>Dossier existant, chemin local, et qui n'est pas lui-même un lien.</summary>
        internal static bool IsCleanableRoot(string? path)
        {
            if (string.IsNullOrWhiteSpace(path))
                return false;
            try
            {
                var info = new DirectoryInfo(path);
                if (!info.Exists)
                    return false;
                if ((info.Attributes & FileAttributes.ReparsePoint) != 0)
                {
                    AppLogger.Warn("SafeDirectoryCleaner", $"« {path} » est un lien : non nettoyé.");
                    return false;
                }

                return true;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
            {
                return false;
            }
        }

        private static void DeleteFile(string fullPath)
        {
            if (OperatingSystem.IsWindows())
                SafePathDelete.Delete(fullPath); // refus (jonction, lien, plusieurs noms) : IOException
            else
                File.Delete(fullPath);
        }
    }
}
