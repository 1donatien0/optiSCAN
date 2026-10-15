using System.IO;

namespace optiSCAN.Services
{
    /// <summary>
    /// Source de vérité unique pour les listes de cibles de scan.
    ///
    /// Avant ce fichier, GetQuickScanTargets était dupliqué dans ClamAvEngine et
    /// dans ScanOrchestrator avec des contenus divergents (l'un incluait
    /// %LOCALAPPDATA%\Temp, l'autre non). Selon le chemin de code emprunté,
    /// l'utilisateur scannait des dossiers différents pour le « même » Quick Scan.
    /// </summary>
    public static class ScanTargets
    {
        /// <summary>
        /// Cibles d'un scan rapide, calquées sur l'esprit du « scan rapide » de
        /// Microsoft Defender : dossiers de démarrage, zones Windows fréquentes
        /// (Temp, Prefetch, pilotes), profil utilisateur (Téléchargements, Bureau,
        /// fichiers récents, caches temporaires). Defender inspecte aussi la mémoire,
        /// le registre et des API noyau — ce que ClamAV/YARA ne reproduisent pas ici.
        /// Liste dédupliquée ; chemins absents ignorés.
        /// </summary>
        public static List<string> QuickScanTargets()
        {
            var dirs = new List<string>();

            void Add(string? path)
            {
                if (!string.IsNullOrWhiteSpace(path) && Directory.Exists(path))
                    dirs.Add(path);
            }

            // Profil — téléchargements, bureau, récents, caches temp (souvent cités avec Defender + RT)
            Add(Environment.GetEnvironmentVariable("TEMP"));
            Add(Environment.GetEnvironmentVariable("TMP"));
            Add(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"));
            Add(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"));
            Add(Environment.GetFolderPath(Environment.SpecialFolder.Desktop));
            Add(Environment.GetFolderPath(Environment.SpecialFolder.Recent));

            // %APPDATA% (Roaming) : emplacement le plus courant des charges qui se réinstallent
            // (dossier au nom aléatoire + clé Run). Il contient aussi le dossier Démarrage.
            // %LOCALAPPDATA% entier reste hors du scan rapide (caches de navigateurs, très volumineux).
            Add(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData));
            // Dossier public : accessible en écriture à tous les comptes, cachette fréquente.
            Add(Environment.GetEnvironmentVariable("PUBLIC"));

            // Démarrage — persistance classique (équivalent des « dossiers de démarrage » Defender)
            Add(Environment.GetFolderPath(Environment.SpecialFolder.Startup));
            Add(Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup));

            // Windows — Temp système, Prefetch, magasin de pilotes (surface élevée sans tout System32)
            var winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            if (!string.IsNullOrWhiteSpace(winDir))
            {
                Add(Path.Combine(winDir, "Temp"));
                Add(Path.Combine(winDir, "Prefetch"));
                Add(Path.Combine(winDir, "System32", "drivers"));
                Add(Path.Combine(winDir, "SysWOW64", "drivers"));
            }

            return RemoveNested(dirs);
        }

        /// <summary>
        /// Sans doublons ni dossiers contenus dans une autre cible (Démarrage est sous %APPDATA%,
        /// %TEMP% sous %LOCALAPPDATA%\Temp) : chaque fichier n'est analysé qu'une fois.
        /// L'ordre d'origine est conservé.
        /// </summary>
        internal static List<string> RemoveNested(IEnumerable<string> paths)
        {
            static string Norm(string p) => Path.TrimEndingDirectorySeparator(Path.GetFullPath(p));

            var list = paths
                .Where(p => !string.IsNullOrWhiteSpace(p))
                .Select(p => (Original: p, Full: Norm(p)))
                .ToList();
            var result = new List<string>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var (original, full) in list)
            {
                if (!seen.Add(full))
                    continue;
                var nested = list.Any(o =>
                    !string.Equals(o.Full, full, StringComparison.OrdinalIgnoreCase)
                    && full.Length > o.Full.Length
                    && full.StartsWith(o.Full, StringComparison.OrdinalIgnoreCase)
                    && (full[o.Full.Length] == Path.DirectorySeparatorChar || o.Full.EndsWith(Path.DirectorySeparatorChar)));
                if (!nested)
                    result.Add(original);
            }

            return result;
        }

        /// <summary>
        /// Cibles d'un scan complet : tous les volumes fixes prêts.
        /// </summary>
        public static List<string> FullScanTargets(bool includeRemovable = false)
        {
            var drives = new List<string>();
            foreach (var d in DriveInfo.GetDrives())
            {
                try
                {
                    if (!d.IsReady)
                        continue;
                    if (d.DriveType == DriveType.Fixed
                        || (includeRemovable && d.DriveType == DriveType.Removable))
                        drives.Add(d.RootDirectory.FullName);
                }
                catch { /* lecteur en cours de remontée — on l'ignore */ }
            }
            return drives;
        }
    }
}
