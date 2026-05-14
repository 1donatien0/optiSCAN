using System.IO;

namespace optiSCAN.Services
{
    /// <summary>
    /// Mises à jour du binaire optiSCAN (OTA / delta). Les signatures antivirus sont
    /// gérées par <see cref="FreshclamUpdater"/> et les règles par <see cref="YaraForgeUpdater"/>.
    /// </summary>
    /// <remarks>
    /// Audit H1 / Q3 : aucun canal de téléchargement applicatif n'est encore relié.
    /// <see cref="optiSCAN.MainWindow"/> n'appelle plus cette API au démarrage tant que l'OTA
    /// n'est pas implémentée (manifest signé + téléchargement vérifié). Réactiver
    /// l'appel depuis l'UI uniquement lorsque le flux complet sera branché ici.
    /// </remarks>
    public class UpdateService
    {
        private readonly string _localUpdatePath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "optiSCAN", "Updates");

        /// <summary>
        /// Vérifie la présence du dossier de staging et journalise l'état.
        /// Pas de téléchargement distant tant qu'aucun canal de distribution n'est branché.
        /// </summary>
        public Task CheckAndPrepareUpdatesAsync()
        {
            try
            {
                if (!Directory.Exists(_localUpdatePath))
                    Directory.CreateDirectory(_localUpdatePath);

                AppLogger.Info("UpdateService",
                    "Contrôle applicatif : aucune mise à jour OTA configurée (dossier staging prêt). " +
                    "Utilisez les mises à jour signatures dans l'onglet Antivirus.");
            }
            catch (Exception ex)
            {
                AppLogger.Warn("UpdateService", "Préparation dossier mises à jour", ex);
            }

            return Task.CompletedTask;
        }

        public Task CheckForUpdatesAsync() => CheckAndPrepareUpdatesAsync();
    }
}