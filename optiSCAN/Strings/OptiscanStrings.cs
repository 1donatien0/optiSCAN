namespace optiSCAN.Strings
{
    /// <summary>
    /// Centralise les chaînes utilisées par l'UI (IDs de navigation, URLs, messages récurrents).
    /// Objectif : réduire la dispersion des littéraux et améliorer la cohérence.
    /// </summary>
    public static class OptiscanStrings
    {
        public static class PanelIds
        {
            public const string Overview = "Overview";
            public const string Clean = "Clean";
            public const string Antivirus = "Antivirus";
            public const string History = "History";
            public const string Options = "Options";
        }

        public static class ActionIds
        {
            public const string Update = "Update";
        }

        public static class Urls
        {
            public const string OptiscanWebsite = "https://sourceforge.net/projects/optiscan/";
            public const string OptiscanSourceForge = "https://sourceforge.net/projects/optiscan/";
            public const string YaraForgeApiLatest = "https://api.github.com/repos/YARAHQ/yara-forge/releases/latest";
            public const string ClamAvRootCertRaw = "https://raw.githubusercontent.com/Cisco-Talos/clamav/main/certs/clamav.crt";
        }

        public static class Confirmations
        {
            public const string Title = "Confirmation";

            public static string QuarantineAll(int count) =>
                $"Placer {count} fichier(s) détecté(s) en quarantaine ?";

            public static string PurgeQuarantine(int count) =>
                $"Supprimer définitivement les {count} entrée(s) de la quarantaine ? Cette action est irréversible.";
        }

        public static class UiMessages
        {
            public const string ProtectionActive = "Protection active.";
            public const string ProtectionReducedTray = "optiSCAN réduit dans la barre système";

            public const string AnalyseInterrompueSurDemande = "Analyse interrompue sur demande.";

            public const string RestoreFromQuarantineSuccess = "Fichier restauré depuis la quarantaine";
            public const string RestoreFromQuarantineError = "Erreur lors de la restauration";
            public const string DeleteThreatPermanentlySuccess = "Fichier supprimé définitivement de la quarantaine";
            public const string DeleteThreatPermanentlyError = "Erreur lors de la suppression";
        }

        public static class StatusUpdates
        {
            public const string SignaturesUpdateAlreadyRunning = "Une mise à jour des signatures est déjà en cours.";
            public const string SignaturesUpdateInProgress = "Mise à jour des signatures en cours…";
            public const string RulesUpdateInProgress = "Mise à jour des règles de détection en cours…";
            public const string FullSignaturesUpdateStarting = "Mise à jour complète des signatures et règles…";
            public const string SignaturesUpdateFinishedSuccess = "Mise à jour terminée avec succès.";
            public const string SignaturesUpdateFinishedError = "Échec de la mise à jour des signatures.";
            public const string FullSignaturesUpdateFinished = "Mise à jour des signatures et règles terminée.";
            public const string FullSignaturesUpdateFinishedWithErrors = "Mise à jour terminée avec des erreurs.";
            public const string SignaturesUpdateStopping = "Arrêt de la mise à jour en cours…";
        }
    }
}
