using System.IO;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace optiSCAN.Services
{
    /// <summary>
    /// Durcit l'ACL des dossiers de données optiSCAN (correctif S-1 de l'audit).
    ///
    /// Le répertoire %LocalAppData%\optiSCAN est ajouté aux exclusions Windows Defender.
    /// Comme il est inscriptible par l'utilisateur courant, un code malveillant s'exécutant
    /// dans son contexte pourrait y déposer une charge utile et échapper à l'analyse.
    /// On restreint donc l'accès au propriétaire courant, à SYSTEM et aux Administrateurs,
    /// en rompant l'héritage des règles larges (groupe Users).
    ///
    /// Best-effort : toute erreur est journalisée sans jamais interrompre l'application.
    /// Si l'identité du propriétaire ne peut être résolue, on n'applique aucune ACL
    /// (pour éviter de verrouiller l'application hors de ses propres données).
    /// </summary>
    [SupportedOSPlatform("windows")]
    internal static class DirectoryHardening
    {
        /// <summary>
        /// Applique une ACL restrictive (propriétaire + SYSTEM + Administrateurs, héritage rompu)
        /// sur le dossier indiqué. Idempotent, sûr à appeler à chaque démarrage.
        /// </summary>
        public static void HardenDataDirectory(string directory)
        {
            if (!OperatingSystem.IsWindows())
                return;
            if (string.IsNullOrWhiteSpace(directory) || !Directory.Exists(directory))
                return;

            try
            {
                var owner = WindowsIdentity.GetCurrent().User;
                if (owner == null)
                {
                    // Impossible d'identifier le propriétaire : ne pas appliquer d'ACL
                    // qui priverait l'application (exécutée sous cet utilisateur) de l'accès.
                    AppLogger.Warn("DirectoryHardening", $"Propriétaire introuvable, durcissement ignoré : {directory}");
                    return;
                }

                var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
                var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);

                const InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;

                var security = new DirectorySecurity();
                // Rompre l'héritage sans conserver les règles héritées (élimine le groupe Users large).
                security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

                security.AddAccessRule(new FileSystemAccessRule(
                    owner, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
                security.AddAccessRule(new FileSystemAccessRule(
                    system, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
                security.AddAccessRule(new FileSystemAccessRule(
                    admins, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));

                new DirectoryInfo(directory).SetAccessControl(security);
                AppLogger.Debug("DirectoryHardening", $"ACL restreinte appliquée : {directory}");
            }
            catch (Exception ex)
            {
                AppLogger.Warn("DirectoryHardening", $"Durcissement ACL ignoré : {directory}", ex);
            }
        }
    }
}
