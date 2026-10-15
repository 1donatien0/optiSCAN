using System.Security.Principal;

namespace optiSCAN.Services;

/// <summary>
/// Instance d'optiSCAN élevée par UAC dans la session d'un utilisateur (jeton administrateur
/// complet, pas SYSTEM).
/// <para>
/// Une telle instance ne doit pas lancer d'outil dont la configuration, le binaire ou le
/// dossier de travail se trouvent dans le profil de l'utilisateur : un programme non élevé du
/// même compte pourrait y glisser une directive (<c>OnUpdateExecute</c> de freshclam.conf),
/// un faux <c>winget.exe</c> dans le PATH ou une jonction, et obtenir ainsi les droits
/// administrateur sans invite UAC.
/// </para>
/// </summary>
public static class ElevatedSessionGuard
{
    private static readonly Lazy<bool> Cached = new(Compute);

    /// <summary>Vrai dans une instance élevée d'un compte utilisateur (hors SYSTEM).</summary>
    public static bool IsElevatedUserSession => Cached.Value;

    private static bool Compute()
    {
        if (!OperatingSystem.IsWindows())
            return false;
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            if (identity.IsSystem)
                return false;
            // Avec UAC, le groupe Administrateurs n'est actif que dans un jeton élevé.
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }
}
