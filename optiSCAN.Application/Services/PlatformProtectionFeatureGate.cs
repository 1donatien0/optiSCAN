namespace optiSCAN.Services;

/// <summary>
/// Bascule produit pour la couche plateforme (service Windows + AMSI + minifiltre).
/// Sur l'édition WinUI 3, l'activation utilisateur est ouverte : le service et AMSI
/// s'installent. Le minifiltre noyau se charge seulement si Windows accepte le
/// pilote (signature Authenticode / attestation — SignPath prévu plus tard).
/// </summary>
public static class PlatformProtectionFeatureGate
{
    /// <summary>
    /// Quand <c>true</c>, Options et l'installeur peuvent activer le mode plateforme.
    /// </summary>
    public static readonly bool IsUserActivatable = true;

    /// <summary>Normalise les préférences si le mode plateforme n'est pas activable.</summary>
    public static void NormalizePreferences(UserPreferences prefs)
    {
        if (!IsUserActivatable && prefs.UsePlatformProtectionService)
        {
            prefs.UsePlatformProtectionService = false;
            prefs.Save();
        }
    }
}
