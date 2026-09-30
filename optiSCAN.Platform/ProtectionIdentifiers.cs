namespace optiSCAN.Platform;

/// <summary>
/// Source unique des identifiants techniques de la protection système.
/// <para>
/// Ces noms sont des <b>contrats</b> entre l'application, le service Windows, la DLL AMSI native
/// et l'installateur. Ils ne contiennent volontairement <b>aucun numéro de version produit</b> :
/// la version d'optiSCAN (assembly / AppVersion) peut évoluer sans renommer le service ni le pipe.
/// </para>
/// <para>
/// Si le format des messages IPC change de façon incompatible, incrémenter
/// <see cref="ProtocolVersion"/> — ne pas renommer le pipe.
/// </para>
/// <para>
/// Miroirs à garder synchronisés (vérifiés par <c>ProtectionIdentifiersTests</c>) :
/// <c>native/optiSCAN.AmsiProvider/protection_identifiers.h</c> et
/// <c>installer/protection_identifiers.iss</c>.
/// </para>
/// </summary>
public static class ProtectionIdentifiers
{
    /// <summary>Nom SCM du service Windows (sc.exe / services.msc).</summary>
    public const string ServiceName = "optiSCANProtection";

    /// <summary>Nom affiché dans services.msc pour le service v3.</summary>
    public const string ServiceDisplayName = "optiSCAN Protection v3";

    /// <summary>Description du service Windows.</summary>
    public const string ServiceDescription = "Moteur de protection optiSCAN (RTP, AMSI, IPC)";

    /// <summary>Source du journal d'événements Windows (Application).</summary>
    public const string EventSourceName = "optiSCAN Protection v3";

    /// <summary>Nom du pipe nommé de protection (sans le préfixe <c>\\.\pipe\</c>).</summary>
    public const string PipeName = "optiSCAN_Protection";

    /// <summary>Version du protocole JSON échangé sur <see cref="PipeName"/>.</summary>
    public const int ProtocolVersion = 1;

    /// <summary>
    /// Anciennes sources du journal d'événements, remplacées par <see cref="EventSourceName"/>.
    /// Les chaînes sont les libellés déjà enregistrés sur le disque, pour pouvoir les retirer.
    /// </summary>
    public static readonly IReadOnlyList<string> LegacyEventSourceNames = new[]
    {
        "optiSCAN Protection v2",
        "optiSCAN Protection",
    };
}
