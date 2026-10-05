using System.Security.Cryptography;
using System.Security.Principal;

namespace optiSCAN.Platform;

/// <summary>
/// Nom du profil AppContainer de clamd.
/// <para>
/// Le SID d'un AppContainer se déduit uniquement de son nom. Avec un nom fixe
/// (« optiSCAN.clamd »), n'importe quel processus pouvait créer son propre profil du même nom,
/// obtenir le même SID, joindre le clamd isolé sur la boucle locale et recevoir les droits
/// accordés à ce SID dans <c>%ProgramData%\optiSCAN</c>. Le nom porte donc un suffixe aléatoire
/// de 128 bits, propre à chaque installation (service) ou à chaque compte (interface),
/// conservé dans un fichier que seul son propriétaire peut lire.
/// </para>
/// </summary>
public static class ClamdContainerName
{
    /// <summary>Ancien nom fixe, conservé pour retirer ses ACE.</summary>
    public const string LegacyName = "optiSCAN.clamd";

    private const string Prefix = "optiSCAN.clamd.";
    private const string FileName = "clamd-container.id";
    private static readonly object Gate = new();
    private static string? _current;

    /// <summary>Nom à utiliser par ce processus ; créé au premier appel. Null si indisponible.</summary>
    public static string? Current()
    {
        lock (Gate)
        {
            if (_current != null)
                return _current;

            string directory;
            if (IsSystem())
            {
                if (!OptiScanProgramData.EnsureTrusted())
                    return null;
                directory = OptiScanProgramData.DirectoryPath;
            }
            else
            {
                directory = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "optiSCAN");
            }

            var path = Path.Combine(directory, FileName);
            var existing = ReadValid(path, requireTrusted: IsSystem());
            if (existing != null)
                return _current = existing;

            try
            {
                Directory.CreateDirectory(directory);
                var name = Prefix + Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
                File.WriteAllText(path, name);
                return _current = name;
            }
            catch
            {
                return null;
            }
        }
    }

    /// <summary>
    /// Nom du conteneur du service, lu dans ProgramData sans le créer. Null s'il n'existe pas
    /// encore ou si le fichier n'est pas fiable (propriétaire ou droits étrangers).
    /// </summary>
    public static string? TryReadServiceName() =>
        ReadValid(Path.Combine(OptiScanProgramData.DirectoryPath, FileName), requireTrusted: true);

    public static bool IsValid(string? name) =>
        name != null
        && name.Length == Prefix.Length + 32
        && name.StartsWith(Prefix, StringComparison.Ordinal)
        && name[Prefix.Length..].All(Uri.IsHexDigit);

    private static string? ReadValid(string path, bool requireTrusted)
    {
        try
        {
            if (!File.Exists(path) || new FileInfo(path).Length > 256)
                return null;
            if (requireTrusted && !OptiScanProgramData.IsTrustedFileStrict(path))
                return null;
            var name = File.ReadAllText(path).Trim();
            return IsValid(name) ? name : null;
        }
        catch
        {
            return null;
        }
    }

    private static bool IsSystem()
    {
        if (!OperatingSystem.IsWindows())
            return false;
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return identity.IsSystem;
        }
        catch
        {
            return false;
        }
    }
}
