using System.Security.Cryptography;
using System.Text;

namespace optiSCAN.Platform;

/// <summary>Jeton d'authentification pour l'opération IPC <c>shutdown</c> (fichier ProgramData).</summary>
public static class ProtectionPipeShutdownToken
{
    public static string TokenFilePath { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "optiSCAN",
        "ipc_shutdown.token");

    public static string Generate() =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

    public static bool Validate(string? expected, string? provided)
    {
        if (string.IsNullOrEmpty(expected) || string.IsNullOrEmpty(provided))
            return false;

        var a = Encoding.UTF8.GetBytes(expected);
        var b = Encoding.UTF8.GetBytes(provided);
        return a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);
    }

    public static void Persist(string token)
    {
        var dir = Path.GetDirectoryName(TokenFilePath)!;
        Directory.CreateDirectory(dir);
        File.WriteAllText(TokenFilePath, token, Encoding.UTF8);
    }

    public static bool TryRead(out string? token)
    {
        token = null;
        try
        {
            if (!File.Exists(TokenFilePath))
                return false;
            token = File.ReadAllText(TokenFilePath, Encoding.UTF8).Trim();
            return !string.IsNullOrEmpty(token);
        }
        catch
        {
            return false;
        }
    }
}
