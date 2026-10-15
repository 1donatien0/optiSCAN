using System.IO;
using optiSCAN.Platform;

namespace optiSCAN.Services;

/// <summary>
/// Un seul hôte de service. Le verrou vit dans ProgramData, pas dans un mutex Global
/// qu'un utilisateur peut créer avant SYSTEM.
/// </summary>
internal static class ServiceHostLock
{
    private static FileStream? _held;

    internal static bool TryAcquire()
    {
        if (!OptiScanProgramData.EnsureTrusted())
            return false;

        var path = Path.Combine(OptiScanProgramData.DirectoryPath, "service-host.lock");
        if ((File.Exists(path) || Directory.Exists(path))
            && (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            return false;

        try
        {
            _held = new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            return true;
        }
        catch (IOException)
        {
            return false;
        }
    }
}
