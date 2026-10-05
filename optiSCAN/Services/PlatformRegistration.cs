using System.Diagnostics;
using System.IO;
using System.Runtime.Versioning;
using Microsoft.Win32;

namespace optiSCAN.Services;

/// <summary>Enregistrement AMSI et chargement du minifilter (nécessite droits admin à l'installation).</summary>
[SupportedOSPlatform("windows")]
public static class PlatformRegistration
{
    private const string AmsiProviderGuid = "{A8F4E2B1-9C3D-4E5F-8A7B-1C2D3E4F5A6B}";

    public static void TryRegisterAmsiProvider()
    {
        AppLogger.Info("PlatformRegistration", "AMSI non enregistré : le fournisseur n'est pas signé et n'est pas chargé");
    }

    /// <summary>
    /// Retire l'enregistrement AMSI (mode complément / protection plateforme désactivée).
    /// La DLL peut rester dans le dossier d'installation sans être chargée par Windows.
    /// </summary>
    public static void TryUnregisterAmsiProvider()
    {
        try
        {
            using var parent = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\AMSI\Providers", writable: true);
            if (parent == null)
                return;

            parent.DeleteSubKey(AmsiProviderGuid, throwOnMissingSubKey: false);
            AppLogger.Info("PlatformRegistration", "Fournisseur AMSI désenregistré");
        }
        catch (Exception ex)
        {
            AppLogger.Warn("PlatformRegistration", "TryUnregisterAmsiProvider", ex);
        }
    }

    public static void TryLoadMinifilter()
    {
        AppLogger.Info("PlatformRegistration", "Minifilter non chargé : le pilote livré n'est pas un filtre signé");
    }

    public static void TryUnloadMinifilter()
    {
        try { RunProcess("fltmc.exe", "unload optiSCANMinifilter"); }
        catch (Exception ex) { AppLogger.Debug("PlatformRegistration", $"TryUnloadMinifilter: {ex.Message}"); }
    }

    private static void RunProcess(string file, string args)
    {
        using var proc = Process.Start(new ProcessStartInfo
        {
            FileName = file,
            Arguments = args,
            UseShellExecute = false,
            CreateNoWindow = true,
        });
        proc?.WaitForExit(15_000);
    }
}
