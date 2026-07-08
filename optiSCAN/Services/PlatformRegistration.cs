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
    private const string AmsiProviderName = "optiSCAN AMSI Provider v9";

    public static void TryRegisterAmsiProvider()
    {
        try
        {
            var dll = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "optiSCAN.AmsiProvider.dll");
            if (!File.Exists(dll))
            {
                AppLogger.Warn("PlatformRegistration", "optiSCAN.AmsiProvider.dll absent — AMSI non enregistré");
                return;
            }

            using var key = Registry.LocalMachine.CreateSubKey($@"SOFTWARE\Microsoft\AMSI\Providers\{AmsiProviderGuid}");
            key?.SetValue(string.Empty, AmsiProviderName);
            key?.SetValue("Path", dll, RegistryValueKind.String);
            AppLogger.Info("PlatformRegistration", "Fournisseur AMSI enregistré");
        }
        catch (Exception ex)
        {
            AppLogger.Warn("PlatformRegistration", "TryRegisterAmsiProvider", ex);
        }
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
        try
        {
            var sys = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "optiSCAN.Minifilter.sys");
            if (!File.Exists(sys))
            {
                AppLogger.Warn("PlatformRegistration", "optiSCAN.Minifilter.sys absent — minifilter non chargé");
                return;
            }

            var dest = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers", "optiSCAN.Minifilter.sys");
            if (!File.Exists(dest))
                File.Copy(sys, dest, overwrite: true);

            RunProcess("fltmc.exe", "load optiSCANMinifilter");
            AppLogger.Info("PlatformRegistration", "Minifilter chargé (ou déjà actif)");
        }
        catch (Exception ex)
        {
            AppLogger.Warn("PlatformRegistration", "TryLoadMinifilter — test signing ou admin requis", ex);
        }
    }

    public static void TryUnloadMinifilter()
    {
        try { RunProcess("fltmc.exe", "unload optiSCANMinifilter"); } catch { }
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
