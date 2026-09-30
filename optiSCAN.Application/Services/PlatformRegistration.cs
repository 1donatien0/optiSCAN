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
    private const string AmsiProviderName = "optiSCAN AMSI Provider";

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

    /// <summary>Nom du service noyau (doit correspondre à <c>ServiceName</c> dans l'INF).</summary>
    internal const string MinifilterServiceName = "optiSCANMinifilter";

    /// <summary>Instance par défaut (doit correspondre à <c>Instance1.Name</c> dans l'INF).</summary>
    internal const string MinifilterInstanceName = "optiSCAN Instance";

    /// <summary>
    /// Altitude provisoire (plage FSFilter Activity Monitor 360000-389999) ; doit correspondre
    /// à <c>Instance1.Altitude</c> dans l'INF. À remplacer par l'altitude attribuée par Microsoft.
    /// </summary>
    internal const string MinifilterAltitude = "385210";

    private const string MinifilterServiceKey = @"SYSTEM\CurrentControlSet\Services\" + MinifilterServiceName;

    /// <summary>Arguments <c>sc.exe create</c> du service noyau (pilote système de fichiers à la demande).</summary>
    internal const string MinifilterScCreateArguments =
        "create " + MinifilterServiceName
        + " type= filesys start= demand error= normal"
        + " binPath= \"System32\\drivers\\optiSCAN.Minifilter.sys\""
        + " group= \"FSFilter Activity Monitor\" depend= FltMgr"
        + " DisplayName= \"optiSCAN Minifilter\"";

    /// <summary>
    /// Copie le pilote, enregistre le service noyau et son instance (altitude) s'ils manquent,
    /// puis tente <c>fltmc load</c>. Sans service ni clé <c>Instances</c>, le gestionnaire de
    /// filtres refuse le chargement même d'un pilote signé.
    /// </summary>
    public static void TryLoadMinifilter()
    {
        try
        {
            var baseDir = AppDomain.CurrentDomain.BaseDirectory;
            var sys = Path.Combine(baseDir, "optiSCAN.Minifilter.sys");
            if (!File.Exists(sys))
            {
                AppLogger.Warn("PlatformRegistration", "optiSCAN.Minifilter.sys absent — minifilter non chargé");
                return;
            }

            if (IsMinifilterLoaded())
            {
                AppLogger.Info("PlatformRegistration", "Minifilter déjà chargé");
                return;
            }

            // Paquet signé (catalogue présent) : pnputil installe le pilote proprement.
            // Sans catalogue, pnputil échoue toujours : inutile de l'appeler.
            var inf = Path.Combine(baseDir, "optiSCAN.Minifilter.inf");
            var cat = Path.Combine(baseDir, "optiSCAN.Minifilter.cat");
            if (File.Exists(inf) && File.Exists(cat))
            {
                var pnp = RunProcess("pnputil.exe", $"/add-driver \"{inf}\" /install");
                if (pnp != 0 && pnp != 3010)
                    AppLogger.Info("PlatformRegistration", $"pnputil /add-driver code {pnp}");
            }

            var dest = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System),
                "drivers",
                "optiSCAN.Minifilter.sys");
            try
            {
                if (!File.Exists(dest) || new FileInfo(dest).Length != new FileInfo(sys).Length
                    || File.GetLastWriteTimeUtc(dest) < File.GetLastWriteTimeUtc(sys))
                    File.Copy(sys, dest, overwrite: true);
            }
            catch (Exception copyEx)
            {
                AppLogger.Warn("PlatformRegistration", "Copie du .sys vers System32\\drivers refusée", copyEx);
            }

            if (!EnsureMinifilterServiceRegistered())
                return;

            var flt = RunProcess("fltmc.exe", "load " + MinifilterServiceName);
            if (flt == 0)
                AppLogger.Info("PlatformRegistration", "Minifilter chargé");
            else
                AppLogger.Info("PlatformRegistration",
                    $"fltmc load code {flt} — Windows x64 refuse un pilote non signé ; service et AMSI restent actifs");
        }
        catch (Exception ex)
        {
            AppLogger.Warn("PlatformRegistration", "TryLoadMinifilter", ex);
        }
    }

    /// <summary>
    /// Crée le service noyau via le SCM s'il n'existe pas, puis la clé <c>Instances</c>
    /// (instance par défaut + altitude) lue par le gestionnaire de filtres.
    /// </summary>
    private static bool EnsureMinifilterServiceRegistered()
    {
        try
        {
            using (var existing = Registry.LocalMachine.OpenSubKey(MinifilterServiceKey))
            {
                if (existing == null)
                {
                    var sc = RunProcess("sc.exe", MinifilterScCreateArguments);
                    // 1073 = ERROR_SERVICE_EXISTS (création concurrente) : acceptable.
                    if (sc != 0 && sc != 1073)
                    {
                        AppLogger.Warn("PlatformRegistration", $"sc create {MinifilterServiceName} code {sc}");
                        return false;
                    }
                }
            }

            using var instances = Registry.LocalMachine.CreateSubKey(MinifilterServiceKey + @"\Instances");
            if (instances == null)
                return false;
            if (instances.GetValue("DefaultInstance") is not string)
                instances.SetValue("DefaultInstance", MinifilterInstanceName, RegistryValueKind.String);

            using var instance = instances.CreateSubKey(MinifilterInstanceName);
            if (instance == null)
                return false;
            if (instance.GetValue("Altitude") is not string)
                instance.SetValue("Altitude", MinifilterAltitude, RegistryValueKind.String);
            if (instance.GetValue("Flags") is not int)
                instance.SetValue("Flags", 0, RegistryValueKind.DWord);

            return true;
        }
        catch (Exception ex)
        {
            AppLogger.Warn("PlatformRegistration", "EnsureMinifilterServiceRegistered", ex);
            return false;
        }
    }

    private static bool IsMinifilterLoaded()
    {
        try
        {
            using var proc = Process.Start(new ProcessStartInfo
            {
                FileName = "fltmc.exe",
                Arguments = "filters",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
            });
            if (proc == null)
                return false;
            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(10_000);
            return output.Contains(MinifilterServiceName, StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    public static void TryUnloadMinifilter()
    {
        try { RunProcess("fltmc.exe", "unload " + MinifilterServiceName); }
        catch (Exception ex) { AppLogger.Debug("PlatformRegistration", $"TryUnloadMinifilter: {ex.Message}"); }
    }

    private static int RunProcess(string file, string args)
    {
        using var proc = Process.Start(new ProcessStartInfo
        {
            FileName = file,
            Arguments = args,
            UseShellExecute = false,
            CreateNoWindow = true,
        });
        if (proc == null)
            return -1;
        if (proc.WaitForExit(15_000))
            return proc.ExitCode;

        // Outil système bloqué : ne pas le laisser tourner derrière le service.
        try { proc.Kill(entireProcessTree: true); }
        catch (Exception ex) { AppLogger.Debug("PlatformRegistration", $"Arrêt {file} : {ex.Message}"); }
        AppLogger.Warn("PlatformRegistration", $"{file} {args} : délai dépassé (15 s)");
        return -1;
    }
}
