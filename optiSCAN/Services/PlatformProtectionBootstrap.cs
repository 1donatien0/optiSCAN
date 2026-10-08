using optiSCAN.Models;
using optiSCAN.Platform;
using System.Diagnostics;
using System.IO;
using System.Runtime.Versioning;

namespace optiSCAN.Services;

/// <summary>
/// Installation et supervision du service Windows optiSCAN.Service (protection système).
/// Les identifiants (nom de service, pipe) viennent de <see cref="ProtectionIdentifiers"/>
/// et ne dépendent pas de la version produit.
/// </summary>
[SupportedOSPlatform("windows")]
public static class PlatformProtectionBootstrap
{
    public const string ServiceName = ProtectionIdentifiers.ServiceName;
    public const string ServiceDisplayName = ProtectionIdentifiers.ServiceDisplayName;

    private static readonly object ReachabilityGate = new();
    private static readonly TimeSpan ReachabilityTimeout = TimeSpan.FromMilliseconds(400);
    private static readonly TimeSpan ReachabilityCacheTtl = TimeSpan.FromSeconds(5);
    private static bool? _reachability;
    private static DateTime _reachabilityAtUtc;

    private static IUserPreferencesAccessor _prefs = new DefaultUserPreferencesAccessor();

    public static void Initialize(IUserPreferencesAccessor? preferences = null)
    {
        if (preferences != null)
            _prefs = preferences;
    }

    public static bool IsPlatformModeEnabled() =>
        _prefs.Current.UsePlatformProtectionService;

    public static bool IsRemoteProtectionActive() => IsRemoteProtectionActive(useCache: true);

    /// <summary>
    /// Ping court (400 ms) du service. Le cache évite de relancer le pipe à chaque clic.
    /// La boucle de démarrage passe <paramref name="useCache"/> à false.
    /// </summary>
    public static bool IsRemoteProtectionActive(bool useCache)
    {
        if (!IsPlatformModeEnabled())
            return false;

        if (useCache && TryReadReachabilityCache(out var cached))
            return cached;

        bool active;
        try
        {
            using var client = new Platform.ProtectionPipeClient(timeout: ReachabilityTimeout);
            active = client.IsServiceReachable();
        }
        catch
        {
            active = false;
        }

        lock (ReachabilityGate)
        {
            _reachability = active;
            _reachabilityAtUtc = DateTime.UtcNow;
        }

        return active;
    }

    /// <summary>Force le prochain <see cref="IsRemoteProtectionActive()"/> à re-pinger le service.</summary>
    public static void InvalidateReachabilityCache()
    {
        lock (ReachabilityGate)
            _reachability = null;
    }

    private static bool TryReadReachabilityCache(out bool active)
    {
        lock (ReachabilityGate)
        {
            if (_reachability.HasValue && (DateTime.UtcNow - _reachabilityAtUtc) < ReachabilityCacheTtl)
            {
                active = _reachability.Value;
                return true;
            }
        }

        active = false;
        return false;
    }

    public static void EnsurePlatformProtectionRunning()
    {
        if (!IsPlatformModeEnabled())
            return;

        if (IsRemoteProtectionActive())
            return;

        TryStartWindowsService();
    }

    public static bool TryInstallWindowsService()
    {
        try
        {
            var serviceExe = Path.Combine(AppContext.BaseDirectory, "optiSCAN.Service.exe");
            if (!File.Exists(serviceExe))
            {
                AppLogger.Warn("PlatformProtection", "optiSCAN.Service.exe absent");
                return false;
            }

            if (IsServiceInstalled())
                return true;

            // Un service SYSTEM sur un binaire qu'un utilisateur peut remplacer serait une
            // élévation de privilèges persistante (build de développement, copie portable,
            // installation hors Program Files).
            if (!InstallLocationTrust.IsCurrentInstallTrusted(out var reason))
            {
                AppLogger.Warn("PlatformProtection",
                    "Service non enregistré : le dossier d'installation n'est pas réservé aux administrateurs (" + reason + ")");
                return false;
            }

            var binPath = $"\"{serviceExe}\"";
            var created = RunSc($"create {ServiceName} binPath= {binPath} start= auto DisplayName= \"{ServiceDisplayName}\"");
            if (created != 0 || !IsServiceInstalled())
            {
                AppLogger.Warn("PlatformProtection", $"Création du service refusée (sc.exe code {created})");
                return false;
            }
            var described = RunSc($"description {ServiceName} \"{ProtectionIdentifiers.ServiceDescription}\"");
            if (described != 0)
                AppLogger.Debug("PlatformProtection", $"Description du service non appliquée (sc.exe code {described})");
            AppLogger.Info("PlatformProtection", "Service Windows enregistré");
            return true;
        }
        catch (Exception ex)
        {
            AppLogger.Warn("PlatformProtection", "TryInstallWindowsService", ex);
            return false;
        }
    }

    public static bool TryStartWindowsService()
    {
        try
        {
            TryInstallWindowsService();
            if (!IsServiceInstalled())
                return false;

            var started = RunSc($"start {ServiceName}");
            // 1056 = ERROR_SERVICE_ALREADY_RUNNING : pas une erreur.
            if (started != 0 && started != 1056)
                AppLogger.Warn("PlatformProtection", $"Démarrage du service refusé (sc.exe code {started})");
            for (var i = 0; i < 10; i++)
            {
                if (IsRemoteProtectionActive(useCache: false))
                    return true;
                Thread.Sleep(500);
            }

            return IsRemoteProtectionActive(useCache: false);
        }
        catch (Exception ex)
        {
            AppLogger.Warn("PlatformProtection", "TryStartWindowsService", ex);
            return false;
        }
    }

    public static void TryLaunchServiceHostProcess()
    {
        try
        {
            var exe = Path.Combine(AppContext.BaseDirectory, "optiSCAN.exe");
            if (!File.Exists(exe))
                return;

            var psi = new ProcessStartInfo
            {
                FileName = exe,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            psi.ArgumentList.Add("--service-host");
            Process.Start(psi);
            AppLogger.Info("PlatformProtection", "Processus --service-host lancé (secours)");
        }
        catch (Exception ex)
        {
            AppLogger.Warn("PlatformProtection", "TryLaunchServiceHostProcess", ex);
        }
    }

    public static void TryStopWindowsService()
    {
        try
        {
            if (IsServiceInstalled())
                RunSc($"stop {ServiceName}");
        }
        catch (Exception ex)
        {
            AppLogger.Warn("PlatformProtection", "TryStopWindowsService", ex);
        }
    }

    public static void TryUninstallWindowsService()
    {
        try
        {
            TryStopWindowsService();
            if (IsServiceInstalled())
                RunSc($"delete {ServiceName}");
        }
        catch (Exception ex)
        {
            AppLogger.Warn("PlatformProtection", "TryUninstallWindowsService", ex);
        }
    }

    private static bool IsServiceInstalled() => IsServiceInstalled(ServiceName);

    private static bool IsServiceInstalled(string serviceName)
    {
        try
        {
            using var proc = Process.Start(new ProcessStartInfo
            {
                FileName = SystemExecutables.System32("sc.exe"),
                Arguments = $"query {serviceName}",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
            });
            if (proc == null)
                return false;
            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(5_000);
            return proc.ExitCode == 0 && output.Contains("SERVICE_NAME", StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Lance sc.exe et rend son code de sortie (-1 : non lancé ou délai dépassé).</summary>
    private static int RunSc(string arguments)
    {
        using var proc = Process.Start(new ProcessStartInfo
        {
            FileName = SystemExecutables.System32("sc.exe"),
            Arguments = arguments,
            UseShellExecute = false,
            CreateNoWindow = true,
        });
        if (proc == null)
            return -1;
        if (!proc.WaitForExit(30_000))
        {
            try { proc.Kill(); } catch { /* déjà terminé */ }
            return -1;
        }
        return proc.ExitCode;
    }
}
