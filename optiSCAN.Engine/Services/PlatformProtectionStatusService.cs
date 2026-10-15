using System.Diagnostics;
using System.IO;
using System.Runtime.Versioning;
using Microsoft.Win32;
using optiSCAN.Platform;

namespace optiSCAN.Services;

public enum PlatformComponentState
{
    Active,
    Inactive,
    Warning,
    NotApplicable,
}

public sealed class PlatformComponentStatus
{
    public string LabelKey { get; init; } = string.Empty;
    public PlatformComponentState State { get; init; }
}

public sealed class PlatformProtectionStatusReport
{
    public IReadOnlyList<PlatformComponentStatus> Components { get; init; } = Array.Empty<PlatformComponentStatus>();
    public bool HasWarnings { get; init; }
}

/// <summary>État AMSI, minifilter, IPC et coexistence Defender.</summary>
[SupportedOSPlatform("windows")]
public static class PlatformProtectionStatusService
{
    private const string AmsiProviderGuid = "{A8F4E2B1-9C3D-4E5F-8A7B-1C2D3E4F5A6B}";

    private static readonly object ReportGate = new();
    private static readonly TimeSpan ReportCacheTtl = TimeSpan.FromSeconds(8);
    private static PlatformProtectionStatusReport? _cachedReport;
    private static DateTime _cachedReportAtUtc;

    public static PlatformProtectionStatusReport Evaluate(IUserPreferencesAccessor? preferences = null)
    {
        // Le cache sert au rafraîchissement de l'interface. Un accès explicite
        // (test, ou préférences qui viennent de changer) ne doit pas le relire.
        if (preferences == null)
        {
            lock (ReportGate)
            {
                if (_cachedReport != null && (DateTime.UtcNow - _cachedReportAtUtc) < ReportCacheTtl)
                    return _cachedReport;
            }
        }

        var report = EvaluateCore(preferences);
        if (preferences == null)
        {
            lock (ReportGate)
            {
                _cachedReport = report;
                _cachedReportAtUtc = DateTime.UtcNow;
            }
        }

        return report;
    }

    /// <summary>Invalide le rapport mis en cache (après un changement d'option ou un correctif).</summary>
    public static void InvalidateCache()
    {
        lock (ReportGate)
            _cachedReport = null;
    }

    private static PlatformProtectionStatusReport EvaluateCore(IUserPreferencesAccessor? preferences)
    {
        var items = new List<PlatformComponentStatus>();
        var prefs = (preferences ?? new DefaultUserPreferencesAccessor()).Current;

        if (prefs.UsePlatformProtectionService)
        {
            var ipc = PlatformProtectionBootstrap.IsRemoteProtectionActive();
            items.Add(new PlatformComponentStatus
            {
                LabelKey = ipc ? "Platform_IpcActive" : "Platform_IpcInactive",
                State = ipc ? PlatformComponentState.Active : PlatformComponentState.Warning,
            });
        }
        else
        {
            items.Add(new PlatformComponentStatus
            {
                LabelKey = "Platform_IpcDisabled",
                State = PlatformComponentState.NotApplicable,
            });
        }

        var dllPath = Path.Combine(AppContext.BaseDirectory, "optiSCAN.AmsiProvider.dll");
        var dllPresent = File.Exists(dllPath);

        if (!prefs.UsePlatformProtectionService)
        {
            items.Add(new PlatformComponentStatus
            {
                LabelKey = dllPresent ? "Platform_AmsiPresentInactive" : "Platform_AmsiDllMissing",
                State = PlatformComponentState.NotApplicable,
            });
        }
        else
        {
            var amsiRegistered = IsAmsiProviderRegistered(dllPath);

            if (!dllPresent)
            {
                items.Add(new PlatformComponentStatus
                {
                    LabelKey = "Platform_AmsiDllMissing",
                    State = PlatformComponentState.Warning,
                });
            }
            else if (!amsiRegistered)
            {
                items.Add(new PlatformComponentStatus
                {
                    LabelKey = "Platform_AmsiNotRegistered",
                    State = PlatformComponentState.Warning,
                });
            }
            else
            {
                items.Add(new PlatformComponentStatus
                {
                    LabelKey = "Platform_AmsiRegistered",
                    State = PlatformComponentState.Active,
                });
            }

            if (IsDefenderServiceRunning() && amsiRegistered)
            {
                items.Add(new PlatformComponentStatus
                {
                    LabelKey = "Platform_DefenderMayOverride",
                    State = PlatformComponentState.Warning,
                });
            }
        }

        var sysPresent = File.Exists(Path.Combine(AppContext.BaseDirectory, "optiSCAN.Minifilter.sys"));
        var fltLoaded = IsMinifilterLoaded();

        if (fltLoaded)
        {
            items.Add(new PlatformComponentStatus
            {
                LabelKey = "Platform_MinifilterLoaded",
                State = PlatformComponentState.Active,
            });
        }
        else if (sysPresent)
        {
            items.Add(new PlatformComponentStatus
            {
                LabelKey = "Platform_MinifilterNotLoaded",
                State = PlatformComponentState.Warning,
            });
        }
        else
        {
            items.Add(new PlatformComponentStatus
            {
                LabelKey = "Platform_MinifilterAbsent",
                State = PlatformComponentState.Inactive,
            });
        }

        return new PlatformProtectionStatusReport
        {
            Components = items,
            HasWarnings = items.Any(c => c.State is PlatformComponentState.Warning or PlatformComponentState.Inactive),
        };
    }

    internal static bool IsAmsiProviderRegistered(string expectedDllPath)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey($@"SOFTWARE\Microsoft\AMSI\Providers\{AmsiProviderGuid}");
            var path = key?.GetValue("Path") as string;
            return !string.IsNullOrWhiteSpace(path)
                && string.Equals(Path.GetFullPath(path), Path.GetFullPath(expectedDllPath), StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    internal static bool IsMinifilterLoaded()
    {
        try
        {
            using var proc = Process.Start(new ProcessStartInfo
            {
                FileName = SystemExecutables.System32("fltmc.exe"),
                Arguments = "filters",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
            });
            if (proc == null)
                return false;

            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(800);
            return output.Contains("optiSCANMinifilter", StringComparison.OrdinalIgnoreCase)
                || output.Contains("optiSCAN.Minifilter", StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private static bool IsDefenderServiceRunning()
    {
        try
        {
            using var sc = new System.ServiceProcess.ServiceController("WinDefend");
            return sc.Status == System.ServiceProcess.ServiceControllerStatus.Running;
        }
        catch
        {
            return false;
        }
    }
}
