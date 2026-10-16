// SPDX-License-Identifier: GPL-3.0-or-later
using System.Reflection;
using optiSCAN.Services;

namespace optiSCAN.Tests;

/// <summary>R10 : le moteur et l'hôte SYSTEM ne chargent aucune bibliothèque d'interface.</summary>
public sealed class EngineArchitectureTests
{
    private static readonly string[] UiAssemblies =
    {
        "PresentationFramework", "PresentationCore", "WindowsBase", "System.Windows.Forms",
        "System.Xaml", "MaterialDesignThemes.Wpf", "MaterialDesignColors", "Microsoft.Toolkit.Uwp.Notifications",
    };

    [Fact]
    public void Engine_references_no_ui_library()
    {
        var engine = typeof(ScanOrchestrator).Assembly;
        Assert.Equal("optiSCAN.Engine", engine.GetName().Name);
        var references = engine.GetReferencedAssemblies().Select(a => a.Name).ToList();
        Assert.DoesNotContain(references, r => UiAssemblies.Contains(r, StringComparer.OrdinalIgnoreCase));
    }

    [Fact]
    public void Host_references_no_ui_library()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "optiSCAN.Host.dll");
        if (!File.Exists(path))
            return; // l'hôte n'est copié que si le projet de tests le référence
        var name = AssemblyName.GetAssemblyName(path);
        var host = System.Runtime.Loader.AssemblyLoadContext.Default.LoadFromAssemblyName(name);
        var references = host.GetReferencedAssemblies().Select(a => a.Name).ToList();
        Assert.Contains("optiSCAN.Engine", references);
        Assert.DoesNotContain(references, r => UiAssemblies.Contains(r, StringComparer.OrdinalIgnoreCase));
        Assert.DoesNotContain("optiSCAN", references);
    }

    [Fact]
    public void Host_container_implements_the_service_host_contract_without_ui_services()
    {
        var type = typeof(ProtectionHostContainer);
        Assert.True(typeof(IProtectionServiceHostDependencies).IsAssignableFrom(type));
        Assert.DoesNotContain(type.GetProperties(), p => p.PropertyType.Assembly != type.Assembly
            && p.PropertyType.Assembly.GetName().Name == "optiSCAN");
    }

    [Fact]
    public void Log_sink_never_throws()
    {
        var sink = new LogNotificationSink();
        var threat = new optiSCAN.Models.ThreatInfo { FilePath = Path.Combine(Path.GetTempPath(), "x.exe"), VirusName = "Test" };
        sink.ShowThreatDetected(threat);
        sink.ShowQuarantined(threat);
        sink.ShowServiceThreat(threat);
        sink.ShowServiceThreatsSummary(2);
        sink.ShowRealTimeDegraded(1);
        sink.ShowRemovableDriveScanStarted("USB");
        sink.ShowRemovableDriveScanCompleted("USB", 0, 3);
    }

    [Fact]
    public void Engine_declares_platform_calls_only_in_its_native_modules()
    {
        var allowed = new HashSet<string>(StringComparer.Ordinal)
        {
            "NativeMethods", "ClamdIsolation", "SafePathDelete", "RealTimePathGuard", "NamedPipeClientAccess",
            "PipeServerAccount", "ProtectionPipeAcl", "MinifilterUserBridge", "ClamdPipeAcl",
        };
        var declaring = typeof(ScanOrchestrator).Assembly.GetTypes()
            .SelectMany(t => t.GetMethods(BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly))
            .Where(m => (m.Attributes & MethodAttributes.PinvokeImpl) != 0)
            .Select(m => OuterName(m.DeclaringType!))
            .Distinct()
            .ToList();
        Assert.NotEmpty(declaring);
        Assert.All(declaring, name => Assert.Contains(name, allowed));
    }

    private static string OuterName(Type type)
    {
        while (type.DeclaringType != null)
            type = type.DeclaringType;
        return type.Name;
    }
}
