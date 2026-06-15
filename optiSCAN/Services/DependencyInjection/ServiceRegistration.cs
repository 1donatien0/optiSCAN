using Microsoft.Extensions.DependencyInjection;

namespace optiSCAN.Services.DependencyInjection;

/// <summary>Enregistrement DI Microsoft.Extensions pour optiSCAN (v8).</summary>
public static class ServiceRegistration
{
    public static IServiceCollection AddOptiscanCoreServices(this IServiceCollection services)
    {
        services.AddSingleton<ClamAvEngine>();
        services.AddSingleton<ClamdEngine>();
        services.AddSingleton<CompositeClamAvBackend>(sp =>
            new CompositeClamAvBackend(sp.GetRequiredService<ClamdEngine>(), sp.GetRequiredService<ClamAvEngine>()));
        services.AddSingleton<YaraEngine>();
        services.AddSingleton<FreshclamUpdater>();
        services.AddSingleton<YaraForgeUpdater>();
        services.AddSingleton<QuarantineManager>();
        services.AddSingleton<ScanLogManager>();
        services.AddSingleton<ActivityLogService>(sp =>
            new ActivityLogService(sp.GetRequiredService<ScanLogManager>()));
        services.AddSingleton<NotificationService>();
        services.AddSingleton<ScanOrchestrator>(sp =>
            new ScanOrchestrator(sp.GetRequiredService<CompositeClamAvBackend>(), sp.GetRequiredService<YaraEngine>()));
        services.AddSingleton<ClamAvScanEngineAdapter>(sp =>
            new ClamAvScanEngineAdapter(sp.GetRequiredService<ClamAvEngine>()));
        services.AddSingleton<IScanEngine>(sp => sp.GetRequiredService<ClamAvScanEngineAdapter>());
        services.AddSingleton<ThreatReputationService>();
        services.AddSingleton<IThreatReputationService>(sp => sp.GetRequiredService<ThreatReputationService>());
        services.AddSingleton<CloudThreatIntelService>();
        services.AddSingleton<ISecurityPostureService, SecurityPostureService>();
        services.AddSingleton<SignatureStatusService>(sp =>
            new SignatureStatusService(
                sp.GetRequiredService<FreshclamUpdater>(),
                sp.GetRequiredService<YaraForgeUpdater>(),
                sp.GetRequiredService<YaraEngine>()));
        services.AddSingleton<RealTimeProtection>(sp =>
            new RealTimeProtection(
                sp.GetRequiredService<ScanOrchestrator>(),
                sp.GetRequiredService<QuarantineManager>(),
                sp.GetRequiredService<NotificationService>()));
        services.AddSingleton<ProcessStartMonitor>(sp =>
        {
            var rtp = sp.GetRequiredService<RealTimeProtection>();
            return new ProcessStartMonitor(
                sp.GetRequiredService<ScanOrchestrator>(),
                sp.GetRequiredService<QuarantineManager>(),
                sp.GetRequiredService<NotificationService>(),
                () => rtp.IsPaused);
        });
        services.AddSingleton<TamperProtectionService>();
        services.AddSingleton<RemovableDriveScanService>(sp =>
            new RemovableDriveScanService(
                sp.GetRequiredService<ScanOrchestrator>(),
                sp.GetRequiredService<QuarantineManager>(),
                sp.GetRequiredService<NotificationService>(),
                sp.GetRequiredService<ScanLogManager>()));
        services.AddSingleton<ScheduledScanService>();
        return services;
    }
}
