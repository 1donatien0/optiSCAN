using Microsoft.Extensions.DependencyInjection;

namespace optiSCAN.Services.DependencyInjection;

/// <summary>
/// Services du moteur (sans interface). L'appelant enregistre <see cref="INotificationSink"/> :
/// toasts dans l'interface, journal dans l'hôte SYSTEM.
/// </summary>
public static class EngineServiceRegistration
{
    public static IServiceCollection AddOptiscanEngineServices(this IServiceCollection services)
    {
        services.AddSingleton<IUserPreferencesAccessor, DefaultUserPreferencesAccessor>();
        services.AddSingleton<IExclusionSettingsAccessor, DefaultExclusionSettingsAccessor>();
        services.AddSingleton<UiEventBus>();
        services.AddSingleton<IUiEventBus>(sp => sp.GetRequiredService<UiEventBus>());
        services.AddSingleton<ClamAvEngine>(sp =>
            new ClamAvEngine(exclusions: sp.GetRequiredService<IExclusionSettingsAccessor>()));
        services.AddSingleton<ClamdEngine>(sp =>
            new ClamdEngine(
                sp.GetRequiredService<IUserPreferencesAccessor>(),
                sp.GetRequiredService<IExclusionSettingsAccessor>()));
        services.AddSingleton<CompositeClamAvBackend>(sp =>
            new CompositeClamAvBackend(sp.GetRequiredService<ClamdEngine>(), sp.GetRequiredService<ClamAvEngine>()));
        services.AddSingleton<YaraEngine>(sp =>
            new YaraEngine(exclusions: sp.GetRequiredService<IExclusionSettingsAccessor>()));
        services.AddSingleton<FreshclamUpdater>();
        services.AddSingleton<YaraForgeUpdater>();
        services.AddSingleton<QuarantineManager>(sp =>
            new QuarantineManager(preferences: sp.GetRequiredService<IUserPreferencesAccessor>()));
        services.AddSingleton<ScanLogManager>();
        services.AddSingleton<ActivityLogService>(sp =>
            new ActivityLogService(sp.GetRequiredService<ScanLogManager>()));
        services.AddSingleton<ScanOrchestrator>(sp =>
            new ScanOrchestrator(
                sp.GetRequiredService<CompositeClamAvBackend>(),
                sp.GetRequiredService<YaraEngine>(),
                sp.GetRequiredService<IUserPreferencesAccessor>(),
                sp.GetRequiredService<IExclusionSettingsAccessor>()));
        services.AddSingleton<ClamAvScanEngineAdapter>(sp =>
            new ClamAvScanEngineAdapter(sp.GetRequiredService<ClamAvEngine>()));
        services.AddSingleton<IScanEngine>(sp => sp.GetRequiredService<ClamAvScanEngineAdapter>());
        services.AddSingleton<ThreatReputationService>(sp =>
            new ThreatReputationService(preferences: sp.GetRequiredService<IUserPreferencesAccessor>()));
        services.AddSingleton<IThreatReputationService>(sp => sp.GetRequiredService<ThreatReputationService>());
        services.AddSingleton<CloudThreatIntelService>();
        services.AddSingleton<ISecurityPostureService, SecurityPostureService>();
        services.AddSingleton<RealTimeProtection>(sp =>
            new RealTimeProtection(
                sp.GetRequiredService<ScanOrchestrator>(),
                sp.GetRequiredService<QuarantineManager>(),
                sp.GetRequiredService<INotificationSink>(),
                sp.GetRequiredService<IUserPreferencesAccessor>(),
                sp.GetRequiredService<IExclusionSettingsAccessor>(),
                sp.GetRequiredService<ScanLogManager>(),
                sp.GetRequiredService<IUiEventBus>()));
        services.AddSingleton<ProcessStartMonitor>(sp =>
        {
            var rtp = sp.GetRequiredService<RealTimeProtection>();
            return new ProcessStartMonitor(
                sp.GetRequiredService<ScanOrchestrator>(),
                sp.GetRequiredService<QuarantineManager>(),
                sp.GetRequiredService<INotificationSink>(),
                () => rtp.IsPaused,
                sp.GetRequiredService<IUserPreferencesAccessor>(),
                sp.GetRequiredService<IExclusionSettingsAccessor>(),
                sp.GetRequiredService<ScanLogManager>(),
                sp.GetRequiredService<IUiEventBus>());
        });
        services.AddSingleton<ProtectionWatchdogService>(sp =>
            new ProtectionWatchdogService(
                sp.GetRequiredService<IUserPreferencesAccessor>(),
                sp.GetRequiredService<IExclusionSettingsAccessor>()));
        services.AddSingleton<RemovableDriveScanService>(sp =>
            new RemovableDriveScanService(
                sp.GetRequiredService<ScanOrchestrator>(),
                sp.GetRequiredService<QuarantineManager>(),
                sp.GetRequiredService<INotificationSink>(),
                sp.GetRequiredService<ScanLogManager>(),
                sp.GetRequiredService<IUiEventBus>(),
                sp.GetRequiredService<IUserPreferencesAccessor>(),
                sp.GetRequiredService<IExclusionSettingsAccessor>()));
        services.AddSingleton<ScheduledScanService>();
        return services;
    }
}
