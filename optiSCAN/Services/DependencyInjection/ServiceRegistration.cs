using Microsoft.Extensions.DependencyInjection;

namespace optiSCAN.Services.DependencyInjection;

/// <summary>Enregistrement DI de l'interface : moteur, puis services propres à WPF.</summary>
public static class ServiceRegistration
{
    public static IServiceCollection AddOptiscanCoreServices(this IServiceCollection services)
    {
        services.AddSingleton<NotificationService>(sp =>
            new NotificationService(sp.GetRequiredService<IUserPreferencesAccessor>()));
        services.AddSingleton<INotificationSink>(sp => sp.GetRequiredService<NotificationService>());
        services.AddOptiscanEngineServices();
        services.AddSingleton<SignatureStatusService>(sp =>
            new SignatureStatusService(
                sp.GetRequiredService<FreshclamUpdater>(),
                sp.GetRequiredService<YaraForgeUpdater>(),
                sp.GetRequiredService<YaraEngine>()));
        services.AddSingleton<IHistoryExportService, HistoryExportService>();
        services.AddSingleton<HistoryExportService>(sp =>
            (HistoryExportService)sp.GetRequiredService<IHistoryExportService>());
        return services;
    }
}
