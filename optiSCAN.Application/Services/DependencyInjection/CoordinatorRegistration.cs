using Microsoft.Extensions.DependencyInjection;
using optiSCAN.Coordinators;
using optiSCAN.Services.Ipc;

namespace optiSCAN.Services.DependencyInjection;

/// <summary>Coordinateurs et client IPC enregistrés dans le conteneur DI.</summary>
public static class CoordinatorRegistration
{
    public static IServiceCollection AddOptiscanCoordinators(this IServiceCollection services)
    {
        services.AddSingleton<IProtectionPipeClient, ProtectionPipeClientAdapter>();
        services.AddSingleton<HistoryThreatRemediationService>();
        services.AddSingleton<SignatureUpdateService>();
        services.AddSingleton<SignatureUpdateUiRunner>();
        return services;
    }
}
