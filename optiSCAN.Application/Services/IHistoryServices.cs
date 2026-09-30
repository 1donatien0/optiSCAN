namespace optiSCAN.Services;

/// <summary>
/// Services exposés à <see cref="optiSCAN.Views.HistoryControl"/> (sans <see cref="ServiceContainer"/> complet).
/// <see cref="ServiceContainer"/> l'implémente ; assigner via <c>Bind()</c> depuis <see cref="optiSCAN.MainWindow"/>.
/// </summary>
public interface IHistoryServices : IViewServices
{
    ActivityLogService ActivityLog { get; }
}
