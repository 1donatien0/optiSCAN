namespace optiSCAN.Services;

/// <summary>Planifie du travail sur le thread UI (WPF Dispatcher ou WinUI DispatcherQueue).</summary>
public interface IUiThreadScheduler
{
    void Invoke(Action action);

    void BeginInvoke(Action action);
}

/// <summary>Exécution synchrone sur le thread appelant (tests, headless).</summary>
public sealed class SyncUiThreadScheduler : IUiThreadScheduler
{
    public static SyncUiThreadScheduler Instance { get; } = new();

    public void Invoke(Action action) => action();

    public void BeginInvoke(Action action) => action();
}
