namespace optiSCAN.Services;

/// <summary>Confirmations utilisateur (découple le ViewModel de MessageBox).</summary>
public interface IUserConfirmService
{
    bool ConfirmYesNo(string message, string title, bool warning = true);

    void Inform(string message, string title);

    void Warn(string message, string title);
}

/// <summary>Refuse par défaut (headless / WinUI sans dialogue encore branché).</summary>
public sealed class DeclineUserConfirmService : IUserConfirmService
{
    public static DeclineUserConfirmService Instance { get; } = new();

    public bool ConfirmYesNo(string message, string title, bool warning = true) => false;

    public void Inform(string message, string title) { }

    public void Warn(string message, string title) { }
}
